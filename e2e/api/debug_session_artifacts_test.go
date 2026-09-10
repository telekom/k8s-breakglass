//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	artifactarchive "github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
)

// This named CI lane requires its fixture; missing configuration is a failure.
func TestDebugSessionArtifactCollectorE2E(t *testing.T) {
	for _, recipe := range []string{artifactarchive.SystemSummaryRecipe, artifactarchive.CrashdumpCollectionRecipe} {
		for _, cleanup := range []string{"terminate", "expire", "delete"} {
			t.Run(recipe+"/"+cleanup, func(t *testing.T) { testArtifactRecipeLifecycle(t, recipe, cleanup) })
		}
	}
}

func testArtifactRecipeLifecycle(t *testing.T, recipe, cleanup string) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	image := os.Getenv("E2E_ARTIFACT_IMAGE_DIGEST")
	backend := os.Getenv("E2E_ARTIFACT_BACKEND")
	require.Contains(t, []string{"local", "s3"}, backend, "backend must be selected explicitly")
	require.Contains(t, image, "@sha256:", "run e2e/fixtures/artifacts/setup.sh first")
	ctx, ns := s.Ctx, s.Namespace
	tc := helpers.NewTestContext(t, ctx)
	requester := helpers.NewAPIClientWithAuth(tc.OIDCProvider().GetTokenForUser(t, ctx, helpers.TestUsers.SecurityRequester))
	outsider := helpers.NewAPIClientWithAuth(tc.OIDCProvider().GetTokenForUser(t, ctx, helpers.TestUsers.UnauthorizedUser))
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("artifact-e2e-%d", time.Now().UnixNano())}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		Mode: breakglassv1alpha1.DebugSessionModeWorkload, TargetNamespace: ns,
		Allowed:            &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{s.Cluster}, Groups: []string{"*"}},
		ArtifactCollection: &breakglassv1alpha1.DebugSessionArtifactCollection{AllowedRecipes: []string{recipe}},
		PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: artifact-target
spec:
  containers:
  - name: target
    image: ` + image + `
    command: ["/bin/sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 65532
      seccompProfile:
        type: RuntimeDefault
`}}
	require.NoError(t, s.Client.Create(ctx, template))
	t.Cleanup(func() { _ = s.Client.Delete(ctx, template) })
	session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "30m", Reason: "artifact real collector proof"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = requester.TerminateDebugSession(ctx, t, session.Name) })
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, ns, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.NotNil(t, active.Status.ConnectionLease)
	require.NotEmpty(t, active.Status.ConnectionLease.UID)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(active), active) != nil {
			return false
		}
		return len(active.Status.AllowedPods) > 0
	}, helpers.WaitForStateTimeout, time.Second)
	pod := active.Status.AllowedPods[0]
	require.NotEmpty(t, pod.UID)
	var target corev1.Pod
	require.NoError(t, s.Client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &target))
	request := helpers.DebugSessionArtifactRequest{Recipe: recipe, PodNamespace: pod.Namespace, PodName: pod.Name}
	expected := artifactarchive.Expected{Recipe: recipe, RecipeVersion: 1, Inputs: artifactarchive.Inputs{MaxArchiveBytes: 16777216}, SessionNamespace: ns, SessionName: session.Name, SessionUID: string(active.UID), RedactionProfile: "credential-text.v1", RedactionVersion: 1}
	if recipe == artifactarchive.SystemSummaryRecipe {
		request.DetailLevel = "basic"
		expected.Inputs.DetailLevel = &request.DetailLevel
	} else {
		request.MaxAgeMinutes = 60
		expected.Node = &target.Spec.NodeName
		expected.Inputs.Node = &target.Spec.NodeName
		expected.Inputs.MaxAgeMinutes = &request.MaxAgeMinutes
	}
	endpoint := "/api/debugSessionArtifacts/" + ns + "/" + session.Name
	status := func(api *helpers.APIClient, method, path string, body []byte, token string) int {
		req, e := http.NewRequestWithContext(ctx, method, api.BaseURL+path, bytes.NewReader(body))
		require.NoError(t, e)
		if token == "" {
			token = api.AuthToken
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := api.HTTPClient.Do(req)
		require.NoError(t, e)
		defer resp.Body.Close()
		_, e = io.Copy(io.Discard, resp.Body)
		require.NoError(t, e)
		return resp.StatusCode
	}
	files := func() []string {
		args := []string{"-n", ns, "exec", "deployment/breakglass-manager", "-c", "artifact-tls", "--", "find", "/artifacts/objects", "-type", "f"}
		if backend == "s3" {
			args = []string{"-n", ns, "exec", "deployment/breakglass-manager", "-c", "artifact-tls", "--", "/fixture", "s3-inventory"}
		}
		output, e := exec.CommandContext(ctx, "kubectl", args...).Output()
		require.NoError(t, e)
		result := []string{}
		for _, name := range strings.Fields(string(output)) {
			if !strings.HasSuffix(name, "/.breakglass-artifact-instance-v1") {
				if backend == "local" {
					mode, e := exec.CommandContext(ctx, "kubectl", "-n", ns, "exec", "deployment/breakglass-manager", "-c", "artifact-tls", "--", "stat", "-c", "%a %u %g", name).Output()
					require.NoError(t, e)
					require.Equal(t, "600 65532 65532", strings.TrimSpace(string(mode)))
				}
				result = append(result, name)
			}
		}
		sort.Strings(result)
		return result
	}
	baseline := files()
	collect := func() (*breakglassv1alpha1.DebugSessionArtifact, []byte, string) {
		admitted, e := requester.CollectDebugSessionArtifact(ctx, ns, session.Name, request)
		require.NoError(t, e)
		var object breakglassv1alpha1.DebugSessionArtifact
		require.Eventually(t, func() bool {
			list := &breakglassv1alpha1.DebugSessionArtifactList{}
			if s.Client.List(ctx, list, client.InNamespace(ns)) != nil {
				return false
			}
			for _, item := range list.Items {
				if item.Spec.ArtifactID == admitted.ArtifactID {
					object = item
					return string(item.Status.State) == "Available" && len(item.Status.Resources) == 2
				}
			}
			return false
		}, helpers.WaitForStateTimeout, time.Second)
		require.NotEmpty(t, object.UID)
		require.Len(t, object.Status.Resources, 2)
		var token string
		for _, ref := range object.Status.Resources {
			require.NotEmpty(t, ref.UID)
			if ref.Kind == "Job" {
				var job batchv1.Job
				require.NoError(t, s.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &job))
				require.Equal(t, ref.UID, string(job.UID))
				require.Eventually(t, func() bool {
					_ = s.Client.Get(ctx, client.ObjectKeyFromObject(&job), &job)
					return job.Status.Succeeded == 1
				}, helpers.WaitForStateTimeout, time.Second)
				require.Equal(t, image, job.Spec.Template.Spec.InitContainers[0].Image)
				require.Equal(t, image, job.Spec.Template.Spec.Containers[0].Image)
				require.NotNil(t, job.Spec.Template.Spec.SecurityContext.FSGroup)
				pods := &corev1.PodList{}
				require.NoError(t, s.Client.List(ctx, pods, client.InNamespace(ref.Namespace), client.MatchingLabels{"job-name": ref.Name}))
				require.Len(t, pods.Items, 1)
				admitted := pods.Items[0].Spec
				require.Equal(t, image, admitted.InitContainers[0].Image)
				require.Equal(t, image, admitted.Containers[0].Image)
				require.False(t, admitted.HostNetwork)
				require.False(t, admitted.HostPID)
				require.False(t, admitted.HostIPC)
				require.Nil(t, admitted.RuntimeClassName)
				require.Nil(t, admitted.ShareProcessNamespace)
				require.Empty(t, admitted.PriorityClassName)
				require.Empty(t, admitted.Overhead)
				require.Equal(t, "default-scheduler", admitted.SchedulerName)
				require.Equal(t, "default", admitted.ServiceAccountName)
				require.Empty(t, admitted.NodeSelector)
				require.Nil(t, admitted.Affinity)
				require.Equal(t, corev1.DNSClusterFirst, admitted.DNSPolicy)
				require.Len(t, admitted.InitContainers, 1)
				require.Len(t, admitted.Containers, 1)
				require.Equal(t, []string{"/usr/local/bin/diagnostic-artifact-collector", "collect", "--recipe", recipe, "--output", "/output/artifact.tar.gz"}, admitted.InitContainers[0].Command)
				require.Equal(t, []string{"/usr/local/bin/diagnostic-artifact-collector", "upload", "--archive", "/output/artifact.tar.gz"}, admitted.Containers[0].Command)
				require.Empty(t, admitted.InitContainers[0].Args)
				require.Empty(t, admitted.Containers[0].Args)
				seconds := int64(300)
				require.ElementsMatch(t, []corev1.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &seconds}, {Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: &seconds}}, admitted.Tolerations)

				require.NotNil(t, admitted.AutomountServiceAccountToken)
				require.False(t, *admitted.AutomountServiceAccountToken)
				for _, c := range append(admitted.InitContainers, admitted.Containers...) {
					require.Empty(t, c.SecurityContext.Capabilities.Add)
					for _, env := range c.Env {
						require.NotContains(t, env.Name, "AWS_")
						require.NotContains(t, env.Value, "artifact-s3")
						require.NotContains(t, env.Value, "artifact-kind")
					}
				}
				hostMounts := 0
				for _, v := range admitted.Volumes {
					if v.HostPath != nil {
						hostMounts++
						require.Equal(t, "/var/lib/systemd/coredump", v.HostPath.Path)
						require.Equal(t, corev1.HostPathDirectory, *v.HostPath.Type)
					}
				}
				if recipe == artifactarchive.CrashdumpCollectionRecipe {
					require.Equal(t, target.Spec.NodeName, admitted.NodeName)
					require.Equal(t, 1, hostMounts)
					require.Contains(t, admitted.InitContainers[0].VolumeMounts, corev1.VolumeMount{Name: "host-coredumps", MountPath: "/host-coredumps", ReadOnly: true})
					require.Len(t, admitted.Containers[0].VolumeMounts, 1)
				} else {
					require.Zero(t, hostMounts)
				}
			} else if ref.Kind == "Secret" {
				var secret corev1.Secret
				require.NoError(t, s.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &secret))
				require.Equal(t, ref.UID, string(secret.UID))
				token = string(secret.Data["token"])
			}
		}
		require.NotEmpty(t, token)
		data, e := requester.DownloadDebugSessionArtifact(ctx, ns, session.Name, admitted.ArtifactID)
		require.NoError(t, e)
		require.Equal(t, object.Status.SHA256, fmt.Sprintf("%x", sha256.Sum256(data)))
		expected.ArtifactID = admitted.ArtifactID
		_, e = artifactarchive.Validate(ctx, bytes.NewReader(data), int64(len(data)), expected, artifactarchive.Limits{})
		require.NoError(t, e)
		reader, e := gzip.NewReader(bytes.NewReader(data))
		require.NoError(t, e)
		tr := tar.NewReader(reader)
		entries := map[string][]byte{}
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			if h.Typeflag == tar.TypeReg {
				contents, err := io.ReadAll(io.LimitReader(tr, 16777217))
				require.NoError(t, err)
				entries[h.Name] = contents
			}
		}
		require.NoError(t, reader.Close())
		require.Contains(t, entries, "stdout.log")
		require.Contains(t, entries, "stderr.log")
		require.Contains(t, entries, "manifest.json")
		if recipe == artifactarchive.CrashdumpCollectionRecipe {
			require.Equal(t, []byte("artifact-kind-synthetic-dump\n"), entries["files/coredumps/core.artifact-kind-fixture"])
		} else {
			require.Contains(t, entries, "files/system-summary.json")
		}
		return &object, data, token
	}
	first, data, token := collect()
	assertArtifactRequesterCannotForge(t, s, first)
	afterFirst := files()
	require.Len(t, afterFirst, len(baseline)+1)
	control, controlData, _ := collect()
	// Restart the actual controller, retaining the PVC or versioned S3 store.
	restart, e := exec.CommandContext(ctx, "kubectl", "-n", ns, "rollout", "restart", "deployment/breakglass-manager").CombinedOutput()
	require.NoError(t, e, string(restart))
	ready, e := exec.CommandContext(ctx, "kubectl", "-n", ns, "rollout", "status", "deployment/breakglass-manager", "--timeout=180s").CombinedOutput()
	require.NoError(t, e, string(ready))
	require.Eventually(t, func() bool {
		got, e := requester.DownloadDebugSessionArtifact(ctx, ns, session.Name, control.Spec.ArtifactID)
		return e == nil && bytes.Equal(got, controlData)
	}, helpers.WaitForStateTimeout, time.Second)
	require.Len(t, files(), len(baseline)+2)
	metadata, err := requester.ListDebugSessionArtifacts(ctx, ns, session.Name)
	require.NoError(t, err)
	require.Len(t, metadata, 2)
	publicJSON, e := json.Marshal(metadata)
	require.NoError(t, e)
	var providerSecret corev1.Secret
	require.NoError(t, s.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: "artifact-e2e-s3"}, &providerSecret))
	for _, value := range providerSecret.Data {
		require.False(t, bytes.Contains(publicJSON, value), "metadata leaked provider credential")
	}
	for _, private := range []string{"artifact-s3", "artifact-kind", "/artifacts/", "accessKeyID", "secretAccessKey"} {
		require.False(t, strings.Contains(string(publicJSON), private), "metadata leaked provider location or credential field")
	}
	if cleanup == "terminate" {
		other, e := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "30m", Reason: "cross-session artifact denial"})
		require.NoError(t, e)
		t.Cleanup(func() { _ = requester.TerminateDebugSession(ctx, t, other.Name) })
		helpers.WaitForDebugSessionState(t, ctx, s.Client, other.Name, ns, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
		require.Equal(t, http.StatusNotFound, status(requester, http.MethodGet, "/api/debugSessionArtifacts/"+ns+"/"+other.Name+"/"+first.Spec.ArtifactID, nil, ""))
		require.NoError(t, requester.TerminateDebugSession(ctx, t, other.Name))
	}

	require.ElementsMatch(t, []string{first.Spec.ArtifactID, control.Spec.ArtifactID}, []string{metadata[0].ArtifactID, metadata[1].ArtifactID})
	require.Equal(t, http.StatusNotFound, status(outsider, http.MethodGet, endpoint, nil, ""))
	require.Equal(t, http.StatusNotFound, status(outsider, http.MethodGet, endpoint+"/"+first.Spec.ArtifactID, nil, ""))
	require.Equal(t, http.StatusConflict, status(requester, http.MethodPut, "/api/debugSessionArtifactUploads/"+ns+"/"+session.Name+"/"+first.Spec.ArtifactID, data, token))
	for _, invalid := range []helpers.DebugSessionArtifactRequest{{Recipe: "unknown", PodNamespace: pod.Namespace, PodName: pod.Name}, {Recipe: request.Recipe, PodNamespace: pod.Namespace, PodName: "not-approved"}} {
		body, marshalErr := json.Marshal(invalid)
		require.NoError(t, marshalErr)
		require.Equal(t, http.StatusForbidden, status(requester, http.MethodPost, endpoint, body, ""))
	}
	for _, field := range []string{"command", "args", "image", "path", "mounts"} {
		invalid := map[string]string{"recipe": request.Recipe, "podNamespace": pod.Namespace, "podName": pod.Name, field: "injected"}
		body, e := json.Marshal(invalid)
		require.NoError(t, e)
		require.Equal(t, http.StatusBadRequest, status(requester, http.MethodPost, endpoint, body, ""))
	}
	body, marshalErr := json.Marshal(request)
	require.NoError(t, marshalErr)
	require.Equal(t, http.StatusForbidden, status(outsider, http.MethodPost, endpoint, body, ""))
	reservations := &breakglassv1alpha1.DebugSessionArtifactList{}
	require.NoError(t, s.Client.List(ctx, reservations, client.InNamespace(ns)))
	count := 0
	for _, r := range reservations.Items {
		if r.Spec.SessionRef.UID == string(active.UID) {
			count++
		}
	}
	require.Equal(t, 2, count)
	require.NoError(t, s.Client.Delete(ctx, first))
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(s.Client.Get(ctx, client.ObjectKeyFromObject(first), &breakglassv1alpha1.DebugSessionArtifact{}))
	}, helpers.WaitForStateTimeout, time.Second)
	for _, ref := range first.Status.Resources {
		var obj client.Object
		if ref.Kind == "Job" {
			obj = &batchv1.Job{}
		} else {
			obj = &corev1.Secret{}
		}
		require.Eventually(t, func() bool {
			return apierrors.IsNotFound(s.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, obj))
		}, helpers.WaitForStateTimeout, time.Second)
	}
	remaining := files()
	require.Len(t, remaining, len(baseline)+1)
	require.NotEqual(t, afterFirst, remaining)
	_, err = requester.DownloadDebugSessionArtifact(ctx, ns, session.Name, control.Spec.ArtifactID)
	require.NoError(t, err, "control object must remain readable")
	switch cleanup {
	case "terminate":
		require.NoError(t, requester.TerminateDebugSession(ctx, t, session.Name))
	case "expire":
		require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(active), active))
		before := active.DeepCopy()
		active.Status.ExpiresAt = &metav1.Time{Time: time.Now().Add(-time.Minute)}
		require.NoError(t, s.Client.Status().Patch(ctx, active, client.MergeFrom(before)))
	case "delete":
		require.NoError(t, s.Client.Delete(ctx, active))
	}
	require.Eventually(t, func() bool { return len(files()) == len(baseline) }, helpers.WaitForStateTimeout, time.Second)
	for _, ref := range control.Status.Resources {
		var obj client.Object = &corev1.Secret{}
		if ref.Kind == "Job" {
			obj = &batchv1.Job{}
		}
		require.Eventually(t, func() bool {
			return apierrors.IsNotFound(s.Client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, obj))
		}, helpers.WaitForStateTimeout, time.Second)
	}
	require.Equal(t, http.StatusNotFound, status(requester, http.MethodGet, endpoint+"/"+control.Spec.ArtifactID, nil, ""))
	require.Equal(t, http.StatusNotFound, status(requester, http.MethodGet, endpoint, nil, ""))
	if e := s.Client.Delete(ctx, control); !apierrors.IsNotFound(e) {
		require.NoError(t, e)
	}
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(s.Client.Get(ctx, client.ObjectKeyFromObject(control), &breakglassv1alpha1.DebugSessionArtifact{}))
	}, helpers.WaitForStateTimeout, time.Second)
	require.Equal(t, baseline, files(), "actual provider files must be removed")
}

// Use the same requester identity/groups as the authenticated collection API.
// Labels never grant permission to mutate the controller execution namespace.
func assertArtifactRequesterCannotForge(t *testing.T, s *helpers.TestSetup, artifact *breakglassv1alpha1.DebugSessionArtifact) {
	t.Helper()
	config := rest.CopyConfig(helpers.GetConfig(t))
	user := helpers.TestUsers.SecurityRequester
	config.Impersonate = rest.ImpersonationConfig{UserName: user.Email, Groups: user.Groups}
	low, err := client.New(config, client.Options{Scheme: s.Client.Scheme()})
	require.NoError(t, err)
	objects := []client.Object{}
	for _, ref := range artifact.Status.Resources {
		var obj client.Object = &corev1.Secret{}
		if ref.Kind == "Job" {
			obj = &batchv1.Job{}
		}
		require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, obj))
		objects = append(objects, obj)
		if ref.Kind == "Job" {
			pods := &corev1.PodList{}
			require.NoError(t, s.Client.List(s.Ctx, pods, client.InNamespace(ref.Namespace), client.MatchingLabels{"job-name": ref.Name}))
			require.Len(t, pods.Items, 1)
			objects = append(objects, &pods.Items[0])
		}
	}
	labels := objects[0].GetLabels()
	objects = append(objects, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: artifact.Name + "-forged", Namespace: artifact.Namespace, Labels: labels}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: labels}}})
	for _, obj := range objects {
		forged := obj.DeepCopyObject().(client.Object)
		forged.SetName(artifact.Name + "-forged")
		forged.SetResourceVersion("")
		forged.SetUID("")
		forged.SetManagedFields(nil)
		forged.SetOwnerReferences(nil)
		require.True(t, apierrors.IsForbidden(low.Create(s.Ctx, forged)), "requester create %T must be forbidden", obj)
		patch := client.RawPatch("application/merge-patch+json", []byte(`{"metadata":{"annotations":{"forged":"true"}}}`))
		require.True(t, apierrors.IsForbidden(low.Patch(s.Ctx, obj, patch)), "requester patch %T must be forbidden", obj)
		require.True(t, apierrors.IsForbidden(low.Delete(s.Ctx, obj)), "requester delete %T must be forbidden", obj)
	}
	// This upstream fixture has no Kyverno installation: verify authorization,
	// without pretending that a fake CRD proves downstream policy execution.
	for _, verb := range []string{"create", "patch", "delete"} {
		review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user.Email, Groups: user.Groups, ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: artifact.Namespace, Group: "kyverno.io", Resource: "policyexceptions", Verb: verb}}}
		require.NoError(t, s.Client.Create(s.Ctx, review))
		require.False(t, review.Status.Allowed)
	}
}
