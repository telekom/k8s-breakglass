//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
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
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	artifactarchive "github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
)

// This named CI lane requires its fixture; missing configuration is a failure.
func TestDebugSessionArtifactCollectorE2E(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	image := os.Getenv("E2E_ARTIFACT_IMAGE_DIGEST")
	require.Contains(t, image, "@sha256:", "run e2e/fixtures/artifacts/setup.sh first")
	ctx, ns := s.Ctx, s.Namespace
	tc := helpers.NewTestContext(t, ctx)
	requester := tc.RequesterClient()
	outsider := helpers.NewAPIClientWithAuth(tc.OIDCProvider().GetTokenForUser(t, ctx, helpers.TestUsers.UnauthorizedUser))
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("artifact-e2e-%d", time.Now().UnixNano())}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		Mode: breakglassv1alpha1.DebugSessionModeWorkload, TargetNamespace: ns,
		Allowed:            &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{s.Cluster}, Groups: []string{"*"}},
		ArtifactCollection: &breakglassv1alpha1.DebugSessionArtifactCollection{AllowedRecipes: []string{artifactarchive.SystemSummaryRecipe}},
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
	request := helpers.DebugSessionArtifactRequest{Recipe: artifactarchive.SystemSummaryRecipe, PodNamespace: pod.Namespace, PodName: pod.Name, DetailLevel: "basic"}
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
		output, e := exec.CommandContext(ctx, "kubectl", "-n", ns, "exec", "deployment/breakglass-manager", "-c", "artifact-tls", "--", "find", "/artifacts/objects", "-type", "f").Output()
		require.NoError(t, e)
		result := []string{}
		for _, name := range strings.Fields(string(output)) {
			if !strings.HasSuffix(name, "/.breakglass-artifact-instance-v1") {
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
		_, e = artifactarchive.Validate(ctx, bytes.NewReader(data), int64(len(data)), artifactarchive.Expected{Recipe: artifactarchive.SystemSummaryRecipe, RecipeVersion: 1, ArtifactID: admitted.ArtifactID, Inputs: artifactarchive.Inputs{MaxArchiveBytes: 16777216, DetailLevel: &request.DetailLevel}, SessionNamespace: ns, SessionName: session.Name, SessionUID: string(active.UID), RedactionProfile: "credential-text.v1", RedactionVersion: 1}, artifactarchive.Limits{})
		require.NoError(t, e)
		return &object, data, token
	}
	first, data, token := collect()
	afterFirst := files()
	require.Len(t, afterFirst, len(baseline)+1)
	control, _, _ := collect()
	require.Len(t, files(), len(baseline)+2)
	metadata, err := requester.ListDebugSessionArtifacts(ctx, ns, session.Name)
	require.NoError(t, err)
	require.Len(t, metadata, 2)
	require.ElementsMatch(t, []string{first.Spec.ArtifactID, control.Spec.ArtifactID}, []string{metadata[0].ArtifactID, metadata[1].ArtifactID})
	require.Equal(t, http.StatusNotFound, status(outsider, http.MethodGet, endpoint, nil, ""))
	require.Equal(t, http.StatusNotFound, status(outsider, http.MethodGet, endpoint+"/"+first.Spec.ArtifactID, nil, ""))
	require.Equal(t, http.StatusConflict, status(requester, http.MethodPut, "/api/debugSessionArtifactUploads/"+ns+"/"+session.Name+"/"+first.Spec.ArtifactID, data, token))
	for _, invalid := range []helpers.DebugSessionArtifactRequest{{Recipe: "unknown", PodNamespace: pod.Namespace, PodName: pod.Name}, {Recipe: request.Recipe, PodNamespace: pod.Namespace, PodName: "not-approved"}} {
		body, marshalErr := json.Marshal(invalid)
		require.NoError(t, marshalErr)
		require.Equal(t, http.StatusForbidden, status(requester, http.MethodPost, endpoint, body, ""))
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
	require.NoError(t, requester.TerminateDebugSession(ctx, t, session.Name))
	require.Equal(t, http.StatusNotFound, status(requester, http.MethodGet, endpoint+"/"+control.Spec.ArtifactID, nil, ""))
	require.Equal(t, http.StatusNotFound, status(requester, http.MethodGet, endpoint, nil, ""))
	require.NoError(t, s.Client.Delete(ctx, control))
	require.Eventually(t, func() bool {
		return apierrors.IsNotFound(s.Client.Get(ctx, client.ObjectKeyFromObject(control), &breakglassv1alpha1.DebugSessionArtifact{}))
	}, helpers.WaitForStateTimeout, time.Second)
	require.Equal(t, baseline, files(), "actual provider files must be removed")
}
