// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Exercise the real OIDC, approval, deployment and kubelet exec paths, without
// creating an escalation or BreakglassSession for the requester.
func TestDebugSessionIdentityOnlyWorkflow(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requester := helpers.TestUsers.DebugSessionRequester
	approver := helpers.TestUsers.DebugSessionApprover
	token := s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester)
	requesterAPI := NewDebugSessionAPIClient(token)
	approverAPI := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, approver))
	outsiderAPI := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, helpers.TestUsers.UnauthorizedUser))

	var grants breakglassv1alpha1.BreakglassSessionList
	require.NoError(t, s.Client.List(ctx, &grants))
	for _, grant := range grants.Items {
		require.NotEqual(t, requester.Email, grant.Spec.User, "identity-only fixture must not carry an escalation grant")
		require.NotEqual(t, requester.Username, grant.Spec.User, "identity-only fixture must not carry an escalation grant")
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("identity-debug")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Identity-only diagnostics",
			Mode:            breakglassv1alpha1.DebugSessionModeWorkload,
			TargetNamespace: "breakglass-debug",
			NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
				DefaultNamespace:   "breakglass-debug",
				AllowUserNamespace: false,
			},
			FailMode:             "closed",
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true), Attach: ptr.To(true)},
			PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: identity-diagnostics
spec:
  containers:
  - name: debug
    image: busybox:1.37
    stdin: true
    command: ["sh", "-c", "while read -r line; do printf 'identity-only-attach:%s\\n' \"$line\"; [ \"$line\" = finish ] && exit 0; done"]
    env:
    - name: SESSION_UID
      value: {{ required "session UID required" .session.uid | yamlQuote }}
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
`,
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m", RetainFor: "10s"},
			AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{
				Name: "uid-proof",
				TemplateString: `apiVersion: batch/v1
kind: Job
metadata:
  name: {{ .session.name }}-uid-proof
  labels:
    e2e-session-proof: {{ .session.name | yamlQuote }}
spec:
  template:
    metadata:
      labels:
        e2e-session-proof: {{ .session.name | yamlQuote }}
      annotations:
        breakglass.t-caas.telekom.com/source-session-uid: {{ required "session UID required" .session.uid | yamlQuote }}
    spec:
      restartPolicy: Never
      containers:
      - name: uid-proof
        image: busybox:1.37
        command: ["sh", "-c", "echo \"$SESSION_UID\""]
        env:
        - name: SESSION_UID
          value: {{ required "session UID required" .session.uid | yamlQuote }}
        securityContext:
          runAsNonRoot: true
          runAsUser: 65532
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
`,
			}},
		},
	}
	require.NoError(t, s.CreateResource(template))
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("identity-global"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{s.Cluster},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"debug-session-test-group"}},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{requester.Email, approver.Email}},
		},
	}
	require.NoError(t, s.CreateResource(binding))
	require.Eventually(t, func() bool {
		templates, status, err := requesterAPI.ListTemplates(ctx, t)
		if err != nil || status != http.StatusOK {
			return false
		}
		for _, discovered := range templates {
			if discovered.Name == template.Name {
				return true
			}
		}
		return false
	}, helpers.WaitForStateTimeout, time.Second, "token groups must discover a binding without escalation")

	discovered, status, err := outsiderAPI.ListTemplates(ctx, t)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	for _, candidate := range discovered {
		assert.NotEqual(t, template.Name, candidate.Name)
	}
	_, status, err = outsiderAPI.GetTemplate(ctx, t, template.Name)
	require.Error(t, err)
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, status)
	_, status, err = outsiderAPI.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
		TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m",
	})
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status)

	for _, namespace := range []string{"kube-system", "default", "tenant-unbound"} {
		_, status, err = requesterAPI.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Namespace: namespace,
		})
		require.Error(t, err, "Function-style fixed namespace must reject %s", namespace)
		require.Equal(t, http.StatusBadRequest, status)
	}

	create := func(duration string) *breakglassv1alpha1.DebugSession {
		session := s.TC.ClientForUser(requester).MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: duration, Reason: "identity-only workflow",
		})
		s.Cleanup.Add(session)
		t.Cleanup(func() { _ = s.TC.ClientForUser(requester).TerminateDebugSession(context.Background(), t, session.Name) })
		return helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	}
	session := create("10m")
	requesterAPI.AuthToken = s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester)
	status, err = requesterAPI.ApproveDebugSession(ctx, t, session.Name, "self approval must be blocked")
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status)
	approverAPI.AuthToken = s.TC.OIDCProvider().GetTokenForUser(t, ctx, approver)
	status, err = approverAPI.ApproveDebugSession(ctx, t, session.Name, "peer approval")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(active), active) != nil {
			return false
		}
		return len(active.Status.AllowedPods) > 0 && active.Status.AllowedPods[0].Ready
	}, helpers.WaitForStateTimeout, time.Second, "approved diagnostic pod must become Ready")

	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	adminConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	userConfig := &rest.Config{
		Host: adminConfig.Host,
		TLSClientConfig: rest.TLSClientConfig{
			CAData: adminConfig.CAData, CAFile: adminConfig.CAFile,
			Insecure: adminConfig.Insecure, ServerName: adminConfig.ServerName,
		},
		BearerToken: s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester),
	}
	kube, err := kubernetes.NewForConfig(userConfig)
	require.NoError(t, err)
	pod := active.Status.AllowedPods[0]
	execRequest := kube.CoreV1().RESTClient().Post().Namespace(pod.Namespace).Resource("pods").
		Name(pod.Name).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: "debug", Command: []string{"sh", "-c", "echo identity-only-exec; echo \"$SESSION_UID\""}, Stdout: true, Stderr: true,
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(userConfig, http.MethodPost, execRequest.URL())
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	require.NoError(t, executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}), stderr.String())
	assert.Contains(t, stdout.String(), "identity-only-exec")
	assert.Contains(t, stdout.String(), string(session.UID), "trusted UID must render in the actual running container")

	admin, err := kubernetes.NewForConfig(adminConfig)
	require.NoError(t, err)
	actualPod, err := admin.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, string(session.UID), actualPod.Annotations["breakglass.t-caas.telekom.com/source-session-uid"])
	require.Eventually(t, func() bool {
		proofs, err := admin.CoreV1().Pods("breakglass-debug").List(ctx, metav1.ListOptions{LabelSelector: "e2e-session-proof=" + session.Name})
		if err != nil || len(proofs.Items) != 1 || proofs.Items[0].Status.Phase != corev1.PodSucceeded {
			return false
		}
		proof := &proofs.Items[0]
		require.Equal(t, string(session.UID), proof.Annotations["breakglass.t-caas.telekom.com/source-session-uid"])
		logs, err := admin.CoreV1().Pods(proof.Namespace).GetLogs(proof.Name, &corev1.PodLogOptions{Container: "uid-proof"}).DoRaw(ctx)
		return err == nil && strings.Contains(string(logs), string(session.UID))
	}, helpers.WaitForStateTimeout, time.Second, "auxiliary child pod must execute with the trusted rendered UID")

	attach := func(active *breakglassv1alpha1.DebugSession) (string, error) {
		pod := active.Status.AllowedPods[0]
		request := kube.CoreV1().RESTClient().Post().Namespace(pod.Namespace).Resource("pods").
			Name(pod.Name).SubResource("attach").VersionedParams(&corev1.PodAttachOptions{
			Container: "debug", Stdin: true, Stdout: true, Stderr: true,
		}, scheme.ParameterCodec)
		executor, err := remotecommand.NewSPDYExecutor(userConfig, http.MethodPost, request.URL())
		if err != nil {
			return "", err
		}
		attachCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var output, errors bytes.Buffer
		err = executor.StreamWithContext(attachCtx, remotecommand.StreamOptions{
			Stdin: strings.NewReader("probe\nfinish\n"), Stdout: &output, Stderr: &errors,
		})
		return output.String(), err
	}
	output, err := attach(active)
	require.NoError(t, err)
	require.Contains(t, output, "identity-only-attach:probe", "real bearer-only attach must exchange data")
	status, err = requesterAPI.TerminateDebugSession(ctx, t, session.Name)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	waitForNoDebugResources(t, ctx, admin, session.Name)

	// Canonical catalogue profiles explicitly disable attach. A new short lease
	// also proves natural expiry without changing status or timestamps.
	template.Spec.AllowedPodOperations.Attach = ptr.To(false)
	require.NoError(t, s.Client.Update(ctx, template))
	expiring := create("90s")
	require.NoError(t, s.TC.ClientForUser(approver).ApproveDebugSession(ctx, t, expiring.Name, "peer approves short lease"))
	expiring = helpers.WaitForDebugSessionState(t, ctx, s.Client, expiring.Name, expiring.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(expiring), expiring) != nil {
			return false
		}
		return len(expiring.Status.AllowedPods) > 0 && expiring.Status.AllowedPods[0].Ready
	}, helpers.WaitForStateTimeout, time.Second)
	_, err = attach(expiring)
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "forbidden", "attach=false must deny a real native attach")
	require.NotNil(t, expiring.Status.ExpiresAt)
	expiresAt := expiring.Status.ExpiresAt.Time
	expiring = helpers.WaitForDebugSessionState(t, ctx, s.Client, expiring.Name, expiring.Namespace, breakglassv1alpha1.DebugSessionStateExpired, 3*time.Minute)
	require.False(t, time.Now().Before(expiresAt), "natural expiry must follow the real lease, never a patched timestamp")
	waitForNoDebugResources(t, ctx, admin, expiring.Name)
	for _, ended := range []*breakglassv1alpha1.DebugSession{session, expiring} {
		require.Eventually(t, func() bool {
			err := s.Client.Get(ctx, client.ObjectKeyFromObject(ended), &breakglassv1alpha1.DebugSession{})
			return apierrors.IsNotFound(err)
		}, 2*time.Minute, time.Second, "terminal audit record must be removed after its configured retention")
	}
}

func waitForNoDebugResources(t *testing.T, ctx context.Context, kube kubernetes.Interface, session string) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, selector := range []string{"breakglass.telekom.com/debug-session=" + session, "e2e-session-proof=" + session} {
			opts := metav1.ListOptions{LabelSelector: selector}
			pods, err := kube.CoreV1().Pods("breakglass-debug").List(ctx, opts)
			if err != nil || len(pods.Items) != 0 {
				return false
			}
			deployments, err := kube.AppsV1().Deployments("breakglass-debug").List(ctx, opts)
			if err != nil || len(deployments.Items) != 0 {
				return false
			}
			daemonSets, err := kube.AppsV1().DaemonSets("breakglass-debug").List(ctx, opts)
			if err != nil || len(daemonSets.Items) != 0 {
				return false
			}
			jobs, err := kube.BatchV1().Jobs("breakglass-debug").List(ctx, opts)
			if err != nil || len(jobs.Items) != 0 {
				return false
			}
			roles, err := kube.RbacV1().Roles("breakglass-debug").List(ctx, opts)
			if err != nil || len(roles.Items) != 0 {
				return false
			}
			bindings, err := kube.RbacV1().RoleBindings("breakglass-debug").List(ctx, opts)
			if err != nil || len(bindings.Items) != 0 {
				return false
			}
			configMaps, err := kube.CoreV1().ConfigMaps("breakglass-debug").List(ctx, opts)
			if err != nil || len(configMaps.Items) != 0 {
				return false
			}
			secrets, err := kube.CoreV1().Secrets("breakglass-debug").List(ctx, opts)
			if err != nil || len(secrets.Items) != 0 {
				return false
			}
		}
		return true
	}, 4*time.Minute, time.Second, "terminated/expired session must leave zero pods, workloads, auxiliary Jobs or RBAC/config resources")
}
