// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
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
			TargetNamespace: "default",
			PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: identity-diagnostics
spec:
  containers:
  - name: debug
    image: busybox:1.37
    command: ["sleep", "3600"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
`,
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m"},
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
	_, status, err = outsiderAPI.CreateDebugSession(ctx, t, DebugSessionCreateRequest{
		TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m",
	})
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status)

	create := func() *breakglassv1alpha1.DebugSession {
		session := s.TC.ClientForUser(requester).MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "identity-only workflow",
		})
		s.Cleanup.Add(session)
		t.Cleanup(func() { _ = s.TC.ClientForUser(requester).TerminateDebugSession(context.Background(), t, session.Name) })
		return helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	}
	session := create()
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
		return apimeta.IsStatusConditionTrue(active.Status.Conditions, string(breakglassv1alpha1.DebugSessionConditionReady)) &&
			len(active.Status.AllowedPods) > 0 && active.Status.AllowedPods[0].Ready
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
		Container: "debug", Command: []string{"echo", "identity-only-exec"}, Stdout: true, Stderr: true,
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(userConfig, http.MethodPost, execRequest.URL())
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	require.NoError(t, executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}), stderr.String())
	assert.Contains(t, stdout.String(), "identity-only-exec")
}
