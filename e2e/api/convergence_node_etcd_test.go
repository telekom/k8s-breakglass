//go:build e2e_convergence

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

const convergenceNodeImage = "docker.io/library/busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

// TestConvergenceNodeDiagnosticsE2E follows the real requester -> approval ->
// createNodeDebugPod path and runs read-only diagnostics against the disposable
// Kind node. It intentionally does not invoke node-maintenance repairs.
func TestConvergenceNodeDiagnosticsE2E(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("convergence-node")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Convergence node diagnostics", Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug", NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{DefaultNamespace: "breakglass-debug"},
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
				Enabled: true, AllowedImages: []string{convergenceNodeImage},
				HostNamespaces: &breakglassv1alpha1.HostNamespacesConfig{HostNetwork: true, HostPID: true},
			}},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "15m", DefaultDuration: "10m", RetainFor: "10s"},
		},
	}
	require.NoError(t, s.Client.Create(ctx, template))
	t.Cleanup(func() { _ = s.Client.Delete(context.Background(), template) })
	requesterUser := helpers.TestUsers.PlatformIdentityRequester
	approverUser := helpers.TestUsers.DebugSessionApprover
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("convergence-node"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{s.Cluster},
			Allowed:   &breakglassv1alpha1.DebugSessionAllowed{Groups: requesterUser.Groups},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{approverUser.Email}},
		},
	}
	require.NoError(t, s.Client.Create(ctx, binding))
	t.Cleanup(func() { _ = s.Client.Delete(context.Background(), binding) })

	requester := helpers.NewAPIClientWithAuth(s.TC.OIDCProvider().GetTokenForUser(t, ctx, requesterUser))
	approver := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, approverUser))
	session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "Read-only convergence node diagnostics on disposable Kind",
	})
	require.NoError(t, err)
	s.Cleanup.Add(session)
	t.Cleanup(func() { _ = requester.TerminateDebugSession(context.Background(), t, session.Name) })
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	status, err := approver.ApproveDebugSession(ctx, t, session.Name, "Approve read-only disposable node diagnostics")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)

	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	kube, err := kubernetes.NewForConfig(config)
	require.NoError(t, err)
	nodes, err := kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, nodes.Items)
	node := ""
	for _, candidate := range nodes.Items {
		for _, condition := range candidate.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
				node = candidate.Name
				break
			}
		}
		if node != "" {
			break
		}
	}
	require.NotEmpty(t, node, "disposable target cluster must have a Ready node")
	requesterDebugAPI := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, ctx, requesterUser))
	status, createdPod, err := requesterDebugAPI.CreateNodeDebugPod(ctx, t, active.Name, CreateNodeDebugPodRequest{NodeName: node})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	podName, ok := createdPod["podName"].(string)
	require.True(t, ok)
	require.NotEmpty(t, podName)
	podNamespace, ok := createdPod["namespace"].(string)
	require.True(t, ok)
	require.NotEmpty(t, podNamespace)
	var pod corev1.Pod
	require.Eventually(t, func() bool {
		current, getErr := kube.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
		if getErr != nil {
			return false
		}
		pod = *current
		return pod.Status.Phase == corev1.PodRunning
	}, helpers.WaitForStateTimeout, time.Second, "node debug pod must become Running")
	t.Cleanup(func() {
		_ = kube.CoreV1().Pods(podNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	})

	request := kube.CoreV1().RESTClient().Post().Namespace(podNamespace).Resource("pods").Name(podName).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: "debugger", Stdout: true, Stderr: true,
			Command: []string{"sh", "-c", "uname -r; test -r /host/etc/os-release && head -n 1 /host/etc/os-release"}}, scheme.ParameterCodec)
	userConfig := &rest.Config{Host: config.Host, TLSClientConfig: rest.TLSClientConfig{CAData: config.CAData, CAFile: config.CAFile, Insecure: config.Insecure, ServerName: config.ServerName}, BearerToken: s.TC.OIDCProvider().GetTokenForUser(t, ctx, requesterUser)}
	executor, err := remotecommand.NewSPDYExecutor(userConfig, http.MethodPost, request.URL())
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	streamCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	require.NoError(t, executor.StreamWithContext(streamCtx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}), stderr.String())
	require.NotEmpty(t, bytes.TrimSpace(stdout.Bytes()), "node kernel and host OS diagnostics should be returned")
	require.Contains(t, stdout.String(), "NAME=", "diagnostics should read the selected node's host OS metadata")
}
