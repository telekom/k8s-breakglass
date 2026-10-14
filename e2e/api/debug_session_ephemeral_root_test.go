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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDebugSessionEphemeralRootNETRAWBindingFence(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requester := helpers.TestUsers.PlatformIdentityRequester
	approver := helpers.TestUsers.DebugSessionApprover
	token := s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester)
	requesterAPI := s.TC.ClientForUser(requester)
	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	target, err := client.New(config, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	cleanup := helpers.NewCleanup(t, target)
	tenant := helpers.GenerateUniqueName("si-ephemeral")
	image := "busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	pods := make([]*corev1.Pod, 0, 2)
	for _, protected := range []bool{false, true} {
		namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: helpers.GenerateUniqueName("si-source"),
			Labels: map[string]string{
				"t-caas.telekom.com/owner": "tenant", "t-caas.telekom.com/tenant": tenant,
			},
		}}
		if protected {
			namespace.Labels["t-caas.telekom.com/protected"] = tenant
		}
		require.NoError(t, target.Create(ctx, namespace))
		cleanup.Add(namespace)
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: namespace.Name},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name: "app", Image: image, Command: []string{"sleep", "1200"},
			}}},
		}
		require.NoError(t, target.Create(ctx, pod))
		cleanup.Add(pod)
		require.NoError(t, helpers.WaitForPodReady(ctx, target, pod.Namespace, pod.Name, 90*time.Second))
		pods = append(pods, pod)
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("si-root-template")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Root NET_RAW ephemeral regression", Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug", FailMode: "closed",
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled: true, AllowedImages: []string{image}, RequireImageDigest: true,
					MaxCapabilities: []string{"NET_RAW"},
				},
			},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration: "20m", DefaultDuration: "10m",
			},
		},
	}
	require.NoError(t, s.CreateResource(template))
	// Helm supplies explicit false; typed omitempty would omit it on CREATE.
	require.NoError(t, s.Client.Patch(ctx, template, client.RawPatch(types.MergePatchType,
		[]byte(`{"spec":{"kubectlDebug":{"ephemeralContainers":{"requireNonRoot":false}}}}`))))
	require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(template), template))
	require.False(t, template.Spec.KubectlDebug.EphemeralContainers.RequireNonRoot)
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("si-root-binding"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{s.Cluster}, Allowed: &breakglassv1alpha1.DebugSessionAllowed{Groups: requester.Groups},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{requester.Email, approver.Email}},
			KubectlDebugTargetNamespaces: &breakglassv1alpha1.KubectlDebugTargetNamespaceConstraints{
				EphemeralContainers: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{{
						MatchLabels: map[string]string{"t-caas.telekom.com/owner": "tenant", "t-caas.telekom.com/tenant": tenant},
						MatchExpressions: []breakglassv1alpha1.NamespaceSelectorRequirement{{
							Key: "t-caas.telekom.com/protected", Operator: breakglassv1alpha1.NamespaceSelectorOpDoesNotExist,
						}},
					}},
				},
			},
		},
	}
	require.NoError(t, s.CreateResource(binding))
	session := requesterAPI.MustCreateDebugSession(t, ctx, helpers.DebugSessionRequest{
		TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m",
		Reason: "SI root NET_RAW namespace-fenced native injection regression",
	})
	s.Cleanup.Add(session)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = requesterAPI.TerminateDebugSession(cleanupCtx, t, session.Name)
	})
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	status, err := NewDebugSessionAPIClient(token).ApproveDebugSession(ctx, t, session.Name, "self approval must fail")
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status)
	require.NoError(t, s.TC.ClientForUser(approver).ApproveDebugSession(ctx, t, session.Name, "independent peer approval"))
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.NotNil(t, active.Status.ResolvedTemplate)
	require.NotNil(t, active.Status.ResolvedTemplate.KubectlDebug)
	require.NotNil(t, active.Status.ResolvedTemplate.KubectlDebug.EphemeralContainers)
	require.False(t, active.Status.ResolvedTemplate.KubectlDebug.EphemeralContainers.RequireNonRoot,
		"explicit false must survive the controller's persisted resolved-template status")
	injection := helpers.EphemeralContainerRequest{
		Namespace: pods[1].Namespace, PodName: pods[1].Name, ContainerName: "si-debug", Image: image,
		Command: []string{"sleep", "600"},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: ptr.To(int64(0)), RunAsNonRoot: ptr.To(false),
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_RAW"}},
		},
	}
	err = requesterAPI.InjectEphemeralContainer(ctx, t, session.Name, injection)
	require.ErrorContains(t, err, "status=403")
	require.NoError(t, target.Get(ctx, client.ObjectKeyFromObject(pods[1]), pods[1]))
	require.Empty(t, pods[1].Spec.EphemeralContainers, "denied source must remain unmodified")
	injection.Namespace = pods[0].Namespace
	require.NoError(t, requesterAPI.InjectEphemeralContainer(ctx, t, session.Name, injection))
	require.Eventually(t, func() bool {
		if target.Get(ctx, client.ObjectKeyFromObject(pods[0]), pods[0]) != nil {
			return false
		}
		for _, container := range pods[0].Status.EphemeralContainerStatuses {
			if container.Name == injection.ContainerName && container.State.Running != nil {
				return true
			}
		}
		return false
	}, helpers.WaitForStateTimeout, time.Second, "root NET_RAW ephemeral container must actually run")
	userConfig := &rest.Config{
		Host: config.Host, TLSClientConfig: rest.TLSClientConfig{
			CAData: config.CAData, CAFile: config.CAFile, ServerName: config.ServerName,
		},
		BearerToken: s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester),
	}
	kube, err := kubernetes.NewForConfig(userConfig)
	require.NoError(t, err)
	request := kube.CoreV1().RESTClient().Post().Namespace(pods[0].Namespace).Resource("pods").
		Name(pods[0].Name).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
		Container: injection.ContainerName, Stdout: true, Stderr: true,
		Command: []string{"sh", "-c", `set -eu; test "$(id -u)" = 0; grep -Eq '^CapEff:[[:space:]]+0000000000002000$' /proc/self/status; ping -c 1 -W 3 127.0.0.1; echo si-netraw-ok`},
	}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(userConfig, http.MethodPost, request.URL())
	require.NoError(t, err)
	var stdout, stderr bytes.Buffer
	require.NoError(t, executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr}), stderr.String())
	require.Contains(t, stdout.String(), "si-netraw-ok")
	require.NoError(t, requesterAPI.TerminateDebugSession(ctx, t, session.Name))
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateTerminated, helpers.WaitForStateTimeout)
	injection.ContainerName = "after-termination"
	err = requesterAPI.InjectEphemeralContainer(ctx, t, session.Name, injection)
	require.ErrorContains(t, err, "status=400")
	require.ErrorContains(t, err, "session is not active")
}
