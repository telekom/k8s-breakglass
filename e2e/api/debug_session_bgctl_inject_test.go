// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestDebugSessionBgctlInjectSecurityContext proves that `bgctl debug kubectl
// inject` without security flags satisfies a requireNonRoot template, and that
// a disallowed context is rejected with an actionable message.
func TestDebugSessionBgctlInjectSecurityContext(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requester := helpers.TestUsers.PlatformIdentityRequester
	approver := helpers.TestUsers.DebugSessionApprover
	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	target, err := client.New(config, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	cleanup := helpers.NewCleanup(t, target)
	tenant := helpers.GenerateUniqueName("bgctl-inject")
	image := "busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   helpers.GenerateUniqueName("bgctl-inject"),
		Labels: map[string]string{"t-caas.telekom.com/owner": "tenant", "t-caas.telekom.com/tenant": tenant},
	}}
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

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("bgctl-inject-template")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "bgctl inject non-root", Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "breakglass-debug", FailMode: "closed",
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				// No template securityContext: the client must send runAsNonRoot.
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled: true, AllowedImages: []string{image}, RequireImageDigest: true, RequireNonRoot: true,
				},
			},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Constraints:          &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m"},
		},
	}
	require.NoError(t, s.CreateResource(template))
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("bgctl-inject-binding"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{s.Cluster}, Allowed: &breakglassv1alpha1.DebugSessionAllowed{Groups: requester.Groups},
			Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{approver.Email}},
			KubectlDebugTargetNamespaces: &breakglassv1alpha1.KubectlDebugTargetNamespaceConstraints{
				EphemeralContainers: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{{
						MatchLabels: map[string]string{"t-caas.telekom.com/tenant": tenant},
					}},
				},
			},
		},
	}
	require.NoError(t, s.CreateResource(binding))

	requesterAPI := s.TC.ClientForUser(requester)
	var session *breakglassv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		created, err := requesterAPI.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m", Reason: "bgctl inject security context e2e",
		})
		if err != nil {
			return false
		}
		session = created
		return true
	}, helpers.WaitForStateTimeout, time.Second, "binding must become usable")
	s.Cleanup.Add(session)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = requesterAPI.TerminateDebugSession(cleanupCtx, t, session.Name)
	})
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	require.NoError(t, s.TC.ClientForUser(approver).ApproveDebugSession(ctx, t, session.Name, "bgctl inject e2e"))
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)

	token := s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester)
	bgctl := func(container string, extra ...string) (string, error) {
		var out bytes.Buffer
		command := bgctlcmd.NewRootCommand(bgctlcmd.Config{OutputWriter: &out})
		command.SetErr(&out)
		command.SetArgs(append([]string{
			"--server", helpers.GetAPIBaseURL(), "--token", token, "--token-storage", "file", "--non-interactive",
			"debug", "kubectl", "inject", session.Name, "--session-namespace", session.Namespace,
			"--namespace", pod.Namespace, "--pod", pod.Name, "--image", image, "--container", container,
			"--command", "sleep,600", "-o", "json",
		}, extra...))
		err := command.ExecuteContext(ctx)
		return out.String(), err
	}

	t.Run("RootRejectedWithPolicyHint", func(t *testing.T) {
		_, err := bgctl("root-attempt", "--run-as-user", "0")
		require.Error(t, err)
		require.ErrorContains(t, err, "debug operation is not allowed")
		require.ErrorContains(t, err, "requireNonRoot=true")
		require.ErrorContains(t, err, `"runAsUser":0`)
		require.ErrorContains(t, err, "--run-as-user")
	})

	t.Run("OptOutSendsNoContextAndIsRejected", func(t *testing.T) {
		_, err := bgctl("opt-out", "--default-security-context=false")
		require.ErrorContains(t, err, "requireNonRoot=true")
	})

	t.Run("DefaultsSatisfyRequireNonRoot", func(t *testing.T) {
		out, err := bgctl("nonroot")
		require.NoError(t, err, out)
		require.Eventually(t, func() bool {
			if target.Get(ctx, client.ObjectKeyFromObject(pod), pod) != nil {
				return false
			}
			for _, status := range pod.Status.EphemeralContainerStatuses {
				if status.Name == "nonroot" && status.State.Running != nil {
					return true
				}
			}
			return false
		}, helpers.WaitForStateTimeout, time.Second, "default non-root ephemeral container must run")
		names := make([]string, 0, len(pod.Spec.EphemeralContainers))
		for _, ec := range pod.Spec.EphemeralContainers {
			names = append(names, ec.Name)
			if ec.Name != "nonroot" {
				continue
			}
			require.NotNil(t, ec.SecurityContext)
			require.Equal(t, ptr.To(true), ec.SecurityContext.RunAsNonRoot)
			require.Equal(t, ptr.To(int64(65534)), ec.SecurityContext.RunAsUser)
			require.Equal(t, ptr.To(false), ec.SecurityContext.AllowPrivilegeEscalation)
		}
		require.Equal(t, []string{"nonroot"}, names, "rejected attempts must leave the pod unmodified")
	})
}
