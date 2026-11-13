// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const (
	runtimeIdentityImage        = "busybox:latest"
	runtimeIdentityTicket       = "INC-1551 runtime identity"
	runtimeIdentitySessionLabel = "breakglass.telekom.com/debug-session"
	runtimeIdentityUIDLabel     = "breakglass.telekom.com/debug-session-uid"
	runtimeIdentityTemplLabel   = "breakglass.telekom.com/debug-template"
	runtimeIdentityRequestedBy  = "breakglass.telekom.com/requested-by"
	runtimeIdentityApprovedBy   = "breakglass.telekom.com/approved-by"
	runtimeIdentityTicketKey    = "breakglass.telekom.com/ticket"
	runtimeIdentityEphemeralKey = "breakglass.telekom.com/ephemeral."
)

// TestDebugSessionRuntimeIdentityMetadata proves that every pod kind a
// DebugSession creates (workload, pod copy, node debug, ephemeral container)
// carries the runtime identity labels and annotations by default, and that
// both escape hatches (template spec.audit.runtimeIdentityMetadata=false and
// the global debugSessions.disableRuntimeIdentityMetadata) turn them off
// without removing the existing session labels.
func TestDebugSessionRuntimeIdentityMetadata(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx

	kubeconfig := helpers.GetKubeconfig()
	if spoke := helpers.GetSpokeAKubeconfig(); spoke != "" {
		kubeconfig = spoke
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	target, err := client.New(config, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	targetCleanup := helpers.NewCleanup(t, target)

	var nodes corev1.NodeList
	require.NoError(t, target.List(ctx, &nodes))
	node := ""
	for _, candidate := range nodes.Items {
		for _, condition := range candidate.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue && node == "" {
				node = candidate.Name
			}
		}
	}
	require.NotEmpty(t, node, "the target cluster must have a Ready node")

	t.Run("Default", func(t *testing.T) {
		runRuntimeIdentityCase(t, s, target, targetCleanup, node, nil, "", true, true)
	})
	t.Run("TemplateOptOut", func(t *testing.T) {
		runRuntimeIdentityCase(t, s, target, targetCleanup, node, ptr.To(false), "", false, false)
	})
	t.Run("GlobalOptOut", func(t *testing.T) {
		// An API-only replica with the global escape hatch serves the
		// kubectl-debug endpoints. Workload pods are created by the main
		// controller's reconciler, which keeps the default; the global switch
		// for workload and collector pods is covered by unit tests.
		name := helpers.GenerateUniqueName("e2e-runtime-identity-off")
		helpers.DeployServerReplica(t, s, helpers.ServerReplica{
			Name: name,
			EditConfig: func(cfg map[string]any) {
				cfg["debugSessions"] = map[string]any{"disableRuntimeIdentityMetadata": true}
			},
		})
		require.NoError(t, helpers.WaitForDeploymentReady(ctx, s.Client, s.Namespace, name, 5*time.Minute))
		port, stop := helpers.StartPortForward(t, ctx, s.Namespace, name, 8080, 0)
		t.Cleanup(stop)
		runRuntimeIdentityCase(t, s, target, targetCleanup, node, nil, fmt.Sprintf("http://localhost:%d", port), true, false)
	})
}

// runRuntimeIdentityCase runs one session. apiURL, when set, serves the
// kubectl-debug operations; wantWorkload and wantOps say whether the workload
// and the kubectl-debug pods must carry runtime identity metadata.
func runRuntimeIdentityCase(t *testing.T, s *helpers.TestSetup, target client.Client, targetCleanup *helpers.Cleanup, node string, templateValue *bool, apiURL string, wantWorkload, wantOps bool) {
	ctx := s.Ctx
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("e2e-rtid"), Labels: helpers.E2ETestLabels()}}
	require.NoError(t, target.Create(ctx, namespace))
	targetCleanup.Add(namespace)
	source := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: namespace.Name},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: runtimeIdentityImage, Command: []string{"sleep", "1200"},
		}}},
	}
	require.NoError(t, target.Create(ctx, source))
	require.NoError(t, helpers.WaitForPodReady(ctx, target, source.Namespace, source.Name, 2*time.Minute))

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("e2e-rtid-pod"), Labels: helpers.E2ETestLabels()},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Runtime identity workload",
			Template: &breakglassv1alpha1.DebugPodSpec{Spec: breakglassv1alpha1.DebugPodSpecInner{
				Containers: []corev1.Container{{Name: "debug", Image: runtimeIdentityImage, Command: []string{"sleep", "1200"}}},
			}},
		},
	}
	require.NoError(t, s.CreateResource(podTemplate))
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("e2e-rtid"), Labels: helpers.E2ETestLabels()},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Runtime identity metadata",
			Mode:            breakglassv1alpha1.DebugSessionModeHybrid,
			WorkloadType:    breakglassv1alpha1.DebugWorkloadDeployment,
			TargetNamespace: namespace.Name,
			PodTemplateRef:  &breakglassv1alpha1.DebugPodTemplateReference{Name: podTemplate.Name},
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}},
				NodeDebug:           &breakglassv1alpha1.NodeDebugConfig{Enabled: true, AllowedImages: []string{"busybox:*"}},
				PodCopy:             &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: namespace.Name, TTL: "1h"},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "20m", DefaultDuration: "10m"},
		},
	}
	if templateValue != nil {
		template.Spec.Audit = &breakglassv1alpha1.DebugSessionAuditConfig{Enabled: true, RuntimeIdentityMetadata: templateValue}
	}
	require.NoError(t, s.CreateResource(template))
	requester := helpers.TestUsers.DebugSessionRequester
	approver := helpers.TestUsers.DebugSessionApprover
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("e2e-rtid"), Namespace: s.Namespace, Labels: helpers.E2ETestLabels()},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{s.Cluster},
			Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: requester.Groups},
			Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{approver.Email}},
		},
	}
	require.NoError(t, s.CreateResource(binding))

	requesterAPI := s.TC.ClientForUser(requester)
	var session *breakglassv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		created, createErr := requesterAPI.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "10m",
			Reason: "Runtime identity metadata e2e", TicketSystemID: runtimeIdentityTicket,
		})
		if createErr != nil {
			return false
		}
		session = created
		return true
	}, helpers.WaitForStateTimeout, time.Second, "the binding must become usable")
	s.Cleanup.Add(session)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = requesterAPI.TerminateDebugSession(cleanupCtx, t, session.Name)
	})
	helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	require.NoError(t, s.TC.ClientForUser(approver).ApproveDebugSession(ctx, t, session.Name, "runtime identity e2e"))
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Equal(t, runtimeIdentityTicket, active.Spec.TicketSystemID, "the ticket reference is persisted in the spec")
	require.NotNil(t, active.Status.Approval)
	require.NotEmpty(t, active.Status.Approval.ApprovedBy)

	assertPod := func(t *testing.T, kind string, meta metav1.ObjectMeta, want bool) {
		t.Helper()
		assert.Equal(t, active.Name, meta.Labels[runtimeIdentitySessionLabel], "%s: the session label is always kept", kind)
		if !want {
			for _, key := range []string{runtimeIdentityRequestedBy, runtimeIdentityApprovedBy, runtimeIdentityTicketKey} {
				assert.NotContains(t, meta.Annotations, key, "%s: opt-out adds no %s annotation", kind, key)
			}
			return
		}
		assert.Equal(t, string(active.UID), meta.Labels[runtimeIdentityUIDLabel], kind)
		assert.Equal(t, template.Name, meta.Labels[runtimeIdentityTemplLabel], kind)
		assert.Equal(t, active.Spec.RequestedBy, meta.Annotations[runtimeIdentityRequestedBy], kind)
		assert.Equal(t, active.Status.Approval.ApprovedBy, meta.Annotations[runtimeIdentityApprovedBy], kind)
		assert.Equal(t, runtimeIdentityTicket, meta.Annotations[runtimeIdentityTicketKey], kind)
	}

	// Workload pods.
	var workloadPod corev1.Pod
	require.Eventually(t, func() bool {
		var pods corev1.PodList
		if target.List(ctx, &pods, client.InNamespace(namespace.Name), client.MatchingLabels{runtimeIdentitySessionLabel: active.Name}) != nil {
			return false
		}
		for _, pod := range pods.Items {
			if pod.Labels["breakglass.telekom.com/debug-copy"] == "" && pod.Labels["breakglass.telekom.com/node-debug"] == "" {
				workloadPod = pod
				return true
			}
		}
		return false
	}, helpers.WaitForStateTimeout, time.Second, "the workload pod must be created")
	assertPod(t, "workload", workloadPod.ObjectMeta, wantWorkload)

	opsAPI := s.TC.ClientForUser(requester)
	if apiURL != "" {
		opsAPI = helpers.NewAPIClientWithAuth(s.TC.OIDCProvider().GetTokenForUser(t, ctx, requester))
		opsAPI.BaseURL = apiURL
	}

	// Pod copy.
	copied, err := opsAPI.CreatePodCopy(ctx, t, active.Name, helpers.PodCopyRequest{Namespace: source.Namespace, PodName: source.Name, DebugImage: runtimeIdentityImage})
	require.NoError(t, err)
	var copyPod corev1.Pod
	require.NoError(t, target.Get(ctx, client.ObjectKey{Namespace: copied.CopyNamespace, Name: copied.CopyName}, &copyPod))
	targetCleanup.Add(&copyPod)
	assertPod(t, "pod copy", copyPod.ObjectMeta, wantOps)

	// Node debug pod.
	nodeDebug, err := opsAPI.CreateNodeDebugPod(ctx, t, active.Name, helpers.NodeDebugRequest{NodeName: node})
	require.NoError(t, err)
	var nodePod corev1.Pod
	require.NoError(t, target.Get(ctx, client.ObjectKey{Namespace: nodeDebug.Namespace, Name: nodeDebug.PodName}, &nodePod))
	targetCleanup.Add(&nodePod)
	assertPod(t, "node debug", nodePod.ObjectMeta, wantOps)

	// Ephemeral container: controller-assigned name and target-pod annotation.
	injected, err := opsAPI.InjectEphemeralContainerNamed(ctx, t, active.Name, helpers.EphemeralContainerRequest{
		Namespace: source.Namespace, PodName: source.Name, ContainerName: "debugger", Image: runtimeIdentityImage,
		Command:         []string{"sleep", "600"},
		SecurityContext: &corev1.SecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65534))},
	})
	require.NoError(t, err)
	require.NoError(t, target.Get(ctx, client.ObjectKeyFromObject(source), source))
	names := make([]string, 0, len(source.Spec.EphemeralContainers))
	for _, ec := range source.Spec.EphemeralContainers {
		names = append(names, ec.Name)
	}
	require.Equal(t, []string{injected}, names)
	ephemeralAnnotations := 0
	for key := range source.Annotations {
		if strings.HasPrefix(key, runtimeIdentityEphemeralKey) {
			ephemeralAnnotations++
		}
	}
	if !wantOps {
		assert.Equal(t, "debugger", injected, "opt-out keeps the requested container name")
		assert.Zero(t, ephemeralAnnotations, "opt-out adds no ephemeral container annotation")
		return
	}
	uid8 := strings.ReplaceAll(string(active.UID), "-", "")[:8]
	assert.Equal(t, "bg-"+uid8+"-1", injected)
	assert.Equal(t, string(active.UID), source.Annotations[runtimeIdentityEphemeralKey+injected])
	assert.Equal(t, 1, ephemeralAnnotations)
}
