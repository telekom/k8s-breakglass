// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type hotfixFixture struct {
	c     *DebugSessionController
	hub   client.Client
	spoke client.Client
	sink  *maintenanceAuditCaptureSink
	tmpl  *breakglassv1alpha1.DebugSessionTemplate
	// failNode makes the simulated executor fail on this node.
	failNode string
	// distinct gives every node its own pre-image in a plan.
	distinct bool
	// failRecordPatches fails this many HotfixRecord status patches.
	failRecordPatches int
	// denyPods makes the target refuse executor Pods like an admission policy.
	denyPods bool
}

var hotfixTestImage = "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64)

func newHotfixFixture(t *testing.T, workers, controlPlanes int) *hotfixFixture {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, breakglassv1alpha1.AddToScheme(s))
	raw, err := clientcmd.Write(clientcmdapi.Config{APIVersion: "v1", Kind: "Config",
		Clusters:  map[string]*clientcmdapi.Cluster{"spoke": {Server: "https://spoke.invalid"}},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {Token: "token"}},
		Contexts:  map[string]*clientcmdapi.Context{"ctx": {Cluster: "spoke", AuthInfo: "admin"}}, CurrentContext: "ctx"})
	require.NoError(t, err)
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: "default", UID: "cluster-uid"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "spoke-kubeconfig", Namespace: "default"}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: "default", ResourceVersion: "1"}, Data: map[string][]byte{"value": raw}}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "hotfix"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		TargetNamespace: breakglassv1alpha1.NodeMaintenanceNamespace, BlockSelfApproval: ptr.To(true),
		Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
		Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "4h"},
		Hotfix: &breakglassv1alpha1.DebugSessionHotfix{ExecutorImage: hotfixTestImage,
			PayloadTypes: []breakglassv1alpha1.HotfixPayloadType{breakglassv1alpha1.HotfixPayloadNodeFile, breakglassv1alpha1.HotfixPayloadNodeDeb, breakglassv1alpha1.HotfixPayloadStaticPodImage},
			AllowedPaths: []string{"/etc/ssh/"}, StaticPods: []breakglassv1alpha1.HotfixStaticPod{"kube-apiserver"}, MinSoakSeconds: 1},
	}}
	f := &hotfixFixture{tmpl: template}
	hub := fake.NewClientBuilder().WithScheme(s).WithObjects(cc, secret, template).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}, &breakglassv1alpha1.HotfixRecord{}).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("uid-" + obj.GetName()))
			}
			return cl.Create(ctx, obj, opts...)
		}, SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if _, ok := obj.(*breakglassv1alpha1.HotfixRecord); ok && f.failRecordPatches > 0 {
				f.failRecordPatches--
				return errors.New("injected record outage")
			}
			return cl.Status().Patch(ctx, obj, patch, opts...)
		}}).Build()
	objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: breakglassv1alpha1.NodeMaintenanceNamespace, UID: "ns-uid"}}}
	ready := corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}
	for i := 0; i < workers; i++ {
		objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("worker-%02d", i), UID: types.UID(fmt.Sprintf("worker-uid-%d", i)),
			Labels: map[string]string{"pool": "w"}}, Status: ready})
	}
	for i := 0; i < controlPlanes; i++ {
		name := fmt.Sprintf("cp-%d", i)
		objects = append(objects, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("cp-uid-" + name),
			Labels: map[string]string{"pool": "cp", "node-role.kubernetes.io/control-plane": ""}}, Status: ready},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver-" + name, Namespace: "kube-system", Labels: map[string]string{"tier": "control-plane"}},
				Spec:   corev1.PodSpec{NodeName: name},
				Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}})
	}
	spoke := fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).WithStatusSubresource(&corev1.Pod{}, &batchv1.Job{}).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*corev1.Pod); ok && f.denyPods {
				return apierrors.NewForbidden(corev1.Resource("pods"), obj.GetName(), errors.New("denied by policy"))
			}
			obj.SetUID(types.UID("uid-" + obj.GetName()))
			return cl.Create(ctx, obj, opts...)
		}}).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return spoke, nil }
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 64, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	c.WithAuditManager(manager)
	previous := hotfixReadyz
	hotfixReadyz = func(context.Context, *rest.Config) error { return nil }
	t.Cleanup(func() { hotfixReadyz = previous })
	f.c, f.hub, f.spoke, f.sink = c, hub, spoke, sink
	return f
}

// session creates an approved, active hotfix session.
func (f *hotfixFixture) session(t *testing.T, name string, request *breakglassv1alpha1.DebugSessionHotfixRequest) *breakglassv1alpha1.DebugSession {
	t.Helper()
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "default/spoke", TemplateRef: "hotfix", RequestedBy: "requester",
			IdentityProviderName: "keycloak", Hotfix: request}}
	require.NoError(t, f.hub.Create(t.Context(), ds))
	live := &breakglassv1alpha1.DebugSessionTemplate{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Name: "hotfix"}, live))
	now := metav1.Now()
	expires := metav1.NewTime(time.Now().Add(3 * time.Hour))
	ds.Status = breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires,
		ResolvedTemplate: live.Spec.DeepCopy(), AuthenticatedUserGroupsCaptured: true,
		Approval: &breakglassv1alpha1.DebugSessionApproval{Required: true, ApprovedBy: "approver", ApprovedByIdentityProvider: "keycloak", ApprovedAt: &now}}
	require.NoError(t, f.hub.Status().Update(t.Context(), ds))
	return ds
}

// executor simulates hotfix-action for every running executor Pod.
func (f *hotfixFixture) executor(t *testing.T) int {
	t.Helper()
	pods := &corev1.PodList{}
	require.NoError(t, f.spoke.List(t.Context(), pods, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
	finished := 0
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != "" {
			continue
		}
		var request hotfixExecutorRequest
		for _, env := range pod.Spec.Containers[0].Env {
			if env.Name == "BREAKGLASS_HOTFIX_REQUEST" {
				require.NoError(t, json.Unmarshal([]byte(env.Value), &request))
			}
		}
		before, after := strings.Repeat("b", 64), strings.Repeat("c", 64)
		if f.distinct && request.Stage == "plan" {
			before = hotfixPayloadSHA256(&breakglassv1alpha1.HotfixPayload{Type: breakglassv1alpha1.HotfixPayloadType(pod.Spec.NodeName)})
		}
		result := hotfixExecutorResult{BeforeSHA256: before, AfterSHA256: after}
		switch request.Stage {
		case "plan":
			result.Result, result.Action, result.Diff = "planned", "apply", "--- a\n+++ b\n"
		case "apply":
			result.Result = "applied"
			require.Equal(t, before, request.Expected.BeforeSHA256)
		case "rollback":
			result.Result, result.BeforeSHA256, result.AfterSHA256 = "rolledBack", after, before
		}
		phase := corev1.PodSucceeded
		if pod.Spec.NodeName == f.failNode {
			result, phase = hotfixExecutorResult{Result: "failed", Message: "injected"}, corev1.PodFailed
		}
		message, _ := json.Marshal(result)
		pod.Status.Phase = phase
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "hotfix", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: string(message)}}}}
		require.NoError(t, f.spoke.Status().Update(t.Context(), pod))
		finished++
	}
	return finished
}

// drive runs the controller until the session leaves Active.
func (f *hotfixFixture) drive(t *testing.T, ds *breakglassv1alpha1.DebugSession) *breakglassv1alpha1.DebugSession {
	t.Helper()
	for i := 0; i < 200; i++ {
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		if ds.Status.State != breakglassv1alpha1.DebugSessionStateActive {
			return ds
		}
		_, err := f.c.handleHotfixActive(t.Context(), ds)
		require.NoError(t, err)
		f.executor(t)
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		if hf := ds.Status.Hotfix; hf != nil && hf.GatePassedAt != nil {
			// Skip the soak time.
			past := metav1.NewTime(time.Now().Add(-time.Hour))
			hf.GatePassedAt = &past
			require.NoError(t, f.hub.Status().Update(t.Context(), ds))
		}
	}
	t.Fatal("hotfix session did not finish")
	return nil
}

func filePlanRequest(selector map[string]string) *breakglassv1alpha1.DebugSessionHotfixRequest {
	return &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStagePlan, FixedIn: "next node image",
		Payload: &breakglassv1alpha1.HotfixPayload{Type: breakglassv1alpha1.HotfixPayloadNodeFile, File: &breakglassv1alpha1.HotfixFilePayload{
			Path: "/etc/ssh/sshd_config", Mode: breakglassv1alpha1.HotfixFileSed, SedExpressions: []string{"s/yes/no/"}}},
		Nodes: &breakglassv1alpha1.HotfixNodeSelection{Selector: &metav1.LabelSelector{MatchLabels: selector}}}
}

func eventTypes(sink *maintenanceAuditCaptureSink) []audit.EventType {
	var types []audit.EventType
	for _, event := range sink.Events() {
		types = append(types, event.Type)
	}
	return types
}

func (f *hotfixFixture) pods(t *testing.T) []corev1.Pod {
	t.Helper()
	pods := &corev1.PodList{}
	require.NoError(t, f.spoke.List(t.Context(), pods, client.InNamespace(breakglassv1alpha1.NodeMaintenanceNamespace)))
	return pods.Items
}

func (f *hotfixFixture) leases(t *testing.T) []coordinationv1.Lease {
	t.Helper()
	leases := &coordinationv1.LeaseList{}
	require.NoError(t, f.spoke.List(t.Context(), leases))
	return leases.Items
}

// planned runs a plan session to success and returns it.
func (f *hotfixFixture) planned(t *testing.T, name string, request *breakglassv1alpha1.DebugSessionHotfixRequest) *breakglassv1alpha1.DebugSession {
	t.Helper()
	plan := f.drive(t, f.session(t, name, request))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, plan.Status.State, plan.Status.Message)
	return plan
}

func TestHotfixPlanApplyRollback(t *testing.T) {
	f := newHotfixFixture(t, 5, 1)
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	hf := plan.Status.Hotfix
	require.NotEmpty(t, hf.PlanHash)
	require.NotNil(t, hf.PlannedAt)
	require.Len(t, hf.Plan.Nodes, 5)
	require.Len(t, hf.Plan.Diffs, 1, "identical pre-images share one reviewed diff")
	require.EqualValues(t, 0, hf.Plan.Nodes[0].Batch)
	require.EqualValues(t, 4, hf.Plan.Nodes[4].Batch, "canary, then batches of one (10% of 5)")
	hash, err := breakglassv1alpha1.HotfixPlanHash(hf.Plan)
	require.NoError(t, err)
	require.Equal(t, hash, hf.PlanHash)
	require.Empty(t, f.pods(t), "plan executors are removed")
	require.Empty(t, f.leases(t))

	apply := f.drive(t, f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: hf.PlanHash}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, apply.Status.State, apply.Status.Message)
	require.Empty(t, f.pods(t))
	require.Empty(t, f.leases(t), "node and cluster Leases are released")
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: apply.Status.Hotfix.RecordName}, record))
	require.Len(t, record.Status.Nodes, 5)
	for _, node := range record.Status.Nodes {
		require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, node.State)
	}
	require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionActive)))
	require.Len(t, record.Spec.Sessions, 2)
	node := &corev1.Node{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-03"}, node))
	require.Contains(t, node.Annotations, hotfixAnnotationKey(record.Name))
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(plan), plan))
	require.Equal(t, "apply-1", plan.Status.Hotfix.AppliedBy)
	types := eventTypes(f.sink)
	for _, want := range []audit.EventType{audit.EventDebugSessionHotfixIntent, audit.EventDebugSessionHotfixNodeIntent,
		audit.EventDebugSessionHotfixNodeResult, audit.EventDebugSessionHotfixResult} {
		require.Contains(t, types, want)
	}

	// A plan is applied at most once.
	again := f.drive(t, f.session(t, "apply-2", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: hf.PlanHash}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, again.Status.State)
	require.Contains(t, again.Status.Message, "already applied")

	rollback := f.drive(t, f.session(t, "rollback-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageRollback, RecordName: record.Name}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, rollback.Status.State, rollback.Status.Message)
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(record), record))
	require.True(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionClosed)))
	require.False(t, meta.IsStatusConditionTrue(record.Status.Conditions, string(breakglassv1alpha1.HotfixRecordConditionActive)))
	require.Len(t, record.Spec.Sessions, 3, "plan, apply and rollback are listed")
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-03"}, node))
	require.NotContains(t, node.Annotations, hotfixAnnotationKey(record.Name))
}

func TestHotfixStopsAtFirstFailedNode(t *testing.T) {
	f := newHotfixFixture(t, 5, 0)
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	f.failNode = "worker-01"
	apply := f.drive(t, f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, apply.Status.State)
	require.Contains(t, apply.Status.Message, "worker-01 failed")
	started := 0
	for _, node := range apply.Status.Hotfix.Nodes {
		if node.CreateAttempted {
			started++
		}
	}
	require.Equal(t, 2, started, "no executor starts after the failed batch")
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: apply.Status.Hotfix.RecordName}, record))
	require.Len(t, record.Status.Nodes, 2)
	require.Empty(t, f.pods(t))
	require.Empty(t, f.leases(t))
}

func TestHotfixSuspendedTemplateStartsNoNode(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	ds := f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash})
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Name: "hotfix"}, template))
	template.Spec.Hotfix.Suspended = true
	require.NoError(t, f.hub.Update(t.Context(), template))
	ds = f.drive(t, ds)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Contains(t, ds.Status.Message, "suspended")
	for _, node := range ds.Status.Hotfix.Nodes {
		require.False(t, node.CreateAttempted)
	}
	require.Empty(t, f.leases(t))
}

type failingAuditSink struct{ maintenanceAuditCaptureSink }

func (s *failingAuditSink) Write(context.Context, *audit.Event) error { return errors.New("sink down") }

func TestHotfixAuditFailureBlocksExecution(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	manager := audit.NewManager(&failingAuditSink{}, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	f.c.WithAuditManager(manager)
	ds := f.session(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	_, err := f.c.handleHotfixActive(t.Context(), ds)
	require.Error(t, err)
	require.Empty(t, f.pods(t), "no executor without a durable audit receipt")
}

func TestHotfixMissingPodIsNeverRecreated(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	ds := f.session(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	for i := 0; i < 5 && len(f.pods(t)) == 0; i++ {
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		_, err := f.c.handleHotfixActive(t.Context(), ds)
		require.NoError(t, err)
	}
	pods := f.pods(t)
	require.Len(t, pods, 1)
	require.NoError(t, f.spoke.Delete(t.Context(), &pods[0]))
	ds = f.drive(t, ds)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Equal(t, "unknown", ds.Status.Hotfix.Nodes[0].Result)
	require.Empty(t, f.pods(t))
}

func TestHotfixControlPlaneGateStopsRollout(t *testing.T) {
	f := newHotfixFixture(t, 0, 2)
	request := &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStagePlan, FixedIn: "1.36.5",
		Payload: &breakglassv1alpha1.HotfixPayload{Type: breakglassv1alpha1.HotfixPayloadStaticPodImage, Image: &breakglassv1alpha1.HotfixImagePayload{
			StaticPod: "kube-apiserver", Image: "registry.k8s.io/kube-apiserver@sha256:" + strings.Repeat("d", 64)}},
		Nodes: &breakglassv1alpha1.HotfixNodeSelection{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"pool": "cp"}}}}
	plan := f.planned(t, "plan-1", request)
	require.EqualValues(t, 1, plan.Status.Hotfix.Plan.Nodes[1].Batch, "control-plane nodes run one at a time")
	hotfixReadyz = func(context.Context, *rest.Config) error { return errors.New("etcd check failed") }
	ds := f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash})
	for i := 0; i < 50; i++ {
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		if ds.Status.State != breakglassv1alpha1.DebugSessionStateActive {
			break
		}
		_, err := f.c.handleHotfixActive(t.Context(), ds)
		require.NoError(t, err)
		f.executor(t)
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		if hf := ds.Status.Hotfix; hf != nil && hf.BatchCompletedAt != nil {
			past := metav1.NewTime(time.Now().Add(-time.Hour))
			hf.BatchCompletedAt = &past
			require.NoError(t, f.hub.Status().Update(t.Context(), ds))
		}
	}
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Contains(t, ds.Status.Message, "health gate")
	require.True(t, ds.Status.Hotfix.Nodes[0].CreateAttempted)
	require.False(t, ds.Status.Hotfix.Nodes[1].CreateAttempted, "the second control-plane node never starts")
}

func TestHotfixPodShapes(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	ds := f.session(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	ds.Status.Hotfix = &breakglassv1alpha1.HotfixStatus{OperationID: "op", Plan: &breakglassv1alpha1.HotfixPlan{Payload: *ds.Spec.Hotfix.Payload}}
	node := &breakglassv1alpha1.HotfixNodeStatus{Name: "worker-00", UID: "worker-uid-0", ActiveDeadlineSeconds: 300, DeadlineUnix: time.Now().Unix() + 300}
	pod, err := f.c.hotfixPod(ds, node)
	require.NoError(t, err)
	container := pod.Spec.Containers[0]
	require.False(t, pod.Spec.HostPID)
	require.False(t, *container.SecurityContext.Privileged)
	require.Equal(t, []corev1.Capability{"CHOWN", "FOWNER", "DAC_OVERRIDE"}, container.SecurityContext.Capabilities.Add)
	require.True(t, container.VolumeMounts[1].ReadOnly, "plan mounts the target read-only")
	require.Equal(t, "/host/etc/ssh", container.VolumeMounts[1].MountPath)
	require.EqualValues(t, 1, *pod.Spec.TerminationGracePeriodSeconds)

	ds.Spec.Hotfix = &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "p", PlanHash: strings.Repeat("a", 64)}
	pod, err = f.c.hotfixPod(ds, node)
	require.NoError(t, err)
	require.False(t, pod.Spec.Containers[0].VolumeMounts[1].ReadOnly)
	require.EqualValues(t, 300, *pod.Spec.TerminationGracePeriodSeconds, "deletion waits for a mutating executor")

	ds.Status.Hotfix.Plan.Payload = breakglassv1alpha1.HotfixPayload{Type: breakglassv1alpha1.HotfixPayloadNodeDeb, Debs: []breakglassv1alpha1.HotfixDeb{{URL: "https://m.example/a.deb", SHA256: strings.Repeat("e", 64), Package: "aa", Version: "1"}}}
	pod, err = f.c.hotfixPod(ds, node)
	require.NoError(t, err)
	require.True(t, pod.Spec.HostPID)
	require.True(t, *pod.Spec.Containers[0].SecurityContext.Privileged)
	require.Len(t, pod.Spec.Volumes, 1, "the host shape mounts no host path")
}

func TestHotfixLayoutCanaryBatchesAndControlPlane(t *testing.T) {
	profile := &breakglassv1alpha1.DebugSessionHotfix{}
	var nodes []breakglassv1alpha1.HotfixNodeStatus
	for i := 0; i < 10; i++ {
		nodes = append(nodes, breakglassv1alpha1.HotfixNodeStatus{Name: fmt.Sprintf("w%d", i)})
	}
	nodes = append(nodes, breakglassv1alpha1.HotfixNodeStatus{Name: "cp0", ControlPlane: true}, breakglassv1alpha1.HotfixNodeStatus{Name: "cp1", ControlPlane: true})
	rollout := breakglassv1alpha1.HotfixEffectiveRollout(profile, &breakglassv1alpha1.HotfixRollout{MaxUnavailable: ptr.To(intstr.FromString("20%"))})
	laid, err := hotfixLayout(profile, &rollout, nodes)
	require.NoError(t, err)
	batches := map[int32][]string{}
	for _, node := range laid {
		batches[node.Batch] = append(batches[node.Batch], node.Name)
	}
	// canary 1, then 9 workers in batches of 2 (20%), then each control-plane node alone.
	require.Equal(t, []string{"w0"}, batches[0])
	require.Len(t, batches[1], 2)
	require.Len(t, batches[5], 1)
	require.Equal(t, []string{"cp0"}, batches[6])
	require.Equal(t, []string{"cp1"}, batches[7])

	all := breakglassv1alpha1.HotfixRollout{Strategy: breakglassv1alpha1.HotfixRolloutAllAtOnce}
	laid, err = hotfixLayout(profile, &all, nodes)
	require.NoError(t, err)
	require.EqualValues(t, 0, laid[9].Batch)
	require.EqualValues(t, 1, laid[10].Batch)
	require.EqualValues(t, 2, laid[11].Batch, "control-plane nodes stay one at a time even all-at-once")
}

// A session must carry a typed hotfix request exactly when its template is a
// hotfix template; anything else fails before any lease or target write.
func TestHotfixSessionTemplateMismatchFailsClosed(t *testing.T) {
	for name, viaTemplate := range map[string]bool{"session spec": false, "template": true} {
		t.Run(name, func(t *testing.T) {
			c, ds, template, _ := newDeploymentFenceFixture(t)
			if viaTemplate {
				template.Spec.Hotfix = &breakglassv1alpha1.DebugSessionHotfix{}
			} else {
				ds.Spec.Hotfix = &breakglassv1alpha1.DebugSessionHotfixRequest{Stage: breakglassv1alpha1.HotfixStageClose, RecordName: "hf-1"}
				require.NoError(t, c.client.Update(t.Context(), ds))
			}
			ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
			ds.Status.ResolvedTemplateIdentityCaptured = true
			ds.Status.ResolvedBindingSnapshotCaptured = true
			ds.Status.State = breakglassv1alpha1.DebugSessionStatePending
			require.NoError(t, c.client.Status().Update(t.Context(), ds))
			_, err := c.activateSession(t.Context(), ds, template, nil)
			require.NoError(t, err)
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, live.Status.State)
			require.Contains(t, live.Status.Message, "hotfix")
			require.Nil(t, live.Status.ConnectionLease)
		})
	}
}

func TestHotfixRequestReferences(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	newSession := func(request *breakglassv1alpha1.DebugSessionHotfixRequest) *breakglassv1alpha1.DebugSession {
		return &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "default"},
			Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "default/spoke", TemplateRef: "hotfix", Hotfix: request}}
	}
	require.NoError(t, validateHotfixReferences(t.Context(), f.hub, f.tmpl, newSession(&breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash})))
	require.Error(t, validateHotfixReferences(t.Context(), f.hub, f.tmpl, newSession(&breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: strings.Repeat("0", 64)})), "wrong hash")
	require.Error(t, validateHotfixReferences(t.Context(), f.hub, f.tmpl, newSession(&breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "missing", PlanHash: plan.Status.Hotfix.PlanHash})), "missing plan")
	require.Error(t, validateHotfixReferences(t.Context(), f.hub, f.tmpl, newSession(&breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageRollback, RecordName: "missing"})), "missing record")
	for _, stage := range []breakglassv1alpha1.HotfixStage{breakglassv1alpha1.HotfixStageReconfirm, breakglassv1alpha1.HotfixStageClose} {
		require.ErrorContains(t, validateHotfixReferences(t.Context(), f.hub, f.tmpl, newSession(&breakglassv1alpha1.DebugSessionHotfixRequest{
			Stage: stage, RecordName: "hf", Lifetime: "1d"})), "not served")
	}
}

// startApply runs a plan and starts the first apply batch without letting the executors finish.
func startApply(t *testing.T, f *hotfixFixture, workers int) *breakglassv1alpha1.DebugSession {
	t.Helper()
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	ds := f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash})
	for i := 0; i < 10 && len(f.pods(t)) == 0; i++ {
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		_, err := f.c.handleHotfixActive(t.Context(), ds)
		require.NoError(t, err)
	}
	require.Len(t, f.pods(t), 1, "the canary executor runs")
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	return ds
}

func TestHotfixTerminationWaitsForRunningExecutor(t *testing.T) {
	f := newHotfixFixture(t, 3, 0)
	ds := startApply(t, f, 3)
	// The session is terminated while the canary executor mutates the node.
	require.Error(t, f.c.cleanupHotfix(t.Context(), ds), "cleanup waits for the running executor")
	require.Len(t, f.pods(t), 1, "a running mutating executor is never deleted")
	require.Equal(t, 1, f.executor(t))
	for i := 0; i < 5; i++ {
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		if f.c.cleanupHotfix(t.Context(), ds) == nil {
			break
		}
	}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	require.True(t, ds.Status.Hotfix.Released)
	require.Equal(t, "applied", ds.Status.Hotfix.Nodes[0].Result)
	require.Empty(t, f.pods(t))
	require.Empty(t, f.leases(t))
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: ds.Status.Hotfix.RecordName}, record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, record.Status.Nodes[0].State, "the result reaches the record")
	started := 0
	for _, node := range ds.Status.Hotfix.Nodes {
		if node.CreateAttempted {
			started++
		}
	}
	require.Equal(t, 1, started, "no executor starts after the termination")
}

func TestHotfixRecordOutageIsRetried(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	ds := startApply(t, f, 1)
	f.executor(t)
	f.failRecordPatches = 1
	_, err := f.c.handleHotfixActive(t.Context(), ds)
	require.ErrorContains(t, err, "injected record outage")
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	require.Empty(t, ds.Status.Hotfix.Nodes[0].Result, "a result is persisted only after the record has it")
	ds = f.drive(t, ds)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, ds.Status.State, ds.Status.Message)
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: ds.Status.Hotfix.RecordName}, record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeApplied, record.Status.Nodes[0].State)
}

func TestHotfixChangedExecutorPodIsUnknown(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	ds := startApply(t, f, 1)
	pod := f.pods(t)[0]
	pod.Spec.Containers[0].Image = "registry.example/other@sha256:" + strings.Repeat("f", 64)
	require.NoError(t, f.spoke.Update(t.Context(), &pod))
	ds = f.drive(t, ds)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Equal(t, "unknown", ds.Status.Hotfix.Nodes[0].Result)
	record := &breakglassv1alpha1.HotfixRecord{}
	require.NoError(t, f.hub.Get(t.Context(), client.ObjectKey{Namespace: "default", Name: ds.Status.Hotfix.RecordName}, record))
	require.Equal(t, breakglassv1alpha1.HotfixNodeFailed, record.Status.Nodes[0].State, "an unknown node is tracked so rollback visits it")
}

func TestHotfixReplacedNodeStopsApply(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	plan := f.planned(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	node := &corev1.Node{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "worker-00"}, node))
	require.NoError(t, f.spoke.Delete(t.Context(), node))
	require.NoError(t, f.spoke.Create(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-00", Labels: map[string]string{"pool": "w"}}}))
	ds := f.drive(t, f.session(t, "apply-1", &breakglassv1alpha1.DebugSessionHotfixRequest{
		Stage: breakglassv1alpha1.HotfixStageApply, PlanRef: "plan-1", PlanHash: plan.Status.Hotfix.PlanHash}))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Contains(t, ds.Status.Message, "replaced")
	require.Empty(t, f.pods(t))
	require.Empty(t, f.leases(t))
}

func TestHotfixPlanRefusesTooManyPreImages(t *testing.T) {
	f := newHotfixFixture(t, hotfixMaxDiffs+1, 0)
	f.distinct = true
	ds := f.drive(t, f.session(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"})))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Contains(t, ds.Status.Message, "distinct pre-images")
}

func TestHotfixStopAfterLeaseReleasesIt(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	ds := f.session(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"}))
	fences := 0
	f.c.beforeDebugTargetWrite = func(string) {
		fences++
		if fences == 2 {
			// The session is revoked between the Lease and the Pod.
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), live))
			live.Status.Approval = nil
			require.NoError(t, f.hub.Status().Update(t.Context(), live))
		}
	}
	for i := 0; i < 10; i++ {
		require.NoError(t, f.hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
		if ds.Status.State != breakglassv1alpha1.DebugSessionStateActive {
			break
		}
		// The revocation races the controller's own status writes; a
		// conflict is retried on the next reconcile as in production.
		if _, err := f.c.handleHotfixActive(t.Context(), ds); err != nil {
			require.True(t, apierrors.IsConflict(err), err)
		}
	}
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State, ds.Status.Message)
	require.Empty(t, f.pods(t))
	require.Empty(t, f.leases(t), "the node Lease is released although no Pod was created")
	jobs := &batchv1.JobList{}
	require.NoError(t, f.spoke.List(t.Context(), jobs))
	require.Empty(t, jobs.Items)
}

func TestHotfixRejectedExecutorStops(t *testing.T) {
	f := newHotfixFixture(t, 2, 0)
	f.denyPods = true
	ds := f.drive(t, f.session(t, "plan-1", filePlanRequest(map[string]string{"pool": "w"})))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	require.Contains(t, ds.Status.Message, "rejected")
	require.Empty(t, f.leases(t))
}

func TestHotfixSelfApprovalAlwaysBlocked(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), f.hub, nil, nil)
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "hf"},
		Spec: breakglassv1alpha1.DebugSessionSpec{TemplateRef: "hotfix", RequestedBy: "requester", Hotfix: filePlanRequest(map[string]string{"pool": "w"})},
		Status: breakglassv1alpha1.DebugSessionStatus{ResolvedBindingSnapshotCaptured: true, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
			BlockSelfApproval: ptr.To(false), Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"requester", "approver"}}}}}
	require.False(t, api.isIdentityAuthorizedToApprove(t.Context(), session, debugSessionReadIdentity{legacyAllowed: true, username: "requester"}),
		"a hotfix requester never approves, whatever blockSelfApproval says")
	require.True(t, api.isIdentityAuthorizedToApprove(t.Context(), session, debugSessionReadIdentity{legacyAllowed: true, username: "approver"}))
}

func TestHotfixAPIRejectsGenericOverrides(t *testing.T) {
	f := newHotfixFixture(t, 1, 0)
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), f.hub, nil, nil)
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set("legacy_identity_allowed", true)
		ctx.Set("username", "requester")
		ctx.Set("email", "requester")
		ctx.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))
	body := `{"templateRef":"hotfix","cluster":"spoke","nodeSelector":{"kubernetes.io/hostname":"x"},"hotfix":{"stage":"close","recordName":"hf"}}`
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/debugSessions", strings.NewReader(body)))
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "hotfix accepts only the typed hotfix request")
}
