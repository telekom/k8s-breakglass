// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestDebugSessionCleanupPreservesConcurrentAuxiliaryDocument(t *testing.T) {
	baseline := []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "bundle", APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", ResourceName: "first", UID: "first-uid"}}
	desired := []breakglassv1alpha1.AuxiliaryResourceStatus{baseline[0]}
	current := []breakglassv1alpha1.AuxiliaryResourceStatus{baseline[0]}
	current[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", ResourceName: "late-document", UID: "late-uid"}}
	merged := mergeAuxiliaryResourceStatuses(baseline, desired, current)
	if len(merged) != 1 || len(merged[0].AdditionalResources) != 1 || merged[0].AdditionalResources[0].UID != "late-uid" {
		t.Fatal("cleanup merge erased concurrently persisted additional-document inventory")
	}
}

func TestReviewFailedCleanupCompletesDeletedHistory(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateFailed,
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
				Name: "completed", Created: true, Deleted: true,
				AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{UID: "child-uid", Deleted: true}},
			}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	result, err := controller.handleFailedCleanup(context.Background(), session)
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter)
}

func TestReviewFailedCleanupRecoversEmptyInventoryFailure(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "recovery", Namespace: "ns", UID: "recovery-uid"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:      breakglassv1alpha1.DebugSessionStateFailed,
			Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", Message: "retry"}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)

	result, err := controller.handleFailedCleanup(context.Background(), session)
	require.NoError(t, err)
	require.Zero(t, result.RequeueAfter)
	condition := session.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "CleanupRecovered", condition.Reason)
}

func TestCleanupStatusPatchRetainsFailureWhenConcurrentResourceArrives(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	condition := metav1.Condition{
		Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue,
		Reason: "CleanupFailed", Message: "residual resource",
	}
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid", Generation: 7},
		Status: breakglassv1alpha1.DebugSessionStatus{
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "Pod", Namespace: "target", Name: "late"}},
			Conditions:        []metav1.Condition{condition},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).WithStatusSubresource(live).Build()
	stale := live.DeepCopy()
	stale.Status.DeployedResources = nil
	stale.Status.Conditions = []metav1.Condition{{
		Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionFalse,
		Reason: "CleanupRecovered", Message: "Cleanup completed; no residual resources remain.",
	}}
	baseline := live.Status.DeepCopy()
	baseline.DeployedResources = nil
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	require.NoError(t, controller.patchDebugSessionCleanupStatus(context.Background(), stale, baseline))
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(live), stored))
	require.Len(t, stored.Status.DeployedResources, 1)
	storedCondition := stored.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, storedCondition)
	require.Equal(t, metav1.ConditionTrue, storedCondition.Status)
	assert.Equal(t, int64(7), storedCondition.ObservedGeneration)
	assert.Contains(t, storedCondition.Message, "late")
}

func TestCleanupStatusPatchRetainsFailureForUnresolvedPodTemplateIntent(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			PodTemplateResourceStatuses: []breakglassv1alpha1.PodTemplateResourceStatus{{
				APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", ResourceName: "late", CreateOperationID: "create-op",
			}},
			Conditions: []metav1.Condition{{
				Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue,
				Reason: "CleanupFailed", Message: "residual resource",
			}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).WithStatusSubresource(live).Build()
	stale := live.DeepCopy()
	stale.Status.PodTemplateResourceStatuses = nil
	stale.Status.Conditions = []metav1.Condition{{
		Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionFalse,
		Reason: "CleanupRecovered", Message: "Cleanup completed; no residual resources remain.",
	}}
	baseline := live.Status.DeepCopy()
	baseline.PodTemplateResourceStatuses = nil
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	require.NoError(t, controller.patchDebugSessionCleanupStatus(context.Background(), stale, baseline))
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(live), stored))
	require.Len(t, stored.Status.PodTemplateResourceStatuses, 1)
	storedCondition := stored.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, storedCondition)
	require.Equal(t, metav1.ConditionTrue, storedCondition.Status)
}

func TestCleanupStatusPatchRetainsFailureForPreparedKubectlOperation(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{
				ID: "prepared-op", State: breakglassv1alpha1.KubectlDebugOperationPrepared,
			}}},
			Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", Message: "retry"}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).WithStatusSubresource(live).Build()
	stale := live.DeepCopy()
	stale.Status.KubectlDebugStatus = nil
	stale.Status.Conditions = []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionFalse, Reason: "CleanupRecovered", Message: "Cleanup completed; no residual resources remain."}}
	baseline := live.Status.DeepCopy()
	baseline.KubectlDebugStatus = nil
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	require.NoError(t, controller.patchDebugSessionCleanupStatus(context.Background(), stale, baseline))

	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(live), stored))
	require.NotNil(t, stored.Status.KubectlDebugStatus)
	require.Len(t, stored.Status.KubectlDebugStatus.Operations, 1)
	assert.Equal(t, breakglassv1alpha1.KubectlDebugOperationPrepared, stored.Status.KubectlDebugStatus.Operations[0].State)
	condition := stored.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
}

func TestCleanupStatusResidualsRespectRetentionAndUnresolvedIntents(t *testing.T) {
	kept := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "kept", DeleteAfter: false}}},
		AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
			Name: "kept", Created: true,
		}},
	}}
	assert.False(t, cleanupStatusHasResiduals(kept), "deleteAfter=false resources are intentionally retained")
	assert.Empty(t, cleanupResidualIdentities(kept), "retained resources must not appear in cleanup evidence")

	unknown := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{
			Name: "unknown", CreateOperationID: "create-op",
			AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{ResourceName: "child", CreateOperationID: "child-op"}},
		}},
	}}
	assert.True(t, cleanupStatusHasResiduals(unknown), "unresolved create intents remain cleanup residuals")
}

func TestCleanupRetainedAuxiliaryResourceSkipsTargetConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "retained", Namespace: "ns", UID: "retained-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "missing-cluster"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate:          &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "kept", DeleteAfter: false}}},
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "kept", Created: true, UID: "kept-uid", Kind: "ConfigMap", APIVersion: "v1", Namespace: "ns", ResourceName: "kept"}},
			DeployedResources:         []breakglassv1alpha1.DeployedResourceRef{{Source: "auxiliary:kept", Kind: "ConfigMap", APIVersion: "v1", Namespace: "ns", Name: "kept", UID: "kept-uid"}},
			Conditions:                []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", Message: "retry"}},
		},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))

	require.NoError(t, controller.cleanupResources(context.Background(), session))
	condition := session.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	session.Status.AuxiliaryResourceStatuses = append(session.Status.AuxiliaryResourceStatuses, breakglassv1alpha1.AuxiliaryResourceStatus{Name: "unknown", Kind: "ConfigMap", Namespace: "ns", ResourceName: "unknown", CreateOperationID: "unknown-operation"})
	require.NoError(t, hub.Status().Update(context.Background(), session))
	require.ErrorContains(t, controller.cleanupResources(context.Background(), session), "cleanup intent remains unresolved")
	condition = session.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.Equal(t, metav1.ConditionTrue, condition.Status)
	require.Contains(t, condition.Message, "ns/ConfigMap/unknown")
	require.NotContains(t, condition.Message, "kept-uid")
	require.Len(t, session.Status.DeployedResources, 1, "retained identity stays durable while another cleanup fails")
}

func TestCleanupRequeuesMergedConcurrentResidual(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "concurrent-residual", Namespace: "ns", UID: "uid", Generation: 3}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated, Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", Message: "prior"}}}}
	injected := false
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).WithStatusSubresource(session).WithInterceptorFuncs(interceptor.Funcs{Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		if !injected {
			injected = true
			live := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, cl.Get(ctx, key, live))
			live.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "ConfigMap", Name: "concurrent", Namespace: "target", UID: "new-uid"}}
			require.NoError(t, cl.Status().Update(ctx, live))
		}
		return cl.Get(ctx, key, obj, opts...)
	}}).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	result, err := controller.handleCleanup(context.Background(), session)
	require.NoError(t, err)
	require.Equal(t, ExpiredSessionRequeue, result.RequeueAfter)
	require.True(t, cleanupConditionFailed(session))
	require.Contains(t, cleanupResidualIdentities(session), "target/ConfigMap/concurrent (uid=new-uid)")
}

func TestCleanupRepeatedRecoveryPreservesTransition(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "recovered", Namespace: "ns", UID: "uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated}}
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).WithStatusSubresource(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))
	require.NoError(t, controller.cleanupResources(context.Background(), session))
	before := session.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)).DeepCopy()
	require.NoError(t, controller.cleanupResources(context.Background(), session))
	require.Equal(t, before, session.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed)))
}
