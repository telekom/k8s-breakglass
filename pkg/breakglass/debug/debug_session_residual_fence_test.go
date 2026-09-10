// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	extensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestKubectlDebugStatusPatchRejectsReplacementSession(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := breakglassv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "replacement"},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).Build()
	stale := live.DeepCopy()
	stale.UID = "original"

	handler := NewKubectlDebugHandler(client, nil)
	err := handler.patchDebugSessionStatusWithRetry(context.Background(), stale, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.Message = "old operation outcome"
	})
	if err == nil {
		t.Fatal("old operation patched a same-name replacement session")
	}
}

func TestDebugSessionCleanupStatusPatchRejectsReplacementSession(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := breakglassv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "replacement"},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).Build()
	stale := live.DeepCopy()
	stale.UID = "original"

	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	err := controller.patchDebugSessionCleanupStatus(context.Background(), stale)
	if err == nil {
		t.Fatal("old cleanup patched a same-name replacement session")
	}
}

func TestDebugSessionCleanupWithTrackedResourcesRequiresClientProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := breakglassv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Status: breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "apps/v1", Kind: "Deployment", Namespace: "target", Name: "debug",
		}}},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(session).Build()

	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	if err := controller.cleanupResources(context.Background(), session); err == nil {
		t.Fatal("cleanup reported success without a client provider for tracked resources")
	}
}

func TestDebugSessionCleanupMergesConcurrentSameUIDInventory(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := breakglassv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "same-session", ResourceVersion: "2"},
		Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateExpired, DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
			APIVersion: "v1", Kind: "Pod", Name: "late-created-pod", Namespace: "target", UID: "late-uid",
		}}},
	}
	hub := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).Build()
	stale := live.DeepCopy()
	stale.ResourceVersion = "1"
	stale.Status.DeployedResources = nil
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	if err := controller.patchDebugSessionCleanupStatus(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	stored := &breakglassv1alpha1.DebugSession{}
	if err := hub.Get(context.Background(), client.ObjectKeyFromObject(live), stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Status.DeployedResources) != 1 || stored.Status.DeployedResources[0].UID != "late-uid" {
		t.Fatal("cleanup erased concurrently persisted target inventory without deleting the target")
	}
}

func TestDebugSessionCleanupMergesConcurrentCreateOperationInventoryAfterConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	liveTransitionTime := metav1.NewTime(time.Date(2026, 9, 10, 18, 0, 0, 0, time.UTC))
	liveCleanupCondition := metav1.Condition{
		Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue,
		ObservedGeneration: 11, LastTransitionTime: liveTransitionTime,
		Reason: "CleanupFailed", Message: "live cleanup failure",
	}
	deployedA := breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", Name: "resource", UID: "", CreateOperationID: "op-a"}
	deployedB := deployedA
	deployedB.CreateOperationID = "op-b"
	podTemplateA := breakglassv1alpha1.PodTemplateResourceStatus{APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", ResourceName: "template-resource", Source: "template", CreateOperationID: "op-a"}
	podTemplateB := podTemplateA
	podTemplateB.CreateOperationID = "op-b"
	mainA := breakglassv1alpha1.AuxiliaryResourceStatus{Name: "aux", APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", ResourceName: "aux-resource", CreateOperationID: "op-a"}
	mainB := mainA
	mainB.CreateOperationID = "op-b"
	nestedA := breakglassv1alpha1.AuxiliaryResourceStatus{Name: "nested", APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", ResourceName: "nested-parent", CreateOperationID: "same-parent"}
	nestedA.AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: "v1", Kind: "Secret", Namespace: "target", ResourceName: "nested", CreateOperationID: "op-a"}}
	nestedB := nestedA.DeepCopy()
	nestedB.AdditionalResources[0].CreateOperationID = "op-b"
	live := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"}, Status: breakglassv1alpha1.DebugSessionStatus{
		DeployedResources:           []breakglassv1alpha1.DeployedResourceRef{deployedA},
		PodTemplateResourceStatuses: []breakglassv1alpha1.PodTemplateResourceStatus{podTemplateA},
		AuxiliaryResourceStatuses:   []breakglassv1alpha1.AuxiliaryResourceStatus{mainA, nestedA},
		Conditions:                  []metav1.Condition{liveCleanupCondition},
	}}
	injected := false
	hub := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).
		WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(ctx context.Context, underlying client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if !injected && subResource == "status" {
				injected = true
				var concurrent breakglassv1alpha1.DebugSession
				require.NoError(t, underlying.Get(ctx, client.ObjectKeyFromObject(live), &concurrent))
				concurrent.Status.DeployedResources = []breakglassv1alpha1.DeployedResourceRef{deployedB}
				concurrent.Status.PodTemplateResourceStatuses = []breakglassv1alpha1.PodTemplateResourceStatus{podTemplateB}
				concurrent.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{mainB, *nestedB}
				require.NoError(t, underlying.Status().Update(ctx, &concurrent))
				return apierrors.NewConflict(schema.GroupResource{Group: "breakglass.t-caas.telekom.com", Resource: "debugsessions"}, live.Name, assert.AnError)
			}
			return underlying.Status().Patch(ctx, obj, patch, opts...)
		}}).Build()
	stale := live.DeepCopy()
	stale.Status.DeployedResources = nil
	stale.Status.PodTemplateResourceStatuses = nil
	stale.Status.Conditions = []metav1.Condition{{
		Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionFalse,
		ObservedGeneration: 3, LastTransitionTime: metav1.NewTime(liveTransitionTime.Add(time.Hour)),
		Reason: "CleanupRecovered", Message: "stale recovery",
	}}
	nestedDesired := nestedA.DeepCopy()
	nestedDesired.AdditionalResources = nil
	stale.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{*nestedDesired}
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
	require.NoError(t, controller.patchDebugSessionCleanupStatus(context.Background(), stale, live.Status.DeepCopy()))
	assert.True(t, injected, "status patch conflict was not injected")
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(live), &stored))
	storedCleanupCondition := stored.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
	require.NotNil(t, storedCleanupCondition)
	assert.Equal(t, metav1.ConditionTrue, storedCleanupCondition.Status)
	assert.Equal(t, liveCleanupCondition.ObservedGeneration, storedCleanupCondition.ObservedGeneration)
	assert.True(t, storedCleanupCondition.LastTransitionTime.Equal(&liveCleanupCondition.LastTransitionTime))
	assert.Equal(t, boundedCleanupConditionMessage(stored.DeepCopy()), storedCleanupCondition.Message)
	require.Len(t, stored.Status.DeployedResources, 1)
	assert.Equal(t, "op-b", stored.Status.DeployedResources[0].CreateOperationID)
	require.Len(t, stored.Status.PodTemplateResourceStatuses, 1)
	assert.Equal(t, "op-b", stored.Status.PodTemplateResourceStatuses[0].CreateOperationID)
	require.Len(t, stored.Status.AuxiliaryResourceStatuses, 2)
	var mainStored, nestedStored *breakglassv1alpha1.AuxiliaryResourceStatus
	for _, status := range stored.Status.AuxiliaryResourceStatuses {
		switch status.Name {
		case "aux":
			mainStored = status.DeepCopy()
		case "nested":
			nestedStored = status.DeepCopy()
		}
	}
	require.NotNil(t, mainStored)
	assert.Equal(t, "op-b", mainStored.CreateOperationID)
	require.NotNil(t, nestedStored)
	require.Len(t, nestedStored.AdditionalResources, 1)
	assert.Equal(t, "op-b", nestedStored.AdditionalResources[0].CreateOperationID)
}

func TestDebugSessionCleanupMergesConcurrentCopiedPodReplacementAfterConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	old := breakglassv1alpha1.CopiedPodRef{CopyNamespace: "target", CopyName: "copy", UID: "old-uid"}
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid", ResourceVersion: "2"},
		Status:     breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{CopiedPods: []breakglassv1alpha1.CopiedPodRef{old}}},
	}
	injected := false
	hub := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithObjects(live).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, underlying client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if !injected && subResource == "status" {
					injected = true
					var concurrent breakglassv1alpha1.DebugSession
					if err := underlying.Get(ctx, client.ObjectKeyFromObject(live), &concurrent); err != nil {
						return err
					}
					concurrent.Status.KubectlDebugStatus.CopiedPods = []breakglassv1alpha1.CopiedPodRef{{CopyNamespace: "target", CopyName: "copy", UID: "new-uid"}}
					if err := underlying.Status().Update(ctx, &concurrent); err != nil {
						return err
					}
				}
				return underlying.Status().Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	stale := live.DeepCopy()
	stale.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{}
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)

	require.NoError(t, controller.patchDebugSessionCleanupStatus(context.Background(), stale, live.Status.DeepCopy()))
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(live), &stored))
	require.Len(t, stored.Status.KubectlDebugStatus.CopiedPods, 1)
	assert.Equal(t, "new-uid", stored.Status.KubectlDebugStatus.CopiedPods[0].UID)
}

func TestDebugSessionCleanupClearsAllowedPodsAndRetainsConcurrentRefs(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	clusterConfig := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: "default"}}
	newSession := func() *breakglassv1alpha1.DebugSession {
		return &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
			Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke"},
			Status: breakglassv1alpha1.DebugSessionStatus{AllowedPods: []breakglassv1alpha1.AllowedPodRef{
				{Name: "old", Namespace: "target", UID: "old-uid"},
			}},
		}
	}

	t.Run("clears persisted baseline", func(t *testing.T) {
		session := newSession()
		hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, clusterConfig).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
		controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))

		require.NoError(t, controller.cleanupResources(context.Background(), session))
		var stored breakglassv1alpha1.DebugSession
		require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
		require.Empty(t, stored.Status.AllowedPods)
	})

	t.Run("retains concurrently added reference", func(t *testing.T) {
		session := newSession()
		var injected bool
		hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, clusterConfig).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, underlying client.Client, subResource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				if !injected && subResource == "status" {
					injected = true
					var concurrent breakglassv1alpha1.DebugSession
					if err := underlying.Get(ctx, client.ObjectKeyFromObject(session), &concurrent); err != nil {
						return err
					}
					concurrent.Status.AllowedPods = append(concurrent.Status.AllowedPods, breakglassv1alpha1.AllowedPodRef{Name: "new", Namespace: "target", UID: "new-uid"})
					if err := underlying.Status().Update(ctx, &concurrent); err != nil {
						return err
					}
				}
				return underlying.Status().Patch(ctx, obj, patch, opts...)
			},
		}).Build()
		controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))

		require.NoError(t, controller.cleanupResources(context.Background(), session))
		var stored breakglassv1alpha1.DebugSession
		require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
		require.Len(t, stored.Status.AllowedPods, 1)
		assert.Equal(t, "new-uid", stored.Status.AllowedPods[0].UID)
	})
}

func TestDebugSessionAdmissionFreezesCapturedNilBinding(t *testing.T) {
	old := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "spoke", TemplateRef: "template", RequestedBy: "alice",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:                           breakglassv1alpha1.DebugSessionStatePending,
			ResolvedBindingSnapshotCaptured: true,
		},
	}
	updated := old.DeepCopy()
	updated.Status.ResolvedBindingSpec = &extensionsv1.JSON{Raw: []byte(`{"displayName":"changed"}`)}
	if _, err := old.ValidateUpdate(context.Background(), old, updated); err == nil {
		t.Fatal("admission accepted a binding decision change after a captured nil binding")
	}
}
