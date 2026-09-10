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
	extensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
