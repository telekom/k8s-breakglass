// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	extensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
