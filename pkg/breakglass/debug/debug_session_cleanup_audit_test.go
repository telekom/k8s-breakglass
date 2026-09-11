// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type cleanupAuditCaptureSink struct {
	mu     sync.Mutex
	events []*audit.Event
}

func (s *cleanupAuditCaptureSink) Write(_ context.Context, event *audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

func (s *cleanupAuditCaptureSink) Close() error { return nil }

func (s *cleanupAuditCaptureSink) Name() string { return "cleanup-audit-capture" }

func (s *cleanupAuditCaptureSink) Events() []*audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*audit.Event(nil), s.events...)
}

func TestCleanupStatusPatchFailureDoesNotEmitCleanupFailureAudit(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "ns", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"},
		Status:     breakglassv1alpha1.DebugSessionStatus{DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "target", Name: "residual", UID: "residual-uid"}}},
	}
	hub := fake.NewClientBuilder().WithScheme(Scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, subResource string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return errors.New("status patch failed")
				}
				return nil
			},
		}).Build()
	sink := &cleanupAuditCaptureSink{}
	auditManager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	defer func() { require.NoError(t, auditManager.Close()) }()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).
		WithAuditManager(auditManager)

	err := controller.cleanupResources(context.Background(), session)
	require.Error(t, err)
	require.ErrorContains(t, err, "status patch failed")
	require.NoError(t, auditManager.Close())
	require.Empty(t, sink.Events(), "status persistence failure must not be classified as cleanup failure")
}

func TestInvalidDebugSessionValidationAuditIsIdempotent(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "ns", UID: types.UID("session-uid")},
	}
	hub := fake.NewClientBuilder().WithScheme(Scheme).
		WithObjects(session).WithStatusSubresource(session).Build()
	sink := &cleanupAuditCaptureSink{}
	auditManager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).
		WithAuditManager(auditManager)
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace}}
	require.NoError(t, func() error { _, err := controller.Reconcile(context.Background(), req); return err }())
	require.NoError(t, func() error { _, err := controller.Reconcile(context.Background(), req); return err }())
	require.NoError(t, auditManager.Close())

	var validationEvents int
	for _, event := range sink.Events() {
		if event.Type == audit.EventDebugSessionValidationFailed {
			validationEvents++
		}
	}
	assert.Equal(t, 1, validationEvents)
}

func TestInvalidDebugSessionValidationAuditWaitsForStatusPersistence(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-write", Namespace: "ns", UID: types.UID("session-uid")},
	}
	hub := fake.NewClientBuilder().WithScheme(Scheme).
		WithObjects(session).WithStatusSubresource(session).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, subResource string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return errors.New("status persistence unavailable")
				}
				return nil
			},
		}).Build()
	sink := &cleanupAuditCaptureSink{}
	auditManager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).
		WithAuditManager(auditManager)
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace}}
	_, firstErr := controller.Reconcile(context.Background(), req)
	_, secondErr := controller.Reconcile(context.Background(), req)
	assert.Error(t, firstErr)
	assert.Error(t, secondErr)
	require.NoError(t, auditManager.Close())
	assert.Empty(t, sink.Events(), "validation failure is audited only after status persistence")
}

func TestCleanupStatusOnlyErrorHasNoResidualFailureAudit(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "status-only", Namespace: "ns", UID: "uid"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated, KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{ID: "done", State: breakglassv1alpha1.KubectlDebugOperationCompleted}}}}}
	patches := 0
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).WithStatusSubresource(session).WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
		patches++
		if patches == 1 {
			return errors.New("bookkeeping unavailable")
		}
		return cl.SubResource(sub).Patch(ctx, obj, patch, opts...)
	}}).Build()
	sink := &cleanupAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).WithAuditManager(manager)
	require.ErrorContains(t, controller.cleanupResources(context.Background(), session), "bookkeeping unavailable")
	require.GreaterOrEqual(t, patches, 2)
	require.False(t, cleanupConditionFailed(session))
	require.NoError(t, manager.Close())
	require.Empty(t, sink.Events())
}

func TestCleanupRecoveredAuditUsesLiveCondition(t *testing.T) {
	live := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "live-recovery", Namespace: "ns", UID: "uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateTerminated, Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", Message: "earlier retry"}}}}
	hub := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(live).WithStatusSubresource(live).Build()
	stale := live.DeepCopy()
	stale.Status.Conditions = nil
	sink := &cleanupAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).WithAuditManager(manager)
	require.NoError(t, controller.cleanupResources(context.Background(), stale))
	require.NoError(t, controller.cleanupResources(context.Background(), stale))
	require.NoError(t, manager.Close())
	require.Len(t, sink.Events(), 1)
	require.Equal(t, audit.EventDebugSessionCleanupRecovered, sink.Events()[0].Type)
}
