// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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
	require.Empty(t, sink.Events(), "status persistence failure must not be classified as cleanup failure")
}
