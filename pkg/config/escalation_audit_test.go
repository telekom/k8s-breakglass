// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
)

type escalationAuditCapture struct {
	mu     sync.Mutex
	events []*audit.Event
}

func (c *escalationAuditCapture) Emit(_ context.Context, event *audit.Event) {
	audittest.Record(event)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *escalationAuditCapture) take() []*audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.events
	c.events = nil
	return events
}

func auditedEscalation(generation, observed int64) *breakglassv1alpha1.BreakglassEscalation {
	return &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-admin", Namespace: "default", UID: "esc-uid", Generation: generation},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin", MaxValidFor: "1h",
			Allowed:   breakglassv1alpha1.BreakglassEscalationAllowed{Groups: []string{"ops"}},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{ObservedGeneration: observed},
	}
}

func reconcileEscalation(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation, capture *escalationAuditCapture) {
	t.Helper()
	cli := fake.NewClientBuilder().WithScheme(newTestEscalationReconcilerScheme()).WithObjects(esc).WithStatusSubresource(esc).Build()
	r := NewEscalationReconciler(cli, zap.NewNop().Sugar(), newEscalationFakeEventRecorder(10), nil, nil, 0).WithAuditEmitter(capture)
	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: esc.Name, Namespace: esc.Namespace}})
	require.NoError(t, err)
	// The status write records the generation: a second reconcile is silent.
	_, err = r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: esc.Name, Namespace: esc.Namespace}})
	require.NoError(t, err)
}

func TestEscalationReconcilerAuditsSpecChanges(t *testing.T) {
	capture := &escalationAuditCapture{}

	reconcileEscalation(t, auditedEscalation(1, 0), capture)
	events := capture.take()
	require.Len(t, events, 1, "one created event; the second reconcile observed the generation")
	created := events[0]
	require.Equal(t, audit.EventEscalationCreated, created.Type)
	require.Equal(t, "escalation/esc-uid/1", created.ID)
	require.Equal(t, "esc-uid", created.Target.UID)
	require.Equal(t, "esc-uid", created.RequestContext.EscalationUID)
	require.Equal(t, "cluster-admin", created.Details["escalatedGroup"])
	require.Len(t, created.Details["specSHA256"], 64)
	require.NoError(t, audittest.Check(created))

	reconcileEscalation(t, auditedEscalation(3, 2), capture)
	events = capture.take()
	require.Len(t, events, 1)
	require.Equal(t, audit.EventEscalationUpdated, events[0].Type)
	require.Equal(t, "escalation/esc-uid/3", events[0].ID)
	require.EqualValues(t, 2, events[0].Details["previousGeneration"])

	reconcileEscalation(t, auditedEscalation(4, 4), capture)
	require.Empty(t, capture.take(), "an observed generation is not audited again")
}

func TestEscalationReconcilerAuditsDeletion(t *testing.T) {
	capture := &escalationAuditCapture{}
	r := NewEscalationReconciler(nil, zap.NewNop().Sugar(), nil, nil, nil, 0).WithAuditEmitter(capture)
	r.auditDeletion(auditedEscalation(5, 5))
	events := capture.take()
	require.Len(t, events, 1)
	require.Equal(t, audit.EventEscalationDeleted, events[0].Type)
	require.Equal(t, "escalation/esc-uid/deleted", events[0].ID)
	require.Equal(t, audit.SeverityWarning, audit.SeverityForEventType(events[0].Type))
	require.NoError(t, audittest.Check(events[0]))

	// Without an emitter nothing happens.
	NewEscalationReconciler(nil, zap.NewNop().Sugar(), nil, nil, nil, 0).auditDeletion(auditedEscalation(1, 1))
}
