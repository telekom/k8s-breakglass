// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
)

type escalationAuditCapture struct {
	mu     sync.Mutex
	state  audit.ConfigurationState
	events []*audit.Event
}

func newEscalationAuditCapture() *escalationAuditCapture {
	return &escalationAuditCapture{state: audit.ConfigurationReady}
}

func (c *escalationAuditCapture) Emit(_ context.Context, event *audit.Event) {
	audittest.Record(event)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *escalationAuditCapture) ConfigurationState() audit.ConfigurationState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *escalationAuditCapture) setState(state audit.ConfigurationState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = state
}

func (c *escalationAuditCapture) take() []*audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	events := c.events
	c.events = nil
	return events
}

func auditedEscalation(generation int64) *breakglassv1alpha1.BreakglassEscalation {
	return &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "prod-admin", Namespace: "default", UID: "esc-uid", Generation: generation},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin", MaxValidFor: "1h",
			Allowed:   breakglassv1alpha1.BreakglassEscalationAllowed{Groups: []string{"ops"}},
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
		// Another status writer may already have advanced observedGeneration;
		// auditing must not depend on it.
		Status: breakglassv1alpha1.BreakglassEscalationStatus{ObservedGeneration: generation},
	}
}

type escalationAuditHarness struct {
	t   *testing.T
	cli client.Client
	r   *EscalationReconciler
}

func newEscalationAuditHarness(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation, capture *escalationAuditCapture) *escalationAuditHarness {
	cli := fake.NewClientBuilder().WithScheme(newTestEscalationReconcilerScheme()).WithObjects(esc).WithStatusSubresource(esc).Build()
	return &escalationAuditHarness{t: t, cli: cli,
		r: NewEscalationReconciler(cli, zap.NewNop().Sugar(), newEscalationFakeEventRecorder(10), nil, nil, 0).WithAuditEmitter(capture)}
}

func (h *escalationAuditHarness) reconcile() reconcile.Result {
	h.t.Helper()
	result, err := h.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "prod-admin", Namespace: "default"}})
	require.NoError(h.t, err)
	return result
}

func (h *escalationAuditHarness) bumpGeneration(generation int64) {
	h.t.Helper()
	esc := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(h.t, h.cli.Get(context.Background(), types.NamespacedName{Name: "prod-admin", Namespace: "default"}, esc))
	esc.Generation = generation
	esc.Spec.EscalatedGroup = "cluster-admin-v2"
	require.NoError(h.t, h.cli.Update(context.Background(), esc))
}

func TestEscalationReconcilerAuditsSpecChanges(t *testing.T) {
	capture := newEscalationAuditCapture()
	h := newEscalationAuditHarness(t, auditedEscalation(1), capture)

	require.Equal(t, reconcile.Result{}, h.reconcile())
	events := capture.take()
	require.Len(t, events, 1)
	created := events[0]
	require.Equal(t, audit.EventEscalationCreated, created.Type)
	require.Equal(t, "escalation/esc-uid/1", created.ID)
	require.Equal(t, "esc-uid", created.Target.UID)
	require.Equal(t, "esc-uid", created.RequestContext.EscalationUID)
	require.Equal(t, "cluster-admin", created.Details["escalatedGroup"])
	require.Len(t, created.Details["specSHA256"], 64)
	require.NoError(t, audittest.Check(created))

	h.reconcile()
	require.Empty(t, capture.take(), "an audited generation is not audited again")

	h.bumpGeneration(2)
	h.reconcile()
	events = capture.take()
	require.Len(t, events, 1)
	require.Equal(t, audit.EventEscalationUpdated, events[0].Type)
	require.Equal(t, "escalation/esc-uid/2", events[0].ID)
	require.EqualValues(t, 1, events[0].Details["previousGeneration"])
	require.NotEqual(t, created.Details["specSHA256"], events[0].Details["specSHA256"])

	// A restarted controller emits the current generation again with the same
	// ID; the previous generation is unknown and omitted.
	restarted := &escalationAuditHarness{t: t, cli: h.cli,
		r: NewEscalationReconciler(h.cli, zap.NewNop().Sugar(), newEscalationFakeEventRecorder(10), nil, nil, 0).WithAuditEmitter(capture)}
	restarted.reconcile()
	events = capture.take()
	require.Len(t, events, 1)
	require.Equal(t, "escalation/esc-uid/2", events[0].ID)
	require.NotContains(t, events[0].Details, "previousGeneration")
}

// Escalations reconciled before the AuditConfig reconciler loaded the audit
// pipeline are audited once it is ready, not dropped; disabled auditing
// emits nothing and does not requeue.
func TestEscalationReconcilerWaitsForAuditPipeline(t *testing.T) {
	capture := newEscalationAuditCapture()
	capture.setState(audit.ConfigurationUnavailable)
	h := newEscalationAuditHarness(t, auditedEscalation(1), capture)

	result := h.reconcile()
	require.Equal(t, h.r.auditRetry, result.RequeueAfter, "retry until the audit pipeline is configured")
	require.Empty(t, capture.take())
	require.Equal(t, escalationAuditRetry, h.reconcile().RequeueAfter)

	capture.setState(audit.ConfigurationReady)
	require.Equal(t, reconcile.Result{}, h.reconcile())
	events := capture.take()
	require.Len(t, events, 1)
	require.Equal(t, audit.EventEscalationCreated, events[0].Type)

	disabled := newEscalationAuditCapture()
	disabled.setState(audit.ConfigurationDisabled)
	require.Equal(t, reconcile.Result{}, newEscalationAuditHarness(t, auditedEscalation(1), disabled).reconcile())
	require.Empty(t, disabled.take())
}

func TestEscalationReconcilerAuditsDeletion(t *testing.T) {
	capture := newEscalationAuditCapture()
	r := NewEscalationReconciler(nil, zap.NewNop().Sugar(), nil, nil, nil, 0).WithAuditEmitter(capture)
	r.auditDeletion(auditedEscalation(5))
	events := capture.take()
	require.Len(t, events, 1)
	require.Equal(t, audit.EventEscalationDeleted, events[0].Type)
	require.Equal(t, "escalation/esc-uid/deleted", events[0].ID)
	require.Equal(t, audit.SeverityWarning, audit.SeverityForEventType(events[0].Type))
	require.NoError(t, audittest.Check(events[0]))

	// A delete observed before the audit pipeline is configured is retained
	// and delivered once it is ready.
	pending := newEscalationAuditCapture()
	pending.setState(audit.ConfigurationUnavailable)
	waiting := NewEscalationReconciler(nil, zap.NewNop().Sugar(), nil, nil, nil, 0).WithAuditEmitter(pending)
	waiting.auditRetry = 10 * time.Millisecond
	waiting.auditDeletion(auditedEscalation(5))
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, pending.take(), "nothing is emitted while the pipeline is unavailable")
	pending.setState(audit.ConfigurationReady)
	require.Eventually(t, func() bool {
		events := pending.take()
		return len(events) == 1 && events[0].ID == "escalation/esc-uid/deleted"
	}, 5*time.Second, 10*time.Millisecond)

	// Intentionally disabled auditing drops it.
	disabled := newEscalationAuditCapture()
	disabled.setState(audit.ConfigurationDisabled)
	NewEscalationReconciler(nil, zap.NewNop().Sugar(), nil, nil, nil, 0).WithAuditEmitter(disabled).auditDeletion(auditedEscalation(5))
	require.Empty(t, disabled.take())

	// Without an emitter nothing happens.
	NewEscalationReconciler(nil, zap.NewNop().Sugar(), nil, nil, nil, 0).auditDeletion(auditedEscalation(1))
}
