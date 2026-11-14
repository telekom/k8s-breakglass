// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/prometheus/client_golang/prometheus/testutil"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

type escalationAuditCapture struct {
	mu     sync.Mutex
	state  audit.ConfigurationState
	reject bool
	events []*audit.Event
}

func newEscalationAuditCapture() *escalationAuditCapture {
	return &escalationAuditCapture{state: audit.ConfigurationReady}
}

func (c *escalationAuditCapture) TryEmitRetryable(_ context.Context, event *audit.Event) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reject {
		return false
	}
	audittest.Record(event)
	c.events = append(c.events, event)
	return true
}

func (c *escalationAuditCapture) ConfigurationState() audit.ConfigurationState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *escalationAuditCapture) set(state audit.ConfigurationState, reject bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state, c.reject = state, reject
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

func newEscalationAuditHarness(t *testing.T, esc *breakglassv1alpha1.BreakglassEscalation, emitter EscalationAuditEmitter) *escalationAuditHarness {
	cli := fake.NewClientBuilder().WithScheme(newTestEscalationReconcilerScheme()).WithObjects(esc).WithStatusSubresource(esc).Build()
	return &escalationAuditHarness{t: t, cli: cli,
		r: NewEscalationReconciler(cli, zap.NewNop().Sugar(), newEscalationFakeEventRecorder(10), nil, nil, 0).WithAuditEmitter(emitter)}
}

func (h *escalationAuditHarness) reconcile() reconcile.Result {
	h.t.Helper()
	result, err := h.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "prod-admin", Namespace: "default"}})
	require.NoError(h.t, err)
	return result
}

// deliver runs one delivery pass, as the audit runnable does.
func (h *escalationAuditHarness) deliver() {
	h.r.auditor.flush(context.Background())
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
	require.Empty(t, capture.take(), "reconcile only records; the runnable delivers")
	h.deliver()
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
	h.deliver()
	require.Empty(t, capture.take(), "an audited generation is not audited again")

	h.bumpGeneration(2)
	h.reconcile()
	h.deliver()
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
	restarted.deliver()
	events = capture.take()
	require.Len(t, events, 1)
	require.Equal(t, "escalation/esc-uid/2", events[0].ID)
	require.NotContains(t, events[0].Details, "previousGeneration")
}

// An event that the pipeline did not accept (not configured yet, or a full
// queue) is retained and retried with backoff, keeps its first observation
// time, and never requeues the reconciler; disabled auditing records nothing.
func TestEscalationAuditRetriesUnacceptedEvents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state audit.ConfigurationState
	}{{"pipeline not configured yet", audit.ConfigurationUnavailable}, {"queue full", audit.ConfigurationReady}} {
		t.Run(tc.name, func(t *testing.T) {
			capture := newEscalationAuditCapture()
			capture.set(tc.state, true)
			h := newEscalationAuditHarness(t, auditedEscalation(1), capture)
			now := time.Now()
			h.r.auditor.now = func() time.Time { return now }
			observedAt := now
			require.Equal(t, reconcile.Result{}, h.reconcile(), "auditing never requeues the reconciler")
			require.Equal(t, 1, h.r.auditor.flush(context.Background()), "not due yet")
			now = now.Add(escalationAuditRetry)
			require.Equal(t, 1, h.r.auditor.flush(context.Background()))
			entry := h.r.auditor.pending[escalationAuditKey{uid: "esc-uid", generation: 1}]
			require.Equal(t, now.Add(h.r.auditor.backoff(entry.attempts)), entry.next, "exponential backoff")
			require.Empty(t, capture.take())

			capture.set(audit.ConfigurationReady, false)
			now = now.Add(escalationAuditMaxRetry)
			require.Zero(t, h.r.auditor.flush(context.Background()))
			events := capture.take()
			require.Len(t, events, 1)
			require.Equal(t, audit.EventEscalationCreated, events[0].Type)
			require.Equal(t, observedAt.UTC(), events[0].Timestamp, "the event keeps its first observation time")
		})
	}

	disabled := newEscalationAuditCapture()
	disabled.set(audit.ConfigurationDisabled, false)
	h := newEscalationAuditHarness(t, auditedEscalation(1), disabled)
	require.Equal(t, reconcile.Result{}, h.reconcile())
	require.Empty(t, disabled.take())
	require.Empty(t, h.r.auditor.pending)
}

// Every observed generation and the deletion are separate snapshots: an
// update or a delete during an outage does not discard an earlier change.
func TestEscalationAuditKeepsEverySnapshotDuringOutage(t *testing.T) {
	for _, tc := range []string{"update", "delete"} {
		t.Run(tc, func(t *testing.T) {
			capture := newEscalationAuditCapture()
			capture.set(audit.ConfigurationUnavailable, true)
			h := newEscalationAuditHarness(t, auditedEscalation(1), capture)
			h.reconcile()
			h.bumpGeneration(2)
			h.reconcile()
			if tc == "delete" {
				esc := auditedEscalation(2)
				h.r.auditor.deletion(esc)
			}
			capture.set(audit.ConfigurationReady, false)
			h.r.auditor.now = func() time.Time { return time.Now().Add(escalationAuditMaxRetry) }
			require.Zero(t, h.r.auditor.flush(context.Background()))
			ids := map[string]bool{}
			for _, e := range capture.take() {
				ids[e.ID] = true
			}
			want := map[string]bool{"escalation/esc-uid/1": true, "escalation/esc-uid/2": true}
			if tc == "delete" {
				want["escalation/esc-uid/deleted"] = true
			}
			require.Equal(t, want, ids)
		})
	}
}

// flush never holds the lock while enqueueing: a blocked enqueue does not
// block reconciliation or the delete handler.
func TestEscalationAuditDoesNotHoldLockDuringEnqueue(t *testing.T) {
	blocking := &blockingEmitter{release: make(chan struct{}), entered: make(chan struct{}, 1)}
	a := newEscalationAuditor(blocking, zap.NewNop().Sugar())
	a.deletion(auditedEscalation(1))
	go a.flush(context.Background())
	<-blocking.entered
	done := make(chan struct{})
	go func() {
		other := auditedEscalation(1)
		other.UID = "other"
		a.deletion(other)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deletion blocked behind an in-flight enqueue")
	}
	close(blocking.release)
}

// Reconciliation returns while the audit pipeline blocks enqueueing: it only
// records the snapshot and wakes the runnable.
func TestEscalationReconcileDoesNotWaitForAuditDelivery(t *testing.T) {
	blocking := &blockingEmitter{release: make(chan struct{}), entered: make(chan struct{}, 1)}
	t.Cleanup(func() { close(blocking.release) })
	h := newEscalationAuditHarness(t, auditedEscalation(1), blocking)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.r.auditor.run(ctx)
	h.bumpGeneration(2)
	done := make(chan struct{})
	go func() {
		h.reconcile()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile waited for audit delivery")
	}
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the runnable was not woken to deliver the event")
	}
	h.reconcile() // still returns while delivery is blocked
}

// The informer hooks record each generation, so changes that the work queue
// coalesces into one reconcile, and a create followed by a delete before any
// reconcile, are all audited.
func TestEscalationAuditRecordsCoalescedChanges(t *testing.T) {
	capture := newEscalationAuditCapture()
	a := newEscalationAuditor(capture, zap.NewNop().Sugar())
	for generation := int64(1); generation <= 3; generation++ {
		a.observe(auditedEscalation(generation))
	}
	a.deletion(auditedEscalation(3))
	a.observe(&breakglassv1alpha1.IdentityProvider{}) // other kinds are ignored
	require.Zero(t, a.flush(context.Background()))
	var ids []string
	for _, e := range capture.take() {
		ids = append(ids, e.ID)
	}
	require.ElementsMatch(t, []string{"escalation/esc-uid/1", "escalation/esc-uid/2", "escalation/esc-uid/3", "escalation/esc-uid/deleted"}, ids)
}

// A reconcile that reads a newer generation before the informer delivers an
// older one does not discard the older one.
func TestEscalationAuditOutOfOrderGenerations(t *testing.T) {
	capture := newEscalationAuditCapture()
	a := newEscalationAuditor(capture, zap.NewNop().Sugar())
	a.specChange(auditedEscalation(3)) // reconcile reads generation 3 from the cache
	a.observe(auditedEscalation(2))    // queued informer callback for generation 2
	a.observe(auditedEscalation(3))    // and for generation 3: deduplicated
	require.Zero(t, a.flush(context.Background()))
	byID := map[string]*audit.Event{}
	for _, e := range capture.take() {
		byID[e.ID] = e
	}
	require.Len(t, byID, 2)
	require.Contains(t, byID, "escalation/esc-uid/2")
	require.Contains(t, byID, "escalation/esc-uid/3")
	require.NotContains(t, byID["escalation/esc-uid/3"].Details, "previousGeneration", "unknown when generation 3 was recorded")
	require.NoError(t, audittest.Check(byID["escalation/esc-uid/2"]))
}

type blockingEmitter struct {
	release chan struct{}
	entered chan struct{}
}

func (b *blockingEmitter) TryEmitRetryable(context.Context, *audit.Event) bool {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return true
}

func (*blockingEmitter) ConfigurationState() audit.ConfigurationState {
	return audit.ConfigurationReady
}

func TestEscalationAuditorBoundsAndExpiry(t *testing.T) {
	capture := newEscalationAuditCapture()
	capture.set(audit.ConfigurationUnavailable, true)
	a := newEscalationAuditor(capture, zap.NewNop().Sugar())
	now := time.Now()
	a.now = func() time.Time { return now }
	dropped := func(reason string) float64 {
		return testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, reason))
	}
	capBefore, ttlBefore := dropped("cap"), dropped("ttl")
	for i := range escalationAuditLimit + 10 {
		esc := auditedEscalation(1)
		esc.UID = types.UID(fmt.Sprintf("uid-%d", i))
		now = now.Add(time.Millisecond)
		if i%2 == 0 {
			a.specChange(esc)
		} else {
			a.deletion(esc)
		}
	}
	require.Len(t, a.pending, escalationAuditLimit, "retained events are bounded")
	require.NotContains(t, a.pending, escalationAuditKey{uid: "uid-0", generation: 1}, "the oldest event is evicted")
	require.Equal(t, capBefore+10, dropped("cap"), "every eviction at the cap is counted")

	now = now.Add(escalationAuditTTL + time.Minute)
	require.Zero(t, a.flush(context.Background()), "expired events are dropped")
	require.Equal(t, ttlBefore+float64(escalationAuditLimit), dropped("ttl"), "every expired event is counted")
	require.Empty(t, a.seen, "a dropped event is forgotten, so a later reconcile records it again")
	capture.set(audit.ConfigurationReady, false)
	a.specChange(auditedEscalation(1))
	require.Zero(t, a.flush(context.Background()))
	require.Len(t, capture.take(), 1, "the current generation is replayed after its earlier snapshot expired")

	// The dedup set of delivered generations is bounded too, evicting the
	// oldest entries.
	for i := range escalationAuditSeenLimit + 10 {
		esc := auditedEscalation(int64(i + 2))
		now = now.Add(time.Millisecond)
		a.specChange(esc)
		a.flush(context.Background())
	}
	capture.take()
	require.Len(t, a.seen, escalationAuditSeenLimit)
	a.specChange(auditedEscalation(escalationAuditSeenLimit + 11))
	_, kept := a.seen[escalationAuditKey{uid: "esc-uid", generation: escalationAuditSeenLimit + 11}]
	require.True(t, kept, "the newest generation is kept")
}

func TestEscalationReconcilerAuditsDeletion(t *testing.T) {
	capture := newEscalationAuditCapture()
	capture.set(audit.ConfigurationUnavailable, true)
	a := newEscalationAuditor(capture, zap.NewNop().Sugar())
	a.retry = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.run(ctx); close(done) }()

	observedAt := time.Now()
	a.deletion(auditedEscalation(5))
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, capture.take(), "nothing is accepted while the pipeline is unavailable")
	capture.set(audit.ConfigurationReady, false)
	var delivered []*audit.Event
	require.Eventually(t, func() bool {
		delivered = append(delivered, capture.take()...)
		return len(delivered) == 1
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, audit.EventEscalationDeleted, delivered[0].Type)
	require.Equal(t, "escalation/esc-uid/deleted", delivered[0].ID)
	require.WithinDuration(t, observedAt, delivered[0].Timestamp, 40*time.Millisecond, "observation time, not delivery time")
	require.Equal(t, audit.SeverityWarning, audit.SeverityForEventType(delivered[0].Type))
	require.NoError(t, audittest.Check(delivered[0]))

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the retry loop must stop when its context ends")
	}

	disabled := newEscalationAuditCapture()
	disabled.set(audit.ConfigurationDisabled, false)
	b := newEscalationAuditor(disabled, zap.NewNop().Sugar())
	b.deletion(auditedEscalation(5))
	require.Zero(t, b.flush(context.Background()))
	require.Empty(t, disabled.take())

	// Without an emitter nothing happens.
	var none *escalationAuditor
	none.deletion(auditedEscalation(1))
	none.specChange(auditedEscalation(1))
}

// With the real audit.Service: no AuditConfig means disabled after the
// initial sync, so nothing is retained and nothing retries.
func TestEscalationAuditWithRealServiceAndNoAuditConfig(t *testing.T) {
	svc := audit.NewService(nil, nil, zap.NewNop(), "ns")
	h := newEscalationAuditHarness(t, auditedEscalation(1), svc)
	require.Equal(t, reconcile.Result{}, h.reconcile())
	require.Len(t, h.r.auditor.pending, 1, "before the initial AuditConfig sync the pipeline is unavailable")

	syncer, _ := newTestAuditConfigReconciler(t)
	syncer.onReloadMultiple = func(ctx context.Context, configs []*breakglassv1alpha1.AuditConfig, unavailable bool) error {
		return svc.ReloadMultipleWithAvailability(ctx, configs, unavailable)
	}
	syncer.initialSync(context.Background())
	require.Equal(t, audit.ConfigurationDisabled, svc.ConfigurationState())

	require.Zero(t, h.r.auditor.flush(context.Background()), "disabled auditing drops retained events")
	h.bumpGeneration(2)
	for range 3 {
		require.Equal(t, reconcile.Result{}, h.reconcile(), "no requeue loop while auditing is disabled")
	}
	h.r.auditor.deletion(auditedEscalation(2))
	require.Empty(t, h.r.auditor.pending)
}

// With the real audit.Manager and a full queue (dropOnFull), the event stays
// pending and is delivered once the queue drains.
func TestEscalationAuditWithRealServiceFullQueue(t *testing.T) {
	block := make(chan struct{})
	var mu sync.Mutex
	var got []*audit.Event
	sink := &blockingEscalationSink{block: block, write: func(e *audit.Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, e)
	}}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 1, WorkerCount: 1, DropOnFull: true}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	emitter := &managerEmitter{m: manager}
	// Occupy the worker and the one queue slot.
	require.True(t, manager.TryEmit(context.Background(), &audit.Event{Type: audit.EventConfigChanged, Actor: audit.Actor{User: "x"}}))
	require.Eventually(t, func() bool { return sink.busy.Load() }, 5*time.Second, time.Millisecond)
	require.True(t, manager.TryEmit(context.Background(), &audit.Event{Type: audit.EventConfigChanged, Actor: audit.Actor{User: "x"}}))

	h := newEscalationAuditHarness(t, auditedEscalation(1), emitter)
	h.reconcile()
	h.deliver()
	require.Contains(t, h.r.auditor.pending, escalationAuditKey{uid: "esc-uid", generation: 1}, "a dropped event stays pending")

	close(block)
	// Make every retry due at once, so a retry that still finds the queue
	// full while the worker drains it is not held back by the backoff.
	retryNow := func() int {
		h.r.auditor.mu.Lock()
		for _, entry := range h.r.auditor.pending {
			entry.next = time.Time{}
		}
		h.r.auditor.mu.Unlock()
		return h.r.auditor.flush(context.Background())
	}
	require.Eventually(t, func() bool { return retryNow() == 0 }, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range got {
			if e.Type == audit.EventEscalationCreated {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
}

type managerEmitter struct{ m *audit.Manager }

func (e *managerEmitter) TryEmitRetryable(ctx context.Context, event *audit.Event) bool {
	return e.m.TryEmitRetryable(ctx, event)
}
func (e *managerEmitter) ConfigurationState() audit.ConfigurationState {
	return audit.ConfigurationReady
}

type blockingEscalationSink struct {
	block chan struct{}
	busy  atomic.Bool
	write func(*audit.Event)
}

func (s *blockingEscalationSink) Write(_ context.Context, e *audit.Event) error {
	s.busy.Store(true)
	<-s.block
	s.write(e)
	return nil
}
func (s *blockingEscalationSink) Close() error { return nil }
func (s *blockingEscalationSink) Name() string { return "blocking" }

// With no AuditConfig at all, the initial sync reports an empty set, so the
// audit service becomes "disabled" instead of staying "unavailable", and
// escalation auditing stops retrying.
func TestAuditConfigInitialSyncWithoutConfigs(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)
	called := false
	var got []*breakglassv1alpha1.AuditConfig
	r.onReloadMultiple = func(_ context.Context, configs []*breakglassv1alpha1.AuditConfig, configuredUnavailable bool) error {
		called = true
		got = configs
		require.False(t, configuredUnavailable)
		return nil
	}
	r.initialSync(context.Background())
	require.True(t, called, "the initial sync must reload the audit service even without AuditConfigs")
	require.Empty(t, got)

	svc := audit.NewService(nil, nil, zap.NewNop(), "ns")
	require.Equal(t, audit.ConfigurationUnavailable, svc.ConfigurationState())
	require.NoError(t, svc.ReloadMultipleWithAvailability(context.Background(), got, false))
	require.Equal(t, audit.ConfigurationDisabled, svc.ConfigurationState())
}

// The startup sync and controller reconciles never overlap, so an older
// AuditConfig snapshot cannot be reloaded after a newer one.
func TestAuditConfigInitialSyncSerializesWithReconcile(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)
	var inside, overlaps, calls atomic.Int32
	r.onReloadMultiple = func(context.Context, []*breakglassv1alpha1.AuditConfig, bool) error {
		if inside.Add(1) > 1 {
			overlaps.Add(1)
		}
		time.Sleep(5 * time.Millisecond)
		inside.Add(-1)
		calls.Add(1)
		return nil
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); r.initialSync(context.Background()) }()
		go func() {
			defer wg.Done()
			_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "any"}})
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.EqualValues(t, 16, calls.Load())
	require.Zero(t, overlaps.Load(), "list/validate/reload passes must not overlap")
}

// Shutdown delivers a deletion that waits in retry backoff, and counts what
// it cannot deliver before its deadline.
func TestEscalationAuditDrainOnShutdown(t *testing.T) {
	shutdownDrops := func() float64 {
		return testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown"))
	}

	// A deletion in retry backoff is delivered: the drain ignores the backoff.
	capture := newEscalationAuditCapture()
	capture.set(audit.ConfigurationReady, true)
	a := newEscalationAuditor(capture, zap.NewNop().Sugar())
	a.deletion(auditedEscalation(5))
	require.Equal(t, 1, a.flush(context.Background()), "rejected once: now in backoff")
	capture.set(audit.ConfigurationReady, false)
	(&EscalationReconciler{auditor: a}).DrainAudit()
	events := capture.take()
	require.Len(t, events, 1)
	require.Equal(t, "escalation/esc-uid/deleted", events[0].ID)
	require.Empty(t, a.pending)

	// Changes observed after the drain are counted, not retained.
	before := shutdownDrops()
	a.deletion(auditedEscalation(7))
	late := auditedEscalation(8)
	late.UID = "late"
	a.specChange(late)
	require.Equal(t, before+2, shutdownDrops())
	require.Empty(t, a.pending)

	// A pipeline that keeps rejecting: the drain ends at its deadline and
	// counts the undelivered event.
	rejecting := newEscalationAuditCapture()
	rejecting.set(audit.ConfigurationReady, true)
	b := newEscalationAuditor(rejecting, zap.NewNop().Sugar())
	b.deletion(auditedEscalation(6))
	require.Len(t, b.pending, 1, "the deletion is pending before the drain")
	before = shutdownDrops()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	b.drain(ctx)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded, "the drain retries until its deadline")
	require.Less(t, time.Since(start), 2*time.Second, "the drain is bounded by its deadline")
	require.Equal(t, before+1, shutdownDrops(), "the undelivered event is counted")
	require.Empty(t, rejecting.take())

	// An observation concurrent with the drain takes the counted-loss path
	// while the retained snapshot keeps draining.
	c := newEscalationAuditor(rejecting, zap.NewNop().Sugar())
	c.deletion(auditedEscalation(9))
	before = shutdownDrops()
	ctx3, cancel3 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel3()
	done := make(chan struct{})
	go func() { c.drain(ctx3); close(done) }()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.stopped
	}, time.Second, time.Millisecond, "the drain stops observations before it starts delivering")
	concurrent := auditedEscalation(10)
	concurrent.UID = "concurrent"
	c.deletion(concurrent)
	<-done
	require.Equal(t, before+2, shutdownDrops(), "the concurrent deletion and the undelivered snapshot are counted")
	require.NotContains(t, c.pending, escalationAuditKey{uid: "concurrent", generation: 10, deleted: true})

	// An attempt in flight when the deadline passes is not counted if it is
	// still accepted, and counted once if it is not.
	for _, accept := range []bool{true, false} {
		gate := make(chan struct{})
		entered := make(chan struct{}, 1)
		slow := &gatedEmitter{gate: gate, entered: entered, accept: accept}
		d := newEscalationAuditor(slow, zap.NewNop().Sugar())
		d.deletion(auditedEscalation(11))
		go d.flush(context.Background()) // the run loop owns the attempt
		<-entered
		before = shutdownDrops()
		ctx4, cancel4 := context.WithTimeout(context.Background(), 50*time.Millisecond)
		d.drain(ctx4)
		cancel4()
		require.Equal(t, before, shutdownDrops(), "nothing is counted while the attempt is in flight")
		close(gate)
		want := before
		if !accept {
			want++
		}
		require.Eventually(t, func() bool {
			d.mu.Lock()
			defer d.mu.Unlock()
			return len(d.pending) == 0
		}, 5*time.Second, 10*time.Millisecond)
		require.Equal(t, want, shutdownDrops(), "accepted=%v", accept)
	}

	// During shutdown a key already recorded is not counted again, a new
	// change is counted once however often it is observed, and it is still
	// counted after the audit service closed (state disabled).
	e := newEscalationAuditor(capture, zap.NewNop().Sugar())
	capture.set(audit.ConfigurationReady, false)
	e.specChange(auditedEscalation(20))
	require.Zero(t, e.flush(context.Background()))
	capture.take()
	ctx5, cancel5 := context.WithTimeout(context.Background(), time.Second)
	e.drain(ctx5)
	cancel5()
	before = shutdownDrops()
	e.specChange(auditedEscalation(20)) // already recorded and delivered
	require.Equal(t, before, shutdownDrops(), "an already recorded generation is not counted again")
	capture.set(audit.ConfigurationDisabled, false) // the audit service closed
	e.specChange(auditedEscalation(21))
	e.specChange(auditedEscalation(21))
	e.observe(auditedEscalation(21))
	require.Equal(t, before+1, shutdownDrops(), "a new change during shutdown is counted once, also after the service closed")

	(&EscalationReconciler{}).DrainAudit() // without auditing it is a no-op
}

type gatedEmitter struct {
	gate    chan struct{}
	entered chan struct{}
	accept  bool
}

func (g *gatedEmitter) TryEmitRetryable(context.Context, *audit.Event) bool {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.gate
	return g.accept
}

func (*gatedEmitter) ConfigurationState() audit.ConfigurationState { return audit.ConfigurationReady }

// The drain runs from audit.Service.Close while the pipeline still accepts.
func TestEscalationAuditDrainRunsBeforeAuditClose(t *testing.T) {
	svc := audit.NewService(nil, nil, zap.NewNop(), "ns")
	require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "log"},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
			Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
		}}},
	}))
	h := newEscalationAuditHarness(t, auditedEscalation(1), svc)
	h.r.auditor.deletion(auditedEscalation(1))
	svc.BeforeClose(h.r.DrainAudit)
	require.NoError(t, svc.Close())
	require.Empty(t, h.r.auditor.pending, "delivered before the pipeline closed")
}

// A pass stops at the first event the pipeline rejects, oldest first, so a
// saturated queue cannot stall one pass for every retained event.
func TestEscalationAuditPassStopsAtFirstRejection(t *testing.T) {
	counting := &countingEmitter{}
	a := newEscalationAuditor(counting, zap.NewNop().Sugar())
	now := time.Now()
	a.now = func() time.Time { return now }
	for i := range 5 {
		esc := auditedEscalation(1)
		esc.UID = types.UID(fmt.Sprintf("uid-%d", i))
		now = now.Add(time.Second)
		a.specChange(esc)
	}
	require.Equal(t, 5, a.flush(context.Background()))
	require.EqualValues(t, 1, counting.calls.Load(), "the pass stops after the first rejection")
	require.Equal(t, "escalation/uid-0/1", counting.first.Load().(string), "the oldest event is attempted first")
	entry := a.pending[escalationAuditKey{uid: "uid-1", generation: 1}]
	require.Zero(t, entry.attempts, "unattempted events keep their retry state")
}

type countingEmitter struct {
	calls atomic.Int32
	first atomic.Value
}

func (c *countingEmitter) TryEmitRetryable(_ context.Context, e *audit.Event) bool {
	if c.calls.Add(1) == 1 {
		c.first.Store(e.ID)
	}
	return false
}

func (*countingEmitter) ConfigurationState() audit.ConfigurationState {
	return audit.ConfigurationReady
}

// Several snapshots wait behind one blocked enqueue when the drain gives up:
// once that enqueue fails, every snapshot of the pass is counted, attempted
// or not, and none stays pending.
func TestEscalationAuditAbandonedPassCountsUnattempted(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	slow := &gatedEmitter{gate: gate, entered: entered, accept: false}
	a := newEscalationAuditor(slow, zap.NewNop().Sugar())
	for i := range 4 {
		esc := auditedEscalation(1)
		esc.UID = types.UID(fmt.Sprintf("uid-%d", i))
		a.deletion(esc)
	}
	passDone := make(chan struct{})
	go func() { a.flush(context.Background()); close(passDone) }() // the run loop's pass
	<-entered
	drops := func() float64 {
		return testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown"))
	}
	before := drops()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	a.drain(ctx)
	cancel()
	require.Equal(t, before, drops(), "nothing counted while the pass holds the snapshots")
	close(gate)
	<-passDone
	require.Equal(t, before+4, drops(), "all four snapshots of the abandoned pass are counted")
	require.Empty(t, a.pending)
}

// Changes after the drain are not audit losses when auditing was
// intentionally disabled at shutdown: nothing is counted.
func TestEscalationAuditDrainWhileDisabledCountsNothing(t *testing.T) {
	capture := newEscalationAuditCapture()
	capture.set(audit.ConfigurationDisabled, false)
	a := newEscalationAuditor(capture, zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a.drain(ctx)
	before := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown"))
	a.specChange(auditedEscalation(1))
	a.deletion(auditedEscalation(1))
	require.Equal(t, before, testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown")))
	require.Empty(t, a.pending)
	require.Empty(t, capture.take())
}
