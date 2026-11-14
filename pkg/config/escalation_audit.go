// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"slices"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// EscalationAuditEmitter receives escalation change audit events.
// audit.Service implements it.
type EscalationAuditEmitter interface {
	// TryEmit reports whether the event was accepted by the audit pipeline.
	TryEmit(ctx context.Context, event *audit.Event) bool
	ConfigurationState() audit.ConfigurationState
}

const (
	// escalationAuditRetry is the retry tick and the first retry delay of an
	// event that the audit pipeline did not accept; the delay doubles up to
	// escalationAuditMaxRetry.
	escalationAuditRetry    = 5 * time.Second
	escalationAuditMaxRetry = 5 * time.Minute
	// escalationAuditTTL bounds how long an unaccepted event is retained.
	escalationAuditTTL = time.Hour
	// escalationAuditLimit bounds the number of retained events.
	escalationAuditLimit = 2000
	// escalationAuditSeenLimit bounds the dedup set of recorded generations.
	// Only its oldest entries are evicted, so the current generation of up to
	// this many escalations is not re-emitted by the periodic resync.
	escalationAuditSeenLimit = 10000
)

// escalationAuditKey identifies one event: a generation of an escalation, or
// its deletion.
type escalationAuditKey struct {
	uid        types.UID
	generation int64
	deleted    bool
}

// pendingEscalationAudit is an immutable event snapshot plus retry state.
type pendingEscalationAudit struct {
	event    *audit.Event
	since    time.Time
	next     time.Time
	attempts int
	inflight bool
}

// escalationAuditor emits escalation.created/updated/deleted events. Each
// observed generation and each deletion becomes an immutable event snapshot
// that is retried independently until the audit pipeline accepts it, bounded
// by escalationAuditLimit and escalationAuditTTL. Enqueueing never happens
// under the lock, so a full audit queue cannot block reconciliation or the
// informer's delete handler. The snapshots are in memory: a controller crash
// loses them, and the next leader re-emits the current generation of every
// escalation with the same event ID.
type escalationAuditor struct {
	emitter EscalationAuditEmitter
	logger  *zap.SugaredLogger
	retry   time.Duration
	now     func() time.Time

	// wake asks run to flush now instead of at the next tick.
	wake chan struct{}

	mu sync.Mutex
	// seen holds every recorded generation and deletion with its time, so
	// each exact UID/generation pair is recorded once regardless of the order
	// in which the informer and reconciles observe them. It is bounded by
	// escalationAuditSeenLimit; the oldest entries are evicted.
	seen    map[escalationAuditKey]time.Time
	pending map[escalationAuditKey]*pendingEscalationAudit
	// stopped is set by the shutdown drain: the audit service closes next,
	// so later changes are counted as lost instead of retained silently.
	stopped bool
	// abandoned is set when the drain deadline passed: an attempt still in
	// flight then counts itself as lost if the pipeline does not accept it.
	abandoned bool
}

func newEscalationAuditor(emitter EscalationAuditEmitter, logger *zap.SugaredLogger) *escalationAuditor {
	if emitter == nil {
		return nil
	}
	return &escalationAuditor{emitter: emitter, logger: logger, retry: escalationAuditRetry, now: time.Now, wake: make(chan struct{}, 1),
		seen: map[escalationAuditKey]time.Time{}, pending: map[escalationAuditKey]*pendingEscalationAudit{}}
}

func (a *escalationAuditor) backoff(attempts int) time.Duration {
	delay := a.retry
	for i := 1; i < attempts && delay < escalationAuditMaxRetry; i++ {
		delay *= 2
	}
	return min(delay, escalationAuditMaxRetry)
}

// record adds a snapshot under a.mu, evicting the oldest beyond the limit.
func (a *escalationAuditor) record(key escalationAuditKey, event *audit.Event) {
	a.seen[key] = event.Timestamp
	a.pruneSeen()
	a.pending[key] = &pendingEscalationAudit{event: event, since: event.Timestamp}
	if len(a.pending) <= escalationAuditLimit {
		return
	}
	var oldest escalationAuditKey
	var oldestEntry *pendingEscalationAudit
	for k, e := range a.pending {
		if oldestEntry == nil || e.since.Before(oldestEntry.since) {
			oldest, oldestEntry = k, e
		}
	}
	a.drop(oldest)
	a.logger.Warnw("Dropping unaudited escalation event: too many events wait for the audit pipeline", "event", oldestEntry.event.ID)
}

// drop discards an unaccepted snapshot under a.mu. It also forgets the
// generation, so a later reconcile (for example on a newly elected leader or
// after auditing is enabled again) records the current generation again
// instead of treating it as audited.
func (a *escalationAuditor) drop(key escalationAuditKey) {
	delete(a.pending, key)
	delete(a.seen, key)
}

// pruneSeen evicts the oldest dedup entries beyond the bound.
func (a *escalationAuditor) pruneSeen() {
	for len(a.seen) > escalationAuditSeenLimit {
		var oldest escalationAuditKey
		var oldestAt time.Time
		for key, at := range a.seen {
			if oldestAt.IsZero() || at.Before(oldestAt) {
				oldest, oldestAt = key, at
			}
		}
		delete(a.seen, oldest)
	}
}

// previousGeneration returns the newest recorded generation of uid below
// generation, or 0.
func (a *escalationAuditor) previousGeneration(uid types.UID, generation int64) int64 {
	var previous int64
	for key := range a.seen {
		if key.uid == uid && !key.deleted && key.generation < generation && key.generation > previous {
			previous = key.generation
		}
	}
	return previous
}

// notify wakes run without blocking.
func (a *escalationAuditor) notify() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// specChange records escalation.created (generation 1) or escalation.updated
// once per exact UID/generation pair, in whatever order the informer and
// reconciles observe generations; run delivers it. It never
// enqueues itself, so a full audit queue cannot hold the reconcile worker. It
// is independent of status.observedGeneration, which other status writers
// also advance. Disabled auditing is a cheap no-op.
func (a *escalationAuditor) specChange(esc *breakglassv1alpha1.BreakglassEscalation) {
	if a == nil {
		return
	}
	a.recordOnce(escalationAuditKey{uid: esc.UID, generation: esc.Generation}, func() *audit.Event {
		eventType := audit.EventEscalationUpdated
		if esc.Generation <= 1 {
			eventType = audit.EventEscalationCreated
		}
		return audit.EscalationChangeEvent(eventType, esc, a.previousGeneration(esc.UID, esc.Generation))
	})
}

// recordOnce records the snapshot built by build for key, once. The order of
// checks matters at shutdown: a key already recorded is never counted again,
// and the drain's stop is checked before the audit state, which turns to
// disabled when the audit service closes, so a real change observed during
// shutdown is counted as lost rather than ignored.
func (a *escalationAuditor) recordOnce(key escalationAuditKey, build func() *audit.Event) {
	state := a.emitter.ConfigurationState()
	a.mu.Lock()
	if _, seen := a.seen[key]; seen {
		a.mu.Unlock()
		return
	}
	if a.stopped {
		a.seen[key] = a.now().UTC()
		a.pruneSeen()
		a.mu.Unlock()
		a.countShutdownLoss()
		return
	}
	if state == audit.ConfigurationDisabled {
		a.mu.Unlock()
		return
	}
	event := build()
	event.Timestamp = a.now().UTC()
	a.record(key, event)
	a.mu.Unlock()
	a.notify()
}

// observe records the generation of an escalation delivered by the informer.
func (a *escalationAuditor) observe(obj client.Object) {
	if esc, ok := obj.(*breakglassv1alpha1.BreakglassEscalation); ok {
		a.specChange(esc)
	}
}

// deletion records escalation.deleted for an observed delete; run delivers
// it. It runs in the informer's event handler and never blocks. Earlier
// snapshots of the escalation stay pending.
func (a *escalationAuditor) deletion(obj client.Object) {
	esc, ok := obj.(*breakglassv1alpha1.BreakglassEscalation)
	if a == nil || !ok {
		return
	}
	a.recordOnce(escalationAuditKey{uid: esc.UID, generation: esc.Generation, deleted: true}, func() *audit.Event {
		return audit.EscalationChangeEvent(audit.EventEscalationDeleted, esc, esc.Generation)
	})
}

// flush tries to emit the due snapshots, oldest first, until the pipeline
// rejects one. It drops all snapshots while auditing is disabled and expired
// ones always. TryEmit runs without a.mu.
// It reports the number of snapshots still retained.
func (a *escalationAuditor) flush(ctx context.Context) int {
	state := a.emitter.ConfigurationState()
	type attempt struct {
		key   escalationAuditKey
		entry *pendingEscalationAudit
	}
	var due []attempt
	a.mu.Lock()
	now := a.now()
	for key, entry := range a.pending {
		switch {
		case state == audit.ConfigurationDisabled:
			a.drop(key)
		case now.Sub(entry.since) > escalationAuditTTL:
			a.drop(key)
			a.logger.Warnw("Dropping unaudited escalation event: the audit pipeline did not accept it within the retention window", "event", entry.event.ID)
		case entry.inflight || now.Before(entry.next):
		case state != audit.ConfigurationReady:
			entry.attempts++
			entry.next = now.Add(a.backoff(entry.attempts))
		default:
			entry.inflight = true
			due = append(due, attempt{key, entry})
		}
	}
	a.mu.Unlock()
	// Oldest first, so a backlog cannot starve the oldest changes.
	slices.SortFunc(due, func(x, y attempt) int { return x.entry.since.Compare(y.entry.since) })

	// Stop the pass at the first event the pipeline does not accept: the
	// ingress queue is full (each attempt may wait for its write timeout), so
	// the rest waits for the next pass instead of stalling this one.
	accepted := make([]bool, len(due))
	attempted := 0
	for i, d := range due {
		attempted = i + 1
		accepted[i] = a.emitter.TryEmit(ctx, d.entry.event)
		if !accepted[i] {
			break
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now = a.now()
	for i, d := range due {
		d.entry.inflight = false
		if a.pending[d.key] != d.entry {
			continue // evicted or dropped meanwhile
		}
		if i < attempted && accepted[i] {
			delete(a.pending, d.key)
			continue
		}
		if a.abandoned {
			// The drain gave up while this pass held these snapshots: count
			// every one that was not accepted, attempted or not.
			delete(a.pending, d.key)
			metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown").Inc()
			continue
		}
		if i >= attempted {
			continue // not attempted in this pass
		}
		d.entry.attempts++
		d.entry.next = now.Add(a.backoff(d.entry.attempts))
	}
	return len(a.pending)
}

// escalationAuditDrainTimeout bounds the shutdown drain of retained events.
const escalationAuditDrainTimeout = 10 * time.Second

// drain delivers every retained snapshot, ignoring retry backoff, until none
// is left or ctx ends; it runs at shutdown before the audit service closes,
// because a deletion cannot be reconstructed by the next process. Snapshots
// still undelivered are counted as dropped with reason "shutdown".
func (a *escalationAuditor) drain(ctx context.Context) {
	if a == nil {
		return
	}
	// Stop first: observations from here on take the counted-loss path,
	// while the snapshots retained so far drain.
	a.mu.Lock()
	a.stopped = true
	a.mu.Unlock()
	for {
		a.mu.Lock()
		for _, entry := range a.pending {
			entry.next = time.Time{}
		}
		a.mu.Unlock()
		left := a.flush(ctx)
		if left == 0 {
			return
		}
		select {
		case <-ctx.Done():
			a.abandon()
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// abandon ends the drain at its deadline. It counts the retained snapshots
// that are not being delivered right now; an attempt still in flight (for
// example in the run loop) counts itself only if it is not accepted, so an
// event that is still accepted is never counted as lost.
func (a *escalationAuditor) abandon() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.abandoned = true
	lost := 0
	for key, entry := range a.pending {
		if entry.inflight {
			continue
		}
		delete(a.pending, key)
		lost++
	}
	metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown").Add(float64(lost))
	a.logger.Warnw("Escalation audit events not delivered before shutdown", "lost", lost, "inFlight", len(a.pending))
}

// countShutdownLoss counts a change observed after the shutdown drain: the
// informer can still deliver events until the manager stops, but the audit
// service is closing.
func (a *escalationAuditor) countShutdownLoss() {
	metrics.AuditEventsDropped.WithLabelValues(escalationAuditSink, "shutdown").Inc()
	a.logger.Warnw("Escalation change observed after the audit shutdown drain is not audited")
}

// escalationAuditSink labels losses of retained escalation audit events.
const escalationAuditSink = "escalation-audit"

// run delivers recorded snapshots and retries unaccepted ones until ctx ends.
func (a *escalationAuditor) run(ctx context.Context) {
	if a == nil {
		return
	}
	ticker := time.NewTicker(a.retry)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.flush(ctx)
		case <-a.wake:
			a.flush(ctx)
		}
	}
}
