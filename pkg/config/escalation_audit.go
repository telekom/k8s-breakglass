// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
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

	mu sync.Mutex
	// recorded is the newest generation per escalation that has a snapshot.
	recorded map[types.UID]int64
	pending  map[escalationAuditKey]*pendingEscalationAudit
}

func newEscalationAuditor(emitter EscalationAuditEmitter, logger *zap.SugaredLogger) *escalationAuditor {
	if emitter == nil {
		return nil
	}
	return &escalationAuditor{emitter: emitter, logger: logger, retry: escalationAuditRetry, now: time.Now,
		recorded: map[types.UID]int64{}, pending: map[escalationAuditKey]*pendingEscalationAudit{}}
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
	delete(a.pending, oldest)
	a.logger.Warnw("Dropping unaudited escalation event: too many events wait for the audit pipeline", "event", oldestEntry.event.ID)
}

// specChange records escalation.created (generation 1) or escalation.updated
// for a generation that has no snapshot yet and tries to emit it. It is
// independent of status.observedGeneration, which other status writers also
// advance. Disabled auditing is a cheap no-op. Unaccepted events are retried
// by run.
func (a *escalationAuditor) specChange(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) {
	if a == nil || a.emitter.ConfigurationState() == audit.ConfigurationDisabled {
		return
	}
	a.mu.Lock()
	previous, seen := a.recorded[esc.UID]
	if seen && previous >= esc.Generation {
		a.mu.Unlock()
		return
	}
	eventType := audit.EventEscalationUpdated
	if esc.Generation <= 1 {
		eventType = audit.EventEscalationCreated
	}
	event := audit.EscalationChangeEvent(eventType, esc, previous)
	event.Timestamp = a.now().UTC()
	a.recorded[esc.UID] = esc.Generation
	a.record(escalationAuditKey{uid: esc.UID, generation: esc.Generation}, event)
	a.mu.Unlock()
	a.flush(ctx)
}

// deletion records escalation.deleted for an observed delete. It does not
// emit: it runs in the informer's event handler and must not block, so run
// delivers it. Earlier snapshots of the escalation stay pending.
func (a *escalationAuditor) deletion(obj client.Object) {
	esc, ok := obj.(*breakglassv1alpha1.BreakglassEscalation)
	if a == nil || !ok || a.emitter.ConfigurationState() == audit.ConfigurationDisabled {
		return
	}
	event := audit.EscalationChangeEvent(audit.EventEscalationDeleted, esc, esc.Generation)
	event.Timestamp = a.now().UTC()
	a.mu.Lock()
	delete(a.recorded, esc.UID)
	a.record(escalationAuditKey{uid: esc.UID, generation: esc.Generation, deleted: true}, event)
	a.mu.Unlock()
}

// flush tries to emit every due snapshot. It drops all snapshots while
// auditing is disabled and expired ones always. TryEmit runs without a.mu.
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
			delete(a.pending, key)
		case now.Sub(entry.since) > escalationAuditTTL:
			delete(a.pending, key)
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

	accepted := make([]bool, len(due))
	for i, d := range due {
		accepted[i] = a.emitter.TryEmit(ctx, d.entry.event)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now = a.now()
	for i, d := range due {
		d.entry.inflight = false
		if a.pending[d.key] != d.entry {
			continue // evicted or dropped meanwhile
		}
		if accepted[i] {
			delete(a.pending, d.key)
			continue
		}
		d.entry.attempts++
		d.entry.next = now.Add(a.backoff(d.entry.attempts))
	}
	return len(a.pending)
}

// run retries retained snapshots until ctx ends.
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
		}
	}
}
