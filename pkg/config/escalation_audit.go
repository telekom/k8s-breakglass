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
	// escalationAuditRetry is the first retry delay of an event that the
	// audit pipeline did not accept; it doubles up to escalationAuditMaxRetry.
	escalationAuditRetry    = 5 * time.Second
	escalationAuditMaxRetry = 5 * time.Minute
	// escalationAuditTTL bounds how long an unaccepted event is retained.
	escalationAuditTTL = time.Hour
	// escalationAuditLimit bounds the retained events per kind.
	escalationAuditLimit = 1000
)

type pendingEscalationAudit struct {
	generation int64
	since      time.Time
	next       time.Time // deletions: earliest next attempt
	attempts   int
	event      *audit.Event // deletions only: the object is gone
}

// escalationAuditor emits escalation.created/updated/deleted events. An event
// counts as audited only once the audit pipeline accepted it; until then it is
// retained (bounded by escalationAuditLimit and escalationAuditTTL) and retried
// with backoff. The retained events are in memory: a controller crash loses
// them, and the next leader re-emits the current generation of every
// escalation with the same event ID.
type escalationAuditor struct {
	emitter EscalationAuditEmitter
	logger  *zap.SugaredLogger
	retry   time.Duration
	now     func() time.Time

	mu      sync.Mutex
	audited map[types.UID]int64
	pending map[types.UID]*pendingEscalationAudit
	deletes map[types.UID]*pendingEscalationAudit
}

func newEscalationAuditor(emitter EscalationAuditEmitter, logger *zap.SugaredLogger) *escalationAuditor {
	if emitter == nil {
		return nil
	}
	return &escalationAuditor{emitter: emitter, logger: logger, retry: escalationAuditRetry, now: time.Now,
		audited: map[types.UID]int64{}, pending: map[types.UID]*pendingEscalationAudit{}, deletes: map[types.UID]*pendingEscalationAudit{}}
}

func (a *escalationAuditor) backoff(attempts int) time.Duration {
	delay := a.retry
	for i := 1; i < attempts && delay < escalationAuditMaxRetry; i++ {
		delay *= 2
	}
	return min(delay, escalationAuditMaxRetry)
}

// retain adds an entry, evicting the oldest one beyond the limit.
func (a *escalationAuditor) retain(entries map[types.UID]*pendingEscalationAudit, uid types.UID, entry *pendingEscalationAudit) {
	entries[uid] = entry
	if len(entries) <= escalationAuditLimit {
		return
	}
	var oldest types.UID
	for id, e := range entries {
		if oldest == "" || e.since.Before(entries[oldest].since) {
			oldest = id
		}
	}
	delete(entries, oldest)
	a.logger.Warnw("Dropping unaudited escalation event: too many events wait for the audit pipeline", "uid", oldest)
}

// specChange emits escalation.created (generation 1) or escalation.updated
// for a generation that has not been audited yet. It is independent of
// status.observedGeneration, which other status writers also advance. It
// returns the delay after which the caller should reconcile again because the
// event was not accepted yet, or 0. Disabled auditing is a cheap no-op.
func (a *escalationAuditor) specChange(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) time.Duration {
	if a == nil {
		return 0
	}
	state := a.emitter.ConfigurationState()
	a.mu.Lock()
	defer a.mu.Unlock()
	if state == audit.ConfigurationDisabled {
		delete(a.pending, esc.UID)
		return 0
	}
	previous, seen := a.audited[esc.UID]
	if seen && previous == esc.Generation {
		return 0
	}
	entry := a.pending[esc.UID]
	if entry == nil || entry.generation != esc.Generation {
		entry = &pendingEscalationAudit{generation: esc.Generation, since: a.now().UTC()}
		a.retain(a.pending, esc.UID, entry)
	}
	if a.now().Sub(entry.since) > escalationAuditTTL {
		delete(a.pending, esc.UID)
		a.audited[esc.UID] = esc.Generation
		a.logger.Warnw("Dropping unaudited escalation change: the audit pipeline did not accept it within the retention window",
			"escalation", esc.Name, "uid", esc.UID, "generation", esc.Generation)
		return 0
	}
	if state == audit.ConfigurationReady {
		eventType := audit.EventEscalationUpdated
		if esc.Generation <= 1 {
			eventType = audit.EventEscalationCreated
		}
		event := audit.EscalationChangeEvent(eventType, esc, previous)
		// The event time is the first observation, also when delivered late.
		event.Timestamp = entry.since
		if a.emitter.TryEmit(ctx, event) {
			delete(a.pending, esc.UID)
			a.audited[esc.UID] = esc.Generation
			return 0
		}
	}
	entry.attempts++
	return a.backoff(entry.attempts)
}

// deletion retains escalation.deleted for an observed delete; run emits it.
// It never blocks: it is called from the informer's event handler.
func (a *escalationAuditor) deletion(obj client.Object) {
	esc, ok := obj.(*breakglassv1alpha1.BreakglassEscalation)
	if a == nil || !ok {
		return
	}
	event := audit.EscalationChangeEvent(audit.EventEscalationDeleted, esc, esc.Generation)
	event.Timestamp = a.now().UTC()
	a.mu.Lock()
	delete(a.audited, esc.UID)
	delete(a.pending, esc.UID)
	a.retain(a.deletes, esc.UID, &pendingEscalationAudit{generation: esc.Generation, since: event.Timestamp, event: event})
	a.mu.Unlock()
}

// flush emits retained deletions that are due, drops expired ones and drops
// all of them when auditing is disabled. It reports the number still retained.
func (a *escalationAuditor) flush(ctx context.Context) int {
	state := a.emitter.ConfigurationState()
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for uid, entry := range a.deletes {
		switch {
		case state != audit.ConfigurationDisabled && now.Before(entry.next):
		case state == audit.ConfigurationDisabled:
			delete(a.deletes, uid)
		case now.Sub(entry.since) > escalationAuditTTL:
			delete(a.deletes, uid)
			a.logger.Warnw("Dropping unaudited escalation deletion: the audit pipeline did not accept it within the retention window", "uid", uid)
		case state == audit.ConfigurationReady && a.emitter.TryEmit(ctx, entry.event):
			delete(a.deletes, uid)
		default:
			entry.attempts++
			entry.next = now.Add(a.backoff(entry.attempts))
		}
	}
	return len(a.deletes)
}

// run retries retained deletions until ctx ends.
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
