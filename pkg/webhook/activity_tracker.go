/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// DefaultFlushInterval is the default interval between buffered status updates.
const DefaultFlushInterval = 30 * time.Second

// maxFlushRetries is the maximum number of consecutive flush failures before an entry is discarded.
// This prevents unbounded memory growth from permanently failing updates.
const maxFlushRetries = 5

// FieldOwnerActivityTracker is the SSA field manager for activity-only status updates.
// A dedicated field manager avoids ownership conflicts with the main controller.
const FieldOwnerActivityTracker = "activity-tracker"

// activityEntry holds buffered activity data for a single session.
type activityEntry struct {
	// namespace and name of the session
	namespace string
	name      string
	// lastSeen is the most recent activity time
	lastSeen time.Time
	// count is the number of requests since last flush
	count int64
	// retries tracks how many consecutive flush failures this entry has had
	retries int
}

// ActivityTracker buffers session activity updates and flushes them periodically
// to the Kubernetes API server. This avoids overwhelming the API server with per-request
// status updates in high-volume webhook scenarios.
//
// Activity is recorded via RecordActivity() (non-blocking), and flushed
// at a configurable interval (default 30s) via a background goroutine.
type ActivityTracker struct {
	client        client.Client
	reader        client.Reader
	log           *zap.SugaredLogger
	flushInterval time.Duration

	mu      sync.Mutex
	entries map[types.NamespacedName]*activityEntry

	// stopCh signals the background goroutine to exit
	stopCh chan struct{}
	// done is closed when the background goroutine exits
	done chan struct{}
	// stopOnce ensures Stop() is idempotent and safe to call multiple times
	stopOnce sync.Once
}

// ActivityTrackerOption configures an ActivityTracker.
type ActivityTrackerOption func(*ActivityTracker)

// WithFlushInterval sets the flush interval for the activity tracker.
func WithFlushInterval(d time.Duration) ActivityTrackerOption {
	return func(at *ActivityTracker) {
		if d > 0 {
			at.flushInterval = d
		}
	}
}

// WithActivityLogger sets a custom logger for the activity tracker.
func WithActivityLogger(log *zap.SugaredLogger) ActivityTrackerOption {
	return func(at *ActivityTracker) {
		if log != nil {
			at.log = log
		}
	}
}

// WithReader sets an uncached client.Reader for session reads.
// When set, the ActivityTracker uses this reader (typically the APIReader)
// instead of the cached client for Get operations, ensuring it sees the
// latest status values and avoiding stale-read races during flush.
func WithReader(r client.Reader) ActivityTrackerOption {
	return func(at *ActivityTracker) {
		if r != nil {
			at.reader = r
		}
	}
}

// NewActivityTracker creates a new ActivityTracker and starts the background flush goroutine.
// Call Stop() to gracefully shut down the background goroutine and flush remaining entries.
func NewActivityTracker(c client.Client, opts ...ActivityTrackerOption) *ActivityTracker {
	at := &ActivityTracker{
		client:        c,
		log:           zap.S().Named("activity-tracker"),
		flushInterval: DefaultFlushInterval,
		entries:       make(map[types.NamespacedName]*activityEntry),
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(at)
		}
	}
	go at.run()
	return at
}

// RecordActivity records that a session was used at the given time.
// This method is safe for concurrent use and does not block on API calls.
func (at *ActivityTracker) RecordActivity(namespace, name string, ts time.Time) {
	key := types.NamespacedName{Namespace: namespace, Name: name}

	at.mu.Lock()
	defer at.mu.Unlock()

	entry, exists := at.entries[key]
	if !exists {
		at.entries[key] = &activityEntry{
			namespace: namespace,
			name:      name,
			lastSeen:  ts,
			count:     1,
		}
		return
	}
	if ts.After(entry.lastSeen) {
		entry.lastSeen = ts
	}
	entry.count++
}

// Pending returns the number of sessions with buffered activity updates.
func (at *ActivityTracker) Pending() int {
	at.mu.Lock()
	defer at.mu.Unlock()
	return len(at.entries)
}

// Stop gracefully shuts down the background goroutine and flushes remaining entries.
// Stop is idempotent and safe to call multiple times from concurrent shutdown paths.
// Respects the caller's context deadline: if the context expires while waiting for
// the background goroutine to finish, Stop returns without performing the final flush.
func (at *ActivityTracker) Stop(ctx context.Context) {
	at.stopOnce.Do(func() {
		close(at.stopCh)

		// Wait for the background goroutine, but respect the caller's context.
		select {
		case <-at.done:
			// Background goroutine exited normally — perform final flush.
		case <-ctx.Done():
			at.log.Warnw("Shutdown context expired waiting for flush goroutine", "error", ctx.Err())
			return
		}

		// Final flush
		at.flush(ctx)
	})
}

// run is the background flush loop.
func (at *ActivityTracker) run() {
	defer close(at.done)

	ticker := time.NewTicker(at.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Use a bounded context for ticker-driven flushes to prevent hangs.
			ctx, cancel := context.WithTimeout(context.Background(), at.flushInterval/2)
			at.flush(ctx)
			cancel()
		case <-at.stopCh:
			return
		}
	}
}

// flush drains all buffered entries and applies status updates.
// Failed entries are re-queued with merged counts for the next flush cycle,
// up to maxFlushRetries to prevent unbounded memory growth.
func (at *ActivityTracker) flush(ctx context.Context) {
	at.mu.Lock()
	if len(at.entries) == 0 {
		at.mu.Unlock()
		return
	}
	// Swap out the entries map so we release the lock quickly.
	entries := at.entries
	at.entries = make(map[types.NamespacedName]*activityEntry)
	at.mu.Unlock()

	var failed []*activityEntry
	for key, entry := range entries {
		if err := at.updateSessionActivity(ctx, key, entry); err != nil {
			at.log.Warnw("Failed to update session activity",
				"session", key.String(),
				"error", err,
				"retries", entry.retries)
			metrics.SessionActivityFlushErrors.Inc()

			entry.retries++
			if entry.retries < maxFlushRetries {
				failed = append(failed, entry)
			} else {
				at.log.Errorw("Discarding activity entry after max retries",
					"session", key.String(),
					"count", entry.count,
					"retries", entry.retries)
			}
		}
	}

	// Re-queue failed entries, merging with any new activity that arrived during flush
	if len(failed) > 0 {
		at.mu.Lock()
		for _, entry := range failed {
			key := types.NamespacedName{Namespace: entry.namespace, Name: entry.name}
			if existing, ok := at.entries[key]; ok {
				// Merge: keep the latest lastSeen and sum counts
				if entry.lastSeen.After(existing.lastSeen) {
					existing.lastSeen = entry.lastSeen
				}
				existing.count += entry.count
				// Keep the higher retry count
				if entry.retries > existing.retries {
					existing.retries = entry.retries
				}
			} else {
				at.entries[key] = entry
			}
		}
		at.mu.Unlock()
	}

	at.log.Debugw("Flushed session activity", "sessions", len(entries), "requeued", len(failed))
	metrics.SessionActivityFlushes.Inc()
}

// updateSessionActivity applies the buffered activity data to a session's status using SSA.
// Uses a dedicated field manager ("activity-tracker") to avoid ownership conflicts
// with the main controller's status updates.
func (at *ActivityTracker) updateSessionActivity(ctx context.Context, key types.NamespacedName, entry *activityEntry) error {
	// Read current session via the uncached reader (if set) to ensure we see
	// the latest status values and avoid stale-read races between flushes.
	reader := at.getReader()
	var session v1alpha1.BreakglassSession
	if err := reader.Get(ctx, key, &session); err != nil {
		if apierrors.IsNotFound(err) {
			// Session was deleted — discard the entry, no point retrying
			return nil
		}
		return err
	}

	// Only update active sessions — skip terminal states
	if session.Status.State != v1alpha1.SessionStateApproved {
		return nil
	}

	// Monotonic merge: LastActivity only moves forward and ActivityCount
	// never decreases. This makes concurrent flushes safe even when
	// the informer cache is slightly behind.
	newLastActivity := entry.lastSeen
	if session.Status.LastActivity != nil && session.Status.LastActivity.Time.After(newLastActivity) {
		newLastActivity = session.Status.LastActivity.Time
	}
	newCount := session.Status.ActivityCount + entry.count

	// Build apply configuration with only the activity fields
	statusApply := ac.BreakglassSessionStatus().
		WithLastActivity(metav1.Time{Time: newLastActivity}).
		WithActivityCount(newCount)

	applyConfig := ac.BreakglassSession(key.Name, key.Namespace).
		WithStatus(statusApply)

	return ssa.ApplyViaUnstructuredWithOwner(ctx, at.client, applyConfig, FieldOwnerActivityTracker)
}

// getReader returns the uncached reader if configured, otherwise falls back to the cached client.
func (at *ActivityTracker) getReader() client.Reader {
	if at.reader != nil {
		return at.reader
	}
	return at.client
}
