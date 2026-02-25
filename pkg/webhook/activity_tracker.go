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
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// DefaultFlushInterval is the default interval between buffered status updates.
const DefaultFlushInterval = 30 * time.Second

// maxFlushRetries is the maximum number of consecutive flush failures before an entry is discarded.
// This prevents unbounded memory growth from permanently failing updates.
const maxFlushRetries = 5

// maxEntries is the upper bound on the number of entries the tracker may hold
// between flushes. Entries beyond this limit are silently dropped. This matches
// the circuit breaker registry cap (maxBreakers = 1000) to prevent unbounded
// memory growth in high-volume webhook scenarios.
const maxEntries = 1000

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
// If the tracker has reached maxEntries, new sessions are silently dropped
// to prevent unbounded memory growth.
func (at *ActivityTracker) RecordActivity(namespace, name string, ts time.Time) {
	key := types.NamespacedName{Namespace: namespace, Name: name}

	at.mu.Lock()
	defer func() {
		metrics.SessionActivityBufferSize.Set(float64(len(at.entries)))
		at.mu.Unlock()
	}()

	entry, exists := at.entries[key]
	if !exists {
		// Cap the map size to prevent unbounded growth
		if len(at.entries) >= maxEntries {
			at.log.Warnw("ActivityTracker at capacity, dropping new entry",
				"maxEntries", maxEntries,
				"session", key.String())
			metrics.SessionActivityDropped.Inc()
			return
		}
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

// Cleanup prunes entries for sessions that are not in the activeSessionIDs set.
// This should be called periodically (e.g., from the cleanup routine) to prevent
// unbounded memory growth from orphaned sessions that no longer exist in Kubernetes.
func (at *ActivityTracker) Cleanup(activeSessionIDs map[types.NamespacedName]bool) int {
	at.mu.Lock()
	defer at.mu.Unlock()

	var pruned int
	for key := range at.entries {
		if !activeSessionIDs[key] {
			delete(at.entries, key)
			pruned++
		}
	}
	if pruned > 0 {
		at.log.Infow("Pruned orphaned activity tracker entries", "pruned", pruned, "remaining", len(at.entries))
	}
	return pruned
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
	metrics.SessionActivityBufferSize.Set(0)
	at.mu.Unlock()

	// Process entries sequentially. While bounded concurrency (e.g., errgroup
	// with a semaphore) could improve throughput, sequential processing avoids
	// thundering-herd pressure on the API server. With typical entry counts
	// (tens, not thousands), the sequential approach is sufficient.
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

// updateSessionActivity applies the buffered activity data to a session's status
// using an optimistic-concurrency status patch.
//
// In multi-replica deployments, concurrent flushes could race: two replicas read
// the same base ActivityCount, each adds its own delta, and the last writer wins
// (losing the other's increments). Using retry.RetryOnConflict with a status
// merge-patch ensures that if the ResourceVersion changes between our read and
// write (i.e., another replica patched first), we re-read the latest status and
// recompute the monotonic merge before retrying.
func (at *ActivityTracker) updateSessionActivity(ctx context.Context, key types.NamespacedName, entry *activityEntry) error {
	reader := at.getReader()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var session breakglassv1alpha1.BreakglassSession
		if err := reader.Get(ctx, key, &session); err != nil {
			if apierrors.IsNotFound(err) {
				// Session was deleted — discard the entry, no point retrying
				return nil
			}
			return err
		}

		// Only update active sessions — skip terminal states
		if session.Status.State != breakglassv1alpha1.SessionStateApproved {
			return nil
		}

		// Monotonic merge: LastActivity only moves forward and ActivityCount
		// never decreases. Combined with retry-on-conflict, this ensures
		// concurrent flushes across replicas converge correctly.
		newLastActivity := entry.lastSeen
		if session.Status.LastActivity != nil && session.Status.LastActivity.Time.After(newLastActivity) {
			newLastActivity = session.Status.LastActivity.Time
		}
		newCount := session.Status.ActivityCount + entry.count

		// Patch only the activity fields via the status subresource.
		// MergeFrom uses the session's ResourceVersion for conflict detection.
		base := session.DeepCopy()
		session.Status.LastActivity = &metav1.Time{Time: newLastActivity}
		session.Status.ActivityCount = newCount

		return at.client.Status().Patch(ctx, &session, client.MergeFrom(base))
	})
}

// getReader returns the uncached reader if configured, otherwise falls back to the cached client.
func (at *ActivityTracker) getReader() client.Reader {
	if at.reader != nil {
		return at.reader
	}
	return at.client
}
