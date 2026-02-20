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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// DefaultFlushInterval is the default interval between buffered status updates.
const DefaultFlushInterval = 30 * time.Second

// activityEntry holds buffered activity data for a single session.
type activityEntry struct {
	// namespace and name of the session
	namespace string
	name      string
	// lastSeen is the most recent activity time
	lastSeen time.Time
	// count is the number of requests since last flush
	count int64
}

// ActivityTracker buffers session activity updates and flushes them periodically
// to the Kubernetes API server. This avoids overwhelming the API server with per-request
// status updates in high-volume webhook scenarios.
//
// Activity is recorded via RecordActivity() (non-blocking), and flushed
// at a configurable interval (default 30s) via a background goroutine.
type ActivityTracker struct {
	client        client.Client
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
func (at *ActivityTracker) Stop(ctx context.Context) {
	at.stopOnce.Do(func() {
		close(at.stopCh)
		<-at.done

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
			at.flush(context.Background())
		case <-at.stopCh:
			return
		}
	}
}

// flush drains all buffered entries and applies status updates.
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

	for key, entry := range entries {
		if err := at.updateSessionActivity(ctx, key, entry); err != nil {
			at.log.Warnw("Failed to update session activity",
				"session", key.String(),
				"error", err)
			metrics.SessionActivityFlushErrors.Inc()
		}
	}

	at.log.Debugw("Flushed session activity", "sessions", len(entries))
	metrics.SessionActivityFlushes.Inc()
}

// updateSessionActivity applies the buffered activity data to a session's status.
func (at *ActivityTracker) updateSessionActivity(ctx context.Context, key types.NamespacedName, entry *activityEntry) error {
	// Read current session
	var session v1alpha1.BreakglassSession
	if err := at.client.Get(ctx, key, &session); err != nil {
		return err
	}

	// Only update active sessions — skip terminal states
	if session.Status.State != v1alpha1.SessionStateApproved {
		return nil
	}

	// Apply cumulative update
	patch := client.MergeFrom(session.DeepCopy())
	session.Status.LastActivity = &metav1.Time{Time: entry.lastSeen}
	session.Status.ActivityCount += entry.count

	return at.client.Status().Patch(ctx, &session, patch)
}
