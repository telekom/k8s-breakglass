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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestActivityScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestActivityTracker_RecordActivity(t *testing.T) {
	t.Run("record single activity", func(t *testing.T) {
		scheme := newTestActivityScheme()
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		tracker := NewActivityTracker(fakeClient,
			WithFlushInterval(1*time.Hour),
			WithActivityLogger(zap.NewNop().Sugar()),
		)
		defer tracker.Stop(context.Background())

		tracker.RecordActivity("breakglass", "session-1", time.Now())
		assert.Equal(t, 1, tracker.Pending())
	})

	t.Run("record multiple activities for same session", func(t *testing.T) {
		scheme := newTestActivityScheme()
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		tracker := NewActivityTracker(fakeClient,
			WithFlushInterval(1*time.Hour),
			WithActivityLogger(zap.NewNop().Sugar()),
		)
		defer tracker.Stop(context.Background())

		now := time.Now()
		tracker.RecordActivity("breakglass", "session-1", now)
		tracker.RecordActivity("breakglass", "session-1", now.Add(1*time.Second))
		tracker.RecordActivity("breakglass", "session-1", now.Add(2*time.Second))
		assert.Equal(t, 1, tracker.Pending(), "Multiple activities for same session should be buffered as one entry")
	})

	t.Run("record activities for different sessions", func(t *testing.T) {
		scheme := newTestActivityScheme()
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		tracker := NewActivityTracker(fakeClient,
			WithFlushInterval(1*time.Hour),
			WithActivityLogger(zap.NewNop().Sugar()),
		)
		defer tracker.Stop(context.Background())

		now := time.Now()
		tracker.RecordActivity("breakglass", "session-1", now)
		tracker.RecordActivity("breakglass", "session-2", now)
		assert.Equal(t, 2, tracker.Pending())
	})
}

func TestActivityTracker_Flush(t *testing.T) {
	scheme := newTestActivityScheme()

	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-flush",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "alice@example.com",
			GrantedGroup: "group-1",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	now := time.Now()
	tracker.RecordActivity("breakglass", "session-flush", now)
	tracker.RecordActivity("breakglass", "session-flush", now.Add(5*time.Second))
	tracker.RecordActivity("breakglass", "session-flush", now.Add(10*time.Second))

	// Manually trigger flush
	tracker.flush(context.Background())

	// Verify the session status was updated
	var updated breakglassv1alpha1.BreakglassSession
	err := fakeClient.Get(context.Background(), client.ObjectKey{
		Namespace: "breakglass",
		Name:      "session-flush",
	}, &updated)
	require.NoError(t, err)

	assert.NotNil(t, updated.Status.LastActivity, "LastActivity should be set after flush")
	assert.Equal(t, now.Add(10*time.Second).Unix(), updated.Status.LastActivity.Unix(),
		"LastActivity should be the most recent activity time")
	assert.Equal(t, int64(3), updated.Status.ActivityCount,
		"ActivityCount should equal total recorded activities")
}

func TestActivityTracker_FlushSkipsTerminalSessions(t *testing.T) {
	scheme := newTestActivityScheme()

	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-expired",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "alice@example.com",
			GrantedGroup: "group-1",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateExpired,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	tracker.RecordActivity("breakglass", "session-expired", time.Now())
	tracker.flush(context.Background())

	// Verify the session status was NOT updated (terminal state)
	var updated breakglassv1alpha1.BreakglassSession
	err := fakeClient.Get(context.Background(), client.ObjectKey{
		Namespace: "breakglass",
		Name:      "session-expired",
	}, &updated)
	require.NoError(t, err)
	assert.Nil(t, updated.Status.LastActivity, "LastActivity should remain nil for terminal sessions")
	assert.Equal(t, int64(0), updated.Status.ActivityCount, "ActivityCount should remain 0 for terminal sessions")
}

func TestActivityTracker_CumulativeFlushes(t *testing.T) {
	scheme := newTestActivityScheme()

	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-cumulative",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "bob@example.com",
			GrantedGroup: "group-2",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	now := time.Now()

	// First batch
	tracker.RecordActivity("breakglass", "session-cumulative", now)
	tracker.RecordActivity("breakglass", "session-cumulative", now.Add(1*time.Second))
	tracker.flush(context.Background())

	// Second batch
	tracker.RecordActivity("breakglass", "session-cumulative", now.Add(30*time.Second))
	tracker.flush(context.Background())

	// Verify cumulative counts
	var updated breakglassv1alpha1.BreakglassSession
	err := fakeClient.Get(context.Background(), client.ObjectKey{
		Namespace: "breakglass",
		Name:      "session-cumulative",
	}, &updated)
	require.NoError(t, err)

	assert.Equal(t, int64(3), updated.Status.ActivityCount,
		"ActivityCount should accumulate across flushes")
	assert.Equal(t, now.Add(30*time.Second).Unix(), updated.Status.LastActivity.Unix(),
		"LastActivity should be the most recent across all flushes")
}

func TestActivityTracker_FlushEmptyIsNoop(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	// Flush with no entries should be a no-op (no panic, no errors)
	tracker.flush(context.Background())
	assert.Equal(t, 0, tracker.Pending())
}

func TestActivityTracker_Stop(t *testing.T) {
	scheme := newTestActivityScheme()

	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-stop",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "charlie@example.com",
			GrantedGroup: "group-3",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)

	tracker.RecordActivity("breakglass", "session-stop", time.Now())

	// Stop should flush remaining entries
	tracker.Stop(context.Background())

	var updated breakglassv1alpha1.BreakglassSession
	err := fakeClient.Get(context.Background(), client.ObjectKey{
		Namespace: "breakglass",
		Name:      "session-stop",
	}, &updated)
	require.NoError(t, err)
	assert.NotNil(t, updated.Status.LastActivity, "Stop should flush remaining entries")
	assert.Equal(t, int64(1), updated.Status.ActivityCount)
}

func TestActivityTracker_Options(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("custom flush interval", func(t *testing.T) {
		tracker := NewActivityTracker(fakeClient,
			WithFlushInterval(5*time.Second),
			WithActivityLogger(zap.NewNop().Sugar()),
		)
		defer tracker.Stop(context.Background())
		assert.Equal(t, 5*time.Second, tracker.flushInterval)
	})

	t.Run("zero flush interval uses default", func(t *testing.T) {
		tracker := NewActivityTracker(fakeClient,
			WithFlushInterval(0),
			WithActivityLogger(zap.NewNop().Sugar()),
		)
		defer tracker.Stop(context.Background())
		assert.Equal(t, DefaultFlushInterval, tracker.flushInterval)
	})

	t.Run("nil logger uses default", func(t *testing.T) {
		tracker := NewActivityTracker(fakeClient,
			WithActivityLogger(nil),
		)
		defer tracker.Stop(context.Background())
		assert.NotNil(t, tracker.log)
	})
}

func TestRecordSessionActivity(t *testing.T) {
	sessions := []breakglassv1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "ses-1", Namespace: "ns-1"},
			Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster-1"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "ses-2", Namespace: "ns-2"},
			Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster-2"},
		},
	}

	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	wc := &WebhookController{
		activityTracker: tracker,
	}

	t.Run("records activity for matching session", func(t *testing.T) {
		wc.recordSessionActivity(sessions, "ses-1", "cluster-1", "group-1")
		assert.Equal(t, 1, tracker.Pending())
	})

	t.Run("no-op when session name not found", func(t *testing.T) {
		initialPending := tracker.Pending()
		wc.recordSessionActivity(sessions, "non-existent", "cluster-1", "group-1")
		assert.Equal(t, initialPending, tracker.Pending(), "Should not add entry for unknown session")
	})

	t.Run("no-op when tracker is nil", func(t *testing.T) {
		wcNoTracker := &WebhookController{}
		// Should not panic
		wcNoTracker.recordSessionActivity(sessions, "ses-1", "cluster-1", "group-1")
	})
}

// --- Test helpers for error injection ---

// errorReader is a client.Reader that always returns the configured error.
type errorReader struct {
	err error
}

func (r *errorReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	return r.err
}

func (r *errorReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return r.err
}

// blockingReader blocks in Get until released, then returns an error.
// Used to test concurrent behavior during flush.
type blockingReader struct {
	enterOnce sync.Once
	enterCh   chan struct{} // closed when Get is entered
	blockCh   chan struct{} // Get blocks until this is closed
	err       error
}

func (r *blockingReader) Get(_ context.Context, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
	r.enterOnce.Do(func() { close(r.enterCh) })
	<-r.blockCh
	return r.err
}

func (r *blockingReader) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return r.err
}

func TestActivityTracker_WithReader(t *testing.T) {
	scheme := newTestActivityScheme()
	mainClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	readerClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("custom reader is used", func(t *testing.T) {
		tracker := NewActivityTracker(mainClient,
			WithFlushInterval(1*time.Hour),
			WithActivityLogger(zap.NewNop().Sugar()),
			WithReader(readerClient),
		)
		defer tracker.Stop(context.Background())
		assert.Equal(t, readerClient, tracker.getReader(),
			"getReader should return the custom reader")
	})

	t.Run("nil reader falls back to client", func(t *testing.T) {
		tracker := NewActivityTracker(mainClient,
			WithFlushInterval(1*time.Hour),
			WithActivityLogger(zap.NewNop().Sugar()),
			WithReader(nil),
		)
		defer tracker.Stop(context.Background())
		assert.Equal(t, mainClient, tracker.getReader(),
			"getReader should fall back to client when WithReader(nil)")
	})
}

func TestActivityTracker_FlushRetriesOnError(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
		WithReader(&errorReader{err: fmt.Errorf("intermittent API error")}),
	)
	defer tracker.Stop(context.Background())

	tracker.RecordActivity("breakglass", "session-retry", time.Now())

	// First flush — should fail and re-queue with retries=1
	tracker.flush(context.Background())
	assert.Equal(t, 1, tracker.Pending(), "Failed entry should be re-queued")

	// Verify retry count incremented
	tracker.mu.Lock()
	key := types.NamespacedName{Namespace: "breakglass", Name: "session-retry"}
	entry := tracker.entries[key]
	require.NotNil(t, entry)
	assert.Equal(t, 1, entry.retries, "Retry count should be incremented")
	tracker.mu.Unlock()
}

func TestActivityTracker_FlushDiscardsAfterMaxRetries(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
		WithReader(&errorReader{err: fmt.Errorf("persistent error")}),
	)
	defer tracker.Stop(context.Background())

	tracker.RecordActivity("breakglass", "session-discard", time.Now())

	// Flush maxFlushRetries times to exhaust retries
	for i := 0; i < maxFlushRetries; i++ {
		tracker.flush(context.Background())
	}

	assert.Equal(t, 0, tracker.Pending(),
		"Entry should be discarded after maxFlushRetries consecutive failures")
}

func TestActivityTracker_FlushDeletedSession(t *testing.T) {
	scheme := newTestActivityScheme()
	// No sessions in the fake client — Get will return NotFound
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	tracker.RecordActivity("breakglass", "deleted-session", time.Now())
	tracker.flush(context.Background())

	assert.Equal(t, 0, tracker.Pending(),
		"Deleted session entry should be silently discarded, not re-queued")
}

func TestActivityTracker_FlushMergesFailedWithNewActivity(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	reader := &blockingReader{
		enterCh: make(chan struct{}),
		blockCh: make(chan struct{}),
		err:     fmt.Errorf("API error"),
	}

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
		WithReader(reader),
	)
	defer tracker.Stop(context.Background())

	now := time.Now()
	tracker.RecordActivity("breakglass", "session-merge", now)

	flushDone := make(chan struct{})
	go func() {
		tracker.flush(context.Background())
		close(flushDone)
	}()

	// Wait for flush to enter the reader.Get (entries map already swapped)
	<-reader.enterCh

	// Record new activity while flush is blocked — writes to the new (swapped) map
	tracker.RecordActivity("breakglass", "session-merge", now.Add(10*time.Second))

	// Release the reader so flush fails and re-queues, merging with the new entry
	close(reader.blockCh)
	<-flushDone

	// Verify merge: failed entry (count=1, retries=1) merged with new entry (count=1)
	tracker.mu.Lock()
	key := types.NamespacedName{Namespace: "breakglass", Name: "session-merge"}
	entry := tracker.entries[key]
	require.NotNil(t, entry)
	assert.Equal(t, int64(2), entry.count, "Counts should be summed: 1 from failed + 1 from new")
	assert.Equal(t, now.Add(10*time.Second).Unix(), entry.lastSeen.Unix(),
		"lastSeen should be the latest of both entries")
	assert.Equal(t, 1, entry.retries, "Retry count should be from the failed entry")
	tracker.mu.Unlock()
}

func TestActivityTracker_StopContextExpired(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create manually to simulate a slow-to-exit background goroutine.
	at := &ActivityTracker{
		client:        fakeClient,
		log:           zap.NewNop().Sugar(),
		flushInterval: 1 * time.Hour,
		entries:       make(map[types.NamespacedName]*activityEntry),
		stopCh:        make(chan struct{}),
		done:          make(chan struct{}),
	}

	// Goroutine that delays closing done to simulate slow shutdown.
	go func() {
		<-at.stopCh
		time.Sleep(500 * time.Millisecond) // Must exceed context timeout below
		close(at.done)
	}()

	at.RecordActivity("breakglass", "session-ctx", time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	at.Stop(ctx) // Should hit ctx.Done() branch

	assert.Equal(t, 1, at.Pending(),
		"Entry should not be flushed when stop context expires")
}

func TestActivityTracker_RunTickerFlush(t *testing.T) {
	scheme := newTestActivityScheme()

	// Session must exist so updateSessionActivity's Get succeeds (avoids NotFound discard).
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-ticker",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "ticker@example.com",
			GrantedGroup: "group-1",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(session).
		Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(100*time.Millisecond), // Short interval to trigger ticker
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	tracker.RecordActivity("breakglass", "session-ticker", time.Now())

	// Verify the ticker-driven flush processes the pending entry.
	// Status updates are already validated by TestActivityTracker_Flush;
	// this test specifically covers the ticker.C path in run().
	require.Eventually(t, func() bool {
		return tracker.Pending() == 0
	}, 5*time.Second, 25*time.Millisecond,
		"Ticker should trigger automatic flush of pending activity")
}

func TestActivityTracker_MaxEntriesCap(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	now := time.Now()

	// Fill up to the cap
	for i := 0; i < maxEntries; i++ {
		tracker.RecordActivity("ns", fmt.Sprintf("session-%d", i), now)
	}
	assert.Equal(t, maxEntries, tracker.Pending(), "Should accept entries up to maxEntries")

	// One more should be dropped
	tracker.RecordActivity("ns", "session-overflow", now)
	assert.Equal(t, maxEntries, tracker.Pending(), "Should not exceed maxEntries")

	// Existing entry should still be updateable
	tracker.RecordActivity("ns", "session-0", now.Add(time.Second))
	assert.Equal(t, maxEntries, tracker.Pending(), "Updating existing entry should not change count")
}

func TestActivityTracker_Cleanup(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	now := time.Now()

	// Record activity for 5 sessions
	for i := 0; i < 5; i++ {
		tracker.RecordActivity("breakglass", fmt.Sprintf("session-%d", i), now)
	}
	assert.Equal(t, 5, tracker.Pending())

	// Only session-0 and session-2 are active
	activeIDs := map[types.NamespacedName]bool{
		{Namespace: "breakglass", Name: "session-0"}: true,
		{Namespace: "breakglass", Name: "session-2"}: true,
	}
	pruned := tracker.Cleanup(activeIDs)
	assert.Equal(t, 3, pruned, "Should prune 3 orphaned entries")
	assert.Equal(t, 2, tracker.Pending(), "Only active sessions should remain")

	// Calling cleanup again with same set should prune nothing
	pruned = tracker.Cleanup(activeIDs)
	assert.Equal(t, 0, pruned, "No entries to prune on second call")
}

func TestActivityTracker_CleanupEmptyTracker(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour),
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	activeIDs := map[types.NamespacedName]bool{
		{Namespace: "ns", Name: "session-1"}: true,
	}
	pruned := tracker.Cleanup(activeIDs)
	assert.Equal(t, 0, pruned, "Cleanup on empty tracker should prune nothing")
	assert.Equal(t, 0, tracker.Pending())
}
