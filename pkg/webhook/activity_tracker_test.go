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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestActivityScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	return scheme
}

func TestActivityTracker_RecordActivity(t *testing.T) {
	scheme := newTestActivityScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	tracker := NewActivityTracker(fakeClient,
		WithFlushInterval(1*time.Hour), // long interval so we control flushing manually
		WithActivityLogger(zap.NewNop().Sugar()),
	)
	defer tracker.Stop(context.Background())

	now := time.Now()

	t.Run("record single activity", func(t *testing.T) {
		tracker.RecordActivity("breakglass", "session-1", now)
		assert.Equal(t, 1, tracker.Pending())
	})

	t.Run("record multiple activities for same session", func(t *testing.T) {
		tracker.RecordActivity("breakglass", "session-1", now.Add(1*time.Second))
		tracker.RecordActivity("breakglass", "session-1", now.Add(2*time.Second))
		assert.Equal(t, 1, tracker.Pending(), "Multiple activities for same session should be buffered as one entry")
	})

	t.Run("record activities for different sessions", func(t *testing.T) {
		tracker.RecordActivity("breakglass", "session-2", now)
		assert.Equal(t, 2, tracker.Pending())
	})
}

func TestActivityTracker_Flush(t *testing.T) {
	scheme := newTestActivityScheme()

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-flush",
			Namespace: "breakglass",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "alice@example.com",
			GrantedGroup: "group-1",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
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
	var updated v1alpha1.BreakglassSession
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

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-expired",
			Namespace: "breakglass",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "alice@example.com",
			GrantedGroup: "group-1",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateExpired,
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
	var updated v1alpha1.BreakglassSession
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

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-cumulative",
			Namespace: "breakglass",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "bob@example.com",
			GrantedGroup: "group-2",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
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
	var updated v1alpha1.BreakglassSession
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

	session := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-stop",
			Namespace: "breakglass",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "production",
			User:         "charlie@example.com",
			GrantedGroup: "group-3",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStateApproved,
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

	var updated v1alpha1.BreakglassSession
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
	sessions := []v1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "ses-1", Namespace: "ns-1"},
			Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "cluster-1"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "ses-2", Namespace: "ns-2"},
			Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "cluster-2"},
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
		wc.recordSessionActivity(sessions, "ses-1", "cluster-1", true)
		assert.Equal(t, 1, tracker.Pending())
	})

	t.Run("no-op when session name not found", func(t *testing.T) {
		initialPending := tracker.Pending()
		wc.recordSessionActivity(sessions, "non-existent", "cluster-1", true)
		assert.Equal(t, initialPending, tracker.Pending(), "Should not add entry for unknown session")
	})

	t.Run("no-op when tracker is nil", func(t *testing.T) {
		wcNoTracker := &WebhookController{}
		// Should not panic
		wcNoTracker.recordSessionActivity(sessions, "ses-1", "cluster-1", true)
	})
}
