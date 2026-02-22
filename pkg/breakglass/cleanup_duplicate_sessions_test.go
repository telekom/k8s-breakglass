// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// stateIndexer is a field index function used by the fake client for status.state queries.
var stateIndexer = func(o client.Object) []string {
	bs := o.(*v1alpha1.BreakglassSession)
	if bs.Status.State != "" {
		return []string{string(bs.Status.State)}
	}
	return nil
}

func newFakeClientWithSessions(objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&v1alpha1.BreakglassSession{}).
		WithIndex(&v1alpha1.BreakglassSession{}, "status.state", stateIndexer).
		WithIndex(&v1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
			return []string{o.GetName()}
		}).
		Build()
}

func TestCleanupDuplicateSessions(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()

	t.Run("no sessions — no-op", func(t *testing.T) {
		fc := newFakeClientWithSessions()
		mgr := NewSessionManagerWithClient(fc)
		// Should not panic or error
		CleanupDuplicateSessions(ctx, logger, &mgr)
	})

	t.Run("nil manager — no-op", func(t *testing.T) {
		CleanupDuplicateSessions(ctx, logger, nil)
	})

	t.Run("single session — no-op", func(t *testing.T) {
		s := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "only-one",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.Now(),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var got v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s), &got))
		assert.Equal(t, v1alpha1.SessionStatePending, got.Status.State, "single session must not be touched")
	})

	t.Run("two sessions different triples — no-op", func(t *testing.T) {
		s1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "sess-a",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.Now(),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		s2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "sess-b",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.Now(),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c2", User: "u2", GrantedGroup: "g2"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var got1, got2 v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))
		assert.Equal(t, v1alpha1.SessionStatePending, got1.Status.State)
		assert.Equal(t, v1alpha1.SessionStateApproved, got2.Status.State)
	})

	t.Run("duplicate pending sessions — oldest kept, newest withdrawn", func(t *testing.T) {
		now := time.Now()
		oldest := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "oldest",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		newest := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "newest",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(oldest, newest)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var gotOld, gotNew v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(oldest), &gotOld))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(newest), &gotNew))

		assert.Equal(t, v1alpha1.SessionStatePending, gotOld.Status.State, "oldest must be kept")
		assert.Equal(t, v1alpha1.SessionStateWithdrawn, gotNew.Status.State, "newest must be withdrawn (Pending→Withdrawn)")
		assert.Equal(t, "withdrawn", gotNew.Status.ReasonEnded)

		// Verify condition was added
		require.NotEmpty(t, gotNew.Status.Conditions)
		cond := gotNew.Status.Conditions[len(gotNew.Status.Conditions)-1]
		assert.Equal(t, string(v1alpha1.SessionConditionTypeCanceled), cond.Type)
		assert.Equal(t, "DuplicateSessionWithdrawn", cond.Reason)
	})

	t.Run("duplicate approved sessions — oldest kept, newest expired with metadata", func(t *testing.T) {
		now := time.Now()
		oldest := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "approved-old",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved},
		}
		newest := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "approved-new",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved},
		}
		fc := newFakeClientWithSessions(oldest, newest)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var gotOld, gotNew v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(oldest), &gotOld))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(newest), &gotNew))

		assert.Equal(t, v1alpha1.SessionStateApproved, gotOld.Status.State, "oldest approved kept")
		assert.Equal(t, v1alpha1.SessionStateExpired, gotNew.Status.State, "newest approved expired")
		assert.Equal(t, "duplicateCleanup", gotNew.Status.ReasonEnded, "ReasonEnded must be documented value")
		assert.False(t, gotNew.Status.ExpiresAt.IsZero(), "ExpiresAt must be set when forcing Expired")

		// Verify condition was added
		require.NotEmpty(t, gotNew.Status.Conditions)
		cond := gotNew.Status.Conditions[len(gotNew.Status.Conditions)-1]
		assert.Equal(t, string(v1alpha1.SessionConditionTypeExpired), cond.Type)
		assert.Equal(t, "DuplicateSessionTerminated", cond.Reason)
	})

	t.Run("three duplicates — approved kept over older pending", func(t *testing.T) {
		now := time.Now()
		s1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s1",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved},
		}
		s2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s2",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		s3 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s3",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateWaitingForScheduledTime},
		}
		fc := newFakeClientWithSessions(s1, s2, s3)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var got1, got2, got3 v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s3), &got3))

		assert.Equal(t, v1alpha1.SessionStateApproved, got1.Status.State, "approved session kept (highest priority)")
		assert.Equal(t, v1alpha1.SessionStateWithdrawn, got2.Status.State, "pending withdrawn")
		assert.Equal(t, v1alpha1.SessionStateWithdrawn, got3.Status.State, "waiting withdrawn")
	})

	t.Run("mixed active and terminal sessions — terminal ignored", func(t *testing.T) {
		now := time.Now()
		active := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "active",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		expired := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "expired",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateExpired},
		}
		fc := newFakeClientWithSessions(active, expired)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var gotActive, gotExpired v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(active), &gotActive))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(expired), &gotExpired))

		assert.Equal(t, v1alpha1.SessionStatePending, gotActive.Status.State, "active session untouched")
		assert.Equal(t, v1alpha1.SessionStateExpired, gotExpired.Status.State, "terminal session untouched")
	})

	t.Run("different groups same cluster/user — not duplicates", func(t *testing.T) {
		now := time.Now()
		s1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "group-a",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "admin"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		s2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "group-b",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "viewer"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var got1, got2 v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))

		assert.Equal(t, v1alpha1.SessionStatePending, got1.Status.State)
		assert.Equal(t, v1alpha1.SessionStatePending, got2.Status.State)
	})

	t.Run("newer approved kept over older pending — state priority wins", func(t *testing.T) {
		now := time.Now()
		olderPending := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "older-pending",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		newerApproved := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "newer-approved",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved},
		}
		fc := newFakeClientWithSessions(olderPending, newerApproved)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var gotPending, gotApproved v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(olderPending), &gotPending))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(newerApproved), &gotApproved))

		assert.Equal(t, v1alpha1.SessionStateWithdrawn, gotPending.Status.State, "older pending withdrawn")
		assert.Equal(t, v1alpha1.SessionStateApproved, gotApproved.Status.State, "newer approved kept")
	})

	t.Run("nil logger — does not panic", func(t *testing.T) {
		now := time.Now()
		s1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "dup1",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		s2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "dup2",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		// Should not panic with nil logger
		CleanupDuplicateSessions(ctx, nil, &mgr)

		var got1, got2 v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))

		assert.Equal(t, v1alpha1.SessionStatePending, got1.Status.State, "oldest kept")
		assert.Equal(t, v1alpha1.SessionStateWithdrawn, got2.Status.State, "newest withdrawn")
	})

	t.Run("name tie-breaker — same state and timestamp", func(t *testing.T) {
		// When two sessions have the same state priority and creation timestamp,
		// the one with the lexicographically smaller name is kept.
		ts := metav1.NewTime(time.Now().Add(-10 * time.Minute))
		sA := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "aaa-session",
				Namespace:         "breakglass",
				CreationTimestamp: ts,
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		sZ := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "zzz-session",
				Namespace:         "breakglass",
				CreationTimestamp: ts,
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(sA, sZ)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, &mgr)

		var gotA, gotZ v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(sA), &gotA))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(sZ), &gotZ))

		assert.Equal(t, v1alpha1.SessionStatePending, gotA.Status.State, "aaa-session (smaller name) must be kept")
		assert.Equal(t, v1alpha1.SessionStateWithdrawn, gotZ.Status.State, "zzz-session (larger name) must be withdrawn")
	})

	t.Run("context cancellation — stops processing early", func(t *testing.T) {
		now := time.Now()
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel() // cancel immediately

		s1 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "ctx-dup1",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		s2 := &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "ctx-dup2",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		// With cancelled context, the duplicate loop should exit early
		CleanupDuplicateSessions(cancelCtx, logger, &mgr)

		var got2 v1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))
		// Duplicate should NOT have been withdrawn because context was cancelled
		assert.Equal(t, v1alpha1.SessionStatePending, got2.Status.State, "cancelled context prevents duplicate processing")
	})
}

func TestSessionStatePriority(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state    v1alpha1.BreakglassSessionState
		expected int
	}{
		{v1alpha1.SessionStateApproved, 3},
		{v1alpha1.SessionStateWaitingForScheduledTime, 2},
		{v1alpha1.SessionStatePending, 1},
		{v1alpha1.SessionStateExpired, 0},
		{v1alpha1.SessionStateWithdrawn, 0},
		{v1alpha1.SessionStateRejected, 0},
		{v1alpha1.BreakglassSessionState("unknown"), 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, sessionStatePriority(tt.state))
		})
	}
}
