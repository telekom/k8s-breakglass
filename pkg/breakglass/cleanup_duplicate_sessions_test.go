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
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap/zaptest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// stateIndexer is a field index function used by the fake client for status.state queries.
var stateIndexer = func(o client.Object) []string {
	bs := o.(*breakglassv1alpha1.BreakglassSession)
	if bs.Status.State != "" {
		return []string{string(bs.Status.State)}
	}
	return nil
}

func newFakeClientWithSessions(objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexer).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
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
		CleanupDuplicateSessions(ctx, logger, mgr)
	})

	t.Run("nil manager — no-op", func(t *testing.T) {
		CleanupDuplicateSessions(ctx, logger, nil)
	})

	t.Run("single session — no-op", func(t *testing.T) {
		s := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "only-one",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.Now(),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var got breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s), &got))
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, got.Status.State, "single session must not be touched")
	})

	t.Run("two sessions different triples — no-op", func(t *testing.T) {
		s1 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "sess-a",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.Now(),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		s2 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "sess-b",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.Now(),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c2", User: "u2", GrantedGroup: "g2"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var got1, got2 breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, got1.Status.State)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got2.Status.State)
	})

	t.Run("duplicate pending sessions — oldest kept, newest withdrawn", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		oldest := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "oldest",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		newest := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "newest",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(oldest, newest)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var gotOld, gotNew breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(oldest), &gotOld))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(newest), &gotNew))

		assert.Equal(t, breakglassv1alpha1.SessionStatePending, gotOld.Status.State, "oldest must be kept")
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, gotNew.Status.State, "newest must be withdrawn (Pending→Withdrawn)")
		assert.Equal(t, "withdrawn", gotNew.Status.ReasonEnded)

		// Verify condition was added
		require.NotEmpty(t, gotNew.Status.Conditions)
		cond := gotNew.GetCondition(string(breakglassv1alpha1.SessionConditionTypeCanceled))
		require.NotNil(t, cond)
		assert.Equal(t, string(breakglassv1alpha1.SessionConditionTypeCanceled), cond.Type)
		assert.Equal(t, "DuplicateSessionWithdrawn", cond.Reason)
		auditCond := gotNew.GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete))
		require.NotNil(t, auditCond)
		assert.Equal(t, metav1.ConditionTrue, auditCond.Status)
		assert.Equal(t, "AuditingDisabledAtCommit", auditCond.Reason)
	})

	t.Run("duplicate approved sessions — oldest kept, newest expired with metadata", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		naturalExpiry := metav1.NewTime(now.Add(-time.Minute))
		oldest := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "approved-old",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved},
		}
		newest := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "approved-new",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved, ExpiresAt: naturalExpiry},
		}
		fc := newFakeClientWithSessions(oldest, newest)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var gotOld, gotNew breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(oldest), &gotOld))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(newest), &gotNew))

		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, gotOld.Status.State, "oldest approved kept")
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, gotNew.Status.State, "newest approved expired")
		assert.Equal(t, "duplicateCleanup", gotNew.Status.ReasonEnded, "ReasonEnded must be documented value")
		assert.False(t, gotNew.Status.ExpiresAt.IsZero(), "ExpiresAt must be set when forcing Expired")
		assert.True(t, gotNew.Status.ExpiresAt.Time.Equal(naturalExpiry.Time), "duplicate cleanup must preserve an elapsed expiry: got %v, want %v", gotNew.Status.ExpiresAt.Time, naturalExpiry.Time)

		// Verify condition was added
		require.NotEmpty(t, gotNew.Status.Conditions)
		cond := gotNew.GetCondition(string(breakglassv1alpha1.SessionConditionTypeExpired))
		require.NotNil(t, cond)
		assert.Equal(t, string(breakglassv1alpha1.SessionConditionTypeExpired), cond.Type)
		assert.Equal(t, "DuplicateSessionTerminated", cond.Reason)
	})

	t.Run("three duplicates — approved kept over older pending", func(t *testing.T) {
		now := time.Now()
		s1 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s1",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved},
		}
		s2 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s2",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		s3 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "s3",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateWaitingForScheduledTime},
		}
		fc := newFakeClientWithSessions(s1, s2, s3)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var got1, got2, got3 breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s3), &got3))

		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, got1.Status.State, "approved session kept (highest priority)")
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, got2.Status.State, "pending withdrawn")
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, got3.Status.State, "waiting withdrawn")
	})

	t.Run("stale duplicate already terminal in live reader is preserved", func(t *testing.T) {
		now := time.Now()
		keepCached := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "live-terminal-keep",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		dupCached := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "live-terminal-dup",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-1 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		keepLive := keepCached.DeepCopy()
		dupLive := dupCached.DeepCopy()
		dupLive.Status.State = breakglassv1alpha1.SessionStateRejected
		dupLive.Status.ReasonEnded = "rejected"

		cacheClient := newFakeClientWithSessions(keepCached, dupCached)
		readerClient := newFakeClientWithSessions(keepLive, dupLive)
		mgr := NewSessionManagerWithClientAndReader(cacheClient, readerClient)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var cachedDup breakglassv1alpha1.BreakglassSession
		require.NoError(t, cacheClient.Get(ctx, client.ObjectKeyFromObject(dupCached), &cachedDup))
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, cachedDup.Status.State,
			"stale cached duplicate must not be withdrawn after live state is terminal")

		var liveDup breakglassv1alpha1.BreakglassSession
		require.NoError(t, readerClient.Get(ctx, client.ObjectKeyFromObject(dupLive), &liveDup))
		assert.Equal(t, breakglassv1alpha1.SessionStateRejected, liveDup.Status.State)
		assert.Equal(t, "rejected", liveDup.Status.ReasonEnded)
	})

	t.Run("cached survivor terminal in live reader is not kept", func(t *testing.T) {
		now := time.Now()
		staleSurvivor := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "stale-survivor",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		remainingOld := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "remaining-old",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		remainingNew := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "remaining-new",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		staleSurvivorLive := staleSurvivor.DeepCopy()
		staleSurvivorLive.Status.State = breakglassv1alpha1.SessionStateExpired
		staleSurvivorLive.Status.ReasonEnded = "expired"

		cacheClient := newFakeClientWithSessions(staleSurvivor, remainingOld, remainingNew)
		readerClient := newFakeClientWithSessions(staleSurvivorLive, remainingOld.DeepCopy(), remainingNew.DeepCopy())
		mgr := NewSessionManagerWithClientAndReader(cacheClient, readerClient)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var gotOld, gotNew breakglassv1alpha1.BreakglassSession
		require.NoError(t, cacheClient.Get(ctx, client.ObjectKeyFromObject(remainingOld), &gotOld))
		require.NoError(t, cacheClient.Get(ctx, client.ObjectKeyFromObject(remainingNew), &gotNew))
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, gotOld.Status.State,
			"oldest still-active live candidate must become the recomputed survivor")
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, gotNew.Status.State,
			"newer still-active live candidate should be withdrawn")

		var liveStaleSurvivor breakglassv1alpha1.BreakglassSession
		require.NoError(t, readerClient.Get(ctx, client.ObjectKeyFromObject(staleSurvivorLive), &liveStaleSurvivor))
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, liveStaleSurvivor.Status.State)
		assert.Equal(t, "expired", liveStaleSurvivor.Status.ReasonEnded)
	})

	t.Run("mixed active and terminal sessions — terminal ignored", func(t *testing.T) {
		now := time.Now()
		active := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "active",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		expired := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "expired",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateExpired},
		}
		fc := newFakeClientWithSessions(active, expired)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var gotActive, gotExpired breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(active), &gotActive))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(expired), &gotExpired))

		assert.Equal(t, breakglassv1alpha1.SessionStatePending, gotActive.Status.State, "active session untouched")
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, gotExpired.Status.State, "terminal session untouched")
	})

	t.Run("different groups same cluster/user — not duplicates", func(t *testing.T) {
		now := time.Now()
		s1 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "group-a",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "admin"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		s2 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "group-b",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "viewer"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var got1, got2 breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))

		assert.Equal(t, breakglassv1alpha1.SessionStatePending, got1.Status.State)
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, got2.Status.State)
	})

	t.Run("newer approved kept over older pending — state priority wins", func(t *testing.T) {
		now := time.Now()
		olderPending := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "older-pending",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		newerApproved := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "newer-approved",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved},
		}
		fc := newFakeClientWithSessions(olderPending, newerApproved)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var gotPending, gotApproved breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(olderPending), &gotPending))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(newerApproved), &gotApproved))

		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, gotPending.Status.State, "older pending withdrawn")
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, gotApproved.Status.State, "newer approved kept")
	})

	t.Run("nil logger — does not panic", func(t *testing.T) {
		now := time.Now()
		s1 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "dup1",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		s2 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "dup2",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		// Should not panic with nil logger
		CleanupDuplicateSessions(ctx, nil, mgr)

		var got1, got2 breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s1), &got1))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))

		assert.Equal(t, breakglassv1alpha1.SessionStatePending, got1.Status.State, "oldest kept")
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, got2.Status.State, "newest withdrawn")
	})

	t.Run("name tie-breaker — same state and timestamp", func(t *testing.T) {
		// When two sessions have the same state priority and creation timestamp,
		// the one with the lexicographically smaller name is kept.
		ts := metav1.NewTime(time.Now().UTC().Add(-10 * time.Minute))
		sA := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "aaa-session",
				Namespace:         "breakglass",
				CreationTimestamp: ts,
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		sZ := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "zzz-session",
				Namespace:         "breakglass",
				CreationTimestamp: ts,
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(sA, sZ)
		mgr := NewSessionManagerWithClient(fc)

		CleanupDuplicateSessions(ctx, logger, mgr)

		var gotA, gotZ breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(sA), &gotA))
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(sZ), &gotZ))

		assert.Equal(t, breakglassv1alpha1.SessionStatePending, gotA.Status.State, "aaa-session (smaller name) must be kept")
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, gotZ.Status.State, "zzz-session (larger name) must be withdrawn")
	})

	t.Run("context cancellation — stops processing early", func(t *testing.T) {
		now := time.Now()
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel() // cancel immediately

		s1 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "ctx-dup1",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-10 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		s2 := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "ctx-dup2",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(now.Add(-5 * time.Minute)),
			},
			Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1", GrantedGroup: "g1"},
			Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
		}
		fc := newFakeClientWithSessions(s1, s2)
		mgr := NewSessionManagerWithClient(fc)

		// With cancelled context, the duplicate loop should exit early
		CleanupDuplicateSessions(cancelCtx, logger, mgr)

		var got2 breakglassv1alpha1.BreakglassSession
		require.NoError(t, fc.Get(ctx, client.ObjectKeyFromObject(s2), &got2))
		// Duplicate should NOT have been withdrawn because context was cancelled
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, got2.Status.State, "cancelled context prevents duplicate processing")
	})
}

func TestDuplicateCleanupAuditFailureLeavesTerminalIntent(t *testing.T) {
	now := time.Now().UTC()
	keep := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "keep-audit", Namespace: "breakglass", UID: "keep-uid", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
	}
	duplicate := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "duplicate-audit", Namespace: "breakglass", UID: "duplicate-uid", CreationTimestamp: metav1.NewTime(now)},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
	}
	fc := newFakeClientWithSessions(keep, duplicate)
	mgr := NewSessionManagerWithClient(fc)
	recorder := &duplicateCleanupAuditRecorder{err: assert.AnError}
	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), mgr, recorder)

	var pending breakglassv1alpha1.BreakglassSession
	require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(duplicate), &pending))
	require.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, pending.Status.State,
		"required audit failure must not restore duplicate access")
	pendingAudit := pending.GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete))
	require.NotNil(t, pendingAudit)
	assert.Equal(t, metav1.ConditionFalse, pendingAudit.Status)
	assert.Equal(t, duplicateCleanupIntentWithdraw, pendingAudit.Reason)
	assert.Empty(t, recorder.events, "a rejected sink must not record acceptance")

	recorder.err = nil
	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), mgr, recorder)
	var acknowledged breakglassv1alpha1.BreakglassSession
	require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(duplicate), &acknowledged))
	ack := acknowledged.GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete))
	require.NotNil(t, ack)
	assert.Equal(t, metav1.ConditionTrue, ack.Status)
	assert.Equal(t, duplicateCleanupIntentWithdraw, ack.Reason)
	require.Len(t, recorder.events, 1)
	assert.Equal(t, "duplicate-cleanup/duplicate-uid", recorder.events[0].ID)
	assert.True(t, ack.LastTransitionTime.Time.Equal(recorder.events[0].Timestamp),
		"the committed acknowledgement and required audit must share one decision timestamp")
	assert.Equal(t, audit.EventSessionTerminationIntent, recorder.events[0].Type)
	assert.Equal(t, string(breakglassv1alpha1.SessionStateWithdrawn), recorder.events[0].Details["terminalDecision"])
	assert.Equal(t, true, recorder.events[0].Details["transitionCommitted"])
}

func TestDuplicateCleanupConfiguredButUnavailableLeavesPendingIntent(t *testing.T) {
	now := time.Now().UTC()
	keep := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "keep-unavailable", Namespace: "breakglass", UID: "keep-uid", CreationTimestamp: metav1.NewTime(now.Add(-time.Minute))},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
	}
	duplicate := keep.DeepCopy()
	duplicate.Name = "duplicate-unavailable"
	duplicate.UID = "duplicate-uid"
	duplicate.CreationTimestamp = metav1.NewTime(now)
	fakeClient := newFakeClientWithSessions(keep, duplicate)
	emitter := &duplicateCleanupAuditRecorder{unavailable: true}

	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fakeClient), emitter)

	var stored breakglassv1alpha1.BreakglassSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(duplicate), &stored))
	assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, stored.Status.State)
	condition := duplicateCleanupAuditCondition(&stored)
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, duplicateCleanupIntentWithdraw, condition.Reason)
	assert.NotEqual(t, "AuditingDisabledAtCommit", condition.Reason)
	assert.Empty(t, emitter.events)

	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fakeClient), emitter)
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(duplicate), &stored))
	assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, stored.Status.State)
}

func TestDuplicateCleanupStillRevokesNewDuplicatesWhileAuditRetries(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(400, 0))
	pendingAudit := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "old-pending-audit", Namespace: "breakglass", UID: "old-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "old", User: "user", GrantedGroup: "admin"},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateWithdrawn,
			Conditions: []metav1.Condition{{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionFalse,
				Reason:             duplicateCleanupIntentWithdraw,
				LastTransitionTime: intentTime,
			}},
		},
	}
	oldest := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "keep-new", Namespace: "breakglass", UID: "keep-uid", CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Minute))},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "new", User: "user", GrantedGroup: "admin"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
	}
	newest := oldest.DeepCopy()
	newest.Name = "revoke-new"
	newest.UID = "revoke-uid"
	newest.CreationTimestamp = metav1.Now()
	fakeClient := newFakeClientWithSessions(pendingAudit, oldest, newest)
	emitter := &duplicateCleanupAuditRecorder{unavailable: true}

	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fakeClient), emitter)

	var stored breakglassv1alpha1.BreakglassSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(newest), &stored))
	assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, stored.Status.State)
	condition := duplicateCleanupAuditCondition(&stored)
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
}

func TestDuplicateCleanupPendingIntentsCommitWhenAuditIsDisabled(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(400, 0))
	for _, test := range []struct {
		name   string
		state  breakglassv1alpha1.BreakglassSessionState
		reason string
		want   breakglassv1alpha1.BreakglassSessionState
	}{
		{name: "current intent", state: breakglassv1alpha1.SessionStateExpired, reason: duplicateCleanupIntentExpire, want: breakglassv1alpha1.SessionStateExpired},
		{name: "legacy intent", state: breakglassv1alpha1.SessionStateWithdrawn, reason: duplicateCleanupLegacyPending, want: breakglassv1alpha1.SessionStateWithdrawn},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &breakglassv1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{Name: "disabled-audit", Namespace: "breakglass", UID: "disabled-audit-uid"},
				Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State: test.state,
					Conditions: []metav1.Condition{{
						Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
						Status:             metav1.ConditionFalse,
						Reason:             test.reason,
						LastTransitionTime: intentTime,
					}},
				},
			}
			fakeClient := newFakeClientWithSessions(session)
			emitter := &duplicateCleanupAuditRecorder{intentionallyDisabled: true}

			CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fakeClient), emitter)

			var stored breakglassv1alpha1.BreakglassSession
			require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
			assert.Equal(t, test.want, stored.Status.State)
			condition := duplicateCleanupAuditCondition(&stored)
			require.NotNil(t, condition)
			assert.Equal(t, metav1.ConditionTrue, condition.Status)
			if test.reason == duplicateCleanupLegacyPending {
				assert.Equal(t, "AuditingDisabledAtCommit", condition.Reason)
			} else {
				assert.Equal(t, test.reason, condition.Reason)
			}
			assert.True(t, condition.LastTransitionTime.Equal(&intentTime))
			assert.Empty(t, emitter.events)
		})
	}
}

func TestDuplicateCleanupAuditAckFailureRetriesIdenticalEvent(t *testing.T) {
	initial := metav1.NewTime(time.Unix(200, 0))
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "ack-retry", Namespace: "breakglass", UID: "ack-retry-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateExpired,
			Conditions: []metav1.Condition{{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionFalse,
				Reason:             duplicateCleanupIntentExpire,
				LastTransitionTime: initial,
			}},
		},
	}
	var ackAttempts int
	fc := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithInterceptorFuncs(interceptor.Funcs{SubResourcePatch: func(_ context.Context, _ client.Client, subResource string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
			if subResource == "status" && ackAttempts == 0 {
				ackAttempts++
				return apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "breakglasssessions"}, session.Name, assert.AnError)
			}
			return nil
		}}).Build()
	recorder := &duplicateCleanupAuditRecorder{}
	mgr := NewSessionManagerWithClient(fc)

	// The first ack attempt conflicts. Since the fake interceptor does not
	// persist the ack, a later drain must truthfully retry the same event.
	require.NoError(t, drainDuplicateCleanupAudit(context.Background(), zaptest.NewLogger(t).Sugar(), mgr, session.Namespace, session.Name, recorder))
	require.NoError(t, drainDuplicateCleanupAudit(context.Background(), zaptest.NewLogger(t).Sugar(), mgr, session.Namespace, session.Name, recorder))
	require.Len(t, recorder.events, 2)
	assert.Equal(t, recorder.events[0].ID, recorder.events[1].ID)
	assert.True(t, recorder.events[0].Timestamp.Equal(recorder.events[1].Timestamp))
	assert.Equal(t, recorder.events[0].Details, recorder.events[1].Details)
}

func TestDuplicateCleanupAuditRestartUsesPersistedTuple(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(300, 0))
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "restart", Namespace: "breakglass", UID: "restart-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateWithdrawn,
			Conditions: []metav1.Condition{{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionFalse,
				Reason:             duplicateCleanupIntentWithdraw,
				LastTransitionTime: intentTime,
			}},
		},
	}
	fc := newFakeClientWithSessions(session)
	recorder := &duplicateCleanupAuditRecorder{}

	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fc), recorder)

	require.Len(t, recorder.events, 1)
	event := recorder.events[0]
	assert.Equal(t, "duplicate-cleanup/restart-uid", event.ID)
	assert.Equal(t, audit.EventSessionTerminationIntent, event.Type)
	assert.True(t, event.Timestamp.Equal(intentTime.Time))
	assert.Equal(t, string(breakglassv1alpha1.SessionStateWithdrawn), event.Details["terminalDecision"])
	var committed breakglassv1alpha1.BreakglassSession
	require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(session), &committed))
	assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, committed.Status.State)
	require.Equal(t, metav1.ConditionTrue, committed.GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete)).Status)
}

func TestDuplicateCleanupDoesNotRevokeActiveIntentWithoutDuplicateProof(t *testing.T) {
	intentTime := metav1.NewTime(time.Unix(350, 0))
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy-active-intent", Namespace: "breakglass", UID: "legacy-active-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
			Conditions: []metav1.Condition{{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionFalse,
				Reason:             duplicateCleanupIntentWithdraw,
				LastTransitionTime: intentTime,
			}},
		},
	}
	fakeClient := newFakeClientWithSessions(session)
	recorder := &duplicateCleanupAuditRecorder{err: assert.AnError}

	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fakeClient), recorder)

	var stored breakglassv1alpha1.BreakglassSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(session), &stored))
	assert.Equal(t, breakglassv1alpha1.SessionStatePending, stored.Status.State,
		"an active intent alone does not prove that another active session survives")
	condition := duplicateCleanupAuditCondition(&stored)
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.True(t, condition.LastTransitionTime.Equal(&intentTime))
	assert.Empty(t, recorder.events)
}

func TestTerminateDuplicateSessionRevalidatesCurrentSetAndOrdering(t *testing.T) {
	now := time.Unix(1_000, 0).UTC()

	for _, test := range []struct {
		name          string
		mutate        func(context.Context, client.WithWatch, *breakglassv1alpha1.BreakglassSession, *breakglassv1alpha1.BreakglassSession)
		wantCandidate breakglassv1alpha1.BreakglassSessionState
	}{
		{
			name: "candidate Pending to Approved",
			mutate: func(ctx context.Context, c client.WithWatch, _ *breakglassv1alpha1.BreakglassSession, candidate *breakglassv1alpha1.BreakglassSession) {
				current := &breakglassv1alpha1.BreakglassSession{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(candidate), current))
				current.Status.State = breakglassv1alpha1.SessionStateApproved
				require.NoError(t, c.Status().Update(ctx, current))
			},
			wantCandidate: breakglassv1alpha1.SessionStateApproved,
		},
		{
			name: "survivor becomes terminal",
			mutate: func(ctx context.Context, c client.WithWatch, survivor, _ *breakglassv1alpha1.BreakglassSession) {
				current := &breakglassv1alpha1.BreakglassSession{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(survivor), current))
				current.Status.State = breakglassv1alpha1.SessionStateRejected
				require.NoError(t, c.Status().Update(ctx, current))
			},
			wantCandidate: breakglassv1alpha1.SessionStatePending,
		},
		{
			name: "duplicate set changes",
			mutate: func(ctx context.Context, c client.WithWatch, survivor, _ *breakglassv1alpha1.BreakglassSession) {
				current := &breakglassv1alpha1.BreakglassSession{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(survivor), current))
				current.Spec.GrantedGroup = "other-group"
				require.NoError(t, c.Update(ctx, current))
			},
			wantCandidate: breakglassv1alpha1.SessionStatePending,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			survivor := &breakglassv1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "survivor",
					Namespace:         "breakglass",
					UID:               "survivor-uid",
					CreationTimestamp: metav1.NewTime(now.Add(-time.Minute)),
				},
				Spec:   breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
				Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending},
			}
			candidate := survivor.DeepCopy()
			candidate.Name = "candidate"
			candidate.UID = "candidate-uid"
			candidate.CreationTimestamp = metav1.NewTime(now)

			var listCalls int
			fc := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(survivor, candidate).
				WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
				WithInterceptorFuncs(interceptor.Funcs{
					List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
						listCalls++
						if listCalls == 1 {
							test.mutate(ctx, c, survivor, candidate)
						}
						return c.List(ctx, list, opts...)
					},
				}).Build()

			selected := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(candidate), selected))
			updated, err := terminateDuplicateSession(
				context.Background(),
				zaptest.NewLogger(t).Sugar(),
				NewSessionManagerWithClient(fc),
				duplicateKeyForSession(*selected),
				*selected,
			)
			require.NoError(t, err)
			assert.False(t, updated)
			assert.Equal(t, 1, listCalls)

			stored := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(candidate), stored))
			assert.Equal(t, test.wantCandidate, stored.Status.State)
			assert.Nil(t, duplicateCleanupAuditCondition(stored))
		})
	}
}

func TestLegacyDuplicateCleanupPendingDeliveryKeepsItsTruthfulEvent(t *testing.T) {
	legacyTime := metav1.NewTime(time.Unix(250, 0))
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "breakglass", UID: "legacy-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "cluster", User: "user", GrantedGroup: "admin"},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateWithdrawn,
			Conditions: []metav1.Condition{{
				Type:               string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete),
				Status:             metav1.ConditionFalse,
				Reason:             duplicateCleanupLegacyPending,
				LastTransitionTime: legacyTime,
			}},
		},
	}
	fc := newFakeClientWithSessions(session)
	recorder := &duplicateCleanupAuditRecorder{}

	CleanupDuplicateSessions(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fc), recorder)

	require.Len(t, recorder.events, 1)
	event := recorder.events[0]
	assert.Equal(t, audit.EventSessionWithdrawn, event.Type)
	assert.Equal(t, "duplicate-cleanup/legacy-uid", event.ID)
	assert.True(t, event.Timestamp.Equal(legacyTime.Time))
	assert.Equal(t, "duplicateCleanup", event.Details["reason"])
	assert.Equal(t, string(breakglassv1alpha1.SessionStateWithdrawn), event.Details["terminalState"])
	assert.NotContains(t, event.Details, "transitionCommitted")

	var acknowledged breakglassv1alpha1.BreakglassSession
	require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(session), &acknowledged))
	condition := duplicateCleanupAuditCondition(&acknowledged)
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "EmissionAccepted", condition.Reason)
	assert.True(t, condition.LastTransitionTime.Equal(&legacyTime))
}

type duplicateCleanupAuditRecorder struct {
	events                []*audit.Event
	err                   error
	unavailable           bool
	intentionallyDisabled bool
}

func (r *duplicateCleanupAuditRecorder) IsEnabled() bool {
	return !r.unavailable && !r.intentionallyDisabled
}
func (r *duplicateCleanupAuditRecorder) IsConfigured() bool {
	return !r.intentionallyDisabled
}
func (r *duplicateCleanupAuditRecorder) Emit(_ context.Context, event *audit.Event) {
	r.events = append(r.events, event)
}
func (r *duplicateCleanupAuditRecorder) EmitSync(_ context.Context, event *audit.Event) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, event)
	return nil
}

func TestDuplicateCleanupAuditIsDurableAndAtLeastOnce(t *testing.T) {
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "duplicate", Namespace: "breakglass", UID: "stable-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "prod", GrantedGroup: "admin"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateExpired},
	}
	condition := metav1.Condition{
		Reason:             duplicateCleanupIntentExpire,
		LastTransitionTime: metav1.NewTime(time.Unix(100, 0)),
	}
	recorder := &duplicateCleanupAuditRecorder{}
	require.NoError(t, emitDuplicateCleanupAudit(context.Background(), duplicateCleanupAuditEvent(session, condition), recorder))
	require.Len(t, recorder.events, 1)
	assert.Equal(t, "duplicate-cleanup/stable-uid", recorder.events[0].ID)
	assert.Equal(t, audit.EventSessionTerminationIntent, recorder.events[0].Type)
	assert.Equal(t, "duplicateCleanup", recorder.events[0].Details["reason"])
	assert.Equal(t, string(breakglassv1alpha1.SessionStateExpired), recorder.events[0].Details["terminalDecision"])

	// Retries use the same ID as a correlation key. Delivery is explicitly
	// at-least-once because sinks are not required to deduplicate event IDs.
	require.NoError(t, emitDuplicateCleanupAudit(context.Background(), duplicateCleanupAuditEvent(session, condition), recorder))
	assert.Equal(t, recorder.events[0].ID, recorder.events[1].ID)

	recorder.err = assert.AnError
	assert.Error(t, emitDuplicateCleanupAudit(context.Background(), duplicateCleanupAuditEvent(session, condition), recorder), "sink failure must be returned")

	// Terminal state and immutable intent are persisted together before delivery.
	stored := session.DeepCopy()
	stored.Status.State = breakglassv1alpha1.SessionStatePending
	stored.Status.TimeoutAt = metav1.NewTime(time.Now().Add(time.Hour))
	survivor := stored.DeepCopy()
	survivor.Name = "survivor"
	survivor.UID = "survivor-uid"
	survivor.CreationTimestamp = metav1.NewTime(stored.CreationTimestamp.Add(-time.Minute))
	fc := newFakeClientWithSessions(stored, survivor)
	mgr := NewSessionManagerWithClient(fc)
	key := duplicateKeyForSession(*stored)
	updated, err := terminateDuplicateSession(context.Background(), zaptest.NewLogger(t).Sugar(), mgr, key, *stored, recorder)
	assert.Error(t, err)
	assert.False(t, updated)
	var terminal breakglassv1alpha1.BreakglassSession
	require.NoError(t, fc.Get(context.Background(), client.ObjectKeyFromObject(stored), &terminal))
	assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, terminal.Status.State)
	intent := terminal.GetCondition(string(breakglassv1alpha1.SessionConditionTypeDuplicateCleanupAuditComplete))
	require.NotNil(t, intent)
	assert.Equal(t, metav1.ConditionFalse, intent.Status)
	assert.Equal(t, duplicateCleanupIntentWithdraw, intent.Reason)
}

func TestDuplicateCleanupAuditRetriesAfterStatusConflict(t *testing.T) {
	now := metav1.NewTime(time.Now().Add(time.Hour))
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "conflict-duplicate", Namespace: "breakglass", UID: "conflict-uid"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "prod", User: "user", GrantedGroup: "admin"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStatePending, TimeoutAt: now},
	}
	survivor := session.DeepCopy()
	survivor.Name = "conflict-survivor"
	survivor.UID = "conflict-survivor-uid"
	survivor.CreationTimestamp = metav1.NewTime(session.CreationTimestamp.Add(-time.Minute))
	fc := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(session, survivor).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).Build()
	recorder := &duplicateCleanupAuditRecorder{}
	updated, err := terminateDuplicateSession(context.Background(), zaptest.NewLogger(t).Sugar(), NewSessionManagerWithClient(fc), duplicateKeyForSession(*session), *session, recorder)
	require.NoError(t, err)
	assert.True(t, updated)
	require.Len(t, recorder.events, 1,
		"an intent persistence conflict must be resolved before the first external delivery")
}

func TestGetLiveDuplicateSessionRequiresNamespace(t *testing.T) {
	t.Parallel()

	fc := newFakeClientWithSessions(&breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "duplicate",
			Namespace: "breakglass",
		},
	})
	mgr := NewSessionManagerWithClient(fc)

	_, err := getLiveDuplicateSession(context.Background(), mgr, breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "duplicate"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "namespace is required")
}

func TestTerminateDuplicateSessionIgnoresStatusPatchNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	ctx := context.Background()
	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "duplicate",
			Namespace: "breakglass",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "prod",
			User:    "developer@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(&session).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexer).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", func(o client.Object) []string {
			return []string{o.GetName()}
		}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, subResource string, obj client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				if subResource == "status" {
					return apierrors.NewNotFound(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "breakglasssessions"}, obj.GetName())
				}
				return nil
			},
		}).
		Build()
	mgr := NewSessionManagerWithClient(fc)

	updated, err := terminateDuplicateSession(ctx, logger, mgr, duplicateKeyForSession(session), session)

	require.NoError(t, err)
	assert.False(t, updated)
}

func TestSessionStatePriority(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state    breakglassv1alpha1.BreakglassSessionState
		expected int
	}{
		{breakglassv1alpha1.SessionStateApproved, 3},
		{breakglassv1alpha1.SessionStateWaitingForScheduledTime, 2},
		{breakglassv1alpha1.SessionStatePending, 1},
		{breakglassv1alpha1.SessionStateExpired, 0},
		{breakglassv1alpha1.SessionStateWithdrawn, 0},
		{breakglassv1alpha1.SessionStateRejected, 0},
		{breakglassv1alpha1.BreakglassSessionState("unknown"), 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, sessionStatePriority(tt.state))
		})
	}
}
