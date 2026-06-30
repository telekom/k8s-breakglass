// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// stateIndexerApproved indexes BreakglassSessions by status.state for field selector support.
var stateIndexerApproved = func(o client.Object) []string {
	bs, ok := o.(*breakglassv1alpha1.BreakglassSession)
	if !ok || bs.Status.State == "" {
		return nil
	}
	return []string{string(bs.Status.State)}
}

// metadataNameIndexerApproved indexes objects by their metadata.name.
var metadataNameIndexerApproved = func(o client.Object) []string {
	return []string{o.GetName()}
}

// newFakeApprovedClient creates a fake client with required indexers for ExpireApprovedSessions tests.
func newFakeApprovedClient(objects ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(Scheme).
		WithObjects(objects...).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexerApproved).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerApproved).
		Build()
}

func TestExpireApprovedSessionsDetailed(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	t.Run("expires approved session past ExpiresAt", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "approved-expired",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-2 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-2 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)), // Already past
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "approved-expired"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updated.Status.State)
		assert.Equal(t, "timeExpired", updated.Status.ReasonEnded)
		require.False(t, updated.Status.RetainedUntil.IsZero(), "expired sessions must get terminal retention")
		assert.True(t, updated.Status.RetainedUntil.After(time.Now()))

		// Verify the Expired condition was added
		var hasExpiredCondition bool
		for _, c := range updated.Status.Conditions {
			if c.Type == string(breakglassv1alpha1.SessionConditionTypeExpired) {
				hasExpiredCondition = true
				assert.Equal(t, metav1.ConditionTrue, c.Status)
				assert.Equal(t, "ExpiredByTime", c.Reason)
			}
		}
		assert.True(t, hasExpiredCondition, "expected Expired condition to be set")
	})

	t.Run("does not expire approved session before ExpiresAt", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "approved-active",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-30 * time.Minute)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-30 * time.Minute)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(30 * time.Minute)), // Still in future
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "approved-active"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("expires recently expired session", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "boundary-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "boundary-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(-30 * time.Second)),
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "boundary-session"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updated.Status.State)
	})

	t.Run("does not expire session with ExpiresAt in the future", func(t *testing.T) {
		// Keep a generous buffer: expiry is checked against the live wall clock,
		// and 1-5s margins have flaked in CI.
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "near-future-boundary",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(30 * time.Second)),
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "near-future-boundary"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State,
			"ExpiresAt in the future should NOT expire")
	})

	t.Run("does not expire session with zero ExpiresAt", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "zero-expiry",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateApproved,
				ApprovedAt: metav1.NewTime(time.Now().UTC().Add(-30 * time.Minute)),
				ExpiresAt:  metav1.Time{}, // Zero value
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "zero-expiry"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("ignores non-approved sessions", func(t *testing.T) {
		pendingSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pending-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStatePending,
				ExpiresAt: metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
			},
		}

		fakeClient := newFakeApprovedClient(pendingSession)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "pending-session"},
			&updated)
		require.NoError(t, err)
		// GetSessionsByState filters for Approved only; pending should be untouched
		assert.Equal(t, breakglassv1alpha1.SessionStatePending, updated.Status.State)
	})

	t.Run("handles multiple sessions correctly", func(t *testing.T) {
		expiredSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-expired",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "user1@example.com",
				Cluster:      "cluster-a",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-3 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-3 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
			},
		}

		activeSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-active",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "user2@example.com",
				Cluster:      "cluster-b",
				GrantedGroup: "viewer",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-30 * time.Minute)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-30 * time.Minute)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(2 * time.Hour)),
			},
		}

		fakeClient := newFakeApprovedClient(expiredSession, activeSession)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		// Expired session should be marked expired
		var updatedExpired breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "multi-expired"},
			&updatedExpired)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updatedExpired.Status.State)

		// Active session should remain approved
		var updatedActive breakglassv1alpha1.BreakglassSession
		err = fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "multi-active"},
			&updatedActive)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updatedActive.Status.State)
	})

	t.Run("already expired session is not re-processed", func(t *testing.T) {
		// A session already in Expired state should not be fetched by GetSessionsByState(Approved)
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "already-expired",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:       breakglassv1alpha1.SessionStateExpired,
				ReasonEnded: "timeExpired",
				ExpiresAt:   metav1.NewTime(time.Now().UTC().Add(-2 * time.Hour)),
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		// Verify session is still expired and not modified
		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "already-expired"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updated.Status.State)
		assert.Equal(t, "timeExpired", updated.Status.ReasonEnded)
	})

	t.Run("session with very large TTL does not expire", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "long-lived",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(720 * time.Hour)), // 30 days
			},
		}

		fakeClient := newFakeApprovedClient(session)
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "long-lived"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updated.Status.State)
	})

	t.Run("no sessions to expire is a no-op", func(t *testing.T) {
		fakeClient := newFakeApprovedClient() // no sessions
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		// Should not panic or error
		assert.NotPanics(t, func() {
			controller.ExpireApprovedSessions()
		})
	})

	t.Run("does not overwrite concurrent terminal transition during retry", func(t *testing.T) {
		session := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "approved-concurrent-terminal",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:         "test@example.com",
				Cluster:      "test-cluster",
				GrantedGroup: "admin",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:           breakglassv1alpha1.SessionStateApproved,
				ApprovedAt:      metav1.NewTime(time.Now().UTC().Add(-2 * time.Hour)),
				ActualStartTime: metav1.NewTime(time.Now().UTC().Add(-2 * time.Hour)),
				ExpiresAt:       metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
			},
		}

		var patchCalls int
		fakeClient := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithObjects(session).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "status.state", stateIndexerApproved).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerApproved).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, cl client.Client, subResourceName string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					patchCalls++
					if patchCalls == 1 {
						var current breakglassv1alpha1.BreakglassSession
						if err := cl.Get(ctx, client.ObjectKeyFromObject(obj), &current); err != nil {
							return err
						}
						current.Status.State = breakglassv1alpha1.SessionStateWithdrawn
						current.Status.ReasonEnded = "withdrawn"
						if err := cl.Status().Update(ctx, &current); err != nil {
							return err
						}
						return apierrors.NewConflict(
							schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "breakglasssessions"},
							obj.GetName(),
							fmt.Errorf("simulated concurrent transition"),
						)
					}
					return cl.SubResource(subResourceName).Patch(ctx, obj, patch, opts...)
				},
			}).
			Build()
		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
			disableEmail:   true,
		}

		controller.ExpireApprovedSessions()

		var updated breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: "breakglass", Name: "approved-concurrent-terminal"},
			&updated)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, updated.Status.State)
		assert.Equal(t, "withdrawn", updated.Status.ReasonEnded)
		assert.Equal(t, 1, patchCalls, "retry must refetch and skip instead of applying expiry again")
	})
}

// TestIsSessionExpiredEdgeCases validates the IsSessionExpired helper for
// edge-case inputs that the main integration-style tests do not cover.
func TestIsSessionExpiredEdgeCases(t *testing.T) {
	t.Run("zero ExpiresAt on Approved session is not expired", func(t *testing.T) {
		session := breakglassv1alpha1.BreakglassSession{
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStateApproved,
				// ExpiresAt is zero-valued
			},
		}
		assert.False(t, IsSessionExpired(session),
			"Approved session with zero ExpiresAt should NOT be considered expired")
	})

	t.Run("nil/zero StartedAt has no effect on expiry", func(t *testing.T) {
		session := breakglassv1alpha1.BreakglassSession{
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(time.Now().UTC().Add(-1 * time.Minute)),
				// ActualStartTime is zero-valued — should still expire via ExpiresAt
			},
		}
		assert.True(t, IsSessionExpired(session),
			"Approved session past ExpiresAt should expire even without ActualStartTime")
	})

	t.Run("ExpiresAt in the near future is not yet expired", func(t *testing.T) {
		session := breakglassv1alpha1.BreakglassSession{
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(time.Now().UTC().Add(30 * time.Second)),
			},
		}
		assert.False(t, IsSessionExpired(session),
			"Session whose ExpiresAt is in the future should NOT be expired")
	})

	t.Run("negative remaining duration — far past ExpiresAt", func(t *testing.T) {
		session := breakglassv1alpha1.BreakglassSession{
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(time.Now().UTC().Add(-7 * 24 * time.Hour)), // a week ago
			},
		}
		assert.True(t, IsSessionExpired(session),
			"Session that expired a week ago must still report as expired")
	})

	t.Run("large future TTL — session is not expired", func(t *testing.T) {
		session := breakglassv1alpha1.BreakglassSession{
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStateApproved,
				ExpiresAt: metav1.NewTime(time.Now().UTC().Add(365 * 24 * time.Hour)), // 1 year from now
			},
		}
		assert.False(t, IsSessionExpired(session),
			"Session with ExpiresAt far in the future must NOT be expired")
	})

	t.Run("non-Approved state with past ExpiresAt is not expired", func(t *testing.T) {
		// Tests the early-return: non-Approved, non-Expired states always return false
		for _, state := range []breakglassv1alpha1.BreakglassSessionState{
			breakglassv1alpha1.SessionStatePending,
			breakglassv1alpha1.SessionStateRejected,
			breakglassv1alpha1.SessionStateWithdrawn,
			breakglassv1alpha1.SessionStateTimeout,
			breakglassv1alpha1.SessionStateIdleExpired,
			breakglassv1alpha1.SessionStateWaitingForScheduledTime,
		} {
			session := breakglassv1alpha1.BreakglassSession{
				Status: breakglassv1alpha1.BreakglassSessionStatus{
					State:     state,
					ExpiresAt: metav1.NewTime(time.Now().UTC().Add(-1 * time.Hour)),
				},
			}
			assert.False(t, IsSessionExpired(session),
				"State %q with past ExpiresAt should NOT be considered expired by IsSessionExpired", state)
		}
	})
}
