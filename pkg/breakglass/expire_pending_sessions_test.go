package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestExpirePendingSessions(t *testing.T) {
	scheme := runtime.NewScheme()
	err := telekomv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	t.Run("expires pending session past approval timeout", func(t *testing.T) {
		// Create a pending session that should be expired
		// TimeoutAt is set in the past
		pendingSession := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pending-expired",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:     telekomv1alpha1.SessionStatePending,
				TimeoutAt: metav1.NewTime(time.Now().Add(-1 * time.Hour)), // Already past
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pendingSession).
			WithStatusSubresource(&telekomv1alpha1.BreakglassSession{}).
			Build()

		mgr := NewSessionManagerWithClient(fakeClient)

		// Create minimal controller
		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: &mgr,
		}

		// Run the expire function
		controller.ExpirePendingSessions()

		// Verify session was expired
		var updatedSession telekomv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: pendingSession.Namespace, Name: pendingSession.Name},
			&updatedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.SessionStateTimeout, updatedSession.Status.State)
	})

	t.Run("does not expire pending session within timeout", func(t *testing.T) {
		// Create a pending session that should NOT be expired
		recentSession := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pending-recent",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-5 * time.Minute)),
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:     telekomv1alpha1.SessionStatePending,
				TimeoutAt: metav1.NewTime(time.Now().Add(25 * time.Minute)), // Still in future
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(recentSession).
			WithStatusSubresource(&telekomv1alpha1.BreakglassSession{}).
			Build()

		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: &mgr,
		}

		controller.ExpirePendingSessions()

		// Verify session was NOT expired
		var updatedSession telekomv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: recentSession.Namespace, Name: recentSession.Name},
			&updatedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.SessionStatePending, updatedSession.Status.State)
	})

	t.Run("ignores approved sessions", func(t *testing.T) {
		approvedSession := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "approved-session",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: telekomv1alpha1.BreakglassSessionStatus{
				State:      telekomv1alpha1.SessionStateApproved,
				ApprovedAt: metav1.NewTime(time.Now().Add(-90 * time.Minute)), // Approved in the past
				TimeoutAt:  metav1.NewTime(time.Now().Add(-1 * time.Hour)),    // Past but should be ignored
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(approvedSession).
			WithStatusSubresource(&telekomv1alpha1.BreakglassSession{}).
			Build()

		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: &mgr,
		}

		controller.ExpirePendingSessions()

		// Verify session was NOT changed
		var updatedSession telekomv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: approvedSession.Namespace, Name: approvedSession.Name},
			&updatedSession)
		require.NoError(t, err)

		assert.Equal(t, telekomv1alpha1.SessionStateApproved, updatedSession.Status.State)
	})
}
