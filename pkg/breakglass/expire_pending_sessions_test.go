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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// metadataNameIndexerExpire indexes objects by their metadata.name for field selector support
var metadataNameIndexerExpire = func(o client.Object) []string {
	return []string{o.GetName()}
}

func TestExpirePendingSessions(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	logger := zaptest.NewLogger(t).Sugar()

	t.Run("expires pending session past approval timeout", func(t *testing.T) {
		// Create a pending session that should be expired
		// TimeoutAt is set in the past
		pendingSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pending-expired",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStatePending,
				TimeoutAt: metav1.NewTime(time.Now().Add(-1 * time.Hour)), // Already past
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pendingSession).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerExpire).
			Build()

		mgr := NewSessionManagerWithClient(fakeClient)

		// Create minimal controller
		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
		}

		// Run the expire function
		controller.ExpirePendingSessions()

		// Verify session was expired
		var updatedSession breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: pendingSession.Namespace, Name: pendingSession.Name},
			&updatedSession)
		require.NoError(t, err)

		assert.Equal(t, breakglassv1alpha1.SessionStateTimeout, updatedSession.Status.State)
		assert.Equal(t, "approvalTimeout", updatedSession.Status.ReasonEnded)
	})

	t.Run("does not expire pending session within timeout", func(t *testing.T) {
		// Create a pending session that should NOT be expired
		recentSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pending-recent",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-5 * time.Minute)),
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStatePending,
				TimeoutAt: metav1.NewTime(time.Now().Add(25 * time.Minute)), // Still in future
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(recentSession).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerExpire).
			Build()

		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
		}

		controller.ExpirePendingSessions()

		// Verify session was NOT expired
		var updatedSession breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: recentSession.Namespace, Name: recentSession.Name},
			&updatedSession)
		require.NoError(t, err)

		assert.Equal(t, breakglassv1alpha1.SessionStatePending, updatedSession.Status.State)
	})

	t.Run("ignores approved sessions", func(t *testing.T) {
		approvedSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "approved-session",
				Namespace:         "breakglass",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour)),
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:      breakglassv1alpha1.SessionStateApproved,
				ApprovedAt: metav1.NewTime(time.Now().Add(-90 * time.Minute)), // Approved in the past
				TimeoutAt:  metav1.NewTime(time.Now().Add(-1 * time.Hour)),    // Past but should be ignored
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(approvedSession).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerExpire).
			Build()

		mgr := NewSessionManagerWithClient(fakeClient)

		controller := &BreakglassSessionController{
			log:            logger,
			sessionManager: mgr,
		}

		controller.ExpirePendingSessions()

		// Verify session was NOT changed
		var updatedSession breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: approvedSession.Namespace, Name: approvedSession.Name},
			&updatedSession)
		require.NoError(t, err)

		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, updatedSession.Status.State)
	})

	t.Run("does not overwrite concurrent terminal transition during retry", func(t *testing.T) {
		pendingSession := &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pending-concurrent-terminal",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				User:    "test@example.com",
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State:     breakglassv1alpha1.SessionStatePending,
				TimeoutAt: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
			},
		}

		var patchCalls int
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(pendingSession).
			WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
			WithIndex(&breakglassv1alpha1.BreakglassSession{}, "metadata.name", metadataNameIndexerExpire).
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
		}

		controller.ExpirePendingSessions()

		var updatedSession breakglassv1alpha1.BreakglassSession
		err := fakeClient.Get(context.Background(),
			client.ObjectKey{Namespace: pendingSession.Namespace, Name: pendingSession.Name},
			&updatedSession)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, updatedSession.Status.State)
		assert.Equal(t, "withdrawn", updatedSession.Status.ReasonEnded)
		assert.Equal(t, 1, patchCalls, "retry must refetch and skip instead of applying approval timeout again")
	})
}
