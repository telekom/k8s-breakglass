package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPatchDebugSessionStatusWithOptimisticLockRequiresResourceVersion(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-session",
			Namespace: "default",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Message: "unchanged",
		},
	}

	mutateCalled := false
	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), nil, session, func(status *breakglassv1alpha1.DebugSessionStatus) {
		mutateCalled = true
		status.Message = "mutated"
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing resourceVersion")
	assert.False(t, mutateCalled)
	assert.Equal(t, "unchanged", session.Status.Message)
}

func TestPatchDebugSessionStatusWithOptimisticLockKeepsTerminalState(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "terminal", Namespace: "default", ResourceVersion: "1"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateExpired},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.State = breakglassv1alpha1.DebugSessionStateActive
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal state")
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &stored))
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, stored.Status.State)
}

func TestPatchDebugSessionStatusWithOptimisticLockCannotRenewAtExpiry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	expiredAt := metav1.NewTime(time.Now().Add(-time.Second).Truncate(time.Second))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-renewal", Namespace: "default", ResourceVersion: "1"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiredAt,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		renewed := metav1.NewTime(expiredAt.Add(time.Hour))
		status.ExpiresAt = &renewed
		status.RenewalCount++
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "active and unexpired")
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &stored))
	require.NotNil(t, stored.Status.ExpiresAt)
	assert.True(t, stored.Status.ExpiresAt.Equal(&expiredAt))
}

func TestPatchDebugSessionStatusRejectsMissingExpiryResurrection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-expiry", Namespace: "default", ResourceVersion: "1"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
		status.ExpiresAt = &expiresAt
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must become terminal")

	err = PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, session.DeepCopy(), func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.State = breakglassv1alpha1.DebugSessionStateFailed
	})
	require.NoError(t, err)
}

func TestApplyDebugSessionStatusRejectsMissingExpiryResurrection(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	current := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-expiry-apply", Namespace: "default"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(current).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	desired := current.DeepCopy()
	future := metav1.NewTime(time.Now().Add(time.Hour))
	desired.Status.ExpiresAt = &future

	err := ApplyDebugSessionStatus(context.Background(), fakeClient, desired)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must become terminal")
}

func TestApplyDebugSessionStatusRejectsJoinLeaveAfterExpiry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	expired := metav1.NewTime(time.Now().Add(-time.Minute))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-join-leave", Namespace: "default"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expired,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	desired := session.DeepCopy()
	desired.Status.Message = "participant left"
	err := ApplyDebugSessionStatus(context.Background(), fakeClient, desired)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired active session")

	terminal := session.DeepCopy()
	terminal.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	require.NoError(t, ApplyDebugSessionStatus(context.Background(), fakeClient, terminal))
}

func TestApplyDebugSessionStatusRejectsStaleFullSnapshot(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "stale-apply", Namespace: "default", ResourceVersion: "2"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:   breakglassv1alpha1.DebugSessionStateActive,
			Message: "newer controller update",
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	stale := live.DeepCopy()
	stale.ResourceVersion = "1"
	stale.Status.Message = "stale snapshot"

	err := ApplyDebugSessionStatus(context.Background(), fakeClient, stale)
	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	var stored breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), client.ObjectKeyFromObject(live), &stored))
	assert.Equal(t, "newer controller update", stored.Status.Message)
}

func TestPatchDebugSessionStatusWithOptimisticLockLeavesInputUnchangedOnConflict(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	live := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "debug-session",
			Namespace:       "default",
			ResourceVersion: "2",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			Message: "live",
		},
	}
	stale := live.DeepCopy()
	stale.ResourceVersion = "1"
	stale.Status.Message = "stale"

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(live).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	err := PatchDebugSessionStatusWithOptimisticLock(context.Background(), fakeClient, stale, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.Message = "mutated"
	})

	require.Error(t, err)
	assert.True(t, apierrors.IsConflict(err))
	assert.Equal(t, "stale", stale.Status.Message)

	var fetched breakglassv1alpha1.DebugSession
	require.NoError(t, fakeClient.Get(context.Background(), types.NamespacedName{Name: "debug-session", Namespace: "default"}, &fetched))
	assert.Equal(t, "live", fetched.Status.Message)
}
