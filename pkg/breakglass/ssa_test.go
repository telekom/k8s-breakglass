package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
