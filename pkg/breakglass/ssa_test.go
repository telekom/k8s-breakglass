package breakglass

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
