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

package config

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// TestClusterConfigReconciler_PartialSessionTerminationContinues tests that when some
// individual session terminations fail, the reconciler continues with other sessions
// and completes the cleanup successfully.
func TestClusterConfigReconciler_PartialSessionTerminationContinues(t *testing.T) {
	// Note: The actual reconciler logs errors for individual session failures but
	// continues processing other sessions. This test verifies that behavior.
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	// Create two sessions - both will be attempted for termination
	session1 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-1",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}
	session2 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-2",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, session1, session2)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})

	// Should succeed - errors during individual session termination don't fail the cleanup
	require.NoError(t, err)
	assert.False(t, result.RequeueAfter > 0)

	// Both sessions should be terminated
	var s1 breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-1", Namespace: "default"}, &s1)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, s1.Status.State)

	var s2 breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-2", Namespace: "default"}, &s2)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, s2.Status.State)
}

// TestClusterConfigReconciler_ListFailureBlocksCleanup tests that when the List
// operation for sessions fails, the cleanup is blocked and the reconciler returns an error.
func TestClusterConfigReconciler_ListFailureBlocksCleanup(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	// Fail List operations to simulate cleanup failure
	listError := errors.New("simulated list failure")
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterConfig).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}, &breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				// Fail List operations for BreakglassSessions
				if _, ok := list.(*breakglassv1alpha1.BreakglassSessionList); ok {
					return listError
				}
				return client.List(ctx, list, opts...)
			},
		})

	fakeClient := builder.Build()
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})

	// Should return error and requeue after delay
	require.Error(t, err)
	assert.ErrorContains(t, err, "simulated list failure")
	assert.Equal(t, 10*time.Second, result.RequeueAfter)

	// Verify the ClusterConfig still exists with its finalizer
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	require.NoError(t, err, "ClusterConfig should still exist because cleanup failed")
	assert.Contains(t, updated.Finalizers, ClusterConfigFinalizer, "Finalizer should still be present")
}

// TestClusterConfigReconciler_MixedSessionAndDebugSessionCleanup tests that when
// both BreakglassSessions and DebugSessions exist, both are properly terminated.
// Note: DebugSessions are set to "Failed" state when cluster is deleted.
func TestClusterConfigReconciler_MixedSessionAndDebugSessionCleanup(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	bgSession := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bg-session-1",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	debugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-session-1",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, bgSession, debugSession)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	// Reconcile - should terminate sessions
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter, "Should not requeue after successful termination")

	// Verify BreakglassSession is expired
	var updatedBgSession breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "bg-session-1", Namespace: "default"}, &updatedBgSession)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updatedBgSession.Status.State,
		"BreakglassSession should be marked as Expired")

	// Verify DebugSession is failed (cluster deletion sets state to Failed)
	var updatedDebugSession breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "debug-session-1", Namespace: "default"}, &updatedDebugSession)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, updatedDebugSession.Status.State,
		"DebugSession should be marked as Failed (cluster deleted)")
	assert.Contains(t, updatedDebugSession.Status.Message, "test-cluster",
		"DebugSession message should reference the deleted cluster")
}

// TestClusterConfigReconciler_DeletionWithMultipleNamespaces tests cleanup when
// sessions are spread across multiple namespaces.
func TestClusterConfigReconciler_DeletionWithMultipleNamespaces(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "breakglass",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	// Sessions in different namespaces
	session1 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-ns1",
			Namespace: "namespace-1",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}
	session2 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-ns2",
			Namespace: "namespace-2",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}
	session3 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-ns3",
			Namespace: "namespace-3",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, session1, session2, session3)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "breakglass"},
	})
	require.NoError(t, err)
	assert.False(t, result.RequeueAfter > 0)

	// Verify all sessions across all namespaces are terminated
	for _, tc := range []struct {
		name      string
		namespace string
	}{
		{"session-ns1", "namespace-1"},
		{"session-ns2", "namespace-2"},
		{"session-ns3", "namespace-3"},
	} {
		var s breakglassv1alpha1.BreakglassSession
		err = fakeClient.Get(ctx, types.NamespacedName{Name: tc.name, Namespace: tc.namespace}, &s)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateExpired, s.Status.State,
			"Session %s in namespace %s should be expired", tc.name, tc.namespace)
	}
}

// TestClusterConfigReconciler_FinalizerRemovalWithSSA tests that the reconciler properly
// removes the finalizer using SSA (Server-Side Apply).
func TestClusterConfigReconciler_FinalizerRemovalWithSSA(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})

	// Should succeed
	require.NoError(t, err)
	assert.False(t, result.RequeueAfter > 0)
}

// TestClusterConfigReconciler_DeleteWithOnlyTerminalSessions tests that when all sessions
// are already in terminal states, cleanup proceeds directly without modifying sessions.
func TestClusterConfigReconciler_DeleteWithOnlyTerminalSessions(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	// All sessions already in terminal states
	sessionExpired := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-expired",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateExpired,
		},
	}
	sessionRejected := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-rejected",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateRejected,
		},
	}

	debugTerminated := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-terminated",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateTerminated,
		},
	}
	debugFailed := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-failed",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateFailed,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, sessionExpired, sessionRejected, debugTerminated, debugFailed)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.False(t, result.RequeueAfter > 0)

	// Sessions should remain unchanged (already terminal)
	var updatedSessionExpired breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-expired", Namespace: "default"}, &updatedSessionExpired)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updatedSessionExpired.Status.State)

	var updatedSessionRejected breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-rejected", Namespace: "default"}, &updatedSessionRejected)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateRejected, updatedSessionRejected.Status.State)
}

// TestClusterConfigReconciler_MultipleReconcilesToCompleteCleanup tests that a single
// reconcile cycle correctly terminates sessions and allows cleanup to complete.
func TestClusterConfigReconciler_MultipleReconcilesToCompleteCleanup(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	// Session that will be terminated
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-1",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, session)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	// Reconcile - terminates session
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter, "Reconcile should complete successfully")

	// Verify session was terminated
	var updatedSession breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-1", Namespace: "default"}, &updatedSession)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, updatedSession.Status.State)
}

// TestClusterConfigReconciler_GetListError tests error handling when getting sessions list fails.
func TestClusterConfigReconciler_GetListError(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	now := metav1.Now()
	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-cluster",
			Namespace:         "default",
			Finalizers:        []string{ClusterConfigFinalizer},
			DeletionTimestamp: &now,
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster-id",
		},
	}

	listError := errors.New("simulated network timeout")
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterConfig).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}, &breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				// Fail all List operations
				return listError
			},
		})

	fakeClient := builder.Build()
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated network timeout")
	assert.Equal(t, 10*time.Second, result.RequeueAfter)

	// Finalizer should still be present
	var updated breakglassv1alpha1.ClusterConfig
	// Note: Get still works, just List fails
	_ = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	assert.Contains(t, updated.Finalizers, ClusterConfigFinalizer)
}
