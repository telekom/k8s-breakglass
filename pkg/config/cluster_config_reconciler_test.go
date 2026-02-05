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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newTestClusterConfigReconcilerScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	return scheme
}

// newTestClusterConfigFakeClient creates a fake client with the required indexes for testing
func newTestClusterConfigFakeClient(scheme *runtime.Scheme, objs ...client.Object) client.Client {
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}, &breakglassv1alpha1.DebugSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "spec.cluster", func(obj client.Object) []string {
			if s, ok := obj.(*breakglassv1alpha1.BreakglassSession); ok && s.Spec.Cluster != "" {
				return []string{s.Spec.Cluster}
			}
			return nil
		}).
		WithIndex(&breakglassv1alpha1.DebugSession{}, "spec.cluster", func(obj client.Object) []string {
			if s, ok := obj.(*breakglassv1alpha1.DebugSession); ok && s.Spec.Cluster != "" {
				return []string{s.Spec.Cluster}
			}
			return nil
		})
	return builder.Build()
}

func TestClusterConfigReconciler_NotFound(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	fakeClient := newTestClusterConfigFakeClient(scheme)
	logger := zap.NewNop().Sugar()

	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    logger,
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestClusterConfigReconciler_AddsFinalizer(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
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

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify finalizer was added
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	require.NoError(t, err)
	assert.Contains(t, updated.Finalizers, ClusterConfigFinalizer)
}

func TestClusterConfigReconciler_SkipsIfFinalizerExists(t *testing.T) {
	scheme := newTestClusterConfigReconcilerScheme()
	ctx := context.Background()

	clusterConfig := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-cluster",
			Namespace:  "default",
			Finalizers: []string{ClusterConfigFinalizer},
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

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify finalizer is still there (no change)
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	require.NoError(t, err)
	assert.Contains(t, updated.Finalizers, ClusterConfigFinalizer)
	assert.Len(t, updated.Finalizers, 1)
}

func TestClusterConfigReconciler_DeleteWithoutSessions(t *testing.T) {
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

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// When finalizer is removed from an object with DeletionTimestamp,
	// the fake client automatically deletes the object
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	assert.True(t, apierrors.IsNotFound(err), "ClusterConfig should be deleted after finalizer removal")
}

func TestClusterConfigReconciler_DeleteTerminatesBreakglassSessions(t *testing.T) {
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

	// Create sessions in different states
	pendingSession := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test-user@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	approvedSession := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "approved-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test-user2@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	// Session for different cluster - should NOT be terminated
	otherClusterSession := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-cluster-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "other-cluster",
			User:    "test-user3@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	// Already expired session - should be skipped
	expiredSession := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "expired-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test-user4@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateExpired,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme,
		clusterConfig, pendingSession, approvedSession, otherClusterSession, expiredSession)
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
	assert.Equal(t, reconcile.Result{}, result)

	// Verify pending session was terminated (expired)
	var pending breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "pending-session", Namespace: "default"}, &pending)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, pending.Status.State)

	// Verify approved session was terminated (expired)
	var approved breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "approved-session", Namespace: "default"}, &approved)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, approved.Status.State)

	// Verify other cluster session was NOT touched
	var other breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "other-cluster-session", Namespace: "default"}, &other)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStatePending, other.Status.State)

	// Verify already expired session state unchanged
	var expired breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "expired-session", Namespace: "default"}, &expired)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, expired.Status.State)

	// When finalizer is removed from an object with DeletionTimestamp,
	// the fake client automatically deletes the object
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	assert.True(t, apierrors.IsNotFound(err), "ClusterConfig should be deleted after finalizer removal")
}

func TestClusterConfigReconciler_DeleteTerminatesDebugSessions(t *testing.T) {
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

	// Create debug sessions in different states
	activeDebugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "active-debug",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
		},
	}

	pendingDebugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pending-debug",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStatePending,
		},
	}

	// Session for different cluster - should NOT be terminated
	otherClusterDebug := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-cluster-debug",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "other-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
		},
	}

	// Already failed session - should be skipped
	failedDebugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "failed-debug",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateFailed,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme,
		clusterConfig, activeDebugSession, pendingDebugSession, otherClusterDebug, failedDebugSession)
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
	assert.Equal(t, reconcile.Result{}, result)

	// Verify active debug session was terminated (failed)
	var active breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "active-debug", Namespace: "default"}, &active)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, active.Status.State)
	assert.Contains(t, active.Status.Message, "ClusterConfig")
	assert.Contains(t, active.Status.Message, "deleted")

	// Verify pending debug session was terminated (failed)
	var pending breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "pending-debug", Namespace: "default"}, &pending)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, pending.Status.State)

	// Verify other cluster session was NOT touched
	var other breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "other-cluster-debug", Namespace: "default"}, &other)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateActive, other.Status.State)

	// Verify already failed session state unchanged
	var failed breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "failed-debug", Namespace: "default"}, &failed)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, failed.Status.State)
}

func TestClusterConfigReconciler_DeleteTerminatesBothSessionTypes(t *testing.T) {
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

	breakglassSession := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bg-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "test-user@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	debugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "debug-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
		},
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, breakglassSession, debugSession)
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
	assert.Equal(t, reconcile.Result{}, result)

	// Verify breakglass session was terminated
	var bg breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "bg-session", Namespace: "default"}, &bg)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, bg.Status.State)

	// Verify debug session was terminated
	var debug breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "debug-session", Namespace: "default"}, &debug)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, debug.Status.State)

	// When finalizer is removed from an object with DeletionTimestamp,
	// the fake client automatically deletes the object
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	assert.True(t, apierrors.IsNotFound(err), "ClusterConfig should be deleted after finalizer removal")
}

func TestClusterConfigReconciler_SkipsTerminalStates(t *testing.T) {
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

	// Test all terminal states for BreakglassSession
	terminalStates := []struct {
		name  string
		state breakglassv1alpha1.BreakglassSessionState
	}{
		{"expired", breakglassv1alpha1.SessionStateExpired},
		{"rejected", breakglassv1alpha1.SessionStateRejected},
		{"withdrawn", breakglassv1alpha1.SessionStateWithdrawn},
		{"timeout", breakglassv1alpha1.SessionStateTimeout},
	}

	var sessions []client.Object
	sessions = append(sessions, clusterConfig)

	for _, ts := range terminalStates {
		sessions = append(sessions, &breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ts.name + "-session",
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster: "test-cluster",
				User:    "user-" + ts.name + "@example.com",
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: ts.state,
			},
		})
	}

	// Add debug sessions in terminal states
	debugTerminalStates := []struct {
		name  string
		state breakglassv1alpha1.DebugSessionState
	}{
		{"debug-failed", breakglassv1alpha1.DebugSessionStateFailed},
		{"debug-terminated", breakglassv1alpha1.DebugSessionStateTerminated},
		{"debug-expired", breakglassv1alpha1.DebugSessionStateExpired},
	}

	for _, ts := range debugTerminalStates {
		sessions = append(sessions, &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ts.name,
				Namespace: "default",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: ts.state,
			},
		})
	}

	fakeClient := newTestClusterConfigFakeClient(scheme, sessions...)
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
	assert.Equal(t, reconcile.Result{}, result)

	// Verify all sessions maintain their original terminal state
	for _, ts := range terminalStates {
		var session breakglassv1alpha1.BreakglassSession
		err = fakeClient.Get(ctx, types.NamespacedName{Name: ts.name + "-session", Namespace: "default"}, &session)
		require.NoError(t, err, "Failed to get session %s", ts.name)
		assert.Equal(t, ts.state, session.Status.State, "Session %s should keep original state", ts.name)
	}

	for _, ts := range debugTerminalStates {
		var session breakglassv1alpha1.DebugSession
		err = fakeClient.Get(ctx, types.NamespacedName{Name: ts.name, Namespace: "default"}, &session)
		require.NoError(t, err, "Failed to get debug session %s", ts.name)
		assert.Equal(t, ts.state, session.Status.State, "Debug session %s should keep original state", ts.name)
	}

	// When finalizer is removed from an object with DeletionTimestamp,
	// the fake client automatically deletes the object
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	assert.True(t, apierrors.IsNotFound(err), "ClusterConfig should be deleted after finalizer removal")
}

// Note: TestClusterConfigReconciler_DeleteWithoutFinalizer is not possible to test with
// the fake client because it panics when creating objects with DeletionTimestamp but no finalizers.
// In real Kubernetes, this scenario could theoretically happen if the finalizer was somehow
// not added, but the reconciler handles it gracefully by doing nothing.

func TestClusterConfigReconciler_MultipleNamespaces(t *testing.T) {
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

	// Sessions in different namespaces for the same cluster
	session1 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-ns1",
			Namespace: "namespace1",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "user1@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	session2 := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "session-ns2",
			Namespace: "namespace2",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "test-cluster",
			User:    "user2@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
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

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify both sessions from different namespaces were terminated
	var s1 breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-ns1", Namespace: "namespace1"}, &s1)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, s1.Status.State)

	var s2 breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "session-ns2", Namespace: "namespace2"}, &s2)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateExpired, s2.Status.State)
}

// TestClusterConfigReconciler_CleanupFailureBlocksDeletion tests that when session listing
// fails, the finalizer is NOT removed and deletion is blocked with a requeue.
// This ensures the ClusterConfig cannot be deleted until all sessions are properly cleaned up.
// Note: Individual session update failures are logged but don't block deletion (best-effort cleanup).
func TestClusterConfigReconciler_CleanupFailureBlocksDeletion(t *testing.T) {
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

	// Create a client that fails List operations to simulate cleanup failure
	listError := errors.New("simulated list failure")
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterConfig).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}, &breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				// Fail List operations for BreakglassSessions to simulate cleanup failure
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
	// (deletion should be blocked because cleanup failed)
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	require.NoError(t, err, "ClusterConfig should still exist because cleanup failed")
	assert.Contains(t, updated.Finalizers, ClusterConfigFinalizer, "Finalizer should still be present")
}

// TestClusterConfigReconciler_DebugSessionCleanupFailureBlocksDeletion tests that when DebugSession
// listing fails, the finalizer is NOT removed and deletion is blocked.
func TestClusterConfigReconciler_DebugSessionCleanupFailureBlocksDeletion(t *testing.T) {
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

	// Create a client that fails List operations for DebugSessions to simulate cleanup failure
	listError := errors.New("simulated debug session list failure")
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clusterConfig).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}, &breakglassv1alpha1.DebugSession{}).
		WithIndex(&breakglassv1alpha1.BreakglassSession{}, "spec.cluster", func(obj client.Object) []string {
			if s, ok := obj.(*breakglassv1alpha1.BreakglassSession); ok && s.Spec.Cluster != "" {
				return []string{s.Spec.Cluster}
			}
			return nil
		}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, client client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				// Fail List operations for DebugSessions to simulate cleanup failure
				if _, ok := list.(*breakglassv1alpha1.DebugSessionList); ok {
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
	assert.ErrorContains(t, err, "simulated debug session list failure")
	assert.Equal(t, 10*time.Second, result.RequeueAfter)

	// Verify the ClusterConfig still exists with its finalizer
	var updated breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updated)
	require.NoError(t, err, "ClusterConfig should still exist because cleanup failed")
	assert.Contains(t, updated.Finalizers, ClusterConfigFinalizer, "Finalizer should still be present")
}
