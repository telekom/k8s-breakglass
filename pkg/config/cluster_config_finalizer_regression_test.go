// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"testing"
)

func TestReviewDeleteBlocksWhenExpiredDebugSessionTracksResources(t *testing.T) {
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
		Spec: breakglassv1alpha1.ClusterConfigSpec{ClusterID: "test-cluster-id"},
	}
	failedDebugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-debug", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateExpired,
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       "debug-pod",
				Namespace:  "default",
				UID:        "original-uid",
			}},
		},
	}
	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, failedDebugSession)
	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    zap.NewNop().Sugar(),
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})
	require.ErrorContains(t, err, "still tracks spoke resources")
	assert.Equal(t, reconcile.Result{}, result)

	var updatedCluster breakglassv1alpha1.ClusterConfig
	require.NoError(t, fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updatedCluster))
	assert.Contains(t, updatedCluster.Finalizers, ClusterConfigFinalizer)
}

func TestReviewDeleteBlocksWhenTerminatedDebugSessionTracksResources(t *testing.T) {
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
		Spec: breakglassv1alpha1.ClusterConfigSpec{ClusterID: "test-cluster-id"},
	}
	failedDebugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-debug", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateTerminated,
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       "debug-pod",
				Namespace:  "default",
				UID:        "original-uid",
			}},
		},
	}
	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, failedDebugSession)
	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    zap.NewNop().Sugar(),
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})
	require.ErrorContains(t, err, "still tracks spoke resources")
	assert.Equal(t, reconcile.Result{}, result)

	var updatedCluster breakglassv1alpha1.ClusterConfig
	require.NoError(t, fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updatedCluster))
	assert.Contains(t, updatedCluster.Finalizers, ClusterConfigFinalizer)
}

func TestReviewDeleteBlocksWhenActiveDebugSessionTracksResources(t *testing.T) {
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
		Spec: breakglassv1alpha1.ClusterConfigSpec{ClusterID: "test-cluster-id"},
	}
	failedDebugSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "failed-debug", Namespace: "default"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			DeployedResources: []breakglassv1alpha1.DeployedResourceRef{{
				APIVersion: "v1",
				Kind:       "Pod",
				Name:       "debug-pod",
				Namespace:  "default",
				UID:        "original-uid",
			}},
		},
	}
	fakeClient := newTestClusterConfigFakeClient(scheme, clusterConfig, failedDebugSession)
	r := &ClusterConfigReconciler{
		Client: fakeClient,
		Scheme: scheme,
		Log:    zap.NewNop().Sugar(),
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-cluster", Namespace: "default"},
	})
	require.ErrorContains(t, err, "still tracks spoke resources")
	assert.Equal(t, reconcile.Result{}, result)

	var updatedCluster breakglassv1alpha1.ClusterConfig
	require.NoError(t, fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &updatedCluster))
	assert.Contains(t, updatedCluster.Finalizers, ClusterConfigFinalizer)
}
