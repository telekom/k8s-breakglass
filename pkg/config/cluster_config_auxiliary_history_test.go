// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestReviewFinalizerReleasesCompletedAuxiliaryHistory(t *testing.T) {
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
			State:                     breakglassv1alpha1.DebugSessionStateExpired,
			AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "completed", Created: true, Deleted: true, UID: "old", AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{UID: "child", Deleted: true}}}},
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
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

}
