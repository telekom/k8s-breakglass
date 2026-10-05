// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestEscalationValidationPreservesGroupWriter(t *testing.T) {
	apiClient := ssatest.Start(t)
	obj := ssatest.Escalation(t, apiClient, "validation")
	desired := obj.DeepCopy()
	desired.Status.ObservedGeneration = desired.Generation
	desired.Status.Conditions = []metav1.Condition{{
		Type:   string(breakglassv1alpha1.BreakglassEscalationConditionReady),
		Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.Now(),
	}}
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := obj.DeepCopy()
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(obj), live))
			live.Status.ApproverGroupMembers = map[string][]string{"admins": {"approver@example.com"}}
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	reconciler := &EscalationReconciler{client: c}
	// This helper returns conflicts to its caller; it does not retry internally.
	require.True(t, apierrors.IsConflict(reconciler.applyStatus(t.Context(), desired)))
	require.NoError(t, reconciler.applyStatus(t.Context(), desired))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
	require.Equal(t, []string{"approver@example.com"}, obj.Status.ApproverGroupMembers["admins"])
	require.Equal(t, metav1.ConditionTrue, apimeta.FindStatusCondition(obj.Status.Conditions, "Ready").Status)
	// Current helper still sends an empty merge patch on an unchanged status.
	require.NoError(t, reconciler.applyStatus(t.Context(), desired))
	require.EqualValues(t, 3, c.StatusPatches.Load())
	desired.Generation++
	require.ErrorContains(t, reconciler.applyStatus(t.Context(), desired), "changed while updating")
	require.EqualValues(t, 3, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), obj))
	require.True(t, apierrors.IsNotFound(reconciler.applyStatus(t.Context(), desired)))
}

func TestSSAEnvtestClusterDeletionDebugStatusRetry(t *testing.T) {
	apiClient := ssatest.Start(t)
	obj := ssatest.DebugSession(t, apiClient, "cluster-deletion")
	obj.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{Constraints: &breakglassv1alpha1.DebugSessionConstraints{RetainFor: "1h"}}
	require.NoError(t, apiClient.Status().Update(t.Context(), obj))
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := obj.DeepCopy()
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(obj), live))
			live.Status.ActivityCount = 4
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	r := &ClusterConfigReconciler{Client: c}
	require.NoError(t, r.terminateDebugSessionsForCluster(t.Context(), "spoke", zap.NewNop().Sugar()))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, obj.Status.State)
	require.EqualValues(t, 4, obj.Status.ActivityCount)
	require.NotNil(t, obj.Status.RetainedUntil)
	require.NoError(t, r.terminateDebugSessionsForCluster(t.Context(), "spoke", zap.NewNop().Sugar()))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), obj))
	require.NoError(t, r.terminateDebugSessionsForCluster(t.Context(), "spoke", zap.NewNop().Sugar()))
}

func TestSSAEnvtestClusterConfigFinalizerApply(t *testing.T) {
	apiClient := ssatest.Start(t)
	obj := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "finalizer", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kubeconfig", Namespace: "default"},
		},
	}
	require.NoError(t, apiClient.Create(t.Context(), obj))
	c := &ssatest.CountingClient{Client: apiClient}
	r := &ClusterConfigReconciler{Client: c, Log: zap.NewNop().Sugar()}
	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	require.NoError(t, err)
	require.EqualValues(t, 1, c.Applies.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
	require.Contains(t, obj.Finalizers, ClusterConfigFinalizer)
	require.Equal(t, "kubeconfig", obj.Spec.KubeconfigSecretRef.Name)
	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	require.NoError(t, err)
	require.EqualValues(t, 1, c.Applies.Load())
}
