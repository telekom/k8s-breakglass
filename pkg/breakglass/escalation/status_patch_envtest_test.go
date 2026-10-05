// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestGroupSyncRetriesPreservingValidation(t *testing.T) {
	apiClient := ssatest.Start(t)
	obj := ssatest.Escalation(t, apiClient, "group-sync")
	desired := obj.DeepCopy()
	desired.Status.ApproverGroupMembers = map[string][]string{"admins": {"approver@example.com"}}
	c := &ssatest.CountingClient{Client: apiClient}
	var once sync.Once
	c.BeforeStatusPatch = func(ctx context.Context, _ client.Object) {
		once.Do(func() {
			live := obj.DeepCopy()
			require.NoError(t, apiClient.Get(ctx, client.ObjectKeyFromObject(obj), live))
			live.Status.ObservedGeneration = live.Generation
			live.Status.Conditions = []metav1.Condition{{
				Type:   string(breakglassv1alpha1.BreakglassEscalationConditionReady),
				Status: metav1.ConditionTrue, Reason: "Valid", LastTransitionTime: metav1.Now(),
			}}
			require.NoError(t, apiClient.Status().Update(ctx, live))
		})
	}
	updater := EscalationStatusUpdater{K8sClient: c}
	require.NoError(t, updater.patchStatus(t.Context(), desired))
	require.EqualValues(t, 2, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
	require.Equal(t, []string{"approver@example.com"}, obj.Status.ApproverGroupMembers["admins"])
	require.Equal(t, "Ready", obj.Status.Conditions[0].Type)
	require.Equal(t, obj.Generation, obj.Status.ObservedGeneration)
	require.NoError(t, updater.patchStatus(t.Context(), desired))
	require.EqualValues(t, 3, c.StatusPatches.Load())
	desired.Generation++
	require.ErrorContains(t, updater.patchStatus(t.Context(), desired), "changed while updating")
	require.EqualValues(t, 3, c.StatusPatches.Load())
	require.NoError(t, apiClient.Delete(t.Context(), obj))
	require.True(t, apierrors.IsNotFound(updater.patchStatus(t.Context(), desired)))
}
