// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// Exercise the production SSA conversion and request payload, then persist its
// status via the fake API. This checks read-back, not just the source Go object.
func TestIdentityProvenanceSurvivesStatusApply(t *testing.T) {
	ctx := context.Background()
	original := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"}}
	base := fake.NewClientBuilder().WithScheme(newPatchTestScheme()).WithStatusSubresource(original).WithObjects(original).Build()
	desired := &breakglassv1alpha1.BreakglassSession{}
	require.NoError(t, base.Get(ctx, client.ObjectKeyFromObject(original), desired))
	desired.Status = breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved, Approver: "a", ApproverIdentityProvider: "provider-a", Approvers: []string{"legacy", "a"}, ApproverIdentityProviders: []string{"", "provider-a"}}
	called := false
	wrapped := interceptor.NewClient(base, interceptor.Funcs{SubResourceApply: func(ctx context.Context, c client.Client, sub string, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
		called = true
		require.Equal(t, "status", sub)
		data, err := json.Marshal(obj)
		require.NoError(t, err)
		u := &unstructured.Unstructured{}
		require.NoError(t, json.Unmarshal(data, u))
		raw, err := json.Marshal(u.Object["status"])
		require.NoError(t, err)
		stored := &breakglassv1alpha1.BreakglassSession{}
		require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(original), stored))
		require.NoError(t, json.Unmarshal(raw, &stored.Status))
		return c.Status().Update(ctx, stored)
	}})
	require.NoError(t, ApplyBreakglassSessionStatus(ctx, wrapped, desired))
	require.True(t, called)
	stored := &breakglassv1alpha1.BreakglassSession{}
	require.NoError(t, base.Get(ctx, client.ObjectKeyFromObject(original), stored))
	require.Equal(t, desired.Status.ApproverIdentityProvider, stored.Status.ApproverIdentityProvider)
	require.Equal(t, desired.Status.ApproverIdentityProviders, stored.Status.ApproverIdentityProviders)

	debug := &breakglassv1alpha1.DebugSessionStatus{Approval: &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "approver", ApprovedByIdentityProvider: "provider-a", ApprovedByIdentities: []string{"approver", "approver@example.com", "oidc:approver"}, ApprovedByIdentitiesIncomplete: true}, Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "owner", Subject: "owner-sub", IdentityProviderName: "provider-a", IdentityProviderIssuer: "https://a.example"}}}
	// Round-trip the same explicit converter used by both controller SSA paths.
	raw, err := json.Marshal(DebugSessionStatusFrom(debug))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, debug.Approval, restored.Approval)
	require.Equal(t, debug.Participants, restored.Participants)
}

func TestSessionStatusApplyPreservesOriginalVersionAcrossCompetingWriter(t *testing.T) {
	for _, patchHelper := range []bool{false, true} {
		t.Run(map[bool]string{false: "apply", true: "patch-apply"}[patchHelper], func(t *testing.T) {
			ctx := context.Background()
			latest := &breakglassv1alpha1.BreakglassSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default", ResourceVersion: "11"}, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateWithdrawn}}
			base := fake.NewClientBuilder().WithScheme(newPatchTestScheme()).WithStatusSubresource(latest).WithObjects(latest).Build()
			stale := latest.DeepCopy()
			stale.ResourceVersion = "10"
			stale.Status.State = breakglassv1alpha1.SessionStateApproved
			called := false
			wrapped := interceptor.NewClient(base, interceptor.Funcs{SubResourceApply: func(_ context.Context, _ client.Client, _ string, config runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
				called = true
				obj := config.(client.Object)
				require.Equal(t, "10", obj.GetResourceVersion(), "later read must not replace original predecessor version")
				return apierrors.NewConflict(breakglassv1alpha1.GroupVersion.WithResource("breakglasssessions").GroupResource(), obj.GetName(), nil)
			}})
			var err error
			if patchHelper {
				_, err = PatchApplyBreakglassSessionStatus(ctx, wrapped, stale)
			} else {
				err = ApplyBreakglassSessionStatus(ctx, wrapped, stale)
			}
			require.True(t, called)
			require.True(t, apierrors.IsConflict(err), err)
			after := &breakglassv1alpha1.BreakglassSession{}
			require.NoError(t, base.Get(ctx, client.ObjectKeyFromObject(latest), after))
			require.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, after.Status.State)
		})
	}
}

// TestDebugSessionStatusRoundTripsCleanupAcknowledgementFields round-trips
// every DebugSession status field the cleanup acknowledgement feature added,
// so the SSA converter cannot silently drop one (#1665).
func TestDebugSessionStatusRoundTripsCleanupAcknowledgementFields(t *testing.T) {
	processedAt := metav1.NewTime(time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC).Local()) // JSON decoding yields local time
	status := &breakglassv1alpha1.DebugSessionStatus{
		Approval: &breakglassv1alpha1.DebugSessionApproval{
			Required: true, ApprovedBy: "approver", ApprovedByIdentityProvider: "provider-a",
			ApprovedByIdentities: []string{"approver", "approver@example.com"}, ApprovedByIdentitiesIncomplete: true,
		},
		CleanupAcknowledgements: []breakglassv1alpha1.DebugSessionCleanupAcknowledgementStatus{{
			Name: "ack", UID: "ack-uid", AcknowledgedBy: "operator", Reason: "CHG-1", Applied: true, Message: "applied",
			ProcessedAt: processedAt,
			Retired: []breakglassv1alpha1.CleanupAcknowledgedIdentity{
				{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "cm", UID: "cm-uid"},
				{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole", Name: "unresolved-intent"},
			},
		}},
		Conditions: []metav1.Condition{{
			Type: string(breakglassv1alpha1.DebugSessionConditionCleanupComplete), Status: metav1.ConditionTrue,
			Reason: "NoTrackedResources", Message: "done", LastTransitionTime: processedAt,
		}},
	}
	raw, err := json.Marshal(DebugSessionStatusFrom(status))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, status.Approval, restored.Approval)
	require.Equal(t, status.CleanupAcknowledgements, restored.CleanupAcknowledgements)
	require.Equal(t, status.Conditions, restored.Conditions)
}
