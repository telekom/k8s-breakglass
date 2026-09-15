// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
	wrapped := interceptor.NewClient(base, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
		called = true
		require.Equal(t, "status", sub)
		u := obj.(*unstructured.Unstructured)
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

	debug := &breakglassv1alpha1.DebugSessionStatus{Approval: &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "approver", ApprovedByIdentityProvider: "provider-a"}, Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "owner", IdentityProviderName: "provider-a", IdentityProviderIssuer: "https://a.example"}}}
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
			wrapped := interceptor.NewClient(base, interceptor.Funcs{SubResourcePatch: func(_ context.Context, _ client.Client, _ string, obj client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				called = true
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
