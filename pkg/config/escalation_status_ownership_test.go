// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestEscalationOwnerPatchInterleaving(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	ready := string(breakglassv1alpha1.BreakglassEscalationConditionReady)
	group := string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved)
	initial := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: "default", UID: "original", Generation: 4}}
	desired := initial.DeepCopy()
	desired.Status.ObservedGeneration = 4
	desired.Status.Conditions = []metav1.Condition{{Type: ready, Status: metav1.ConditionTrue, Reason: "ValidationComplete", ObservedGeneration: 4}}
	calls := 0
	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initial).WithObjects(initial).WithInterceptorFuncs(interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, raw client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			calls++
			if calls == 1 {
				// Another owner writes after this writer's fresh read but before its patch.
				live := &breakglassv1alpha1.BreakglassEscalation{}
				require.NoError(t, raw.Get(ctx, client.ObjectKeyFromObject(initial), live))
				live.Status.ApproverGroupMembers = map[string][]string{"ops": {"alice"}}
				live.Status.IDPGroupMemberships = map[string]map[string][]string{"idp": {"ops": {"alice"}}}
				live.Status.Conditions = []metav1.Condition{{Type: group, Status: metav1.ConditionTrue, Reason: "GroupSyncComplete", ObservedGeneration: 4}}
				require.NoError(t, raw.Status().Update(ctx, live))
			}
			return raw.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	require.True(t, apierrors.IsConflict((&EscalationReconciler{client: cli}).applyStatus(ctx, desired)))
	require.NoError(t, (&EscalationReconciler{client: cli}).applyStatus(ctx, desired))
	require.Equal(t, 2, calls)
	got := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(initial), got))
	require.Equal(t, int64(4), got.Status.ObservedGeneration)
	require.True(t, got.IsReady())
	require.Equal(t, "ValidationComplete", apimeta.FindStatusCondition(got.Status.Conditions, ready).Reason)
	require.Equal(t, "GroupSyncComplete", apimeta.FindStatusCondition(got.Status.Conditions, group).Reason)
	require.Equal(t, map[string][]string{"ops": {"alice"}}, got.Status.ApproverGroupMembers)
	require.Equal(t, map[string]map[string][]string{"idp": {"ops": {"alice"}}}, got.Status.IDPGroupMemberships)
}

func TestEscalationOwnerPatchRejectsChangedIdentity(t *testing.T) {
	for _, changed := range []string{"uid", "generation"} {
		t.Run(changed, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			live := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: "default", UID: "original", Generation: 4}}
			desired := live.DeepCopy()
			if changed == "uid" {
				desired.UID = "replaced"
			} else {
				desired.Generation--
			}
			writes := 0
			cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(live).WithObjects(live).WithInterceptorFuncs(interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, raw client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					writes++
					return raw.SubResource(sub).Patch(ctx, obj, patch, opts...)
				},
			}).Build()
			require.Error(t, (&EscalationReconciler{client: cli}).applyStatus(ctx, desired))
			require.Zero(t, writes)
		})
	}
}

func TestEscalationValidationFailureStatusConflictRequeues(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	initial := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "default", UID: "original", Generation: 4}}
	initial.Spec.MaxValidFor = "not-duration"
	initial.Status.ApproverGroupMembers = map[string][]string{"ops": {"alice"}}
	initial.Status.Conditions = []metav1.Condition{{Type: string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved), Status: metav1.ConditionTrue, Reason: "GroupSyncComplete", ObservedGeneration: 4}}
	writes := 0
	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initial).WithObjects(initial).WithInterceptorFuncs(interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, raw client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			writes++
			if writes == 1 {
				return apierrors.NewConflict(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "breakglassescalations"}, obj.GetName(), fmt.Errorf("concurrent status write"))
			}
			return raw.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	r := NewEscalationReconciler(cli, zap.NewNop().Sugar(), nil, nil, nil, 0)
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(initial)}
	_, err := r.Reconcile(ctx, req)
	require.True(t, apierrors.IsConflict(err), "status conflict must be returned for reconciliation retry: %v", err)
	got := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, cli.Get(ctx, req.NamespacedName, got))
	require.Nil(t, apimeta.FindStatusCondition(got.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionReady)))
	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)
	require.NoError(t, cli.Get(ctx, req.NamespacedName, got))
	require.Equal(t, 2, writes)
	require.Equal(t, int64(4), got.Status.ObservedGeneration)
	for _, typ := range []breakglassv1alpha1.BreakglassEscalationConditionType{breakglassv1alpha1.BreakglassEscalationConditionReady, breakglassv1alpha1.BreakglassEscalationConditionConfigValidated} {
		condition := apimeta.FindStatusCondition(got.Status.Conditions, string(typ))
		require.NotNil(t, condition)
		require.Equal(t, metav1.ConditionFalse, condition.Status)
		require.Equal(t, int64(4), condition.ObservedGeneration)
	}
	require.Equal(t, map[string][]string{"ops": {"alice"}}, got.Status.ApproverGroupMembers)
	require.Equal(t, "GroupSyncComplete", apimeta.FindStatusCondition(got.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved)).Reason)
}
