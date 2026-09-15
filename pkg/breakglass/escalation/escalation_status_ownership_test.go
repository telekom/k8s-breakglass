// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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
	desired.Status.ApproverGroupMembers = map[string][]string{"ops": {"alice"}}
	desired.Status.IDPGroupMemberships = map[string]map[string][]string{"idp": {"ops": {"alice"}}}
	desired.Status.Conditions = []metav1.Condition{{Type: group, Status: metav1.ConditionTrue, Reason: "GroupSyncComplete", ObservedGeneration: 4}}
	calls := 0
	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initial).WithObjects(initial).WithInterceptorFuncs(interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, raw client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			calls++
			if calls == 1 {
				// Another owner writes after this writer's fresh read but before its patch.
				live := &breakglassv1alpha1.BreakglassEscalation{}
				require.NoError(t, raw.Get(ctx, client.ObjectKeyFromObject(initial), live))
				live.Status.ObservedGeneration = 4
				live.Status.Conditions = []metav1.Condition{{Type: ready, Status: metav1.ConditionTrue, Reason: "ValidationComplete", ObservedGeneration: 4}}
				require.NoError(t, raw.Status().Update(ctx, live))
			}
			return raw.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	require.NoError(t, (EscalationStatusUpdater{K8sClient: cli}).patchStatus(ctx, desired))
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
			require.Error(t, (EscalationStatusUpdater{K8sClient: cli}).patchStatus(ctx, desired))
			require.Zero(t, writes)
		})
	}
}

func TestEscalationGroupRunOncePreservesConcurrentValidation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	initial := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: "default", UID: "original", Generation: 4}}
	lists := 0
	cli := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(initial).WithObjects(initial).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, raw client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if err := raw.List(ctx, list, opts...); err != nil {
				return err
			}
			if _, ok := list.(*breakglassv1alpha1.BreakglassEscalationList); ok {
				lists++
				// Keep the returned list stale while validation finishes in persistent state.
				live := &breakglassv1alpha1.BreakglassEscalation{}
				require.NoError(t, raw.Get(ctx, client.ObjectKeyFromObject(initial), live))
				live.Status.ObservedGeneration = 4
				live.Status.Conditions = []metav1.Condition{{Type: string(breakglassv1alpha1.BreakglassEscalationConditionReady), Status: metav1.ConditionTrue, Reason: "ValidationComplete", ObservedGeneration: 4}}
				require.NoError(t, raw.Status().Update(ctx, live))
			}
			return nil
		},
	}).Build()
	(EscalationStatusUpdater{K8sClient: cli}).runOnce(ctx, zap.NewNop().Sugar())
	require.Equal(t, 1, lists)
	got := &breakglassv1alpha1.BreakglassEscalation{}
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(initial), got))
	require.True(t, got.IsReady())
	require.Equal(t, int64(4), got.Status.ObservedGeneration)
	condition := apimeta.FindStatusCondition(got.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionApprovalGroupMembersResolved))
	require.NotNil(t, condition)
	require.Equal(t, "NoApproverGroupsConfigured", condition.Reason)
}
