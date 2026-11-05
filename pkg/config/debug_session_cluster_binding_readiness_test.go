// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestClusterBindingEmptySelectionReadiness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*breakglassv1alpha1.DebugSessionClusterBinding)
		ready  bool
		reason string
	}{
		{name: "no cluster matches", ready: true, reason: "NoClustersMatched"},
		{name: "no template matches", ready: true, reason: "NoClustersMatched", mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
			b.Spec.TemplateRef = nil
			b.Spec.TemplateSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"catalogue": "optional"}}
		}},
		{name: "missing explicit cluster", reason: "ResolutionFailed", mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) { b.Spec.Clusters = []string{"missing"} }},
		{name: "missing explicit template", reason: "NoClustersMatched", mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) { b.Spec.TemplateRef.Name = "missing" }},
		{name: "invalid configuration", reason: "NoClustersMatched", mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) { b.Spec.TemplateRef = nil }},
		{name: "invalid selector", reason: "ResolutionFailed", mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
			b.Spec.ClusterSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "stage", Operator: "invalid"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, scheme := newTestClusterBindingReconciler()
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "diagnostics"}}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default", Generation: 2},
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					TemplateRef:     &breakglassv1alpha1.TemplateReference{Name: template.Name},
					ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "prd"}},
				},
			}
			if tc.mutate != nil {
				tc.mutate(binding)
			}
			r.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, template).WithStatusSubresource(binding).Build()
			_, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(binding)})
			require.NoError(t, err)
			require.NoError(t, r.client.Get(t.Context(), client.ObjectKeyFromObject(binding), binding))
			require.Equal(t, tc.ready, apimeta.IsStatusConditionTrue(binding.Status.Conditions, "Ready"))
			condition := apimeta.FindStatusCondition(binding.Status.Conditions, "ClustersResolved")
			require.NotNil(t, condition)
			require.Equal(t, tc.reason, condition.Reason)
			require.Equal(t, binding.Generation, binding.Status.ObservedGeneration)
			require.Empty(t, binding.Status.ResolvedClusters)
			if tc.name == "no template matches" {
				condition := apimeta.FindStatusCondition(binding.Status.Conditions, "TemplateResolved")
				require.NotNil(t, condition)
				require.Equal(t, metav1.ConditionTrue, condition.Status)
				require.Equal(t, "NoTemplatesMatched", condition.Reason)
				require.Empty(t, binding.Status.ResolvedTemplates)
			}
		})
	}
}

func TestClusterBindingSelectionClearsStaleReferences(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "diagnostics", Labels: map[string]string{"catalogue": "optional"}}}
	cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", Labels: map[string]string{"stage": "prd"}}}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"catalogue": "optional"}},
			ClusterSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "prd"}},
		},
	}
	r.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, template, cluster).WithStatusSubresource(binding).Build()
	reconcileBinding := func() {
		t.Helper()
		_, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(binding)})
		require.NoError(t, err)
		require.NoError(t, r.client.Get(t.Context(), client.ObjectKeyFromObject(binding), binding))
		require.True(t, apimeta.IsStatusConditionTrue(binding.Status.Conditions, "Ready"))
	}
	reconcileBinding()
	require.Equal(t, []breakglassv1alpha1.ResolvedTemplateRef{{Name: template.Name}}, binding.Status.ResolvedTemplates)
	require.Equal(t, []breakglassv1alpha1.ResolvedClusterRef{{Name: cluster.Name, MatchedBy: "selector"}}, binding.Status.ResolvedClusters)
	require.NoError(t, r.client.Delete(t.Context(), template))
	require.NoError(t, r.client.Delete(t.Context(), cluster))
	reconcileBinding()
	require.Empty(t, binding.Status.ResolvedTemplates)
	require.Empty(t, binding.Status.ResolvedClusters)
}
