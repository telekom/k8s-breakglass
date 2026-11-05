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

type bindingConditionExpectation struct {
	status metav1.ConditionStatus
	reason string
}

func requireBindingCondition(t *testing.T, binding *breakglassv1alpha1.DebugSessionClusterBinding, conditionType string, want bindingConditionExpectation) {
	t.Helper()
	condition := apimeta.FindStatusCondition(binding.Status.Conditions, conditionType)
	require.NotNilf(t, condition, "condition %s is missing: %#v", conditionType, binding.Status.Conditions)
	require.Equalf(t, want.status, condition.Status, "condition %s status", conditionType)
	require.Equalf(t, want.reason, condition.Reason, "condition %s reason", conditionType)
}

func TestClusterBindingEmptySelectionReadiness(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(*breakglassv1alpha1.DebugSessionClusterBinding)
		ready      bool
		template   bindingConditionExpectation
		clusters   bindingConditionExpectation
		validation bindingConditionExpectation
	}{
		{
			name:       "no cluster matches",
			ready:      true,
			template:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "TemplatesResolved"},
			clusters:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "NoClustersMatched"},
			validation: bindingConditionExpectation{status: metav1.ConditionTrue, reason: "Valid"},
		},
		{
			name:  "no template matches",
			ready: true,
			mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
				b.Spec.TemplateRef = nil
				b.Spec.TemplateSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"catalogue": "optional"}}
			},
			template:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "NoTemplatesMatched"},
			clusters:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "NoClustersMatched"},
			validation: bindingConditionExpectation{status: metav1.ConditionTrue, reason: "Valid"},
		},
		{
			name:  "missing explicit cluster",
			ready: false,
			mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
				b.Spec.Clusters = []string{"missing"}
			},
			template:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "TemplatesResolved"},
			clusters:   bindingConditionExpectation{status: metav1.ConditionFalse, reason: "ResolutionFailed"},
			validation: bindingConditionExpectation{status: metav1.ConditionTrue, reason: "Valid"},
		},
		{
			name:  "missing explicit template",
			ready: false,
			mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
				b.Spec.TemplateRef.Name = "missing"
			},
			template:   bindingConditionExpectation{status: metav1.ConditionFalse, reason: "ResolutionFailed"},
			clusters:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "NoClustersMatched"},
			validation: bindingConditionExpectation{status: metav1.ConditionTrue, reason: "Valid"},
		},
		{
			name:  "invalid configuration",
			ready: false,
			mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
				b.Spec.TemplateRef = nil
			},
			template:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "NoTemplatesMatched"},
			clusters:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "NoClustersMatched"},
			validation: bindingConditionExpectation{status: metav1.ConditionFalse, reason: "ValidationFailed"},
		},
		{
			name:  "invalid selector",
			ready: false,
			mutate: func(b *breakglassv1alpha1.DebugSessionClusterBinding) {
				b.Spec.ClusterSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "stage", Operator: "invalid"}}}
			},
			template:   bindingConditionExpectation{status: metav1.ConditionTrue, reason: "TemplatesResolved"},
			clusters:   bindingConditionExpectation{status: metav1.ConditionFalse, reason: "ResolutionFailed"},
			validation: bindingConditionExpectation{status: metav1.ConditionFalse, reason: "ValidationFailed"},
		},
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

			require.Equal(t, tc.ready, apimeta.IsStatusConditionTrue(binding.Status.Conditions, string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady)))
			requireBindingCondition(t, binding, string(breakglassv1alpha1.DebugSessionClusterBindingConditionTemplateResolved), tc.template)
			requireBindingCondition(t, binding, string(breakglassv1alpha1.DebugSessionClusterBindingConditionClustersResolved), tc.clusters)
			requireBindingCondition(t, binding, string(breakglassv1alpha1.DebugSessionClusterBindingConditionValid), tc.validation)
			require.Equal(t, binding.Generation, binding.Status.ObservedGeneration)
			require.Empty(t, binding.Status.ResolvedClusters)
			if tc.template.reason == "NoTemplatesMatched" {
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
	}
	reconcileBinding()
	require.True(t, apimeta.IsStatusConditionTrue(binding.Status.Conditions, string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady)))
	require.Equal(t, []breakglassv1alpha1.ResolvedTemplateRef{{Name: template.Name}}, binding.Status.ResolvedTemplates)
	require.Equal(t, []breakglassv1alpha1.ResolvedClusterRef{{Name: cluster.Name, MatchedBy: "selector"}}, binding.Status.ResolvedClusters)

	// When the last selector match disappears, the resolved lists are cleared and
	// the binding remains ready because the selectors themselves are still valid.
	require.NoError(t, r.client.Delete(t.Context(), template))
	require.NoError(t, r.client.Delete(t.Context(), cluster))
	reconcileBinding()
	require.True(t, apimeta.IsStatusConditionTrue(binding.Status.Conditions, string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady)))
	require.Empty(t, binding.Status.ResolvedTemplates)
	require.Empty(t, binding.Status.ResolvedClusters)
}

func TestClusterBindingResolutionErrorRetainsLastKnownReferences(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "diagnostics"}}
	cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default"}}
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:    []string{cluster.Name},
		},
	}
	r.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding, template, cluster).WithStatusSubresource(binding).Build()
	reconcileBinding := func() {
		t.Helper()
		_, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(binding)})
		require.NoError(t, err)
		require.NoError(t, r.client.Get(t.Context(), client.ObjectKeyFromObject(binding), binding))
	}
	reconcileBinding()
	require.True(t, apimeta.IsStatusConditionTrue(binding.Status.Conditions, string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady)))
	require.Equal(t, []breakglassv1alpha1.ResolvedClusterRef{{Name: cluster.Name, MatchedBy: "explicit"}}, binding.Status.ResolvedClusters)

	// A missing explicit reference is an error. The last known list is kept so a
	// transient API/cache error does not flap the status, but Ready is false.
	require.NoError(t, r.client.Delete(t.Context(), cluster))
	reconcileBinding()
	require.False(t, apimeta.IsStatusConditionTrue(binding.Status.Conditions, string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady)))
	requireBindingCondition(t, binding, string(breakglassv1alpha1.DebugSessionClusterBindingConditionClustersResolved), bindingConditionExpectation{status: metav1.ConditionFalse, reason: "ResolutionFailed"})
	require.Equal(t, []breakglassv1alpha1.ResolvedClusterRef{{Name: cluster.Name, MatchedBy: "explicit"}}, binding.Status.ResolvedClusters)

	// Switching to a valid selector that matches nothing clears the stale list.
	binding.Spec.Clusters = nil
	binding.Spec.ClusterSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"stage": "prd"}}
	require.NoError(t, r.client.Update(t.Context(), binding))
	reconcileBinding()
	require.True(t, apimeta.IsStatusConditionTrue(binding.Status.Conditions, string(breakglassv1alpha1.DebugSessionClusterBindingConditionReady)))
	require.Empty(t, binding.Status.ResolvedClusters)
}
