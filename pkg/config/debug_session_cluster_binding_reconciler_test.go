/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestClusterBindingReconciler() (*DebugSessionClusterBindingReconciler, *runtime.Scheme) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	logger := zap.NewNop().Sugar()

	return &DebugSessionClusterBindingReconciler{
		logger: logger,
	}, scheme
}

func TestDebugSessionClusterBindingReconciler_Reconcile_NotFound(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()
	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	ctx := context.Background()
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "non-existent",
			Namespace: "test-ns",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestDebugSessionClusterBindingReconciler_Reconcile_TemplateRefValid(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	// Create a template
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-template",
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
		},
		Status: breakglassv1alpha1.DebugSessionTemplateStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	// Create a cluster config
	cluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "test-cluster",
		},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	// Create the binding
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "test-ns",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: "test-template",
			},
			Clusters: []string{"test-cluster"},
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template, cluster, binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionClusterBinding{}).
		Build()

	ctx := context.Background()
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	var updated breakglassv1alpha1.DebugSessionClusterBinding
	err = r.client.Get(ctx, types.NamespacedName{Name: "test-binding", Namespace: "test-ns"}, &updated)
	require.NoError(t, err)

	// Check resolved templates
	require.Len(t, updated.Status.ResolvedTemplates, 1)
	assert.Equal(t, "test-template", updated.Status.ResolvedTemplates[0].Name)
	assert.True(t, updated.Status.ResolvedTemplates[0].Ready)

	// Check resolved clusters
	require.Len(t, updated.Status.ResolvedClusters, 1)
	assert.Equal(t, "test-cluster", updated.Status.ResolvedClusters[0].Name)
	assert.True(t, updated.Status.ResolvedClusters[0].Ready)
	assert.Equal(t, "explicit", updated.Status.ResolvedClusters[0].MatchedBy)
}

func TestDebugSessionClusterBindingReconciler_Reconcile_TemplateNotFound(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "test-ns",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: "non-existent-template",
			},
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionClusterBinding{}).
		Build()

	ctx := context.Background()
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
	})

	// Should not return an error, just update status
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestDebugSessionClusterBindingReconciler_Reconcile_ClusterNotFound(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionTemplateStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "test-ns",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: "test-template",
			},
			Clusters: []string{"non-existent-cluster"},
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template, binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionClusterBinding{}).
		Build()

	ctx := context.Background()
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
	})

	// Should not return an error, just update status
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestDebugSessionClusterBindingReconciler_Reconcile_TemplateSelector(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	// Create templates with labels
	template1 := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template-1",
			Labels: map[string]string{
				"tier": "standard",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Template 1",
		},
		Status: breakglassv1alpha1.DebugSessionTemplateStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	template2 := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template-2",
			Labels: map[string]string{
				"tier": "standard",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Template 2",
		},
		Status: breakglassv1alpha1.DebugSessionTemplateStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	template3 := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "template-3",
			Labels: map[string]string{
				"tier": "premium", // Different label, should not match
			},
		},
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "test-ns",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"tier": "standard",
				},
			},
			DisplayNamePrefix: "[Test] ",
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template1, template2, template3, binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionClusterBinding{}).
		Build()

	ctx := context.Background()
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	var updated breakglassv1alpha1.DebugSessionClusterBinding
	err = r.client.Get(ctx, types.NamespacedName{Name: "test-binding", Namespace: "test-ns"}, &updated)
	require.NoError(t, err)

	// Should have matched 2 templates (template-1 and template-2)
	require.Len(t, updated.Status.ResolvedTemplates, 2)

	// Verify display name prefix was applied
	names := make(map[string]string)
	for _, t := range updated.Status.ResolvedTemplates {
		names[t.Name] = t.DisplayName
	}
	assert.Equal(t, "[Test] Template 1", names["template-1"])
	assert.Equal(t, "[Test] Template 2", names["template-2"])
}

func TestDebugSessionClusterBindingReconciler_Reconcile_ClusterSelector(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-template",
		},
		Status: breakglassv1alpha1.DebugSessionTemplateStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	// Create clusters with labels
	cluster1 := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-1",
			Labels: map[string]string{
				"env": "production",
			},
		},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	cluster2 := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-2",
			Labels: map[string]string{
				"env": "production",
			},
		},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionFalse},
			},
		},
	}

	cluster3 := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-3",
			Labels: map[string]string{
				"env": "staging", // Should not match
			},
		},
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-binding",
			Namespace:  "test-ns",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{
				Name: "test-template",
			},
			ClusterSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"env": "production",
				},
			},
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template, cluster1, cluster2, cluster3, binding).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionClusterBinding{}).
		Build()

	ctx := context.Background()
	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	var updated breakglassv1alpha1.DebugSessionClusterBinding
	err = r.client.Get(ctx, types.NamespacedName{Name: "test-binding", Namespace: "test-ns"}, &updated)
	require.NoError(t, err)

	// Should have matched 2 clusters (cluster-1 and cluster-2)
	require.Len(t, updated.Status.ResolvedClusters, 2)

	// Verify cluster states
	clusterStates := make(map[string]bool)
	for _, c := range updated.Status.ResolvedClusters {
		clusterStates[c.Name] = c.Ready
		assert.Equal(t, "selector", c.MatchedBy)
	}
	assert.True(t, clusterStates["cluster-1"])
	assert.False(t, clusterStates["cluster-2"])
}

func TestDebugSessionClusterBindingReconciler_ResolveTemplates_EmptyResult(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"non-existent": "label",
				},
			},
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(binding).
		Build()

	ctx := context.Background()
	resolved, err := r.resolveTemplates(ctx, binding)

	require.NoError(t, err)
	assert.Empty(t, resolved)
}

func TestDebugSessionClusterBindingReconciler_ResolveClusters_DeduplicatesExplicitAndSelector(t *testing.T) {
	r, scheme := newTestClusterBindingReconciler()

	cluster := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "shared-cluster",
			Labels: map[string]string{
				"env": "test",
			},
		},
		Status: breakglassv1alpha1.ClusterConfigStatus{
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}

	// Binding references same cluster both explicitly and via selector
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-binding",
			Namespace: "test-ns",
		},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			Clusters: []string{"shared-cluster"},
			ClusterSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"env": "test",
				},
			},
		},
	}

	r.client = fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cluster, binding).
		Build()

	ctx := context.Background()
	resolved, err := r.resolveClusters(ctx, binding)

	require.NoError(t, err)
	// Should only appear once (deduplicated)
	require.Len(t, resolved, 1)
	assert.Equal(t, "shared-cluster", resolved[0].Name)
	assert.Equal(t, "explicit", resolved[0].MatchedBy) // Explicit takes precedence
}
