package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestNewDebugSessionTemplateReconciler(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	assert.NotNil(t, r)
	assert.Equal(t, fakeClient, r.client)
	assert.Equal(t, logger, r.logger)
}

func TestDebugSessionTemplateReconciler_Reconcile_ValidTemplate(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Create the pod template that will be referenced
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-pod-template",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Test Pod Template",
		},
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-template",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "Test Template",
			Description:  "A test template",
			Mode:         breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
				Name: "test-pod-template",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(template, podTemplate).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionTemplate{}).
		Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-template"},
	}

	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	updated := &breakglassv1alpha1.DebugSessionTemplate{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check Ready condition
	readyCond := apimeta.FindStatusCondition(updated.Status.Conditions, DebugSessionTemplateConditionReady)
	require.NotNil(t, readyCond, "Ready condition should be set")
	assert.Equal(t, metav1.ConditionTrue, readyCond.Status)
	assert.Equal(t, "Ready", readyCond.Reason)
	assert.Equal(t, int64(1), updated.Status.ObservedGeneration)
	assert.True(t, updated.Status.PodTemplateResolved)
}

func TestDebugSessionTemplateReconciler_Reconcile_WithValidPodTemplateRef(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-pod-template",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			DisplayName: "Test Pod Template",
		},
	}

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-template",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "Test Template",
			Mode:         breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
				Name: "test-pod-template",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(podTemplate, sessionTemplate).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionTemplate{}, &breakglassv1alpha1.DebugPodTemplate{}).
		Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-template"},
	}

	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	updated := &breakglassv1alpha1.DebugSessionTemplate{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check Ready condition
	readyCond := apimeta.FindStatusCondition(updated.Status.Conditions, DebugSessionTemplateConditionReady)
	require.NotNil(t, readyCond, "Ready condition should be set")
	assert.Equal(t, metav1.ConditionTrue, readyCond.Status)

	// Check PodTemplateRefValid condition
	podRefCond := apimeta.FindStatusCondition(updated.Status.Conditions, DebugSessionTemplateConditionPodTemplateValid)
	require.NotNil(t, podRefCond, "PodTemplateRefValid condition should be set")
	assert.Equal(t, metav1.ConditionTrue, podRefCond.Status)
	assert.Equal(t, "PodTemplateFound", podRefCond.Reason)
}

func TestDebugSessionTemplateReconciler_Reconcile_WithMissingPodTemplateRef(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-template",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:  "Test Template",
			Mode:         breakglassv1alpha1.DebugSessionModeWorkload,
			WorkloadType: breakglassv1alpha1.DebugWorkloadDaemonSet,
			PodTemplateRef: &breakglassv1alpha1.DebugPodTemplateReference{
				Name: "nonexistent-pod-template",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sessionTemplate).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionTemplate{}).
		Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-template"},
	}

	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	updated := &breakglassv1alpha1.DebugSessionTemplate{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check PodTemplateRefValid condition - should be false
	podRefCond := apimeta.FindStatusCondition(updated.Status.Conditions, DebugSessionTemplateConditionPodTemplateValid)
	require.NotNil(t, podRefCond, "PodTemplateRefValid condition should be set")
	assert.Equal(t, metav1.ConditionFalse, podRefCond.Status)
	assert.Equal(t, "PodTemplateNotFound", podRefCond.Reason)
	assert.False(t, updated.Status.PodTemplateResolved)
}

func TestDebugSessionTemplateReconciler_Reconcile_BindingStatusFields(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-template",
			Generation: 3,
			Labels: map[string]string{
				"tier": "standard",
			},
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Test Template",
			Mode:        breakglassv1alpha1.DebugSessionModeKubectlDebug,
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled: true,
				},
			},
		},
	}
	explicitBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "explicit-binding", Namespace: "team-a"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "test-template"},
			Clusters:    []string{"cluster-a"},
		},
	}
	selectorBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "selector-binding", Namespace: "team-b"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"tier": "standard"},
			},
			ClusterSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}
	disabledBinding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-binding", Namespace: "team-c"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "test-template"},
			Clusters:    []string{"cluster-disabled"},
			Disabled:    true,
		},
	}
	clusterA := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-a", Namespace: "default", Labels: map[string]string{"env": "dev"}},
	}
	clusterB := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-b", Namespace: "default", Labels: map[string]string{"env": "prod"}},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sessionTemplate, explicitBinding, selectorBinding, disabledBinding, clusterA, clusterB).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionTemplate{}).
		Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "test-template"}}
	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	updated := &breakglassv1alpha1.DebugSessionTemplate{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	assert.Equal(t, int64(3), updated.Status.ObservedGeneration)
	assert.True(t, updated.Status.PodTemplateResolved)
	assert.Equal(t, int32(2), updated.Status.BindingCount)
	assert.ElementsMatch(t, []string{"cluster-a", "cluster-b"}, updated.Status.BoundClusters)
}

func TestDebugSessionTemplateReconciler_TemplatesForBindingSkipsDisabledBinding(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()
	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-binding"},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &breakglassv1alpha1.TemplateReference{Name: "test-template"},
			Disabled:    true,
		},
	}

	requests := r.templatesForBinding(context.Background(), binding)
	assert.Empty(t, requests)
}

func TestDebugSessionTemplateReconciler_Reconcile_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	}

	result, err := r.Reconcile(ctx, req)

	// Should not return error for not found
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestDebugSessionTemplateReconciler_Reconcile_NoPodTemplateRef(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Template without PodTemplateRef - uses KubectlDebug mode which doesn't require it
	sessionTemplate := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "kubectl-debug-template",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Kubectl Debug Template",
			Mode:        breakglassv1alpha1.DebugSessionModeKubectlDebug,
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled: true,
				},
			},
			// No PodTemplateRef - valid for KubectlDebug mode
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sessionTemplate).
		WithStatusSubresource(&breakglassv1alpha1.DebugSessionTemplate{}).
		Build()

	r := NewDebugSessionTemplateReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "kubectl-debug-template"},
	}

	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	updated := &breakglassv1alpha1.DebugSessionTemplate{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check Ready condition
	readyCond := apimeta.FindStatusCondition(updated.Status.Conditions, DebugSessionTemplateConditionReady)
	require.NotNil(t, readyCond, "Ready condition should be set")
	assert.Equal(t, metav1.ConditionTrue, readyCond.Status)

	// Check PodTemplateRefValid condition - should NOT be set since no ref specified
	podRefCond := apimeta.FindStatusCondition(updated.Status.Conditions, DebugSessionTemplateConditionPodTemplateValid)
	assert.Nil(t, podRefCond, "PodTemplateRefValid condition should not be set when no ref specified")
}
