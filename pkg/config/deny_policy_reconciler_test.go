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

func TestNewDenyPolicyReconciler(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewDenyPolicyReconciler(fakeClient, logger)

	assert.NotNil(t, r)
	assert.Equal(t, fakeClient, r.client)
	assert.Equal(t, logger, r.logger)
}

func TestDenyPolicyReconciler_Reconcile_ValidPolicy(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	precedence := int32(100)
	policy := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Generation: 1,
		},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			Precedence: &precedence,
			Rules: []breakglassv1alpha1.DenyRule{
				{
					Verbs:     []string{"get", "list"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(&breakglassv1alpha1.DenyPolicy{}).
		Build()

	r := NewDenyPolicyReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-policy"},
	}

	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	updated := &breakglassv1alpha1.DenyPolicy{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check ObservedGeneration
	assert.Equal(t, int64(1), updated.Status.ObservedGeneration)

	// Check Ready condition
	readyCond := apimeta.FindStatusCondition(updated.Status.Conditions, DenyPolicyConditionReady)
	require.NotNil(t, readyCond, "Ready condition should be set")
	assert.Equal(t, metav1.ConditionTrue, readyCond.Status)
	assert.Equal(t, "Ready", readyCond.Reason)
	assert.Equal(t, int64(1), readyCond.ObservedGeneration)

	// Check Valid condition
	validCond := apimeta.FindStatusCondition(updated.Status.Conditions, DenyPolicyConditionValid)
	require.NotNil(t, validCond, "Valid condition should be set")
	assert.Equal(t, metav1.ConditionTrue, validCond.Status)
	assert.Equal(t, "ValidationSucceeded", validCond.Reason)
}

func TestDenyPolicyReconciler_Reconcile_EmptyRules(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	precedence := int32(50)
	policy := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "empty-policy",
			Generation: 2,
		},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			Precedence: &precedence,
			Rules:      []breakglassv1alpha1.DenyRule{}, // Empty rules are valid
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(&breakglassv1alpha1.DenyPolicy{}).
		Build()

	r := NewDenyPolicyReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "empty-policy"},
	}

	result, err := r.Reconcile(ctx, req)

	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	updated := &breakglassv1alpha1.DenyPolicy{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Empty rules should still be valid
	readyCond := apimeta.FindStatusCondition(updated.Status.Conditions, DenyPolicyConditionReady)
	require.NotNil(t, readyCond)
	assert.Equal(t, metav1.ConditionTrue, readyCond.Status)
}

func TestDenyPolicyReconciler_Reconcile_NotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	r := NewDenyPolicyReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	}

	result, err := r.Reconcile(ctx, req)

	// Should not return error for not found (handled gracefully)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestDenyPolicyReconciler_ObservedGenerationUpdates(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)

	precedence := int32(100)
	policy := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "gen-test",
			Generation: 5,
		},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			Precedence: &precedence,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(&breakglassv1alpha1.DenyPolicy{}).
		Build()

	r := NewDenyPolicyReconciler(fakeClient, logger)

	ctx := context.Background()
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "gen-test"},
	}

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	updated := &breakglassv1alpha1.DenyPolicy{}
	err = fakeClient.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// ObservedGeneration should match spec generation
	assert.Equal(t, int64(5), updated.Status.ObservedGeneration)

	// Condition's ObservedGeneration should also match
	readyCond := apimeta.FindStatusCondition(updated.Status.Conditions, DenyPolicyConditionReady)
	require.NotNil(t, readyCond)
	assert.Equal(t, int64(5), readyCond.ObservedGeneration)
}

func TestDenyPolicyReconciler_ValidatePolicy(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	r := NewDenyPolicyReconciler(fakeClient, logger)

	tests := []struct {
		name      string
		policy    *breakglassv1alpha1.DenyPolicy
		wantError bool
	}{
		{
			name: "valid policy with rules",
			policy: &breakglassv1alpha1.DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "valid"},
				Spec: breakglassv1alpha1.DenyPolicySpec{
					Rules: []breakglassv1alpha1.DenyRule{
						{
							Verbs:     []string{"get", "list"},
							APIGroups: []string{""},
							Resources: []string{"pods"},
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid empty policy",
			policy: &breakglassv1alpha1.DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "empty"},
				Spec: breakglassv1alpha1.DenyPolicySpec{
					Rules: []breakglassv1alpha1.DenyRule{},
				},
			},
			wantError: false,
		},
		{
			name: "rule with subresources",
			policy: &breakglassv1alpha1.DenyPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "with-subresources"},
				Spec: breakglassv1alpha1.DenyPolicySpec{
					Rules: []breakglassv1alpha1.DenyRule{
						{
							Verbs:        []string{"create"},
							APIGroups:    []string{""},
							Resources:    []string{"pods"},
							Subresources: []string{"exec", "attach"},
						},
					},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.validatePolicy(tt.policy)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
