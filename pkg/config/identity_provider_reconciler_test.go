package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrltest "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newTestScheme creates a scheme with v1alpha1 types registered for testing
func newTestScheme(t *testing.T) *runtime.Scheme {
	scheme := runtime.NewScheme()
	err := v1alpha1.AddToScheme(scheme)
	require.NoError(t, err, "failed to add v1alpha1 to scheme")
	return scheme
}

// TestIdentityProviderReconciler_NewCreation tests reconciler creation
func TestIdentityProviderReconciler_NewCreation(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := ctrltest.NewFakeClient()
	reloadFn := func(ctx context.Context) error {
		return nil
	}

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	require.NotNil(t, reconciler)
	assert.Equal(t, 10*time.Minute, reconciler.resyncPeriod)
	assert.NotNil(t, reconciler.client)
	assert.NotNil(t, reconciler.logger)
	assert.NotNil(t, reconciler.onReload)
}

// TestIdentityProviderReconciler_WithErrorHandler tests error handler builder
func TestIdentityProviderReconciler_WithErrorHandler(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := ctrltest.NewFakeClient()
	reloadFn := func(ctx context.Context) error { return nil }

	errorCallCount := 0
	errorFn := func(ctx context.Context, err error) {
		errorCallCount++
	}

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn).
		WithErrorHandler(errorFn)

	require.NotNil(t, reconciler.onError)
	reconciler.onError(context.Background(), fmt.Errorf("test error"))
	assert.Equal(t, 1, errorCallCount)
}

// TestIdentityProviderReconciler_WithResyncPeriod tests resync period configuration
func TestIdentityProviderReconciler_WithResyncPeriod(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := ctrltest.NewFakeClient()
	reloadFn := func(ctx context.Context) error { return nil }

	customPeriod := 5 * time.Minute
	reconciler := NewIdentityProviderReconciler(client, log, reloadFn).
		WithResyncPeriod(customPeriod)

	assert.Equal(t, customPeriod, reconciler.resyncPeriod)
}

// TestIdentityProviderReconciler_ReconcileSuccess tests successful reconciliation
func TestIdentityProviderReconciler_ReconcileSuccess(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	// Create a test IdentityProvider
	idp := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: v1alpha1.IdentityProviderSpec{
			OIDC: v1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
		},
	}

	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(idp).WithStatusSubresource(idp).Build()
	reloadCalled := false
	reloadFn := func(ctx context.Context) error {
		reloadCalled = true
		return nil
	}

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: "test-idp",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)

	assert.NoError(t, err)
	assert.Equal(t, 10*time.Minute, result.RequeueAfter)
	assert.True(t, reloadCalled)
}

// TestIdentityProviderReconciler_ReconcileNotFound tests reconciliation when IDP doesn't exist
func TestIdentityProviderReconciler_ReconcileNotFound(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)
	client := ctrltest.NewClientBuilder().WithScheme(scheme).Build()
	reloadCalled := false
	reloadFn := func(ctx context.Context) error {
		reloadCalled = true
		return nil
	}

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: "nonexistent-idp",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)

	// Should handle gracefully - not found is not an error
	assert.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
	// Reload should NOT be called if IDP doesn't exist
	assert.False(t, reloadCalled)
}

// TestIdentityProviderReconciler_ReconcileReloadError tests handling of reload errors
func TestIdentityProviderReconciler_ReconcileReloadError(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	idp := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: v1alpha1.IdentityProviderSpec{
			OIDC: v1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
		},
	}

	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(idp).WithStatusSubresource(idp).Build()
	reloadErr := fmt.Errorf("reload failed")
	reloadFn := func(ctx context.Context) error {
		return reloadErr
	}

	errorCallCount := 0
	reconciler := NewIdentityProviderReconciler(client, log, reloadFn).
		WithErrorHandler(func(ctx context.Context, err error) {
			errorCallCount++
		})

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: "test-idp",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)

	// Should return error and requeue
	assert.Error(t, err)
	assert.Equal(t, reloadErr, err)
	assert.Equal(t, 30*time.Second, result.RequeueAfter)
	assert.Equal(t, 1, errorCallCount)
}

// TestIdentityProviderReconciler_ReconcileWithMultipleIDPs tests that only specified IDP is reconciled
func TestIdentityProviderReconciler_ReconcileWithMultipleIDPs(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	idp1 := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "idp-1",
		},
		Spec: v1alpha1.IdentityProviderSpec{
			OIDC: v1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Primary: true,
		},
	}

	idp2 := &v1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "idp-2",
		},
		Spec: v1alpha1.IdentityProviderSpec{
			OIDC: v1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Primary: false,
		},
	}

	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(idp1, idp2).WithStatusSubresource(idp1, idp2).Build()
	reloadCalls := 0
	reloadFn := func(ctx context.Context) error {
		reloadCalls++
		return nil
	}

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	// Request reconciliation of idp-1
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: "idp-1",
		},
	}

	_, err := reconciler.Reconcile(context.Background(), req)

	assert.NoError(t, err)
	assert.Equal(t, 1, reloadCalls)

	// Request reconciliation of idp-2
	req2 := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name: "idp-2",
		},
	}

	_, err = reconciler.Reconcile(context.Background(), req2)

	assert.NoError(t, err)
	assert.Equal(t, 2, reloadCalls)
}

// TestIdentityProviderReconciler_NilLogger tests handling of nil logger
func TestIdentityProviderReconciler_NilLogger(t *testing.T) {
	client := ctrltest.NewFakeClient()
	reloadFn := func(ctx context.Context) error { return nil }

	// Should not panic with nil logger
	reconciler := NewIdentityProviderReconciler(client, nil, reloadFn)

	require.NotNil(t, reconciler)
	assert.NotNil(t, reconciler.logger)
}
