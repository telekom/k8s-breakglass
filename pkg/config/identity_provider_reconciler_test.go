package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrltest "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newTestScheme creates a scheme with v1alpha1 types registered for testing
func newTestScheme(t *testing.T) *runtime.Scheme {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err, "failed to add v1alpha1 to scheme")
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err, "failed to add corev1 to scheme")
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
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
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

	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
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

	// Should return error (controller-runtime handles exponential backoff automatically)
	assert.Error(t, err)
	assert.Equal(t, reloadErr, err)
	assert.Equal(t, time.Duration(0), result.RequeueAfter, "RequeueAfter should be 0 when returning error (controller-runtime handles backoff)")
	assert.Equal(t, 1, errorCallCount)
}

// TestIdentityProviderReconciler_ReconcileWithMultipleIDPs tests that only specified IDP is reconciled
func TestIdentityProviderReconciler_ReconcileWithMultipleIDPs(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	idp1 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "idp-1",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Primary: true,
		},
	}

	idp2 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "idp-2",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
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

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_NoProvider(t *testing.T) {
	reconciler := NewIdentityProviderReconciler(ctrltest.NewFakeClient(), zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{}
	idp.SetCondition(metav1.Condition{Type: string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy)})

	reconciler.updateGroupSyncHealth(context.Background(), idp)

	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	assert.Nil(t, condition)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_UnknownProvider(t *testing.T) {
	reconciler := NewIdentityProviderReconciler(ctrltest.NewFakeClient(), zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: "unknown",
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "UnknownProvider", condition.Reason)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_KeycloakMissing(t *testing.T) {
	reconciler := NewIdentityProviderReconciler(ctrltest.NewFakeClient(), zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "KeycloakMissing", condition.Reason)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_KeycloakIncomplete(t *testing.T) {
	reconciler := NewIdentityProviderReconciler(ctrltest.NewFakeClient(), zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				BaseURL:  "",
				Realm:    "realm",
				ClientID: "client",
			},
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "KeycloakIncomplete", condition.Reason)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_ClientSecretRefMissing(t *testing.T) {
	reconciler := NewIdentityProviderReconciler(ctrltest.NewFakeClient(), zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				BaseURL:  "https://kc.example.com",
				Realm:    "realm",
				ClientID: "client",
			},
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "ClientSecretRefInvalid", condition.Reason)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_SecretNotFound(t *testing.T) {
	scheme := newTestScheme(t)
	client := ctrltest.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := NewIdentityProviderReconciler(client, zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				BaseURL:  "https://kc.example.com",
				Realm:    "realm",
				ClientID: "client",
				ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
					Name:      "missing-secret",
					Namespace: "default",
				},
			},
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "SecretNotFound", condition.Reason)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_SecretKeyMissing(t *testing.T) {
	scheme := newTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc-secret", Namespace: "default"},
		Data:       map[string][]byte{"other": []byte("value")},
	}
	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	reconciler := NewIdentityProviderReconciler(client, zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				BaseURL:  "https://kc.example.com",
				Realm:    "realm",
				ClientID: "client",
				ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
					Name:      "kc-secret",
					Namespace: "default",
					Key:       "value",
				},
			},
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionFalse, condition.Status)
	assert.Equal(t, "SecretKeyNotFound", condition.Reason)
}

func TestIdentityProviderReconciler_UpdateGroupSyncHealth_Healthy(t *testing.T) {
	scheme := newTestScheme(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kc-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": []byte("secret")},
	}
	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()

	reconciler := NewIdentityProviderReconciler(client, zap.NewNop().Sugar(), func(ctx context.Context) error {
		return nil
	})

	idp := &breakglassv1alpha1.IdentityProvider{
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				BaseURL:  "https://kc.example.com",
				Realm:    "realm",
				ClientID: "client",
				ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
					Name:      "kc-secret",
					Namespace: "default",
					Key:       "value",
				},
			},
		},
	}

	reconciler.updateGroupSyncHealth(context.Background(), idp)
	condition := findConditionByType(idp.Status.Conditions, string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))
	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
	assert.Equal(t, "GroupSyncOperational", condition.Reason)
}

func findConditionByType(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
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

// TestIdentityProviderReconciler_WithEventRecorder tests event recorder configuration
func TestIdentityProviderReconciler_WithEventRecorder(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := ctrltest.NewFakeClient()
	reloadFn := func(ctx context.Context) error { return nil }

	recorder := &fakeEventRecorder{}
	reconciler := NewIdentityProviderReconciler(client, log, reloadFn).
		WithEventRecorder(recorder)

	require.NotNil(t, reconciler.recorder)
	assert.Same(t, recorder, reconciler.recorder)
}

// TestIdentityProviderReconciler_GetCachedIdentityProviders tests cache retrieval
func TestIdentityProviderReconciler_GetCachedIdentityProviders(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
		},
	}

	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(idp).WithStatusSubresource(idp).Build()
	reloadFn := func(ctx context.Context) error { return nil }

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	// GetCachedIdentityProviders now queries the controller-runtime cache directly
	// The IDP should be available immediately (no reconcile needed)
	cached := reconciler.GetCachedIdentityProviders()
	assert.Len(t, cached, 1)
	assert.Equal(t, "test-idp", cached[0].Name)

	// Verify it returns a copy (modifying returned slice doesn't affect future calls)
	cached[0] = nil
	cachedAgain := reconciler.GetCachedIdentityProviders()
	assert.Len(t, cachedAgain, 1)
	assert.NotNil(t, cachedAgain[0])
}

// TestIdentityProviderReconciler_GetEnabledIdentityProviders tests the new context-aware method
func TestIdentityProviderReconciler_GetEnabledIdentityProviders(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
		},
	}

	client := ctrltest.NewClientBuilder().WithScheme(scheme).WithObjects(idp).WithStatusSubresource(idp).Build()
	reloadFn := func(ctx context.Context) error { return nil }

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	// Use the new context-aware method
	ctx := context.Background()
	idps, err := reconciler.GetEnabledIdentityProviders(ctx)
	require.NoError(t, err)
	assert.Len(t, idps, 1)
	assert.Equal(t, "test-idp", idps[0].Name)
}

// TestIdentityProviderReconciler_DisabledIDPsFilteredFromCache tests that disabled IDPs are filtered
func TestIdentityProviderReconciler_DisabledIDPsFilteredFromCache(t *testing.T) {
	log := zap.NewNop().Sugar()
	scheme := newTestScheme(t)

	enabledIDP := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			Disabled: false,
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
		},
	}

	disabledIDP := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "disabled-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			Disabled: true,
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "test-client-2",
			},
		},
	}

	client := ctrltest.NewClientBuilder().WithScheme(scheme).
		WithObjects(enabledIDP, disabledIDP).
		WithStatusSubresource(enabledIDP, disabledIDP).
		Build()
	reloadFn := func(ctx context.Context) error { return nil }

	reconciler := NewIdentityProviderReconciler(client, log, reloadFn)

	// GetCachedIdentityProviders filters disabled IDPs automatically
	cached := reconciler.GetCachedIdentityProviders()
	assert.Len(t, cached, 1)
	assert.Equal(t, "enabled-idp", cached[0].Name)
}

// fakeEventRecorder is a simple fake implementation of events.EventRecorder for testing
type fakeEventRecorder struct {
	events []string
}

func (f *fakeEventRecorder) Eventf(object runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	message := note
	if len(args) > 0 {
		message = fmt.Sprintf(note, args...)
	}
	f.events = append(f.events, fmt.Sprintf("%s: %s - %s", eventtype, reason, message))
}
