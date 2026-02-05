package config

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newTestEscalationReconcilerScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func TestNewEscalationReconciler(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()
	recorder := newEscalationFakeEventRecorder(10)

	t.Run("creates reconciler with default resync period", func(t *testing.T) {
		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 0)
		require.NotNil(t, r)
		assert.Equal(t, 10*time.Minute, r.resyncPeriod)
	})

	t.Run("creates reconciler with custom resync period", func(t *testing.T) {
		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 5*time.Minute)
		require.NotNil(t, r)
		assert.Equal(t, 5*time.Minute, r.resyncPeriod)
	})

	t.Run("creates reconciler with callbacks", func(t *testing.T) {
		onReloadCalled := false
		onErrorCalled := false

		onReload := func(ctx context.Context) error {
			onReloadCalled = true
			return nil
		}
		onError := func(ctx context.Context, err error) {
			onErrorCalled = true
		}

		r := NewEscalationReconciler(fakeClient, logger, recorder, onReload, onError, 0)
		require.NotNil(t, r)
		require.NotNil(t, r.onReload)
		require.NotNil(t, r.onError)

		// Verify callbacks are stored (not executed yet)
		assert.False(t, onReloadCalled)
		assert.False(t, onErrorCalled)
	})
}

type escalationFakeEventRecorder struct {
	Events chan string
}

func newEscalationFakeEventRecorder(buffer int) *escalationFakeEventRecorder {
	return &escalationFakeEventRecorder{Events: make(chan string, buffer)}
}

func (f *escalationFakeEventRecorder) Eventf(_ runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	message := note
	if len(args) > 0 {
		message = fmt.Sprintf(note, args...)
	}
	if f.Events != nil {
		f.Events <- fmt.Sprintf("%s %s %s %s", eventtype, reason, action, message)
	}
}

func TestEscalationReconciler_Reconcile(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	logger := zap.NewNop().Sugar()
	recorder := newEscalationFakeEventRecorder(10)

	t.Run("not found escalation returns no error", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 0)

		result, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
		})

		require.NoError(t, err)
		assert.Equal(t, reconcile.Result{}, result)
	})

	t.Run("valid escalation reconciles successfully", func(t *testing.T) {
		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-escalation",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "test-group",
				MaxValidFor:    "1h",
				Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"allowed-group"},
				},
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(escalation).
			Build()

		onReloadCalled := false
		onReload := func(ctx context.Context) error {
			onReloadCalled = true
			return nil
		}

		r := NewEscalationReconciler(fakeClient, logger, recorder, onReload, nil, 0)

		result, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test-escalation", Namespace: "default"},
		})

		require.NoError(t, err)
		assert.Equal(t, reconcile.Result{}, result)
		assert.True(t, onReloadCalled, "onReload callback should be called")
	})

	t.Run("escalation with missing cluster ref fails validation", func(t *testing.T) {
		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-escalation",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:    "test-group",
				MaxValidFor:       "1h",
				ClusterConfigRefs: []string{"nonexistent-cluster"},
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(escalation).
			Build()

		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 0)

		result, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test-escalation", Namespace: "default"},
		})

		// Validation errors are now persisted to status instead of returning an error
		require.NoError(t, err)
		assert.Equal(t, reconcile.Result{}, result)

		// Verify the status condition was set
		var updated breakglassv1alpha1.BreakglassEscalation
		err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-escalation", Namespace: "default"}, &updated)
		require.NoError(t, err)
		cond := apimeta.FindStatusCondition(updated.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionClusterRefsValid))
		require.NotNil(t, cond)
		assert.Equal(t, metav1.ConditionFalse, cond.Status)
		assert.Contains(t, cond.Message, "ClusterConfigRefs not found")
	})

	t.Run("escalation with missing IDP ref fails validation", func(t *testing.T) {
		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-escalation",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "test-group",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"nonexistent-idp"},
				Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"allowed-group"},
				},
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(escalation).
			Build()

		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 0)

		result, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test-escalation", Namespace: "default"},
		})

		// Validation errors are now persisted to status instead of returning an error
		require.NoError(t, err)
		assert.Equal(t, reconcile.Result{}, result)

		// Verify the status condition was set
		var updated breakglassv1alpha1.BreakglassEscalation
		err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-escalation", Namespace: "default"}, &updated)
		require.NoError(t, err)
		cond := apimeta.FindStatusCondition(updated.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionIDPRefsValid))
		require.NotNil(t, cond)
		assert.Equal(t, metav1.ConditionFalse, cond.Status)
		assert.Contains(t, cond.Message, "IdentityProvider refs not found")
	})

	t.Run("escalation with disabled IDP ref fails validation", func(t *testing.T) {
		disabledIDP := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				Disabled: true,
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://example.com",
					ClientID:  "test",
				},
			},
		}

		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-escalation",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "test-group",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"disabled-idp"},
				Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"allowed-group"},
				},
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation, disabledIDP).
			WithStatusSubresource(escalation).
			Build()

		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 0)

		result, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test-escalation", Namespace: "default"},
		})

		// Validation errors are now persisted to status instead of returning an error
		require.NoError(t, err)
		assert.Equal(t, reconcile.Result{}, result)

		// Verify the status condition was set
		var updated breakglassv1alpha1.BreakglassEscalation
		err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-escalation", Namespace: "default"}, &updated)
		require.NoError(t, err)
		cond := apimeta.FindStatusCondition(updated.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionIDPRefsValid))
		require.NotNil(t, cond)
		assert.Equal(t, metav1.ConditionFalse, cond.Status)
		assert.Contains(t, cond.Message, "IdentityProvider refs disabled")
	})

	t.Run("escalation with missing deny policy ref fails validation", func(t *testing.T) {
		escalation := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-escalation",
				Namespace:  "default",
				Generation: 1,
			},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "test-group",
				MaxValidFor:    "1h",
				DenyPolicyRefs: []string{"nonexistent-policy"},
				Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"allowed-group"},
				},
				Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(escalation).
			WithStatusSubresource(escalation).
			Build()

		r := NewEscalationReconciler(fakeClient, logger, recorder, nil, nil, 0)

		result, err := r.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test-escalation", Namespace: "default"},
		})

		// Validation errors are now persisted to status instead of returning an error
		require.NoError(t, err)
		assert.Equal(t, reconcile.Result{}, result)

		// Verify the status condition was set
		var updated breakglassv1alpha1.BreakglassEscalation
		err = fakeClient.Get(context.Background(), types.NamespacedName{Name: "test-escalation", Namespace: "default"}, &updated)
		require.NoError(t, err)
		cond := apimeta.FindStatusCondition(updated.Status.Conditions, string(breakglassv1alpha1.BreakglassEscalationConditionDenyPolicyRefsValid))
		require.NotNil(t, cond)
		assert.Equal(t, metav1.ConditionFalse, cond.Status)
		assert.Contains(t, cond.Message, "DenyPolicy refs not found")
	})
}

func TestEscalationReconciler_GetCachedEscalationIDPMapping(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	logger := zap.NewNop().Sugar()

	t.Run("returns empty map when no escalations", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		mapping := r.GetCachedEscalationIDPMapping()
		assert.Empty(t, mapping)
	})

	t.Run("returns mapping from escalation objects", func(t *testing.T) {
		// Create escalation objects with AllowedIdentityProviders
		esc1 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc1", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "group1",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"idp1", "idp2"},
			},
		}
		esc2 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc2", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "group2",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"idp3"},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(esc1, esc2).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		mapping := r.GetCachedEscalationIDPMapping()
		assert.Len(t, mapping, 2)
		assert.Equal(t, []string{"idp1", "idp2"}, mapping["esc1"])
		assert.Equal(t, []string{"idp3"}, mapping["esc2"])
	})

	t.Run("returns independent copy of mapping", func(t *testing.T) {
		esc1 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc1", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "group1",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"idp1", "idp2"},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(esc1).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		mapping := r.GetCachedEscalationIDPMapping()
		assert.Len(t, mapping, 1)
		assert.Equal(t, []string{"idp1", "idp2"}, mapping["esc1"])

		// Modify the returned map to ensure it's an independent copy
		mapping["esc1"][0] = "modified"

		// Get again and verify original is unchanged
		mapping2 := r.GetCachedEscalationIDPMapping()
		assert.Equal(t, []string{"idp1", "idp2"}, mapping2["esc1"])
	})
}

func TestEscalationReconciler_ValidateClusterRef(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	logger := zap.NewNop().Sugar()

	t.Run("no cluster refs is valid", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec:       breakglassv1alpha1.BreakglassEscalationSpec{},
		}

		err := r.validateClusterRef(context.Background(), esc)
		require.NoError(t, err)
	})

	t.Run("empty string cluster ref is ignored", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				ClusterConfigRefs: []string{"", "  "},
			},
		}

		err := r.validateClusterRef(context.Background(), esc)
		require.NoError(t, err)
	})

	t.Run("valid cluster ref passes", func(t *testing.T) {
		cluster := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "default"},
			Spec:       breakglassv1alpha1.ClusterConfigSpec{},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(cluster).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				ClusterConfigRefs: []string{"my-cluster"},
			},
		}

		err := r.validateClusterRef(context.Background(), esc)
		require.NoError(t, err)
	})
}

func TestEscalationReconciler_ValidateIDPRefs(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	logger := zap.NewNop().Sugar()

	enabledIDP := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "enabled-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://example.com",
				ClientID:  "test",
			},
		},
	}

	disabledIDP := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			Disabled: true,
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://example.com",
				ClientID:  "test",
			},
		},
	}

	t.Run("validates AllowedIdentityProvidersForRequests", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(enabledIDP).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				AllowedIdentityProvidersForRequests: []string{"nonexistent"},
			},
		}

		err := r.validateIDPRefs(context.Background(), esc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IdentityProvider refs not found")
	})

	t.Run("validates AllowedIdentityProvidersForApprovers", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(enabledIDP).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				AllowedIdentityProvidersForApprovers: []string{"nonexistent"},
			},
		}

		err := r.validateIDPRefs(context.Background(), esc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IdentityProvider refs not found")
	})

	t.Run("reports both missing and disabled IDPs", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(enabledIDP, disabledIDP).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				AllowedIdentityProviders: []string{"disabled-idp", "nonexistent"},
			},
		}

		err := r.validateIDPRefs(context.Background(), esc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing")
		assert.Contains(t, err.Error(), "disabled")
	})
}

func TestEscalationReconciler_ValidateDenyPolicyRefs(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	logger := zap.NewNop().Sugar()

	t.Run("no deny policy refs is valid", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{},
		}

		err := r.validateDenyPolicyRefs(context.Background(), esc)
		require.NoError(t, err)
	})

	t.Run("empty string deny policy ref is ignored", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				DenyPolicyRefs: []string{"", "  "},
			},
		}

		err := r.validateDenyPolicyRefs(context.Background(), esc)
		require.NoError(t, err)
	})

	t.Run("valid deny policy ref passes", func(t *testing.T) {
		policy := &breakglassv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "my-policy"},
			Spec:       breakglassv1alpha1.DenyPolicySpec{},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		esc := &breakglassv1alpha1.BreakglassEscalation{
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				DenyPolicyRefs: []string{"my-policy"},
			},
		}

		err := r.validateDenyPolicyRefs(context.Background(), esc)
		require.NoError(t, err)
	})
}

func TestValidateMailProviderRef(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	enabledProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-enabled"},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP:   breakglassv1alpha1.SMTPConfig{Host: "smtp.enabled", Port: 587},
			Sender: breakglassv1alpha1.SenderConfig{Address: "noreply@enabled"},
		},
	}

	disabledProvider := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-disabled"},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Disabled: true,
			SMTP:     breakglassv1alpha1.SMTPConfig{Host: "smtp.disabled", Port: 587},
			Sender:   breakglassv1alpha1.SenderConfig{Address: "noreply@disabled"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledProvider, disabledProvider).Build()
	reconciler := &EscalationReconciler{client: fakeClient}

	tests := []struct {
		name         string
		mailProvider string
		expectErr    bool
	}{
		{name: "no mail provider configured", mailProvider: "", expectErr: false},
		{name: "enabled provider", mailProvider: "mail-enabled", expectErr: false},
		{name: "missing provider", mailProvider: "does-not-exist", expectErr: true},
		{name: "disabled provider", mailProvider: "mail-disabled", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			esc := &breakglassv1alpha1.BreakglassEscalation{
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{MailProvider: tt.mailProvider},
			}

			err := reconciler.validateMailProviderRef(context.Background(), esc)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEscalationReconciler_GetEscalationIDPMapping(t *testing.T) {
	scheme := newTestEscalationReconcilerScheme()
	logger := zap.NewNop().Sugar()

	t.Run("builds mapping from escalations", func(t *testing.T) {
		esc1 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc1", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "group1",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"idp1", "idp2"},
			},
		}
		esc2 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc2", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "group2",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"idp3"},
			},
		}
		esc3 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc3", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "group3",
				MaxValidFor:    "1h",
				// No AllowedIdentityProviders - should not appear in mapping
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(esc1, esc2, esc3).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		// GetCachedEscalationIDPMapping now queries the controller-runtime cache directly
		mapping := r.GetCachedEscalationIDPMapping()
		assert.Len(t, mapping, 2)
		assert.Equal(t, []string{"idp1", "idp2"}, mapping["esc1"])
		assert.Equal(t, []string{"idp3"}, mapping["esc2"])
		_, hasEsc3 := mapping["esc3"]
		assert.False(t, hasEsc3, "esc3 should not be in mapping as it has no AllowedIdentityProviders")
	})

	t.Run("GetEscalationIDPMapping with context", func(t *testing.T) {
		esc1 := &breakglassv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "esc1", Namespace: "default"},
			Spec: breakglassv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:           "group1",
				MaxValidFor:              "1h",
				AllowedIdentityProviders: []string{"idp1"},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(esc1).
			Build()
		r := NewEscalationReconciler(fakeClient, logger, nil, nil, nil, 0)

		// Use the new context-aware method
		ctx := context.Background()
		mapping, err := r.GetEscalationIDPMapping(ctx)
		require.NoError(t, err)
		assert.Len(t, mapping, 1)
		assert.Equal(t, []string{"idp1"}, mapping["esc1"])
	})
}
