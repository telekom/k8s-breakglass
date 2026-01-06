/*
Copyright 2026.

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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestMailProviderScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	return scheme
}

func newTestMailProviderClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newTestMailProviderScheme()).
		WithObjects(objs...).
		WithStatusSubresource(&breakglassv1alpha1.MailProvider{}).
		Build()
}

func TestMailProviderReconciler_ReconcileNotFound(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	cli := newTestMailProviderClient()

	loader := NewMailProviderLoader(cli).WithLogger(logger)

	changeNotified := false
	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
		Loader: loader,
		OnMailProviderChange: func(providerName string) {
			changeNotified = true
			assert.Equal(t, "test-provider", providerName)
		},
	}

	// Pre-populate cache to test invalidation
	loader.cache["test-provider"] = &MailProviderConfig{}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-provider",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
	assert.True(t, changeNotified, "OnMailProviderChange should be called on deletion")

	// Verify cache was invalidated
	_, exists := loader.cache["test-provider"]
	assert.False(t, exists, "Cache should be invalidated on deletion")
}

func TestMailProviderReconciler_ReconcileDisabled(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	mp := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-provider",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Disabled: true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
			Sender: breakglassv1alpha1.SenderConfig{
				Address: "noreply@example.com",
			},
		},
	}

	cli := newTestMailProviderClient(mp)

	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-provider",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify status was updated
	var updated breakglassv1alpha1.MailProvider
	err = cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &updated)
	require.NoError(t, err)

	// Check that Ready condition is False with reason "Disabled"
	found := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionReady) {
			found = true
			assert.Equal(t, metav1.ConditionFalse, cond.Status)
			assert.Equal(t, "Disabled", cond.Reason)
		}
	}
	assert.True(t, found, "Ready condition should be present")
}

func TestMailProviderReconciler_UpdateCondition(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	reconciler := &MailProviderReconciler{Log: logger}

	t.Run("add new condition", func(t *testing.T) {
		conditions := []metav1.Condition{}
		newCond := metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "Configured",
			Message:            "Provider is configured",
			LastTransitionTime: metav1.Now(),
		}

		result := reconciler.updateCondition(conditions, newCond)
		assert.Len(t, result, 1)
		assert.Equal(t, "Ready", result[0].Type)
		assert.Equal(t, metav1.ConditionTrue, result[0].Status)
	})

	t.Run("update existing condition status change", func(t *testing.T) {
		oldTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		conditions := []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "NotConfigured",
				Message:            "Provider is not configured",
				LastTransitionTime: oldTime,
			},
		}
		newCond := metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "Configured",
			Message:            "Provider is configured",
			LastTransitionTime: metav1.Now(),
		}

		result := reconciler.updateCondition(conditions, newCond)
		assert.Len(t, result, 1)
		assert.Equal(t, metav1.ConditionTrue, result[0].Status)
		// LastTransitionTime should be updated because status changed
		assert.NotEqual(t, oldTime, result[0].LastTransitionTime)
	})

	t.Run("update existing condition same status", func(t *testing.T) {
		oldTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		conditions := []metav1.Condition{
			{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				Reason:             "Configured",
				Message:            "Old message",
				LastTransitionTime: oldTime,
			},
		}
		newCond := metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "Configured",
			Message:            "New message",
			LastTransitionTime: metav1.Now(),
		}

		result := reconciler.updateCondition(conditions, newCond)
		assert.Len(t, result, 1)
		// LastTransitionTime should be preserved because status didn't change
		assert.Equal(t, oldTime, result[0].LastTransitionTime)
		// But message should be updated
		assert.Equal(t, "New message", result[0].Message)
	})
}

func TestMailProviderReconciler_GetSecretValue(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	t.Run("successful secret retrieval", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "smtp-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"password": []byte("secret-password"),
			},
		}

		cli := newTestMailProviderClient(secret)
		reconciler := &MailProviderReconciler{
			Client: cli,
			Log:    logger,
		}

		ref := &breakglassv1alpha1.SecretKeyReference{
			Name:      "smtp-secret",
			Namespace: "default",
			Key:       "password",
		}

		value, err := reconciler.getSecretValue(context.Background(), ref)
		assert.NoError(t, err)
		assert.Equal(t, "secret-password", value)
	})

	t.Run("default key is password", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "smtp-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"password": []byte("default-key-password"),
			},
		}

		cli := newTestMailProviderClient(secret)
		reconciler := &MailProviderReconciler{
			Client: cli,
			Log:    logger,
		}

		ref := &breakglassv1alpha1.SecretKeyReference{
			Name:      "smtp-secret",
			Namespace: "default",
			// Key not specified, should default to "password"
		}

		value, err := reconciler.getSecretValue(context.Background(), ref)
		assert.NoError(t, err)
		assert.Equal(t, "default-key-password", value)
	})

	t.Run("secret not found", func(t *testing.T) {
		cli := newTestMailProviderClient()
		reconciler := &MailProviderReconciler{
			Client: cli,
			Log:    logger,
		}

		ref := &breakglassv1alpha1.SecretKeyReference{
			Name:      "nonexistent-secret",
			Namespace: "default",
			Key:       "password",
		}

		_, err := reconciler.getSecretValue(context.Background(), ref)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get secret")
	})

	t.Run("key not found in secret", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "smtp-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"other-key": []byte("value"),
			},
		}

		cli := newTestMailProviderClient(secret)
		reconciler := &MailProviderReconciler{
			Client: cli,
			Log:    logger,
		}

		ref := &breakglassv1alpha1.SecretKeyReference{
			Name:      "smtp-secret",
			Namespace: "default",
			Key:       "password",
		}

		_, err := reconciler.getSecretValue(context.Background(), ref)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key password not found")
	})

	t.Run("nil reference", func(t *testing.T) {
		cli := newTestMailProviderClient()
		reconciler := &MailProviderReconciler{
			Client: cli,
			Log:    logger,
		}

		_, err := reconciler.getSecretValue(context.Background(), nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secret reference is nil")
	})
}

func TestMailProviderReconciler_UpdateStatusHealthy(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	mp := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-provider",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
		},
	}

	cli := newTestMailProviderClient(mp)
	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
	}

	// Get a fresh copy for status update
	var fresh breakglassv1alpha1.MailProvider
	err := cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &fresh)
	require.NoError(t, err)

	result, err := reconciler.updateStatusHealthy(context.Background(), &fresh)
	assert.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status was updated
	var updated breakglassv1alpha1.MailProvider
	err = cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &updated)
	require.NoError(t, err)

	// Check Ready condition is True
	readyFound := false
	healthyFound := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionReady) {
			readyFound = true
			assert.Equal(t, metav1.ConditionTrue, cond.Status)
			assert.Equal(t, "Configured", cond.Reason)
		}
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionHealthy) {
			healthyFound = true
			assert.Equal(t, metav1.ConditionTrue, cond.Status)
			assert.Equal(t, "HealthCheckPassed", cond.Reason)
		}
	}
	assert.True(t, readyFound, "Ready condition should be present")
	assert.True(t, healthyFound, "Healthy condition should be present")
}

func TestMailProviderReconciler_UpdateStatusUnhealthy(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	mp := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-provider",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
		},
	}

	cli := newTestMailProviderClient(mp)
	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
	}

	// Get a fresh copy for status update
	var fresh breakglassv1alpha1.MailProvider
	err := cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &fresh)
	require.NoError(t, err)

	testErr := assert.AnError
	result, err := reconciler.updateStatusUnhealthy(context.Background(), &fresh, testErr)
	assert.NoError(t, err)
	assert.Equal(t, 30*time.Second, result.RequeueAfter)

	// Verify status was updated
	var updated breakglassv1alpha1.MailProvider
	err = cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &updated)
	require.NoError(t, err)

	// Check Ready condition is False
	readyFound := false
	healthyFound := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionReady) {
			readyFound = true
			assert.Equal(t, metav1.ConditionFalse, cond.Status)
			assert.Equal(t, "HealthCheckFailed", cond.Reason)
		}
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionHealthy) {
			healthyFound = true
			assert.Equal(t, metav1.ConditionFalse, cond.Status)
			assert.Equal(t, "Unhealthy", cond.Reason)
		}
	}
	assert.True(t, readyFound, "Ready condition should be present")
	assert.True(t, healthyFound, "Healthy condition should be present")
	assert.NotEmpty(t, updated.Status.LastSendError)
}

func TestMailProviderReconciler_UpdateStatusDisabled(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	mp := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-provider",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Disabled: true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
		},
	}

	cli := newTestMailProviderClient(mp)
	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
	}

	// Get a fresh copy for status update
	var fresh breakglassv1alpha1.MailProvider
	err := cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &fresh)
	require.NoError(t, err)

	result, err := reconciler.updateStatusDisabled(context.Background(), &fresh)
	assert.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result) // No requeue for disabled

	// Verify status was updated
	var updated breakglassv1alpha1.MailProvider
	err = cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &updated)
	require.NoError(t, err)

	// Check Ready condition is False with reason "Disabled"
	readyFound := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionReady) {
			readyFound = true
			assert.Equal(t, metav1.ConditionFalse, cond.Status)
			assert.Equal(t, "Disabled", cond.Reason)
		}
	}
	assert.True(t, readyFound, "Ready condition should be present")
}

func TestMailProviderReconciler_WithPasswordRef(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "smtp-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"password": []byte("secret-password"),
		},
	}

	mp := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-provider",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host:     "smtp.example.com",
				Port:     587,
				Username: "user@example.com",
				PasswordRef: &breakglassv1alpha1.SecretKeyReference{
					Name:      "smtp-secret",
					Namespace: "default",
					Key:       "password",
				},
			},
		},
	}

	cli := newTestMailProviderClient(secret, mp)
	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
	}

	// Get a fresh copy
	var fresh breakglassv1alpha1.MailProvider
	err := cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &fresh)
	require.NoError(t, err)

	// Update status with password loaded condition
	fresh.Spec.SMTP.PasswordRef = mp.Spec.SMTP.PasswordRef
	result, err := reconciler.updateStatusHealthy(context.Background(), &fresh)
	assert.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify PasswordLoaded condition was added
	var updated breakglassv1alpha1.MailProvider
	err = cli.Get(context.Background(), types.NamespacedName{Name: "test-provider", Namespace: "default"}, &updated)
	require.NoError(t, err)

	passwordLoadedFound := false
	for _, cond := range updated.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.MailProviderConditionPasswordLoaded) {
			passwordLoadedFound = true
			assert.Equal(t, metav1.ConditionTrue, cond.Status)
			assert.Equal(t, "SecretLoaded", cond.Reason)
		}
	}
	assert.True(t, passwordLoadedFound, "PasswordLoaded condition should be present")
}

func TestMailProviderReconciler_OnMailProviderChangeCallback(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	mp := &breakglassv1alpha1.MailProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-provider",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.MailProviderSpec{
			Disabled: true,
			SMTP: breakglassv1alpha1.SMTPConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
		},
	}

	cli := newTestMailProviderClient(mp)

	callbackCalled := false
	callbackProviderName := ""

	reconciler := &MailProviderReconciler{
		Client: cli,
		Log:    logger,
		OnMailProviderChange: func(providerName string) {
			callbackCalled = true
			callbackProviderName = providerName
		},
	}

	// Delete the provider to trigger callback
	err := cli.Delete(context.Background(), mp)
	require.NoError(t, err)

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-provider",
			Namespace: "default",
		},
	}

	_, err = reconciler.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.True(t, callbackCalled, "OnMailProviderChange callback should be called")
	assert.Equal(t, "test-provider", callbackProviderName)
}
