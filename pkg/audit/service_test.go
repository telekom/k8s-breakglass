// SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestNewService(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")
	assert.NotNil(t, svc)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadDisablesOnNilConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	err := svc.Reload(context.Background(), nil)
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadDisablesOnDisabledConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: false,
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadWithLogSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
					Log: &breakglassv1alpha1.LogSinkSpec{
						Level:  "info",
						Format: "json",
					},
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	err = svc.Close()
	assert.NoError(t, err)
	assert.False(t, svc.IsEnabled())
}

func TestService_ReloadWithQueueConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Queue: &breakglassv1alpha1.AuditQueueConfig{
				Size:       5000,
				Workers:    3,
				DropOnFull: true,
			},
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_ReloadWithSampling(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sampling: &breakglassv1alpha1.AuditSamplingConfig{
				Rate: "0.5",
			},
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_ReloadNoSinks(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks:   []breakglassv1alpha1.AuditSinkConfig{}, // no sinks
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	// No sinks means disabled
	assert.False(t, svc.IsEnabled())
}

func TestService_EmitWhenDisabled(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	// Service is disabled by default
	event := &Event{
		ID:        "test-1",
		Type:      EventSessionRequested,
		Timestamp: time.Now(),
		Actor:     Actor{User: "test@example.com"},
	}

	// Should not panic
	svc.Emit(context.Background(), event)

	// Sync emit should return nil
	err := svc.EmitSync(context.Background(), event)
	assert.NoError(t, err)
}

func TestService_EmitWhenEnabled(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	event := &Event{
		ID:        "test-1",
		Type:      EventSessionRequested,
		Timestamp: time.Now(),
		Actor:     Actor{User: "test@example.com"},
	}

	// Should not panic
	svc.Emit(context.Background(), event)

	// Sync emit
	err = svc.EmitSync(context.Background(), event)
	assert.NoError(t, err)

	// Cleanup
	_ = svc.Close()
}

func TestService_CloseWhenNotInitialized(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	// Close without Reload
	err := svc.Close()
	assert.NoError(t, err)
}

func TestService_ReloadMultipleTimes(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config1 := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config1"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{Name: "log1", Type: breakglassv1alpha1.AuditSinkTypeLog},
			},
		},
	}

	// First reload
	err := svc.Reload(context.Background(), config1)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	config2 := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config2"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{Name: "log2", Type: breakglassv1alpha1.AuditSinkTypeLog},
				{Name: "log3", Type: breakglassv1alpha1.AuditSinkTypeLog},
			},
		},
	}

	// Second reload should close old sinks and create new ones
	err = svc.Reload(context.Background(), config2)
	require.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Disable via nil
	err = svc.Reload(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_BuildWebhookSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: &breakglassv1alpha1.WebhookSinkSpec{
						URL:            "https://example.com/audit",
						TimeoutSeconds: 10,
						Headers: map[string]string{
							"X-Custom-Header": "value",
						},
					},
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_BuildKubernetesSink(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "k8s-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKubernetes,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_SkipsInvalidSinkType(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "invalid-sink",
					Type: "unknown-type",
				},
				{
					Name: "valid-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	// Still enabled because valid log sink exists
	assert.True(t, svc.IsEnabled())

	// Cleanup
	_ = svc.Close()
}

func TestService_KafkaSinkMissingConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:  "kafka-sink",
					Type:  breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: nil, // missing config
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	// Disabled because no valid sinks
	assert.False(t, svc.IsEnabled())
}

func TestService_WebhookSinkMissingConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config"},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:    "webhook-sink",
					Type:    breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: nil, // missing config
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	assert.NoError(t, err)
	// Disabled because no valid sinks
	assert.False(t, svc.IsEnabled())
}

func TestService_GetSecretKey(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"username": []byte("testuser"),
			"password": []byte("testpass"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	svc := NewService(client, logger, "test-namespace")

	// Get existing key
	data, err := svc.getSecretKey(context.Background(), "test-secret", "test-namespace", "username")
	assert.NoError(t, err)
	assert.Equal(t, []byte("testuser"), data)

	// Get missing key
	_, err = svc.getSecretKey(context.Background(), "test-secret", "test-namespace", "missing-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Get from missing secret
	_, err = svc.getSecretKey(context.Background(), "missing-secret", "test-namespace", "username")
	assert.Error(t, err)
}
