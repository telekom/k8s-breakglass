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

func TestDefaultQueuedSinkConfig(t *testing.T) {
	cfg := DefaultQueuedSinkConfig()

	assert.Equal(t, 10000, cfg.QueueSize)
	assert.Equal(t, 2, cfg.WorkerCount)
	assert.Equal(t, 5*time.Second, cfg.WriteTimeout)
	assert.True(t, cfg.DropOnFull)
	assert.Equal(t, 5, cfg.CircuitBreakerThreshold)
	assert.Equal(t, 30*time.Second, cfg.CircuitBreakerResetTime)
}

func TestService_GetSinkHealth_NoSinks(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	health := svc.GetSinkHealth()
	assert.Empty(t, health)
}

func TestService_GetSinkHealth_WithLogSink(t *testing.T) {
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
	require.NoError(t, err)

	health := svc.GetSinkHealth()
	// With isolated queuing, we should have one sink
	assert.NotEmpty(t, health)

	_ = svc.Close()
}

func TestService_GetQueuedSinkHealth_NoSinks(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	health := svc.GetQueuedSinkHealth()
	assert.Nil(t, health)
}

func TestService_GetQueuedSinkHealth_WithSink(t *testing.T) {
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
	require.NoError(t, err)

	health := svc.GetQueuedSinkHealth()
	assert.NotNil(t, health)
	assert.Len(t, health, 1)
	// The queued sink wraps the log sink and uses its name
	assert.NotEmpty(t, health[0].Name)

	_ = svc.Close()
}

func TestService_BuildKafkaTLSConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-ca",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("test-ca-cert-data"),
		},
	}

	clientCertSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-client-cert",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("test-client-cert"),
			"tls.key": []byte("test-client-key"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(caSecret, clientCertSecret).
		Build()

	svc := NewService(client, logger, "test-namespace")
	ctx := context.Background()

	t.Run("with CA only", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			InsecureSkipVerify: false,
			CASecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-ca",
			},
		}

		cfg, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		require.NoError(t, err)
		assert.True(t, cfg.Enabled)
		assert.False(t, cfg.InsecureSkipVerify)
		assert.Equal(t, []byte("test-ca-cert-data"), cfg.CACert)
	})

	t.Run("with client cert", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			ClientCertSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-client-cert",
			},
		}

		cfg, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		require.NoError(t, err)
		assert.Equal(t, []byte("test-client-cert"), cfg.ClientCert)
		assert.Equal(t, []byte("test-client-key"), cfg.ClientKey)
	})

	t.Run("with insecure skip verify", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			InsecureSkipVerify: true,
		}

		cfg, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		require.NoError(t, err)
		assert.True(t, cfg.InsecureSkipVerify)
	})

	t.Run("CA secret not found", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			CASecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "missing-ca",
			},
		}

		_, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CA certificate")
	})

	t.Run("client cert secret not found", func(t *testing.T) {
		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			ClientCertSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "missing-client",
			},
		}

		_, err := svc.buildKafkaTLSConfig(ctx, tlsCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client certificate")
	})

	t.Run("client key missing", func(t *testing.T) {
		// Create secret without tls.key
		secretNoKey := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kafka-cert-no-key",
				Namespace: "test-namespace",
			},
			Data: map[string][]byte{
				"tls.crt": []byte("test-client-cert"),
			},
		}
		clientWithNoKey := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(secretNoKey).
			Build()
		svcNoKey := NewService(clientWithNoKey, logger, "test-namespace")

		tlsCfg := &breakglassv1alpha1.KafkaTLSSpec{
			ClientCertSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-cert-no-key",
			},
		}

		_, err := svcNoKey.buildKafkaTLSConfig(ctx, tlsCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client key")
	})
}

func TestService_BuildKafkaSASLConfig(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	saslSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-sasl",
			Namespace: "test-namespace",
		},
		Data: map[string][]byte{
			"username": []byte("kafka-user"),
			"password": []byte("kafka-pass"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(saslSecret).
		Build()

	svc := NewService(client, logger, "test-namespace")
	ctx := context.Background()

	t.Run("with PLAIN mechanism", func(t *testing.T) {
		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-sasl",
			},
		}

		cfg, err := svc.buildKafkaSASLConfig(ctx, saslCfg)
		require.NoError(t, err)
		assert.Equal(t, "PLAIN", cfg.Mechanism)
		assert.Equal(t, "kafka-user", cfg.Username)
		assert.Equal(t, "kafka-pass", cfg.Password)
	})

	t.Run("with SCRAM-SHA-256", func(t *testing.T) {
		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "SCRAM-SHA-256",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-sasl",
			},
		}

		cfg, err := svc.buildKafkaSASLConfig(ctx, saslCfg)
		require.NoError(t, err)
		assert.Equal(t, "SCRAM-SHA-256", cfg.Mechanism)
	})

	t.Run("secret not found", func(t *testing.T) {
		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "missing-secret",
			},
		}

		_, err := svc.buildKafkaSASLConfig(ctx, saslCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SASL username")
	})

	t.Run("password missing", func(t *testing.T) {
		secretNoPass := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kafka-sasl-no-pass",
				Namespace: "test-namespace",
			},
			Data: map[string][]byte{
				"username": []byte("kafka-user"),
			},
		}
		clientNoPass := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(secretNoPass).
			Build()
		svcNoPass := NewService(clientNoPass, logger, "test-namespace")

		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name: "kafka-sasl-no-pass",
			},
		}

		_, err := svcNoPass.buildKafkaSASLConfig(ctx, saslCfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SASL password")
	})

	t.Run("explicit namespace", func(t *testing.T) {
		saslSecretOtherNS := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kafka-sasl-other",
				Namespace: "other-namespace",
			},
			Data: map[string][]byte{
				"username": []byte("other-user"),
				"password": []byte("other-pass"),
			},
		}
		clientOtherNS := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(saslSecretOtherNS).
			Build()
		svcOtherNS := NewService(clientOtherNS, logger, "test-namespace")

		saslCfg := &breakglassv1alpha1.KafkaSASLSpec{
			Mechanism: "PLAIN",
			CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
				Name:      "kafka-sasl-other",
				Namespace: "other-namespace",
			},
		}

		cfg, err := svcOtherNS.buildKafkaSASLConfig(ctx, saslCfg)
		require.NoError(t, err)
		assert.Equal(t, "other-user", cfg.Username)
	})
}

func TestService_GetStats_NoManager(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	// No manager initialized
	stats := svc.GetStats()
	assert.Nil(t, stats)
}

func TestService_GetStats_WithManager(t *testing.T) {
	logger := zap.NewNop()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	svc := NewService(client, logger, "test-namespace")

	// Reload with a valid config to initialize the manager
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-stats-config",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	err := svc.Reload(context.Background(), config)
	require.NoError(t, err)

	// Manager should now be initialized
	stats := svc.GetStats()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.ProcessedEvents, int64(0))
	assert.GreaterOrEqual(t, stats.DroppedEvents, int64(0))

	_ = svc.Close()
}
