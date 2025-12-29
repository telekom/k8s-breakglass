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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestAuditConfigReconciler(t *testing.T, objs ...runtime.Object) (*AuditConfigReconciler, *record.FakeRecorder) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objs...).
		WithStatusSubresource(&breakglassv1alpha1.AuditConfig{}).
		Build()

	recorder := record.NewFakeRecorder(10)
	logger := zaptest.NewLogger(t).Sugar()

	reconciler := NewAuditConfigReconciler(
		client,
		logger,
		recorder,
		nil, // no reload callback for tests
		nil, // no error callback for tests
		time.Minute,
	)

	return reconciler, recorder
}

func TestAuditConfigReconciler_Reconcile_NotFound(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	})

	assert.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestAuditConfigReconciler_Reconcile_ValidConfig(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-config",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
					Log: &breakglassv1alpha1.LogSinkSpec{
						Level:  "info",
						Format: "json",
					},
				},
			},
		},
	}

	reloadCalled := false
	r, recorder := newTestAuditConfigReconciler(t, config)
	r.onReload = func(ctx context.Context, cfg *breakglassv1alpha1.AuditConfig) error {
		reloadCalled = true
		assert.Equal(t, "test-config", cfg.Name)
		return nil
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-config"},
	})

	assert.NoError(t, err)
	assert.True(t, reloadCalled)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Check event was recorded
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "Reconciled")
	default:
		t.Error("Expected event to be recorded")
	}
}

func TestAuditConfigReconciler_Reconcile_KafkaSink_MissingBrokers(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-kafka-invalid",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{}, // Empty brokers
						Topic:   "test-topic",
					},
				},
			},
		},
	}

	r, recorder := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-kafka-invalid"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Check validation failed event
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "ValidationFailed")
	default:
		t.Error("Expected validation failed event")
	}
}

func TestAuditConfigReconciler_Reconcile_KafkaSink_MissingTopic(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-kafka-no-topic",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{"localhost:9092"},
						Topic:   "", // Empty topic
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-kafka-no-topic"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_KafkaSink_MissingKafkaConfig(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-kafka-no-config",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:  "kafka-sink",
					Type:  breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: nil, // Missing kafka config
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-kafka-no-config"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_WebhookSink_MissingURL(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-no-url",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: &breakglassv1alpha1.WebhookSinkSpec{
						URL: "", // Empty URL
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-webhook-no-url"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_WebhookSink_MissingWebhookConfig(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-webhook-no-config",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:    "webhook-sink",
					Type:    breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: nil, // Missing webhook config
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-webhook-no-config"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_KubernetesSink(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-k8s-sink",
		},
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

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-k8s-sink"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_MultipleSinks(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-multi-sink",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{"localhost:9092"},
						Topic:   "test",
					},
				},
				{
					Name: "webhook-sink",
					Type: breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: &breakglassv1alpha1.WebhookSinkSpec{
						URL: "https://example.com/webhook",
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-multi-sink"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Check cached config
	cached := r.GetActiveConfig()
	require.NotNil(t, cached)
	assert.Equal(t, 3, len(cached.Spec.Sinks))
}

func TestAuditConfigReconciler_Reconcile_TLSSecretNotFound(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tls-missing",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{"localhost:9092"},
						Topic:   "test",
						TLS: &breakglassv1alpha1.KafkaTLSSpec{
							Enabled: true,
							CASecretRef: &breakglassv1alpha1.SecretKeySelector{
								Name:      "nonexistent-secret",
								Namespace: "default",
							},
						},
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-tls-missing"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_TLSSecretExists(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-ca",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("fake-ca-cert"),
		},
	}

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-tls-valid",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{"localhost:9092"},
						Topic:   "test",
						TLS: &breakglassv1alpha1.KafkaTLSSpec{
							Enabled: true,
							CASecretRef: &breakglassv1alpha1.SecretKeySelector{
								Name:      "kafka-ca",
								Namespace: "default",
							},
						},
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, secret, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-tls-valid"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_SASLSecretValidation(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kafka-creds",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("user"),
			"password": []byte("pass"),
		},
	}

	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-sasl-valid",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{"localhost:9092"},
						Topic:   "test",
						SASL: &breakglassv1alpha1.KafkaSASLSpec{
							Mechanism: "SCRAM-SHA-512",
							CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
								Name:      "kafka-creds",
								Namespace: "default",
							},
						},
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, secret, config)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-sasl-valid"},
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_GetActiveConfig_NilWhenEmpty(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	cached := r.GetActiveConfig()
	assert.Nil(t, cached)
}

func TestAuditConfigReconciler_Reconcile_DisabledConfig(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-disabled",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: false,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	reloadCalled := false
	r, _ := newTestAuditConfigReconciler(t, config)
	r.onReload = func(ctx context.Context, cfg *breakglassv1alpha1.AuditConfig) error {
		reloadCalled = true
		return nil
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-disabled"},
	})

	assert.NoError(t, err)
	assert.True(t, reloadCalled)
	assert.Equal(t, time.Minute, result.RequeueAfter)
}

func TestAuditConfigReconciler_Reconcile_ReloadError(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-reload-error",
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

	errorHandlerCalled := false
	r, recorder := newTestAuditConfigReconciler(t, config)
	r.onReload = func(ctx context.Context, cfg *breakglassv1alpha1.AuditConfig) error {
		return assert.AnError
	}
	r.onError = func(ctx context.Context, err error) {
		errorHandlerCalled = true
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-reload-error"},
	})

	assert.Error(t, err)
	assert.True(t, errorHandlerCalled)
	assert.Equal(t, 30*time.Second, result.RequeueAfter)

	// Check error event was recorded
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "ReloadFailed")
	default:
		t.Error("Expected reload failed event")
	}
}

func TestAuditConfigReconciler_ValidateSink_UnknownType(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	sink := breakglassv1alpha1.AuditSinkConfig{
		Name: "unknown-sink",
		Type: "unknown",
	}

	errors := r.validateSink(context.Background(), sink, 0)
	assert.Len(t, errors, 1)
	assert.Contains(t, errors[0], "unknown sink type")
}

func TestNewAuditConfigReconciler_DefaultResyncPeriod(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	logger := zap.NewNop().Sugar()

	r := NewAuditConfigReconciler(client, logger, nil, nil, nil, 0)

	// Default should be 10 minutes
	assert.Equal(t, 10*time.Minute, r.resyncPeriod)
}
