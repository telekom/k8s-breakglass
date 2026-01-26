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
	"fmt"
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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func newTestAuditConfigReconciler(t *testing.T, objs ...runtime.Object) (*AuditConfigReconciler, *auditFakeEventRecorder) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(objs...).
		WithStatusSubresource(&breakglassv1alpha1.AuditConfig{}).
		Build()

	recorder := newAuditFakeEventRecorder(10)
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

type auditFakeEventRecorder struct {
	Events chan string
}

func newAuditFakeEventRecorder(buffer int) *auditFakeEventRecorder {
	return &auditFakeEventRecorder{Events: make(chan string, buffer)}
}

func (f *auditFakeEventRecorder) Eventf(_ runtime.Object, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	message := note
	if len(args) > 0 {
		message = fmt.Sprintf(note, args...)
	}
	if f.Events != nil {
		f.Events <- fmt.Sprintf("%s %s %s %s", eventtype, reason, action, message)
	}
}

func TestAuditConfigReconciler_Reconcile_NotFound(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent"},
	})

	assert.NoError(t, err)
	// When listing all configs and none exist, we still requeue after resync period
	assert.Equal(t, time.Minute, result.RequeueAfter)
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
	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
		reloadCalled = true
		require.Len(t, cfgs, 1)
		assert.Equal(t, "test-config", cfgs[0].Name)
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
	// With aggregation, we still requeue even if this specific config is invalid
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
	// With aggregation, we still requeue even if this specific config is invalid
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
	// With aggregation, we still requeue even if this specific config is invalid
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
	// With aggregation, we still requeue even if this specific config is invalid
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
	// With aggregation, we still requeue even if this specific config is invalid
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
	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
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
	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
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

func TestAuditConfigReconciler_Reconcile_MultipleConfigs_Aggregation(t *testing.T) {
	// Create two valid AuditConfigs with different sinks
	config1 := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "config-kafka",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "kafka-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: &breakglassv1alpha1.KafkaSinkSpec{
						Brokers: []string{"localhost:9092"},
						Topic:   "audit-events",
					},
				},
			},
		},
	}

	config2 := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "config-webhook",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: &breakglassv1alpha1.WebhookSinkSpec{
						URL: "https://audit.example.com/events",
					},
				},
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	// Create a disabled config that should be skipped
	configDisabled := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "config-disabled",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: false,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "ignored-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
		},
	}

	var receivedConfigs []*breakglassv1alpha1.AuditConfig
	r, _ := newTestAuditConfigReconciler(t, config1, config2, configDisabled)
	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
		receivedConfigs = cfgs
		return nil
	}

	// Trigger reconcile (any trigger will list all configs)
	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "config-kafka"},
	})

	require.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Should have received exactly 2 enabled configs
	require.Len(t, receivedConfigs, 2)

	// Verify both enabled configs are included
	configNames := make(map[string]bool)
	totalSinks := 0
	for _, cfg := range receivedConfigs {
		configNames[cfg.Name] = true
		totalSinks += len(cfg.Spec.Sinks)
	}

	assert.True(t, configNames["config-kafka"], "config-kafka should be included")
	assert.True(t, configNames["config-webhook"], "config-webhook should be included")
	assert.False(t, configNames["config-disabled"], "config-disabled should NOT be included")

	// Total sinks: 1 from kafka + 2 from webhook = 3
	assert.Equal(t, 3, totalSinks, "Should have 3 total sinks from all enabled configs")

	// Verify GetActiveConfigs returns the same
	activeConfigs := r.GetActiveConfigs()
	assert.Len(t, activeConfigs, 2)
}

func TestAuditConfigReconciler_Reconcile_MixedValidInvalid(t *testing.T) {
	// One valid config
	validConfig := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-config",
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

	// One invalid config (missing kafka config)
	invalidConfig := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-config",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name:  "broken-kafka",
					Type:  breakglassv1alpha1.AuditSinkTypeKafka,
					Kafka: nil, // Missing kafka config
				},
			},
		},
	}

	var receivedConfigs []*breakglassv1alpha1.AuditConfig
	r, _ := newTestAuditConfigReconciler(t, validConfig, invalidConfig)
	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
		receivedConfigs = cfgs
		return nil
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "valid-config"},
	})

	require.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Should only receive the valid config
	require.Len(t, receivedConfigs, 1)
	assert.Equal(t, "valid-config", receivedConfigs[0].Name)
}

func TestAuditConfigReconciler_SetSinkHealthProvider(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	// Initially no health provider
	assert.Nil(t, r.getSinkHealth)

	// Set health provider
	healthProvider := func() []SinkHealthInfo {
		return []SinkHealthInfo{
			{Name: "sink-1", Ready: true, CircuitState: "closed"},
			{Name: "sink-2", Ready: false, CircuitState: "open", LastError: "connection failed"},
		}
	}
	r.SetSinkHealthProvider(healthProvider)

	// Verify it was set
	assert.NotNil(t, r.getSinkHealth)

	// Verify the provider returns expected data
	healthInfos := r.getSinkHealth()
	require.Len(t, healthInfos, 2)
	assert.Equal(t, "sink-1", healthInfos[0].Name)
	assert.True(t, healthInfos[0].Ready)
	assert.Equal(t, "sink-2", healthInfos[1].Name)
	assert.False(t, healthInfos[1].Ready)
	assert.Equal(t, "connection failed", healthInfos[1].LastError)
}

func TestAuditConfigReconciler_UpdateStatus_Valid(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-valid",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "log-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
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

	// Update status with no validation errors
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status was updated
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-valid"}, updatedConfig)
	require.NoError(t, err)

	// Check Ready condition
	readyCondition := findCondition(updatedConfig.Status.Conditions, "Ready")
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
	assert.Equal(t, "ConfigurationValid", readyCondition.Reason)

	// Check active sinks
	assert.ElementsMatch(t, []string{"log-sink", "webhook-sink"}, updatedConfig.Status.ActiveSinks)
}

func TestAuditConfigReconciler_UpdateStatus_ValidationErrors(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-errors",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "broken-sink",
					Type: breakglassv1alpha1.AuditSinkTypeKafka,
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	// Update status with validation errors
	validationErrors := []string{"kafka config required for type=kafka", "at least one broker required"}
	err := r.updateStatus(context.Background(), config, validationErrors)
	require.NoError(t, err)

	// Verify status was updated
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-errors"}, updatedConfig)
	require.NoError(t, err)

	// Check Ready condition shows failure
	readyCondition := findCondition(updatedConfig.Status.Conditions, "Ready")
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "ValidationFailed", readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "kafka config required")
}

func TestAuditConfigReconciler_UpdateStatus_WithSinkHealth_AllHealthy(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-healthy",
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

	r, _ := newTestAuditConfigReconciler(t, config)

	// Set up sink health provider that returns all healthy sinks
	r.SetSinkHealthProvider(func() []SinkHealthInfo {
		return []SinkHealthInfo{
			{Name: "log-sink", Ready: true, CircuitState: "closed"},
		}
	})

	// Update status
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-healthy"}, updatedConfig)
	require.NoError(t, err)

	// Check SinksHealthy condition
	healthyCondition := findCondition(updatedConfig.Status.Conditions, "SinksHealthy")
	require.NotNil(t, healthyCondition)
	assert.Equal(t, metav1.ConditionTrue, healthyCondition.Status)
	assert.Equal(t, "AllSinksOperational", healthyCondition.Reason)

	// Check SinkStatuses
	require.Len(t, updatedConfig.Status.SinkStatuses, 1)
	assert.Equal(t, "log-sink", updatedConfig.Status.SinkStatuses[0].Name)
	assert.True(t, updatedConfig.Status.SinkStatuses[0].Ready)
}

func TestAuditConfigReconciler_UpdateStatus_WithSinkHealth_SomeUnhealthy(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-unhealthy",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "healthy-sink",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
				{
					Name: "unhealthy-sink",
					Type: breakglassv1alpha1.AuditSinkTypeWebhook,
					Webhook: &breakglassv1alpha1.WebhookSinkSpec{
						URL: "https://down.example.com/webhook",
					},
				},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)

	// Set up sink health provider with one unhealthy sink
	r.SetSinkHealthProvider(func() []SinkHealthInfo {
		return []SinkHealthInfo{
			{Name: "healthy-sink", Ready: true, CircuitState: "closed"},
			{Name: "unhealthy-sink", Ready: false, CircuitState: "open", LastError: "connection timeout"},
		}
	})

	// Update status
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-unhealthy"}, updatedConfig)
	require.NoError(t, err)

	// Check SinksHealthy condition shows unhealthy
	healthyCondition := findCondition(updatedConfig.Status.Conditions, "SinksHealthy")
	require.NotNil(t, healthyCondition)
	assert.Equal(t, metav1.ConditionFalse, healthyCondition.Status)
	assert.Equal(t, "SinksUnhealthy", healthyCondition.Reason)
	assert.Contains(t, healthyCondition.Message, "unhealthy-sink")

	// Check SinkStatuses
	require.Len(t, updatedConfig.Status.SinkStatuses, 2)

	// Find unhealthy sink status
	var unhealthySinkStatus *breakglassv1alpha1.AuditSinkStatus
	for i := range updatedConfig.Status.SinkStatuses {
		if updatedConfig.Status.SinkStatuses[i].Name == "unhealthy-sink" {
			unhealthySinkStatus = &updatedConfig.Status.SinkStatuses[i]
			break
		}
	}
	require.NotNil(t, unhealthySinkStatus)
	assert.False(t, unhealthySinkStatus.Ready)
	assert.Equal(t, "connection timeout", unhealthySinkStatus.LastError)
}

func TestAuditConfigReconciler_UpdateStatus_NoHealthProvider(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-no-health",
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

	r, _ := newTestAuditConfigReconciler(t, config)
	// Don't set health provider - it should be nil

	// Update status
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-no-health"}, updatedConfig)
	require.NoError(t, err)

	// Ready should be set
	readyCondition := findCondition(updatedConfig.Status.Conditions, "Ready")
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)

	// SinksHealthy should NOT be set when no health provider
	healthyCondition := findCondition(updatedConfig.Status.Conditions, "SinksHealthy")
	assert.Nil(t, healthyCondition)

	// SinkStatuses should be empty
	assert.Empty(t, updatedConfig.Status.SinkStatuses)
}

// Helper function to find a condition by type
func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func TestAuditConfigReconciler_ReconcileWithSinkHealth(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-reconcile-health",
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

	r, _ := newTestAuditConfigReconciler(t, config)

	// Set up sink health provider
	r.SetSinkHealthProvider(func() []SinkHealthInfo {
		return []SinkHealthInfo{
			{Name: "log-sink", Ready: true, CircuitState: "closed", ConsecutiveFailures: 0},
		}
	})

	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
		return nil
	}

	result, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-reconcile-health"},
	})

	require.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Verify sink health was included in status
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-reconcile-health"}, updatedConfig)
	require.NoError(t, err)

	healthyCondition := findCondition(updatedConfig.Status.Conditions, "SinksHealthy")
	require.NotNil(t, healthyCondition)
	assert.Equal(t, metav1.ConditionTrue, healthyCondition.Status)
}

func TestAuditConfigReconciler_IsConfigInList(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	configs := []*breakglassv1alpha1.AuditConfig{
		{ObjectMeta: metav1.ObjectMeta{Name: "config-a"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "config-b"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "config-c"}},
	}

	assert.True(t, r.isConfigInList("config-a", configs))
	assert.True(t, r.isConfigInList("config-b", configs))
	assert.True(t, r.isConfigInList("config-c", configs))
	assert.False(t, r.isConfigInList("config-d", configs))
	assert.False(t, r.isConfigInList("", configs))
	assert.False(t, r.isConfigInList("config-a", nil))
	assert.False(t, r.isConfigInList("config-a", []*breakglassv1alpha1.AuditConfig{}))
}

func TestAuditConfigReconciler_GetActiveConfigs_Empty(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	configs := r.GetActiveConfigs()
	assert.Empty(t, configs)
	assert.NotNil(t, configs) // Should return empty slice, not nil
}

func TestAuditConfigReconciler_GetActiveConfigs_ReturnsDeepCopy(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deep-copy",
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{Name: "sink-1", Type: breakglassv1alpha1.AuditSinkTypeLog},
			},
		},
	}

	r, _ := newTestAuditConfigReconciler(t, config)
	r.onReloadMultiple = func(ctx context.Context, cfgs []*breakglassv1alpha1.AuditConfig) error {
		return nil
	}

	// Reconcile to populate activeConfigs
	_, err := r.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test-deep-copy"},
	})
	require.NoError(t, err)

	// Get configs twice
	configs1 := r.GetActiveConfigs()
	configs2 := r.GetActiveConfigs()

	require.Len(t, configs1, 1)
	require.Len(t, configs2, 1)

	// Modify one - the other should not be affected (deep copy)
	configs1[0].Spec.Enabled = false

	assert.True(t, configs2[0].Spec.Enabled, "GetActiveConfigs should return deep copies")
}

func TestAuditConfigReconciler_SetStatsProvider(t *testing.T) {
	r, _ := newTestAuditConfigReconciler(t)

	// Initially no stats provider
	assert.Nil(t, r.getStats)

	// Set stats provider
	statsProvider := func() *AuditStats {
		return &AuditStats{
			ProcessedEvents: 1000,
			DroppedEvents:   5,
		}
	}
	r.SetStatsProvider(statsProvider)

	// Verify it was set
	assert.NotNil(t, r.getStats)

	// Verify the provider returns expected data
	stats := r.getStats()
	require.NotNil(t, stats)
	assert.Equal(t, int64(1000), stats.ProcessedEvents)
	assert.Equal(t, int64(5), stats.DroppedEvents)
}

func TestAuditConfigReconciler_UpdateStatus_WithStats(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-with-stats",
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

	r, _ := newTestAuditConfigReconciler(t, config)

	// Set stats provider
	r.SetStatsProvider(func() *AuditStats {
		return &AuditStats{
			ProcessedEvents: 500,
			DroppedEvents:   10,
		}
	})

	// Update status with no validation errors
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status was updated with stats
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-with-stats"}, updatedConfig)
	require.NoError(t, err)

	// Check stats fields were populated
	assert.Equal(t, int64(500), updatedConfig.Status.EventsProcessed)
	assert.Equal(t, int64(10), updatedConfig.Status.EventsDropped)
	assert.NotNil(t, updatedConfig.Status.LastEventTime, "LastEventTime should be set when events are processed")
}

func TestAuditConfigReconciler_UpdateStatus_NoStats(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-no-stats",
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

	r, _ := newTestAuditConfigReconciler(t, config)

	// No stats provider set

	// Update status with no validation errors
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status was updated without stats
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-no-stats"}, updatedConfig)
	require.NoError(t, err)

	// Check stats fields are zero (no provider)
	assert.Equal(t, int64(0), updatedConfig.Status.EventsProcessed)
	assert.Equal(t, int64(0), updatedConfig.Status.EventsDropped)
	assert.Nil(t, updatedConfig.Status.LastEventTime)
}

func TestAuditConfigReconciler_UpdateStatus_StatsProviderReturnsNil(t *testing.T) {
	config := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-status-nil-stats",
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

	r, _ := newTestAuditConfigReconciler(t, config)

	// Set stats provider that returns nil (no manager initialized)
	r.SetStatsProvider(func() *AuditStats {
		return nil
	})

	// Update status with no validation errors
	err := r.updateStatus(context.Background(), config, nil)
	require.NoError(t, err)

	// Verify status was updated without stats
	updatedConfig := &breakglassv1alpha1.AuditConfig{}
	err = r.client.Get(context.Background(), types.NamespacedName{Name: "test-status-nil-stats"}, updatedConfig)
	require.NoError(t, err)

	// Check stats fields are zero (provider returned nil)
	assert.Equal(t, int64(0), updatedConfig.Status.EventsProcessed)
	assert.Equal(t, int64(0), updatedConfig.Status.EventsDropped)
	assert.Nil(t, updatedConfig.Status.LastEventTime)
}
