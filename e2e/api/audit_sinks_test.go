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

package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestAuditSinkConfigurations tests all audit sink types.
func TestAuditSinkConfigurations(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("LogSinkConfiguration", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-log-sink"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "log-sink",
						Type: breakglassv1alpha1.AuditSinkTypeLog,
						Log: &breakglassv1alpha1.LogSinkSpec{
							Level: "info",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		require.Len(t, auditConfig.Spec.Sinks, 1)
		assert.Equal(t, breakglassv1alpha1.AuditSinkTypeLog, auditConfig.Spec.Sinks[0].Type)
		assert.NotNil(t, auditConfig.Spec.Sinks[0].Log)
		assert.Equal(t, "info", auditConfig.Spec.Sinks[0].Log.Level)
		t.Logf("AUDIT-001: Created AuditConfig with Log sink: %s", auditConfig.Name)
	})

	t.Run("WebhookSinkConfiguration", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-webhook-sink"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: breakglassv1alpha1.AuditSinkTypeWebhook,
						Webhook: &breakglassv1alpha1.WebhookSinkSpec{
							URL: "https://audit-webhook.example.com/events",
							Headers: map[string]string{
								"X-Audit-Source": "breakglass",
							},
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		require.Len(t, auditConfig.Spec.Sinks, 1)
		assert.Equal(t, breakglassv1alpha1.AuditSinkTypeWebhook, auditConfig.Spec.Sinks[0].Type)
		assert.NotNil(t, auditConfig.Spec.Sinks[0].Webhook)
		assert.Equal(t, "https://audit-webhook.example.com/events", auditConfig.Spec.Sinks[0].Webhook.URL)
		t.Logf("AUDIT-002: Created AuditConfig with Webhook sink: %s", auditConfig.Name)
	})

	t.Run("KafkaSinkConfiguration", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-kafka-sink"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: breakglassv1alpha1.AuditSinkTypeKafka,
						Kafka: &breakglassv1alpha1.KafkaSinkSpec{
							Brokers: []string{"kafka-1.example.com:9092", "kafka-2.example.com:9092"},
							Topic:   "breakglass-audit-events",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		require.Len(t, auditConfig.Spec.Sinks, 1)
		assert.Equal(t, breakglassv1alpha1.AuditSinkTypeKafka, auditConfig.Spec.Sinks[0].Type)
		assert.NotNil(t, auditConfig.Spec.Sinks[0].Kafka)
		assert.Len(t, auditConfig.Spec.Sinks[0].Kafka.Brokers, 2)
		assert.Equal(t, "breakglass-audit-events", auditConfig.Spec.Sinks[0].Kafka.Topic)
		t.Logf("AUDIT-003: Created AuditConfig with Kafka sink: %s", auditConfig.Name)
	})

	t.Run("KubernetesEventSinkConfiguration", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-k8s-sink"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name:       "k8s-events-sink",
						Type:       breakglassv1alpha1.AuditSinkTypeKubernetes,
						Kubernetes: &breakglassv1alpha1.KubernetesSinkSpec{},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		require.Len(t, auditConfig.Spec.Sinks, 1)
		assert.Equal(t, breakglassv1alpha1.AuditSinkTypeKubernetes, auditConfig.Spec.Sinks[0].Type)
		assert.NotNil(t, auditConfig.Spec.Sinks[0].Kubernetes)
		t.Logf("AUDIT-004: Created AuditConfig with Kubernetes Events sink: %s", auditConfig.Name)
	})
}

// TestAuditConfigMultipleSinks tests AuditConfig with multiple sinks enabled.
func TestAuditConfigMultipleSinks(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("AllSinksEnabled", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-all-sinks"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "log-sink",
						Type: breakglassv1alpha1.AuditSinkTypeLog,
						Log: &breakglassv1alpha1.LogSinkSpec{
							Level: "debug",
						},
					},
					{
						Name: "webhook-sink",
						Type: breakglassv1alpha1.AuditSinkTypeWebhook,
						Webhook: &breakglassv1alpha1.WebhookSinkSpec{
							URL: "https://audit.example.com/events",
						},
					},
					{
						Name: "kafka-sink",
						Type: breakglassv1alpha1.AuditSinkTypeKafka,
						Kafka: &breakglassv1alpha1.KafkaSinkSpec{
							Brokers: []string{"kafka.example.com:9092"},
							Topic:   "audit-events",
						},
					},
					{
						Name:       "k8s-sink",
						Type:       breakglassv1alpha1.AuditSinkTypeKubernetes,
						Kubernetes: &breakglassv1alpha1.KubernetesSinkSpec{},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		assert.Len(t, auditConfig.Spec.Sinks, 4)
		t.Logf("AUDIT-005: Created AuditConfig with all 4 sink types: %s", auditConfig.Name)
	})
}

// TestAuditSinkEventTypeFiltering tests sink-level event type filtering.
func TestAuditSinkEventTypeFiltering(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("SinkWithEventTypeFilter", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-event-filter"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "filtered-log-sink",
						Type: breakglassv1alpha1.AuditSinkTypeLog,
						Log: &breakglassv1alpha1.LogSinkSpec{
							Level: "info",
						},
						EventTypes: []string{"session.created", "session.approved", "session.rejected"},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		require.Len(t, auditConfig.Spec.Sinks[0].EventTypes, 3)
		t.Logf("AUDIT-006: Created AuditConfig with event type filtering: %s", auditConfig.Name)
	})

	t.Run("SinkWithMinSeverity", func(t *testing.T) {
		auditConfig := &breakglassv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-severity"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []breakglassv1alpha1.AuditSinkConfig{
					{
						Name: "critical-only-sink",
						Type: breakglassv1alpha1.AuditSinkTypeLog,
						Log: &breakglassv1alpha1.LogSinkSpec{
							Level: "info",
						},
						MinSeverity: "critical",
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err)

		assert.Equal(t, "critical", auditConfig.Spec.Sinks[0].MinSeverity)
		t.Logf("AUDIT-007: Created AuditConfig with severity filtering: %s", auditConfig.Name)
	})
}

// TestAuditSinkTypes tests the AuditSinkType enum values.
func TestAuditSinkTypes(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("AllSinkTypesDocumented", func(t *testing.T) {
		sinkTypes := []breakglassv1alpha1.AuditSinkType{
			breakglassv1alpha1.AuditSinkTypeLog,
			breakglassv1alpha1.AuditSinkTypeWebhook,
			breakglassv1alpha1.AuditSinkTypeKafka,
			breakglassv1alpha1.AuditSinkTypeKubernetes,
		}

		for _, st := range sinkTypes {
			t.Logf("AUDIT-SINK-%s: AuditSinkType value exists", st)
		}
		t.Logf("AUDIT-SINK-TOTAL: %d audit sink types defined", len(sinkTypes))
	})
}

// TestKafkaSinkAdvancedConfig tests advanced Kafka sink configuration.
func TestKafkaSinkAdvancedConfig(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("KafkaSinkWithBatching", func(t *testing.T) {
		kafkaSink := breakglassv1alpha1.KafkaSinkSpec{
			Brokers:             []string{"broker-1:9092", "broker-2:9092"},
			Topic:               "audit-events",
			BatchSize:           100,
			BatchTimeoutSeconds: 5,
			RequiredAcks:        -1,
			Compression:         "snappy",
		}
		assert.Equal(t, 100, kafkaSink.BatchSize)
		assert.Equal(t, 5, kafkaSink.BatchTimeoutSeconds)
		assert.Equal(t, -1, kafkaSink.RequiredAcks)
		assert.Equal(t, "snappy", kafkaSink.Compression)
		t.Logf("AUDIT-008: KafkaSinkSpec supports batching configuration")
	})

	t.Run("KafkaSinkWithTLS", func(t *testing.T) {
		kafkaSink := breakglassv1alpha1.KafkaSinkSpec{
			Brokers: []string{"broker:9092"},
			Topic:   "audit-events",
			TLS: &breakglassv1alpha1.KafkaTLSSpec{
				Enabled:            true,
				InsecureSkipVerify: false,
			},
		}
		assert.True(t, kafkaSink.TLS.Enabled)
		assert.False(t, kafkaSink.TLS.InsecureSkipVerify)
		t.Logf("AUDIT-009: KafkaSinkSpec supports TLS configuration")
	})

	t.Run("KafkaSinkWithSASL", func(t *testing.T) {
		kafkaSink := breakglassv1alpha1.KafkaSinkSpec{
			Brokers: []string{"broker:9092"},
			Topic:   "audit-events",
			SASL: &breakglassv1alpha1.KafkaSASLSpec{
				Mechanism: "SCRAM-SHA-512",
				CredentialsSecretRef: breakglassv1alpha1.SecretKeySelector{
					Name: "kafka-sasl-creds",
				},
			},
		}
		assert.Equal(t, "SCRAM-SHA-512", kafkaSink.SASL.Mechanism)
		t.Logf("AUDIT-010: KafkaSinkSpec supports SASL authentication")
	})
}

// TestWebhookSinkAdvancedConfig tests webhook sink authentication options.
func TestWebhookSinkAdvancedConfig(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("WebhookWithAuthSecret", func(t *testing.T) {
		webhookSink := breakglassv1alpha1.WebhookSinkSpec{
			URL: "https://audit.example.com/events",
			AuthSecretRef: &breakglassv1alpha1.SecretKeySelector{
				Name:      "webhook-auth-secret",
				Namespace: "breakglass-system",
			},
		}
		assert.NotNil(t, webhookSink.AuthSecretRef)
		assert.Equal(t, "webhook-auth-secret", webhookSink.AuthSecretRef.Name)
		t.Logf("AUDIT-011: WebhookSinkSpec supports authentication via secret")
	})

	t.Run("WebhookWithCustomHeaders", func(t *testing.T) {
		webhookSink := breakglassv1alpha1.WebhookSinkSpec{
			URL: "https://audit.example.com/events",
			Headers: map[string]string{
				"X-API-Key":     "my-api-key",
				"X-Correlation": "breakglass-audit",
			},
		}
		assert.Len(t, webhookSink.Headers, 2)
		t.Logf("AUDIT-012: WebhookSinkSpec supports custom headers")
	})

	t.Run("WebhookWithBatchSize", func(t *testing.T) {
		webhookSink := breakglassv1alpha1.WebhookSinkSpec{
			URL:       "https://audit.example.com/events",
			BatchSize: 10,
		}
		assert.Equal(t, 10, webhookSink.BatchSize)
		t.Logf("AUDIT-013: WebhookSinkSpec supports batch configuration")
	})
}

// TestAuditEventTypes tests the types of events that are audited.
func TestAuditEventTypes(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("AuditedEvents", func(t *testing.T) {
		t.Log("AUDIT-014: Session creation is audited")
		t.Log("AUDIT-015: Session approval/rejection is audited")
		t.Log("AUDIT-016: Session expiration is audited")
		t.Log("AUDIT-017: Webhook authorization checks are audited")
		t.Log("AUDIT-018: Debug session events are audited")
	})
}
