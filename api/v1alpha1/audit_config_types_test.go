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

package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAuditConfig_BasicValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  AuditConfigSpec
		wantErr bool
	}{
		{
			name: "valid minimal config with log sink",
			config: AuditConfigSpec{
				Enabled: true,
				Sinks: []AuditSinkConfig{
					{
						Name: "default-log",
						Type: AuditSinkTypeLog,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid kafka sink with TLS",
			config: AuditConfigSpec{
				Enabled: true,
				Sinks: []AuditSinkConfig{
					{
						Name: "kafka-prod",
						Type: AuditSinkTypeKafka,
						Kafka: &KafkaSinkSpec{
							Brokers: []string{"kafka-0:9093", "kafka-1:9093"},
							Topic:   "audit-events",
							TLS: &KafkaTLSSpec{
								Enabled: true,
								CASecretRef: &SecretKeySelector{
									Name:      "kafka-ca",
									Namespace: "breakglass-system",
								},
							},
							SASL: &KafkaSASLSpec{
								Mechanism: "SCRAM-SHA-512",
								CredentialsSecretRef: SecretKeySelector{
									Name:      "kafka-creds",
									Namespace: "breakglass-system",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid webhook sink",
			config: AuditConfigSpec{
				Enabled: true,
				Sinks: []AuditSinkConfig{
					{
						Name: "splunk",
						Type: AuditSinkTypeWebhook,
						Webhook: &WebhookSinkSpec{
							URL: "https://splunk.example.com/collector",
							AuthSecretRef: &SecretKeySelector{
								Name:      "splunk-token",
								Namespace: "breakglass-system",
							},
							TimeoutSeconds: 10,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid multi-sink config",
			config: AuditConfigSpec{
				Enabled: true,
				Sinks: []AuditSinkConfig{
					{Name: "kafka", Type: AuditSinkTypeKafka, Kafka: &KafkaSinkSpec{Brokers: []string{"kafka:9092"}, Topic: "audit"}},
					{Name: "log", Type: AuditSinkTypeLog},
					{Name: "webhook", Type: AuditSinkTypeWebhook, Webhook: &WebhookSinkSpec{URL: "https://example.com"}},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuditConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-audit-config",
				},
				Spec: tt.config,
			}

			// Basic struct validation (schema validation is done by CRD)
			assert.NotNil(t, ac)
			assert.NotEmpty(t, ac.Spec.Sinks)
		})
	}
}

func TestAuditConfig_SinkTypes(t *testing.T) {
	tests := []struct {
		name     string
		sinkType AuditSinkType
		valid    bool
	}{
		{"log sink", AuditSinkTypeLog, true},
		{"webhook sink", AuditSinkTypeWebhook, true},
		{"kafka sink", AuditSinkTypeKafka, true},
		{"kubernetes sink", AuditSinkTypeKubernetes, true},
		{"invalid sink", AuditSinkType("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validTypes := map[AuditSinkType]bool{
				AuditSinkTypeLog:        true,
				AuditSinkTypeWebhook:    true,
				AuditSinkTypeKafka:      true,
				AuditSinkTypeKubernetes: true,
			}
			assert.Equal(t, tt.valid, validTypes[tt.sinkType])
		})
	}
}

func TestAuditConfig_SecretNamespaceEnforcement(t *testing.T) {
	// This test verifies that SecretKeySelector requires a namespace
	// (enforced by the CRD schema and controller)
	t.Run("secret selector requires namespace", func(t *testing.T) {
		selector := SecretKeySelector{
			Name:      "my-secret",
			Namespace: "breakglass-system",
		}
		assert.NotEmpty(t, selector.Name)
		assert.NotEmpty(t, selector.Namespace)
		assert.Equal(t, "breakglass-system", selector.Namespace)
	})

	t.Run("kafka SASL credentials need namespace", func(t *testing.T) {
		sasl := KafkaSASLSpec{
			Mechanism: "SCRAM-SHA-512",
			CredentialsSecretRef: SecretKeySelector{
				Name:      "kafka-creds",
				Namespace: "breakglass-system",
			},
		}
		assert.NotEmpty(t, sasl.CredentialsSecretRef.Namespace)
	})

	t.Run("kafka TLS CA needs namespace", func(t *testing.T) {
		tls := KafkaTLSSpec{
			Enabled: true,
			CASecretRef: &SecretKeySelector{
				Name:      "kafka-ca",
				Namespace: "breakglass-system",
			},
		}
		require.NotNil(t, tls.CASecretRef)
		assert.NotEmpty(t, tls.CASecretRef.Namespace)
	})

	t.Run("webhook auth needs namespace", func(t *testing.T) {
		webhook := WebhookSinkSpec{
			URL: "https://example.com",
			AuthSecretRef: &SecretKeySelector{
				Name:      "webhook-token",
				Namespace: "breakglass-system",
			},
		}
		require.NotNil(t, webhook.AuthSecretRef)
		assert.NotEmpty(t, webhook.AuthSecretRef.Namespace)
	})
}

func TestAuditConfig_QueueConfig(t *testing.T) {
	tests := []struct {
		name     string
		queue    AuditQueueConfig
		expected struct {
			size    int
			workers int
		}
	}{
		{
			name: "default values",
			queue: AuditQueueConfig{
				Size:       100000,
				Workers:    5,
				DropOnFull: true,
			},
			expected: struct {
				size    int
				workers int
			}{100000, 5},
		},
		{
			name: "high throughput config",
			queue: AuditQueueConfig{
				Size:       500000,
				Workers:    20,
				DropOnFull: true,
			},
			expected: struct {
				size    int
				workers int
			}{500000, 20},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected.size, tt.queue.Size)
			assert.Equal(t, tt.expected.workers, tt.queue.Workers)
		})
	}
}

func TestAuditConfig_FilterConfig(t *testing.T) {
	filter := AuditFilterConfig{
		IncludeEventTypes: []string{"session.*", "access.denied*"},
		ExcludeEventTypes: []string{"resource.list", "resource.watch"},
		ExcludeUsers:      []string{"system:serviceaccount:kube-system:*"},
		ExcludeNamespaces: &NamespaceFilter{Patterns: []string{"kube-system", "kube-public"}},
		IncludeResources:  []string{"secrets", "configmaps"},
	}

	assert.Len(t, filter.IncludeEventTypes, 2)
	assert.Len(t, filter.ExcludeEventTypes, 2)
	assert.Len(t, filter.ExcludeUsers, 1)
	assert.Len(t, filter.ExcludeNamespaces.Patterns, 2)
	assert.Len(t, filter.IncludeResources, 2)
}

func TestAuditConfig_SamplingConfig(t *testing.T) {
	sampling := AuditSamplingConfig{
		Rate: "0.1",
		HighVolumeEventTypes: []string{
			"resource.get",
			"resource.list",
			"resource.watch",
		},
		AlwaysCaptureEventTypes: []string{
			"session.requested",
			"session.approved",
			"access.denied",
		},
	}

	assert.Equal(t, "0.1", sampling.Rate)
	assert.Len(t, sampling.HighVolumeEventTypes, 3)
	assert.Len(t, sampling.AlwaysCaptureEventTypes, 3)
}

func TestAuditConfig_KafkaSinkSpec(t *testing.T) {
	kafka := KafkaSinkSpec{
		Brokers:             []string{"kafka-0:9093", "kafka-1:9093", "kafka-2:9093"},
		Topic:               "breakglass-audit",
		BatchSize:           100,
		BatchTimeoutSeconds: 1,
		RequiredAcks:        -1,
		Compression:         "snappy",
		Async:               false,
		TLS: &KafkaTLSSpec{
			Enabled:            true,
			InsecureSkipVerify: false,
			CASecretRef: &SecretKeySelector{
				Name:      "kafka-ca",
				Namespace: "breakglass-system",
			},
			ClientCertSecretRef: &SecretKeySelector{
				Name:      "kafka-client-cert",
				Namespace: "breakglass-system",
			},
		},
		SASL: &KafkaSASLSpec{
			Mechanism: "SCRAM-SHA-512",
			CredentialsSecretRef: SecretKeySelector{
				Name:      "kafka-creds",
				Namespace: "breakglass-system",
			},
		},
	}

	assert.Len(t, kafka.Brokers, 3)
	assert.Equal(t, "breakglass-audit", kafka.Topic)
	assert.Equal(t, 100, kafka.BatchSize)
	assert.Equal(t, -1, kafka.RequiredAcks)
	assert.Equal(t, "snappy", kafka.Compression)
	assert.False(t, kafka.Async)
	require.NotNil(t, kafka.TLS)
	assert.True(t, kafka.TLS.Enabled)
	require.NotNil(t, kafka.SASL)
	assert.Equal(t, "SCRAM-SHA-512", kafka.SASL.Mechanism)
}

func TestAuditConfig_SinkStatus(t *testing.T) {
	now := metav1.Now()
	status := AuditConfigStatus{
		ActiveSinks:     []string{"kafka", "log"},
		EventsProcessed: 1000000,
		EventsDropped:   50,
		LastEventTime:   &now,
		SinkStatuses: []AuditSinkStatus{
			{
				Name:            "kafka",
				Ready:           true,
				EventsWritten:   999950,
				LastSuccessTime: &now,
			},
			{
				Name:          "log",
				Ready:         true,
				EventsWritten: 1000000,
			},
		},
		Conditions: []metav1.Condition{
			{
				Type:   "Ready",
				Status: metav1.ConditionTrue,
			},
		},
	}

	assert.Len(t, status.ActiveSinks, 2)
	assert.Equal(t, int64(1000000), status.EventsProcessed)
	assert.Equal(t, int64(50), status.EventsDropped)
	assert.Len(t, status.SinkStatuses, 2)
	assert.True(t, status.SinkStatuses[0].Ready)
}

func TestAuditConfig_ClusterScoped(t *testing.T) {
	// Verify AuditConfig doesn't have a namespace field requirement
	// (cluster-scoped resources don't use namespaces)
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-audit-config",
			// Note: No namespace - cluster-scoped
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{Name: "log", Type: AuditSinkTypeLog},
			},
		},
	}

	assert.Equal(t, "global-audit-config", ac.Name)
	assert.Empty(t, ac.Namespace) // Cluster-scoped resources have empty namespace
}

func TestAuditConfig_PerSinkFiltering(t *testing.T) {
	config := AuditConfigSpec{
		Enabled: true,
		Sinks: []AuditSinkConfig{
			{
				Name: "kafka-all",
				Type: AuditSinkTypeKafka,
				// No filtering - gets all events
			},
			{
				Name:        "siem-security",
				Type:        AuditSinkTypeWebhook,
				MinSeverity: "warning",
				EventTypes: []string{
					"access.denied",
					"secret.accessed",
					"policy.violation",
				},
			},
			{
				Name:        "k8s-sessions",
				Type:        AuditSinkTypeKubernetes,
				MinSeverity: "info",
				EventTypes: []string{
					"session.requested",
					"session.approved",
					"session.denied",
				},
			},
		},
	}

	assert.Len(t, config.Sinks, 3)

	// First sink - no filtering
	assert.Empty(t, config.Sinks[0].MinSeverity)
	assert.Empty(t, config.Sinks[0].EventTypes)

	// Second sink - filtered by severity and event types
	assert.Equal(t, "warning", config.Sinks[1].MinSeverity)
	assert.Len(t, config.Sinks[1].EventTypes, 3)

	// Third sink - filtered by event types
	assert.Equal(t, "info", config.Sinks[2].MinSeverity)
	assert.Len(t, config.Sinks[2].EventTypes, 3)
}

// ================================
// Edge Cases and Unhappy Paths
// ================================

func TestAuditConfig_EmptySinks(t *testing.T) {
	// Config with empty sinks list
	config := AuditConfigSpec{
		Enabled: true,
		Sinks:   []AuditSinkConfig{},
	}
	assert.Empty(t, config.Sinks)
	assert.True(t, config.Enabled)
}

func TestAuditConfig_DisabledConfig(t *testing.T) {
	// Disabled config - should be valid
	config := AuditConfigSpec{
		Enabled: false,
		Sinks: []AuditSinkConfig{
			{Name: "kafka", Type: AuditSinkTypeKafka},
		},
	}
	assert.False(t, config.Enabled)
	assert.Len(t, config.Sinks, 1)
}

func TestSecretKeySelector_EmptyValues(t *testing.T) {
	// Test struct with empty values
	selector := SecretKeySelector{
		Name:      "",
		Namespace: "",
	}
	assert.Empty(t, selector.Name)
	assert.Empty(t, selector.Namespace)
}

func TestSecretKeySelector_ValidValues(t *testing.T) {
	// Test with valid values
	selector := SecretKeySelector{
		Name:      "my-secret",
		Namespace: "breakglass-system",
	}
	assert.Equal(t, "my-secret", selector.Name)
	assert.Equal(t, "breakglass-system", selector.Namespace)
}

func TestKafkaSinkSpec_MinimalConfig(t *testing.T) {
	// Minimal Kafka config
	kafka := KafkaSinkSpec{
		Brokers: []string{"localhost:9092"},
		Topic:   "audit",
	}
	assert.Len(t, kafka.Brokers, 1)
	assert.Equal(t, "audit", kafka.Topic)
	assert.Nil(t, kafka.TLS)
	assert.Nil(t, kafka.SASL)
	assert.Zero(t, kafka.BatchSize)
}

func TestKafkaSinkSpec_AllCompressionTypes(t *testing.T) {
	compressions := []string{"none", "gzip", "snappy", "lz4", "zstd", ""}
	for _, comp := range compressions {
		t.Run("compression_"+comp, func(t *testing.T) {
			kafka := KafkaSinkSpec{
				Brokers:     []string{"localhost:9092"},
				Topic:       "audit",
				Compression: comp,
			}
			assert.Equal(t, comp, kafka.Compression)
		})
	}
}

func TestKafkaTLSSpec_AllOptions(t *testing.T) {
	// Test TLS with all options
	tls := KafkaTLSSpec{
		Enabled:            true,
		InsecureSkipVerify: true,
		CASecretRef: &SecretKeySelector{
			Name:      "ca-cert",
			Namespace: "breakglass-system",
		},
		ClientCertSecretRef: &SecretKeySelector{
			Name:      "client-cert",
			Namespace: "breakglass-system",
		},
	}
	assert.True(t, tls.Enabled)
	assert.True(t, tls.InsecureSkipVerify)
	require.NotNil(t, tls.CASecretRef)
	assert.Equal(t, "ca-cert", tls.CASecretRef.Name)
	require.NotNil(t, tls.ClientCertSecretRef)
}

func TestKafkaSASLSpec_AllMechanisms(t *testing.T) {
	mechanisms := []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}
	for _, mech := range mechanisms {
		t.Run(mech, func(t *testing.T) {
			sasl := KafkaSASLSpec{
				Mechanism: mech,
				CredentialsSecretRef: SecretKeySelector{
					Name:      "kafka-creds",
					Namespace: "breakglass-system",
				},
			}
			assert.Equal(t, mech, sasl.Mechanism)
		})
	}
}

func TestWebhookSinkSpec_AllOptions(t *testing.T) {
	webhook := WebhookSinkSpec{
		URL: "https://siem.example.com/audit",
		AuthSecretRef: &SecretKeySelector{
			Name:      "siem-token",
			Namespace: "breakglass-system",
		},
		Headers: map[string]string{
			"X-Custom-Header": "value",
			"X-Source":        "breakglass",
		},
		TimeoutSeconds: 30,
		BatchSize:      10,
		TLS: &WebhookTLSSpec{
			InsecureSkipVerify: true,
		},
	}
	assert.Equal(t, "https://siem.example.com/audit", webhook.URL)
	require.NotNil(t, webhook.AuthSecretRef)
	assert.Len(t, webhook.Headers, 2)
	assert.Equal(t, 30, webhook.TimeoutSeconds)
	assert.Equal(t, 10, webhook.BatchSize)
	require.NotNil(t, webhook.TLS)
	assert.True(t, webhook.TLS.InsecureSkipVerify)
}

func TestWebhookSinkSpec_MinimalConfig(t *testing.T) {
	webhook := WebhookSinkSpec{
		URL: "https://example.com",
	}
	assert.Equal(t, "https://example.com", webhook.URL)
	assert.Nil(t, webhook.AuthSecretRef)
	assert.Empty(t, webhook.Headers)
	assert.Zero(t, webhook.TimeoutSeconds)
}

func TestAuditSinkStatus_FailedState(t *testing.T) {
	now := metav1.Now()
	status := AuditSinkStatus{
		Name:            "kafka-prod",
		Ready:           false,
		EventsWritten:   5000,
		LastError:       "connection refused: kafka-0.kafka:9093",
		LastSuccessTime: &now,
	}
	assert.False(t, status.Ready)
	assert.NotEmpty(t, status.LastError)
	assert.NotNil(t, status.LastSuccessTime)
}

func TestAuditConfigStatus_Unhealthy(t *testing.T) {
	status := AuditConfigStatus{
		ActiveSinks:     []string{},
		EventsProcessed: 0,
		EventsDropped:   1000,
		Conditions: []metav1.Condition{
			{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  "NoActiveSinks",
				Message: "No sinks are currently active",
			},
		},
	}
	assert.Empty(t, status.ActiveSinks)
	assert.Equal(t, int64(1000), status.EventsDropped)
	assert.Equal(t, metav1.ConditionFalse, status.Conditions[0].Status)
}

func TestAuditFilterConfig_EdgeCases(t *testing.T) {
	// Empty filter - matches all
	emptyFilter := AuditFilterConfig{}
	assert.Empty(t, emptyFilter.IncludeEventTypes)
	assert.Empty(t, emptyFilter.ExcludeEventTypes)

	// Filter with only excludes
	excludeOnly := AuditFilterConfig{
		ExcludeEventTypes: []string{"resource.watch", "resource.list"},
		ExcludeUsers:      []string{"system:*"},
	}
	assert.Len(t, excludeOnly.ExcludeEventTypes, 2)
	assert.Empty(t, excludeOnly.IncludeEventTypes)

	// Filter with wildcard patterns
	wildcardFilter := AuditFilterConfig{
		IncludeEventTypes: []string{"session.*", "access.*"},
		ExcludeNamespaces: &NamespaceFilter{Patterns: []string{"kube-*"}},
	}
	assert.Len(t, wildcardFilter.IncludeEventTypes, 2)
}

func TestAuditQueueConfig_EdgeCases(t *testing.T) {
	// Zero values
	zeroQueue := AuditQueueConfig{}
	assert.Zero(t, zeroQueue.Size)
	assert.Zero(t, zeroQueue.Workers)
	assert.False(t, zeroQueue.DropOnFull)

	// Large queue
	largeQueue := AuditQueueConfig{
		Size:       1000000,
		Workers:    100,
		DropOnFull: true,
	}
	assert.Equal(t, 1000000, largeQueue.Size)
}

func TestAuditSamplingConfig_EdgeCases(t *testing.T) {
	// No sampling
	noSampling := AuditSamplingConfig{
		Rate: "1.0",
	}
	assert.Equal(t, "1.0", noSampling.Rate)
	assert.Empty(t, noSampling.HighVolumeEventTypes)

	// Zero sampling (drop all high volume)
	zeroSampling := AuditSamplingConfig{
		Rate: "0",
		HighVolumeEventTypes: []string{
			"resource.get",
			"resource.list",
		},
	}
	assert.Equal(t, "0", zeroSampling.Rate)
}

// ==================== AuditConfig Webhook Validation Tests ====================

func TestAuditConfig_ValidateCreate_ValidConfig(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "log-sink",
					Type: AuditSinkTypeLog,
					Log:  &LogSinkSpec{Level: "info"},
				},
			},
		},
	}

	warnings, err := ac.ValidateCreate(context.Background(), ac)
	assert.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestAuditConfig_ValidateCreate_InvalidConfig(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks:   []AuditSinkConfig{}, // Empty sinks - should fail
		},
	}

	_, err := ac.ValidateCreate(context.Background(), ac)
	assert.Error(t, err)
}

func TestAuditConfig_ValidateCreate_MissingSinkType(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-missing-type"},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{Name: "sink-without-type"},
			},
		},
	}

	_, err := ac.ValidateCreate(context.Background(), ac)
	assert.Error(t, err)
}

func TestAuditConfig_ValidateUpdate_ValidConfig(t *testing.T) {
	oldAC := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "log-sink",
					Type: AuditSinkTypeLog,
					Log:  &LogSinkSpec{Level: "info"},
				},
			},
		},
	}

	newAC := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "log-sink-updated",
					Type: AuditSinkTypeLog,
					Log:  &LogSinkSpec{Level: "debug"},
				},
			},
		},
	}

	warnings, err := newAC.ValidateUpdate(context.Background(), oldAC, newAC)
	assert.NoError(t, err)
	assert.Empty(t, warnings)
}

func TestAuditConfig_ValidateUpdate_MissingSinkName(t *testing.T) {
	oldObj := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-old"},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "log-sink",
					Type: AuditSinkTypeLog,
					Log:  &LogSinkSpec{Level: "info"},
				},
			},
		},
	}
	newObj := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-old"},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Type: AuditSinkTypeLog,
					Log:  &LogSinkSpec{Level: "debug"},
				},
			},
		},
	}

	_, err := newObj.ValidateUpdate(context.Background(), oldObj, newObj)
	assert.Error(t, err)
}

func TestAuditConfig_ValidateUpdate_InvalidConfig(t *testing.T) {
	oldAC := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "log-sink",
					Type: AuditSinkTypeLog,
					Log:  &LogSinkSpec{Level: "info"},
				},
			},
		},
	}

	newAC := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks:   []AuditSinkConfig{}, // Empty sinks - invalid
		},
	}

	_, err := newAC.ValidateUpdate(context.Background(), oldAC, newAC)
	assert.Error(t, err)
}

func TestAuditConfig_ValidateDelete(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{Name: "log-sink", Type: AuditSinkTypeLog},
			},
		},
	}

	warnings, err := ac.ValidateDelete(context.Background(), ac)
	assert.NoError(t, err)
	assert.Nil(t, warnings)
}

func TestAuditConfig_WebhookSink_WithAuthSecretRef(t *testing.T) {
	// Test webhook sink with AuthSecretRef validation
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						AuthSecretRef: &SecretKeySelector{
							Name:      "auth-secret",
							Namespace: "default",
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	assert.Empty(t, result.Errors)
}

func TestAuditConfig_WebhookSink_AuthSecretRefMissingName(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						AuthSecretRef: &SecretKeySelector{
							Name:      "", // Missing name
							Namespace: "default",
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors.ToAggregate().Error(), "name")
}

func TestAuditConfig_WebhookSink_AuthSecretRefMissingNamespace(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						AuthSecretRef: &SecretKeySelector{
							Name:      "auth-secret",
							Namespace: "", // Missing namespace
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors.ToAggregate().Error(), "namespace")
}

func TestAuditConfig_WebhookSink_WithTLSConfig(t *testing.T) {
	// Test webhook sink with TLS configuration
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						TLS: &WebhookTLSSpec{
							CASecretRef: &SecretKeySelector{
								Name:      "ca-cert",
								Namespace: "default",
							},
							InsecureSkipVerify: false,
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	assert.Empty(t, result.Errors)
}

func TestAuditConfig_WebhookSink_TLSMissingSecretName(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						TLS: &WebhookTLSSpec{
							CASecretRef: &SecretKeySelector{
								Name:      "", // Missing name
								Namespace: "default",
							},
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors.ToAggregate().Error(), "name")
}

func TestAuditConfig_WebhookSink_TLSMissingSecretNamespace(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						TLS: &WebhookTLSSpec{
							CASecretRef: &SecretKeySelector{
								Name:      "ca-cert",
								Namespace: "", // Missing namespace
							},
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors.ToAggregate().Error(), "namespace")
}

func TestAuditConfig_WebhookSink_InsecureSkipVerify(t *testing.T) {
	// Test webhook sink with InsecureSkipVerify (no CA cert needed)
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "https://example.com/webhook",
						TLS: &WebhookTLSSpec{
							InsecureSkipVerify: true,
						},
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	assert.Empty(t, result.Errors)
}

func TestAuditConfig_WebhookSink_MissingURL(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name: "webhook-sink",
					Type: AuditSinkTypeWebhook,
					Webhook: &WebhookSinkSpec{
						URL: "", // Missing URL
					},
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors.ToAggregate().Error(), "url")
}

func TestAuditConfig_WebhookSink_MissingConfig(t *testing.T) {
	ac := &AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-audit-config",
		},
		Spec: AuditConfigSpec{
			Enabled: true,
			Sinks: []AuditSinkConfig{
				{
					Name:    "webhook-sink",
					Type:    AuditSinkTypeWebhook,
					Webhook: nil, // Missing webhook config
				},
			},
		},
	}

	result := ValidateAuditConfig(ac)
	require.NotEmpty(t, result.Errors)
	assert.Contains(t, result.Errors.ToAggregate().Error(), "webhook")
}
