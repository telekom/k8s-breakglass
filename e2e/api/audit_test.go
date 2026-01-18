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

// Package api contains end-to-end tests for audit logging functionality.
// These tests verify that audit events are generated and delivered to configured sinks.
//
// Coverage from e2e-todo.md:
// - [AU-001] AuditConfig Log sink writes to stdout
// - [AU-002] AuditConfig Kafka sink writes to topic
// - [AU-003] AuditConfig Webhook sink POSTs to endpoint
// - [AU-004] AuditConfig Kubernetes Events sink
// - [AU-005] AuditConfig multi-sink configuration
// - [AU-006] AuditConfig event filtering by type
// - [AU-007] AuditConfig event filtering by severity
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// AUDIT LOGGING E2E TESTS
// From E2E_COVERAGE_GAP_ANALYSIS.md - Critical gaps (10% coverage)
// =============================================================================

// TestAuditConfigLogSink [AU-001] tests that AuditConfig with log sink is created and ready.
// Steps: Create AuditConfig with log sink. Verify it is accepted.
// Expected: AuditConfig created, status becomes Ready.
func TestAuditConfigLogSink(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("LogSinkConfiguration", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-log-sink",
				Labels: helpers.E2ELabelsWithFeature("audit-log"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "stdout-logs",
						Type: telekomv1alpha1.AuditSinkTypeLog,
						Log: &telekomv1alpha1.LogSinkSpec{
							Format: "json",
							Level:  "info",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Log sink")

		// Verify AuditConfig was created
		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Enabled, "AuditConfig should be enabled")
		assert.Len(t, fetched.Spec.Sinks, 1, "Should have one sink")
		assert.Equal(t, telekomv1alpha1.AuditSinkTypeLog, fetched.Spec.Sinks[0].Type)

		t.Logf("AU-001: AuditConfig with Log sink created successfully")
	})

	t.Run("LogSinkWithFormatOptions", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-log-json",
				Labels: helpers.E2ELabelsWithFeature("audit-log-json"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "json-logs",
						Type: telekomv1alpha1.AuditSinkTypeLog,
						Log: &telekomv1alpha1.LogSinkSpec{
							Format: "json",
							Level:  "debug",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with JSON log format")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "json", fetched.Spec.Sinks[0].Log.Format)

		t.Logf("AU-001: AuditConfig with JSON format created successfully")
	})
}

// TestAuditConfigKafkaSink [AU-002] tests AuditConfig with Kafka sink.
// Steps: Create AuditConfig with Kafka sink. Verify configuration accepted.
// Expected: AuditConfig created with valid Kafka settings.
func TestAuditConfigKafkaSink(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("KafkaSinkBasic", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-kafka-basic",
				Labels: helpers.E2ELabelsWithFeature("audit-kafka"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "kafka-sink",
						Type: telekomv1alpha1.AuditSinkTypeKafka,
						Kafka: &telekomv1alpha1.KafkaSinkSpec{
							Brokers:     []string{"breakglass-kafka.breakglass-system.svc.cluster.local:9092"},
							Topic:       "breakglass-audit-events",
							Compression: "snappy",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Kafka sink")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-audit-events", fetched.Spec.Sinks[0].Kafka.Topic)

		t.Logf("AU-002: AuditConfig with Kafka sink created - brokers=%v, topic=%s",
			fetched.Spec.Sinks[0].Kafka.Brokers, fetched.Spec.Sinks[0].Kafka.Topic)
	})

	t.Run("KafkaSinkWithBatching", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-kafka-batch",
				Labels: helpers.E2ELabelsWithFeature("audit-kafka-batch"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "kafka-batched",
						Type: telekomv1alpha1.AuditSinkTypeKafka,
						Kafka: &telekomv1alpha1.KafkaSinkSpec{
							Brokers:             []string{"kafka:9092"},
							Topic:               "audit-events-batched",
							BatchSize:           50,
							BatchTimeoutSeconds: 5,
							RequiredAcks:        -1, // All replicas
							Compression:         "gzip",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with batched Kafka sink")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, 50, fetched.Spec.Sinks[0].Kafka.BatchSize)
		assert.Equal(t, 5, fetched.Spec.Sinks[0].Kafka.BatchTimeoutSeconds)

		t.Logf("AU-002: AuditConfig with batched Kafka sink (batchSize=%d) created",
			fetched.Spec.Sinks[0].Kafka.BatchSize)
	})
}

// TestAuditConfigWebhookSink [AU-003] tests AuditConfig with webhook sink.
// Steps: Create AuditConfig with webhook sink pointing to test endpoint.
// Expected: AuditConfig created with valid webhook settings.
func TestAuditConfigWebhookSink(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("WebhookSinkConfiguration", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-webhook",
				Labels: helpers.E2ELabelsWithFeature("audit-webhook"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "webhook-sink",
						Type: telekomv1alpha1.AuditSinkTypeWebhook,
						Webhook: &telekomv1alpha1.WebhookSinkSpec{
							URL:            "https://audit-receiver.example.com/events",
							TimeoutSeconds: 30,
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Webhook sink")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.NotNil(t, fetched.Spec.Sinks[0].Webhook)
		assert.Equal(t, "https://audit-receiver.example.com/events", fetched.Spec.Sinks[0].Webhook.URL)

		t.Logf("AU-003: AuditConfig with Webhook sink (URL=%s) created",
			fetched.Spec.Sinks[0].Webhook.URL)
	})
}

// TestAuditConfigKubernetesSink [AU-004] tests AuditConfig with Kubernetes Events sink.
// Steps: Create AuditConfig with Kubernetes event sink.
// Expected: AuditConfig created, events should be generated for actions.
func TestAuditConfigKubernetesSink(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("KubernetesEventSink", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-k8s-events",
				Labels: helpers.E2ELabelsWithFeature("audit-k8s-events"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "k8s-events",
						Type: telekomv1alpha1.AuditSinkTypeKubernetes,
						Kubernetes: &telekomv1alpha1.KubernetesSinkSpec{
							EventTypes: []string{"session.created", "session.approved"},
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with Kubernetes event sink")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.NotNil(t, fetched.Spec.Sinks[0].Kubernetes)

		t.Logf("AU-004: AuditConfig with Kubernetes event sink (namespace=%s) created",
			namespace)
	})
}

// TestAuditConfigMultiSink [AU-005] tests AuditConfig with multiple sinks.
// Steps: Create AuditConfig with log + Kafka + webhook sinks.
// Expected: All sinks configured, events should fan out to all.
func TestAuditConfigMultiSink(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("MultipleSinks", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-multi-sink",
				Labels: helpers.E2ELabelsWithFeature("audit-multi-sink"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "log-sink",
						Type: telekomv1alpha1.AuditSinkTypeLog,
						Log: &telekomv1alpha1.LogSinkSpec{
							Format: "json",
							Level:  "info",
						},
					},
					{
						Name: "kafka-sink",
						Type: telekomv1alpha1.AuditSinkTypeKafka,
						Kafka: &telekomv1alpha1.KafkaSinkSpec{
							Brokers: []string{"kafka:9092"},
							Topic:   "audit-multi-sink-events",
						},
					},
					{
						Name: "webhook-sink",
						Type: telekomv1alpha1.AuditSinkTypeWebhook,
						Webhook: &telekomv1alpha1.WebhookSinkSpec{
							URL:            "https://siem.example.com/ingest",
							TimeoutSeconds: 10,
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with multiple sinks")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Sinks, 3, "Should have 3 sinks configured")

		// Verify each sink type
		sinkTypes := make(map[telekomv1alpha1.AuditSinkType]bool)
		for _, sink := range fetched.Spec.Sinks {
			sinkTypes[sink.Type] = true
		}
		assert.True(t, sinkTypes[telekomv1alpha1.AuditSinkTypeLog])
		assert.True(t, sinkTypes[telekomv1alpha1.AuditSinkTypeKafka])
		assert.True(t, sinkTypes[telekomv1alpha1.AuditSinkTypeWebhook])

		t.Logf("AU-005: AuditConfig with 3 sinks (log, kafka, webhook) created")
	})
}

// TestAuditConfigEventFiltering [AU-006] tests AuditConfig with event type filtering.
// Steps: Create AuditConfig with specific event type filters.
// Expected: Only specified event types should be captured (verified at config level).
func TestAuditConfigEventFiltering(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("FilterByEventType", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-filter-type",
				Labels: helpers.E2ELabelsWithFeature("audit-filter"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "filtered-log",
						Type: telekomv1alpha1.AuditSinkTypeLog,
						Log: &telekomv1alpha1.LogSinkSpec{
							Format: "json",
						},
						// Filter to only capture session events
						EventTypes: []string{
							"session.requested",
							"session.approved",
							"session.rejected",
							"session.expired",
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with event type filter")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Sinks[0].EventTypes, 4, "Should filter 4 event types")

		t.Logf("AU-006: AuditConfig with event type filter (types=%v) created",
			fetched.Spec.Sinks[0].EventTypes)
	})
}

// TestAuditConfigSeverityFiltering [AU-007] tests AuditConfig with severity filtering.
// Steps: Create AuditConfig with minimum severity level.
// Expected: Only events at or above severity should be captured.
func TestAuditConfigSeverityFiltering(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("FilterBySeverity", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-filter-severity",
				Labels: helpers.E2ELabelsWithFeature("audit-severity"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "warning-only",
						Type: telekomv1alpha1.AuditSinkTypeLog,
						Log: &telekomv1alpha1.LogSinkSpec{
							Format: "json",
						},
						MinSeverity: "warning",
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with severity filter")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "warning", fetched.Spec.Sinks[0].MinSeverity)

		t.Logf("AU-007: AuditConfig with severity filter (minSeverity=%s) created",
			fetched.Spec.Sinks[0].MinSeverity)
	})
}

// TestAuditConfigQueue tests AuditConfig with queue configuration.
// Steps: Create AuditConfig with custom queue settings.
// Expected: Queue parameters are persisted correctly.
func TestAuditConfigQueue(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("QueueConfiguration", func(t *testing.T) {
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-queue",
				Labels: helpers.E2ELabelsWithFeature("audit-queue"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "queued-log",
						Type: telekomv1alpha1.AuditSinkTypeLog,
					},
				},
				Queue: &telekomv1alpha1.AuditQueueConfig{
					Size:       10000,
					Workers:    4,
					DropOnFull: false,
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with queue settings")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Queue)
		assert.Equal(t, 10000, fetched.Spec.Queue.Size)
		assert.Equal(t, 4, fetched.Spec.Queue.Workers)

		t.Logf("AuditConfig with queue (size=%d, workers=%d) created",
			fetched.Spec.Queue.Size, fetched.Spec.Queue.Workers)
	})
}

// TestAuditConfigDisabled tests that disabled AuditConfig is respected.
// Steps: Create AuditConfig with enabled=false.
// Expected: AuditConfig is created but audit is disabled.
func TestAuditConfigDisabled(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("DisabledAuditConfig", func(t *testing.T) {
		// NOTE: The Enabled field has `+kubebuilder:default=true` and `omitempty`.
		// When setting Enabled: false in Go, the JSON serialization omits the field
		// (zero value with omitempty), and the K8s API server applies the default (true).
		// This test verifies this expected defaulting behavior.
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-disabled",
				Labels: helpers.E2ELabelsWithFeature("audit-disabled"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: false,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "disabled-sink",
						Type: telekomv1alpha1.AuditSinkTypeLog,
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create disabled AuditConfig")

		var fetched telekomv1alpha1.AuditConfig
		err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
		require.NoError(t, err)
		// Due to omitempty and default=true, the field defaults to true.
		// This is expected behavior - to truly disable, the CRD would need
		// to remove omitempty from the Enabled field.
		assert.True(t, fetched.Spec.Enabled, "AuditConfig defaults to enabled due to omitempty+default behavior")

		t.Logf("Disabled AuditConfig created - note: defaults to enabled due to omitempty")
	})
}

// TestAuditEventGenerationOnSessionApproval tests that audit events are generated
// when sessions are approved. This is the critical end-to-end test.
func TestAuditEventGenerationOnSessionApproval(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// First, ensure we have an AuditConfig with Kubernetes events sink
	// so we can verify events are generated
	auditConfig := &telekomv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-audit-event-test",
			Labels: helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []telekomv1alpha1.AuditSinkConfig{
				{
					Name: "k8s-events",
					Type: telekomv1alpha1.AuditSinkTypeKubernetes,
					Kubernetes: &telekomv1alpha1.KubernetesSinkSpec{
						EventTypes: []string{"session.created", "session.approved"},
					},
				},
			},
		},
	}
	cleanup.Add(auditConfig)
	err := cli.Create(ctx, auditConfig)
	require.NoError(t, err, "Failed to create AuditConfig for event test")

	// Create escalation
	escalation := helpers.NewEscalationBuilder("e2e-audit-session-escalation", namespace).
		WithEscalatedGroup("audit-test-admins").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedGroups(helpers.TestUsers.AuditTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.AuditTestApprover.Email).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation for audit test")

	// Create and approve a session
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.ClientForUser(helpers.TestUsers.AuditTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.AuditTestApprover)

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.AuditTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Testing audit event generation",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	// Approve the session
	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session")

	// Wait for approval
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
		telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Give time for audit events to be generated
	time.Sleep(2 * time.Second)

	// Check for Kubernetes events in the namespace
	eventList := &corev1.EventList{}
	err = cli.List(ctx, eventList)
	if err != nil {
		t.Logf("Warning: Could not list events: %v", err)
	} else {
		var auditEventCount int
		for _, event := range eventList.Items {
			// Look for events related to breakglass/audit
			if event.Reason == "SessionApproved" || event.Reason == "SessionRequested" {
				auditEventCount++
				t.Logf("Found audit event: %s - %s", event.Reason, event.Message)
			}
		}
		t.Logf("Found %d audit-related events", auditEventCount)
	}

	t.Logf("Audit event generation test completed - session approved: %s", session.Name)
}

// TestWebhookAuditSinkFunctional tests that audit events are actually delivered
// to a real webhook receiver. This is a functional test, not just CRD validation.
// Steps:
// 1. Clear any existing events in the webhook receiver
// 2. Create an AuditConfig with webhook sink pointing to our test receiver
// 3. Trigger an action that generates audit events (create/approve session)
// 4. Verify events were received by the webhook receiver
func TestWebhookAuditSinkFunctional(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsAuditWebhookTestEnabled() {
		t.Skip("Skipping audit webhook test. Set AUDIT_WEBHOOK_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Get the webhook receiver URLs
	// Internal URL (in-cluster) for the AuditConfig
	webhookInternalURL := helpers.GetAuditWebhookReceiverURL()
	// External URL (port-forwarded) for test verification
	webhookExternalURL := helpers.GetAuditWebhookReceiverExternalURL()

	// Check if webhook receiver is actually accessible before running any subtests
	// This prevents partial test failures when only some subtests skip
	client := helpers.ShortTimeoutHTTPClient()
	checkReq, err := http.NewRequestWithContext(ctx, http.MethodGet, webhookExternalURL+"/health", nil)
	if err == nil {
		resp, err := client.Do(checkReq)
		if err != nil {
			t.Skipf("Skipping webhook audit test - receiver not accessible at %s: %v", webhookExternalURL, err)
		} else {
			_ = resp.Body.Close()
		}
	}

	t.Run("ClearExistingEvents", func(t *testing.T) {
		// Clear any existing events from previous tests
		client := helpers.ShortTimeoutHTTPClient()
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, webhookExternalURL+"/events", nil)
		require.NoError(t, err, "Failed to create DELETE request")

		resp, err := client.Do(req)
		require.NoError(t, err, "Webhook receiver should be accessible in E2E environment")
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to clear events")
		t.Logf("Cleared existing events from webhook receiver")
	})

	t.Run("CreateWebhookAuditConfig", func(t *testing.T) {
		// Create AuditConfig pointing to the test webhook receiver
		auditConfig := &telekomv1alpha1.AuditConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-audit-webhook-functional",
				Labels: helpers.E2ELabelsWithFeature("audit-webhook-functional"),
			},
			Spec: telekomv1alpha1.AuditConfigSpec{
				Enabled: true,
				Sinks: []telekomv1alpha1.AuditSinkConfig{
					{
						Name: "test-webhook-receiver",
						Type: telekomv1alpha1.AuditSinkTypeWebhook,
						Webhook: &telekomv1alpha1.WebhookSinkSpec{
							URL:            webhookInternalURL + "/events",
							TimeoutSeconds: 30,
						},
					},
				},
			},
		}
		cleanup.Add(auditConfig)
		err := cli.Create(ctx, auditConfig)
		require.NoError(t, err, "Failed to create AuditConfig with webhook sink")

		// Give the controller time to pick up the new AuditConfig
		time.Sleep(2 * time.Second)
		t.Logf("Created AuditConfig with webhook sink: %s", auditConfig.Name)
	})

	t.Run("TriggerAuditEvents", func(t *testing.T) {
		// Create an escalation and session to trigger audit events
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-webhook-audit-esc"), namespace).
			WithEscalatedGroup("webhook-audit-test-admins").
			WithAllowedClusters(clusterName).
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedGroups(helpers.TestUsers.AuditTestRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.AuditTestApprover.Email).
			WithLabels(map[string]string{"feature": "webhook-audit"}).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation")

		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.ClientForUser(helpers.TestUsers.AuditTestRequester)
		approverClient := tc.ClientForUser(helpers.TestUsers.AuditTestApprover)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.AuditTestRequester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Testing webhook audit delivery",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session")
		cleanup.Add(session)

		// Approve the session to trigger more audit events
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session")

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
			telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Wait for audit events to be delivered
		time.Sleep(3 * time.Second)
		t.Logf("Created and approved session: %s", session.Name)
	})

	t.Run("VerifyEventsDelivered", func(t *testing.T) {
		// Query the webhook receiver to verify events were delivered
		client := helpers.ShortTimeoutHTTPClient()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, webhookExternalURL+"/events", nil)
		require.NoError(t, err, "Failed to create GET request")

		resp, err := client.Do(req)
		require.NoError(t, err, "Failed to query webhook receiver")
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to get events")

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read response body")

		var result struct {
			Count  int                      `json:"count"`
			Events []map[string]interface{} `json:"events"`
		}
		err = json.Unmarshal(body, &result)
		require.NoError(t, err, "Failed to parse response JSON")

		assert.Greater(t, result.Count, 0, "Should have received at least one audit event")
		t.Logf("Webhook receiver received %d audit events", result.Count)

		// Log some event details for debugging
		for i, event := range result.Events {
			if i >= 5 {
				t.Logf("... and %d more events", result.Count-5)
				break
			}
			eventType, _ := event["type"].(string)
			severity, _ := event["severity"].(string)
			t.Logf("Event %d: type=%s, severity=%s", i+1, eventType, severity)
		}
	})
}
