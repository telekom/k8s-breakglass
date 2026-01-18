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

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/audit"
)

// maxKafkaReadErrors is the maximum number of consecutive Kafka read errors before giving up.
// This prevents infinite loops when Kafka is unavailable or misconfigured.
// Set to 60 to allow up to 60 seconds of waiting (with 1s MaxWait per read).
const maxKafkaReadErrors = 60

// AuditEvent represents the structure of the audit event JSON (matches pkg/audit/types.go Event)
type AuditEvent struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Timestamp string                 `json:"timestamp"`
	Actor     AuditActor             `json:"actor"`
	Target    AuditTarget            `json:"target"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// AuditActor represents who triggered the event
type AuditActor struct {
	User string `json:"user"`
}

// AuditTarget represents what was affected
type AuditTarget struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Cluster   string `json:"cluster,omitempty"`
}

func TestAuditLogging(t *testing.T) {
	// Skip if KAFKA_TEST is not set - Kafka tests require special infrastructure
	if os.Getenv("KAFKA_TEST") != "true" {
		t.Skip("Skipping Kafka audit test: KAFKA_TEST != true")
	}

	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Ensure Kafka is accessible on localhost:9094
	// We try to connect first. If it fails, we try to start a port-forward.
	// This handles both cases:
	// 1. CI/Script already set up port-forward (port 9094 taken and listening)
	// 2. Local run without script (port 9094 free, we start it)

	conn, err := net.DialTimeout("tcp", "localhost:9094", 1*time.Second)
	if err == nil {
		conn.Close()
		t.Log("Kafka TCP port accessible on localhost:9094")
	} else {
		t.Log("Starting port-forward for Kafka on localhost:9094")
		// Try to start port forward
		// Note: This might fail if port is taken but not responding, or if we don't have permissions
		_, stopPF := helpers.StartPortForward(t, ctx, "breakglass-system", "breakglass-kafka", 9094, 9094)
		defer stopPF()

		// Wait for port-forward to be ready
		time.Sleep(2 * time.Second)
	}

	// Validate Kafka is actually responding at the protocol level
	// TCP connection works doesn't mean Kafka is working - verify with actual Kafka API call
	t.Log("Validating Kafka connectivity at protocol level...")
	kafkaConn, err := kafka.DialContext(ctx, "tcp", "localhost:9094")
	if err != nil {
		t.Fatalf("Failed to connect to Kafka at localhost:9094: %v (port-forward may not be working)", err)
	}

	// Fetch cluster metadata to verify Kafka is responding
	brokers, err := kafkaConn.Brokers()
	if err != nil {
		kafkaConn.Close()
		t.Fatalf("Failed to fetch Kafka brokers: %v (Kafka may not be ready)", err)
	}
	t.Logf("✓ Kafka connectivity verified, brokers: %v", brokers)

	// Also verify we can read topic metadata
	partitions, err := kafkaConn.ReadPartitions("breakglass-audit-events")
	if err != nil {
		// Topic might not exist yet - this is OK, it will be auto-created
		t.Logf("Note: Could not read partitions for topic (may be auto-created): %v", err)
	} else {
		t.Logf("✓ Topic 'breakglass-audit-events' has %d partitions", len(partitions))
	}
	kafkaConn.Close()

	// Connect to Kafka
	// The topic "breakglass-audit-events" is defined in config/dev/resources/crs/audit-config-test.yaml
	// IMPORTANT: Use a UNIQUE consumer group per test run to avoid stale offset issues.
	// Consumer groups remember their last committed offset, so reusing the same group name
	// across test runs would cause the consumer to skip old messages.
	consumerGroupID := fmt.Sprintf("e2e-audit-test-%d", time.Now().UnixNano())
	t.Logf("Using Kafka consumer group: %s", consumerGroupID)

	kafkaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{"localhost:9094"},
		Topic:    "breakglass-audit-events",
		GroupID:  consumerGroupID, // Unique group per test run reads from all partitions
		MinBytes: 1,               // Read even small messages immediately
		MaxBytes: 10e6,            // 10MB
		MaxWait:  1 * time.Second, // Wait up to 1 second for new messages
		// With a fresh GroupID, StartOffset=FirstOffset will read from beginning
		StartOffset: kafka.FirstOffset,
	})
	defer kafkaReader.Close()

	// Log connection info
	t.Logf("Connected to Kafka with consumer group, will read from all partitions")

	// Give Kafka reader a moment to connect and join the consumer group
	time.Sleep(2 * time.Second)

	// CRITICAL: Wait for AuditConfig to be Ready BEFORE creating sessions.
	// The AuditConfig is applied during e2e setup, but the reconciler needs time to:
	// 1. Validate the config
	// 2. Build sinks (Kafka, webhook, log)
	// 3. Reload the audit service
	// Without this wait, audit events may be silently dropped because IsEnabled() returns false.
	// The AuditConfig name is "breakglass-e2e-audit-config" (prefixed by kind-setup-single.sh)
	auditConfigName := "breakglass-e2e-audit-config"
	t.Logf("Waiting for AuditConfig %s to be Ready...", auditConfigName)
	auditCfg := helpers.WaitForAuditConfigReady(t, ctx, cli, auditConfigName, helpers.WaitForConditionTimeout)
	t.Logf("AuditConfig %s is Ready with sinks: %v", auditConfigName, auditCfg.Status.ActiveSinks)

	// Additional wait for audit service to connect to Kafka
	// The AuditConfig being Ready means the controller has validated the config,
	// but the audit service inside the controller needs time to:
	// 1. Receive the config reload signal
	// 2. Build and start the Kafka producer
	// 3. Establish connection to Kafka broker
	t.Log("Waiting additional 5s for audit service to connect to Kafka...")
	time.Sleep(5 * time.Second)

	// 1. Create a Breakglass Session
	// Use unique name to avoid collisions and for filtering audit logs
	sessionName := helpers.GenerateUniqueName("audit-test")
	t.Logf("Creating session for audit test: %s", sessionName)

	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	// Pre-cleanup: Delete any existing sessions for the audit-test-group to avoid 409 "already approved" errors.
	// This handles stale sessions from previous test runs that haven't expired yet.
	existingSessions := &telekomv1alpha1.BreakglassSessionList{}
	if err := cli.List(ctx, existingSessions, client.InNamespace("breakglass-system"),
		client.MatchingLabels{"breakglass.t-caas.telekom.com/group": "audit-test-group"}); err == nil {
		for i := range existingSessions.Items {
			s := &existingSessions.Items[i]
			t.Logf("Deleting stale audit-test-group session: %s/%s (state: %s)", s.Namespace, s.Name, s.Status.State)
			if delErr := cli.Delete(ctx, s); delErr != nil && !apierrors.IsNotFound(delErr) {
				t.Logf("Warning: failed to delete stale session %s: %v", s.Name, delErr)
			}
		}
		// Wait a moment for deletion to propagate
		if len(existingSessions.Items) > 0 {
			time.Sleep(1 * time.Second)
		}
	}

	// Create via API
	session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   "audit-test-group", // Must match test-audit-escalation's escalatedGroup in e2e/fixtures/escalations/audit-test.yaml
		Reason:  "Audit logging test",
	})
	require.NoError(t, err)

	// Add to cleanup
	cleanup.Add(&telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
	})

	// 2. Approve the session
	t.Logf("Approving session: %s", sessionName)
	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
	require.NoError(t, err)

	// 3. Wait for session to be Ready/Active
	helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// 4. Verify Audit Events
	// We expect:
	// - session.requested (when session is created)
	// - session.approved (when session is approved)

	expectedEvents := map[string]bool{
		string(audit.EventSessionRequested): false,
		string(audit.EventSessionApproved):  false,
	}

	// Read messages from Kafka
	// We'll try to read for a few seconds
	readCtx, readCancel := context.WithTimeout(ctx, helpers.WaitForStateTimeout)
	defer readCancel()

	t.Log("Reading audit events from Kafka...")

	foundCount := 0
	totalMessages := 0
	consecutiveErrors := 0
	allEvents := make([]string, 0) // For diagnostics

	for foundCount < len(expectedEvents) {
		m, err := kafkaReader.ReadMessage(readCtx)
		if err != nil {
			// Check for context deadline using multiple methods since kafka-go wraps errors
			if errors.Is(err, context.DeadlineExceeded) ||
				errors.Is(readCtx.Err(), context.DeadlineExceeded) ||
				strings.Contains(err.Error(), "context deadline exceeded") {
				consecutiveErrors++
				if consecutiveErrors >= maxKafkaReadErrors {
					t.Logf("Reached max consecutive Kafka read errors (%d), stopping read loop after %d messages",
						maxKafkaReadErrors, totalMessages)
					break
				}
				t.Logf("Error reading kafka message (%d/%d): %v", consecutiveErrors, maxKafkaReadErrors, err)
				continue
			}
			// Other errors - also count towards limit but log differently
			consecutiveErrors++
			if consecutiveErrors >= maxKafkaReadErrors {
				t.Logf("Reached max consecutive Kafka errors (%d), stopping: %v", maxKafkaReadErrors, err)
				break
			}
			t.Logf("Error reading kafka message (%d/%d): %v", consecutiveErrors, maxKafkaReadErrors, err)
			continue
		}

		// Reset consecutive error counter on successful read
		consecutiveErrors = 0
		totalMessages++

		var event AuditEvent
		if err := json.Unmarshal(m.Value, &event); err != nil {
			t.Logf("Failed to unmarshal audit event #%d: %v (raw: %s)", totalMessages, err, string(m.Value)[:min(200, len(m.Value))])
			continue
		}

		// Log all events for debugging
		eventSummary := fmt.Sprintf("type=%s target=%s/%s", event.Type, event.Target.Namespace, event.Target.Name)
		allEvents = append(allEvents, eventSummary)
		t.Logf("Kafka message #%d: %s", totalMessages, eventSummary)

		// Filter by our session name (Target.Name should match session name)
		if event.Target.Name == session.Name {
			t.Logf("✓ Found matching audit event for our session: %s", event.Type)
			if _, ok := expectedEvents[event.Type]; ok {
				expectedEvents[event.Type] = true
				foundCount++
			}
		}
	}

	// Log summary
	t.Logf("Kafka read complete: %d total messages, %d matching our session (%s)", totalMessages, foundCount, session.Name)
	if len(allEvents) > 0 {
		t.Logf("All events found: %v", allEvents)
	} else {
		t.Log("WARNING: No events found in Kafka topic!")
	}

	// Verify we found all expected events
	for eventType, found := range expectedEvents {
		assert.True(t, found, "Did not find audit event: %s for session %s", eventType, session.Name)
	}
}
