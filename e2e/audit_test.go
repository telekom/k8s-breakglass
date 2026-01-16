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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/audit"
)

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
		t.Log("Kafka already accessible on localhost:9094")
	} else {
		t.Log("Starting port-forward for Kafka on localhost:9094")
		// Try to start port forward
		// Note: This might fail if port is taken but not responding, or if we don't have permissions
		_, stopPF := helpers.StartPortForward(t, ctx, "breakglass-system", "breakglass-kafka", 9094, 9094)
		defer stopPF()
	}

	// Connect to Kafka
	// The topic "breakglass-audit-events" is defined in config/dev/resources/crs/audit-config-test.yaml
	// IMPORTANT: Use FirstOffset to read ALL messages from the beginning of the topic,
	// not just new ones. This ensures we don't miss events that were written before
	// the consumer connected.
	kafkaReader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{"localhost:9094"},
		Topic:     "breakglass-audit-events",
		Partition: 0,
		MinBytes:  1,    // Read even small messages immediately
		MaxBytes:  10e6, // 10MB
		MaxWait:   500 * time.Millisecond,
		// CRITICAL: Start from the BEGINNING to read all messages
		StartOffset: kafka.FirstOffset,
	})
	defer kafkaReader.Close()

	// Log the current offset info
	t.Logf("Connected to Kafka, will read from beginning of topic")

	// Give Kafka reader a moment to connect/seek
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

	// 1. Create a Breakglass Session
	// Use unique name to avoid collisions and for filtering audit logs
	sessionName := helpers.GenerateUniqueName("audit-test")
	t.Logf("Creating session for audit test: %s", sessionName)

	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	// Create via API
	session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
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
	allEvents := make([]string, 0) // For diagnostics

	for foundCount < len(expectedEvents) {
		m, err := kafkaReader.ReadMessage(readCtx)
		if err != nil {
			if err == context.DeadlineExceeded {
				t.Logf("Timeout reading from Kafka after %d messages", totalMessages)
				break
			}
			t.Logf("Error reading kafka message: %v", err)
			continue
		}

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
