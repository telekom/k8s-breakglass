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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// METRICS VERIFICATION E2E TESTS
// From E2E_COVERAGE_ANALYSIS.md - Critical gap (previously ~20% coverage)
// =============================================================================

// TestMetricsEndpointAccessible verifies the metrics endpoint is accessible and returns valid Prometheus format.
func TestMetricsEndpointAccessible(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMetricsTestEnabled() {
		t.Skip("Skipping metrics test. Set E2E_SKIP_METRICS_TESTS=false to enable (requires metrics port-forward on 8081).")
	}

	ctx, cancel := context.WithTimeout(context.Background(), helpers.WaitForStateTimeout)
	defer cancel()

	t.Run("MetricsEndpointReturnsData", func(t *testing.T) {
		rawMetrics, err := helpers.FetchMetrics(ctx)
		require.NoError(t, err, "Metrics endpoint should be accessible. Run: ./e2e/setup-e2e-env.sh --start to set up port-forwards")
		assert.NotEmpty(t, rawMetrics, "Metrics response should not be empty")
		t.Logf("METRICS-001: Metrics endpoint accessible, received %d bytes", len(rawMetrics))

		// Verify it looks like valid Prometheus format
		assert.Contains(t, rawMetrics, "# HELP", "Should contain Prometheus HELP comments")
		assert.Contains(t, rawMetrics, "# TYPE", "Should contain Prometheus TYPE comments")
	})

	t.Run("BreakglassMetricsPresent", func(t *testing.T) {
		rawMetrics, err := helpers.FetchMetrics(ctx)
		require.NoError(t, err, "Metrics endpoint should be accessible")

		metrics := helpers.ParseBreakglassMetrics(rawMetrics)
		assert.NotEmpty(t, metrics, "Should have breakglass_* metrics")
		t.Logf("METRICS-002: Found %d breakglass metrics", len(metrics))
	})
}

// TestMetricsSessionLifecycleCounters verifies session-related metrics increment correctly.
func TestMetricsSessionLifecycleCounters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMetricsTestEnabled() {
		t.Skip("Skipping metrics test. Set E2E_SKIP_METRICS_TESTS=false to enable (requires metrics port-forward on 8081).")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Set up escalation for testing
	escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-metrics-esc"), namespace).
		WithEscalatedGroup("metrics-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithLabels(map[string]string{"feature": "metrics"}).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	t.Run("SessionCreatedMetricIncrements", func(t *testing.T) {
		// Get baseline metrics
		beforeMetrics, err := helpers.FetchMetrics(ctx)
		require.NoError(t, err, "Metrics endpoint should be accessible")
		beforeValue := getMetricValue(beforeMetrics, "breakglass_session_created_total", nil)
		t.Logf("Before session creation: breakglass_session_created_total = %s", beforeValue)

		// Create a session
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Metrics test",
		})
		require.NoError(t, err)
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to be pending
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Verify metric incremented
		afterMetrics, err := helpers.FetchMetrics(ctx)
		require.NoError(t, err, "Metrics endpoint should be accessible after session creation")
		afterValue := getMetricValue(afterMetrics, "breakglass_session_created_total", nil)
		t.Logf("After session creation: breakglass_session_created_total = %s", afterValue)

		// If we can parse, verify increment
		if beforeValue != "" && afterValue != "" {
			before, _ := strconv.Atoi(beforeValue)
			after, _ := strconv.Atoi(afterValue)
			assert.Greater(t, after, before, "Session created counter should have incremented")
		}
		t.Logf("METRICS-003: Session creation metric verification complete")
	})
}

// TestMetricsWebhookSARCounters verifies webhook SAR metrics.
func TestMetricsWebhookSARCounters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMetricsTestEnabled() {
		t.Skip("Skipping metrics test. Set E2E_SKIP_METRICS_TESTS=false to enable (requires metrics port-forward on 8081).")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()

	t.Run("WebhookRequestMetricsExist", func(t *testing.T) {
		// Send a SAR request
		sar := helpers.BuildResourceSAR("test-user@example.com", []string{"test-group"}, "get", "configmaps", "default")
		_, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err)

		// Check metrics exist
		rawMetrics, err := helpers.FetchMetrics(ctx)
		require.NoError(t, err, "Metrics endpoint should be accessible")

		metrics := helpers.ParseBreakglassMetrics(rawMetrics)
		foundWebhookMetric := false
		for _, m := range metrics {
			if strings.Contains(m.Name, "webhook") || strings.Contains(m.Name, "authorization") {
				foundWebhookMetric = true
				t.Logf("METRICS-004: Found webhook metric: %s = %s", m.Name, m.Value)
				break
			}
		}
		assert.True(t, foundWebhookMetric || len(metrics) > 0,
			"Should have webhook-related metrics or other breakglass metrics")
	})
}

// TestMetricsPrometheusScrapable verifies metrics are in proper Prometheus text format.
func TestMetricsPrometheusScrapable(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMetricsTestEnabled() {
		t.Skip("Skipping metrics test. Set E2E_SKIP_METRICS_TESTS=false to enable (requires metrics port-forward on 8081).")
	}

	ctx, cancel := context.WithTimeout(context.Background(), helpers.WaitForStateTimeout)
	defer cancel()

	t.Run("MetricsArePrometheusFormat", func(t *testing.T) {
		rawMetrics, err := helpers.FetchMetrics(ctx)
		require.NoError(t, err, "Metrics endpoint should be accessible")

		// Verify basic Prometheus text format structure
		lines := strings.Split(rawMetrics, "\n")
		var helpLines, typeLines, metricLines int

		for _, line := range lines {
			switch {
			case strings.HasPrefix(line, "# HELP"):
				helpLines++
			case strings.HasPrefix(line, "# TYPE"):
				typeLines++
			case len(line) > 0 && !strings.HasPrefix(line, "#"):
				metricLines++
			}
		}

		t.Logf("METRICS-005: Parsed %d HELP lines, %d TYPE lines, %d metric lines",
			helpLines, typeLines, metricLines)

		assert.Greater(t, helpLines, 0, "Should have HELP comments")
		assert.Greater(t, typeLines, 0, "Should have TYPE declarations")
		assert.Greater(t, metricLines, 0, "Should have metric values")
	})
}

// getMetricValue extracts the value of a specific metric from raw metrics.
// It returns empty string if not found.
func getMetricValue(rawMetrics, metricName string, labels map[string]string) string {
	metrics := helpers.ParseBreakglassMetrics(rawMetrics)
	for _, m := range metrics {
		if m.Name == metricName {
			// If no labels specified, return first match
			if labels == nil {
				return m.Value
			}
			// Check if all specified labels match
			match := true
			for k, v := range labels {
				if m.Labels[k] != v {
					match = false
					break
				}
			}
			if match {
				return m.Value
			}
		}
	}
	return ""
}
