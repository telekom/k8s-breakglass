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

// Package helpers provides utility functions for E2E tests.
package helpers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// GetMetricsURL returns the metrics URL for the breakglass controller.
// The controller exposes Prometheus metrics on port 8081 inside the cluster.
// In e2e tests, this port is forwarded to localhost:8181 by default.
func GetMetricsURL() string {
	return getEnvOrDefault("BREAKGLASS_METRICS_URL", "http://localhost:8181/metrics")
}

// MetricValue represents a parsed Prometheus metric with its labels and value.
type MetricValue struct {
	Name   string
	Labels map[string]string
	Value  string
}

// FetchMetrics retrieves all metrics from the controller's /metrics endpoint.
func FetchMetrics(ctx context.Context) (string, error) {
	client := NewHTTPClient(DefaultHTTPClientConfig())
	metricsURL := GetMetricsURL()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating metrics request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching metrics from %s: %w", metricsURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("metrics request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading metrics response: %w", err)
	}

	return string(body), nil
}

// IsMetricsEndpointReachable checks if the metrics endpoint is accessible.
// Returns true if the endpoint responds, false if connection fails.
func IsMetricsEndpointReachable(ctx context.Context) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	metricsURL := GetMetricsURL()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK
}

// ParseBreakglassMetrics filters and parses only breakglass_* metrics from the raw Prometheus output.
func ParseBreakglassMetrics(rawMetrics string) []MetricValue {
	var metrics []MetricValue
	scanner := bufio.NewScanner(strings.NewReader(rawMetrics))

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Only include breakglass_ metrics
		if !strings.HasPrefix(line, "breakglass_") {
			continue
		}

		metric := parseMetricLine(line)
		if metric.Name != "" {
			metrics = append(metrics, metric)
		}
	}

	return metrics
}

// parseMetricLine parses a single Prometheus metric line into a MetricValue.
// Format: metric_name{label="value",label2="value2"} 123
// or: metric_name 123
func parseMetricLine(line string) MetricValue {
	result := MetricValue{
		Labels: make(map[string]string),
	}

	// Find the value (last space-separated token)
	lastSpace := strings.LastIndex(line, " ")
	if lastSpace == -1 {
		return result
	}
	result.Value = line[lastSpace+1:]
	nameAndLabels := line[:lastSpace]

	// Check for labels
	if idx := strings.Index(nameAndLabels, "{"); idx != -1 {
		result.Name = nameAndLabels[:idx]
		labelsStr := strings.TrimSuffix(strings.TrimPrefix(nameAndLabels[idx:], "{"), "}")
		result.Labels = parseLabels(labelsStr)
	} else {
		result.Name = nameAndLabels
	}

	return result
}

// parseLabels parses a comma-separated label string into a map.
func parseLabels(labelsStr string) map[string]string {
	labels := make(map[string]string)
	if labelsStr == "" {
		return labels
	}

	// Simple parser for label="value" pairs
	// This handles basic cases; complex values with commas inside quotes
	// would need a more sophisticated parser
	parts := strings.Split(labelsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx := strings.Index(part, "="); idx != -1 {
			key := part[:idx]
			value := strings.Trim(part[idx+1:], "\"")
			labels[key] = value
		}
	}

	return labels
}

// LogBreakglassMetrics fetches and logs all breakglass_* metrics to stdout.
// This is useful for debugging and observing the controller state after e2e tests.
func LogBreakglassMetrics(t *testing.T) {
	if !IsE2EEnabled() {
		t.Skip("Skipping metrics logging. Set E2E_TEST=true to enable.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Log("=== Fetching Breakglass Controller Metrics ===")

	rawMetrics, err := FetchMetrics(ctx)
	if err != nil {
		t.Logf("Warning: could not fetch metrics: %v", err)
		return
	}

	metrics := ParseBreakglassMetrics(rawMetrics)
	if len(metrics) == 0 {
		t.Log("No breakglass_* metrics found")
		return
	}

	// Group metrics by name for organized output
	grouped := make(map[string][]MetricValue)
	for _, m := range metrics {
		grouped[m.Name] = append(grouped[m.Name], m)
	}

	// Sort metric names for consistent output
	var names []string
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)

	t.Log("")
	t.Log("=== Breakglass Controller Metrics Summary ===")
	t.Log("")

	for _, name := range names {
		values := grouped[name]
		t.Logf("📊 %s", name)
		for _, v := range values {
			if len(v.Labels) > 0 {
				t.Logf("   %s = %s", formatLabels(v.Labels), v.Value)
			} else {
				t.Logf("   (no labels) = %s", v.Value)
			}
		}
	}

	t.Log("")
	t.Logf("=== Total: %d breakglass metrics ===", len(metrics))
}

// formatLabels formats a label map as a readable string.
func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "(no labels)"
	}

	var parts []string
	// Sort keys for consistent output
	var keys []string
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, labels[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// PrintMetricsSummary prints a summary of key breakglass metrics to stdout.
// This is intended to be called at the end of an e2e test run.
func PrintMetricsSummary() {
	if os.Getenv("E2E_TEST") != "true" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("")
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║           BREAKGLASS CONTROLLER METRICS SUMMARY            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("")

	rawMetrics, err := FetchMetrics(ctx)
	if err != nil {
		fmt.Printf("⚠️  Could not fetch metrics: %v\n", err)
		return
	}

	metrics := ParseBreakglassMetrics(rawMetrics)
	if len(metrics) == 0 {
		fmt.Println("ℹ️  No breakglass_* metrics found")
		return
	}

	// Print key metrics categories
	printMetricCategory(metrics, "Session Lifecycle", []string{
		"breakglass_session_created_total",
		"breakglass_session_activated_total",
		"breakglass_session_approved_total",
		"breakglass_session_rejected_total",
		"breakglass_session_expired_total",
		"breakglass_session_deleted_total",
	})

	printMetricCategory(metrics, "Webhook Authorization", []string{
		"breakglass_webhook_sar_requests_total",
		"breakglass_webhook_sar_allowed_total",
		"breakglass_webhook_sar_denied_total",
	})

	printMetricCategory(metrics, "Cluster Config", []string{
		"breakglass_clusterconfigs_checked_total",
		"breakglass_clusterconfigs_failed_total",
		"breakglass_cluster_cache_hits_total",
		"breakglass_cluster_cache_misses_total",
	})

	printMetricCategory(metrics, "Mail Notifications", []string{
		"breakglass_mail_queued_total",
		"breakglass_mail_sent_total",
		"breakglass_mail_send_success_total",
		"breakglass_mail_send_failure_total",
	})

	printMetricCategory(metrics, "Audit Events", []string{
		"breakglass_audit_events_total",
		"breakglass_audit_sink_errors_total",
	})

	fmt.Println("")
	fmt.Printf("📊 Total breakglass metrics: %d\n", len(metrics))
	fmt.Println("")
}

// printMetricCategory prints metrics for a specific category.
func printMetricCategory(metrics []MetricValue, category string, metricNames []string) {
	fmt.Printf("📌 %s:\n", category)

	found := false
	for _, name := range metricNames {
		for _, m := range metrics {
			if m.Name == name {
				found = true
				if len(m.Labels) > 0 {
					fmt.Printf("   %-50s %s = %s\n", name, formatLabels(m.Labels), m.Value)
				} else {
					fmt.Printf("   %-50s = %s\n", name, m.Value)
				}
			}
		}
	}

	if !found {
		fmt.Println("   (no metrics recorded)")
	}
	fmt.Println("")
}
