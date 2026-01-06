package e2e

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

// Package e2e contains end-to-end tests for the breakglass controller.

import (
	"testing"

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestZZZ_MetricsSummary is named with ZZZ prefix to ensure it runs last in the e2e test suite.
// This test fetches and logs all breakglass controller metrics after other e2e tests complete.
// It provides visibility into the controller's state and can help diagnose issues.
//
// Run with: E2E_TEST=true BREAKGLASS_METRICS_URL=http://localhost:8081/metrics go test -v ./e2e/... -run TestZZZ_MetricsSummary
func TestZZZ_MetricsSummary(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	// Log all breakglass metrics using the test logger
	helpers.LogBreakglassMetrics(t)

	// Also print to stdout for CI visibility
	helpers.PrintMetricsSummary()
}
