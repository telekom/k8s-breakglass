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

package helpers

import "time"

// Test timeout constants - use these instead of hardcoded durations
const (
	// ShortTestTimeout for simple tests that don't require many API calls
	ShortTestTimeout = 2 * time.Minute

	// MediumTestTimeout for standard tests with multiple operations
	MediumTestTimeout = 5 * time.Minute

	// LongTestTimeout for complex tests with many API calls or wait cycles
	LongTestTimeout = 10 * time.Minute

	// WaitForStateTimeout for CLI poll loops waiting on session state transitions
	// (e.g., Pending → Approved, Active → Terminated). Set high enough to account
	// for controller reconciliation latency in resource-constrained CI environments.
	// Uses DefaultTimeout from wait.go as the single source of truth.
	WaitForStateTimeout = DefaultTimeout

	// WaitForConditionTimeout for waiting on Kubernetes status conditions
	// (e.g., ClusterConfig readiness, deployment availability).
	WaitForConditionTimeout = 60 * time.Second

	// APIReadyTimeout for waiting for API to be ready
	APIReadyTimeout = 30 * time.Second

	// PollInterval for polling in Eventually/Consistently calls
	PollInterval = 1 * time.Second

	// ShortPollInterval for fast polling
	ShortPollInterval = 500 * time.Millisecond

	// ShortWaitDuration for short waits
	ShortWaitDuration = 15 * time.Second
)

// Escalation duration constants - use these for consistent test values
const (
	// DefaultMaxValidFor is the standard session validity period for tests
	DefaultMaxValidFor = "4h"

	// DefaultApprovalTimeout is the standard approval timeout for tests
	DefaultApprovalTimeout = "2h"

	// ShortMaxValidFor for testing session expiry (set very short)
	ShortMaxValidFor = "30s"

	// ShortApprovalTimeout for testing approval timeout behavior
	ShortApprovalTimeout = "20s"

	// VeryShortMaxValidFor for immediate expiry tests
	VeryShortMaxValidFor = "5s"
)

// Label constants - use these for consistent labeling
const (
	// E2ETestLabelKey is the label key used to mark E2E test resources
	E2ETestLabelKey = "e2e-test"

	// E2ETestLabelValue is the value for E2E test label
	E2ETestLabelValue = "true"

	// E2ETestLabels returns a map with the standard E2E test label
)

// E2ETestLabels returns a map with the standard E2E test label.
// Use this when creating resources in tests.
func E2ETestLabels() map[string]string {
	return map[string]string{E2ETestLabelKey: E2ETestLabelValue}
}

// E2ELabelsWithFeature returns E2E test labels with an additional feature label.
// Example: E2ELabelsWithFeature("audit-log") returns {"e2e-test": "true", "feature": "audit-log"}
func E2ELabelsWithFeature(feature string) map[string]string {
	return map[string]string{
		E2ETestLabelKey: E2ETestLabelValue,
		"feature":       feature,
	}
}

// E2ELabelsWithExtra returns E2E test labels merged with additional labels.
// The E2E test label will be included automatically.
func E2ELabelsWithExtra(extra map[string]string) map[string]string {
	labels := E2ETestLabels()
	for k, v := range extra {
		labels[k] = v
	}
	return labels
}

// Common test group names - groups that have RBAC bindings in the test cluster
const (
	// TestGroupPodsAdmin has permissions to manage pods
	TestGroupPodsAdmin = "breakglass-pods-admin"

	// TestGroupReadOnly has read-only permissions
	TestGroupReadOnly = "breakglass-read-only"

	// TestGroupEmergencyAdmin has emergency admin permissions
	TestGroupEmergencyAdmin = "breakglass-emergency-admin"

	// TestGroupClusterAdmin has cluster-admin permissions
	TestGroupClusterAdmin = "cluster-admin"
)
