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

package breakglass

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Tests for getCleanupInterval
// ============================================================================

func TestGetCleanupInterval_Default(t *testing.T) {
	// Clear any existing env var
	origVal := os.Getenv("CLEANUP_INTERVAL")
	os.Unsetenv("CLEANUP_INTERVAL")
	defer func() {
		if origVal != "" {
			os.Setenv("CLEANUP_INTERVAL", origVal)
		}
	}()

	result := getCleanupInterval()
	assert.Equal(t, 5*time.Minute, result, "default cleanup interval should be 5 minutes")
}

func TestGetCleanupInterval_EnvVarValid(t *testing.T) {
	// Save original and set test value
	origVal := os.Getenv("CLEANUP_INTERVAL")
	defer func() {
		if origVal != "" {
			os.Setenv("CLEANUP_INTERVAL", origVal)
		} else {
			os.Unsetenv("CLEANUP_INTERVAL")
		}
	}()

	tests := []struct {
		envValue string
		expected time.Duration
	}{
		{"10s", 10 * time.Second},
		{"1m", 1 * time.Minute},
		{"30m", 30 * time.Minute},
		{"1h", 1 * time.Hour},
		{"2h30m", 2*time.Hour + 30*time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.envValue, func(t *testing.T) {
			os.Setenv("CLEANUP_INTERVAL", tc.envValue)
			result := getCleanupInterval()
			assert.Equal(t, tc.expected, result, "cleanup interval should match env var")
		})
	}
}

func TestGetCleanupInterval_EnvVarInvalid(t *testing.T) {
	// Save original and set invalid test value
	origVal := os.Getenv("CLEANUP_INTERVAL")
	defer func() {
		if origVal != "" {
			os.Setenv("CLEANUP_INTERVAL", origVal)
		} else {
			os.Unsetenv("CLEANUP_INTERVAL")
		}
	}()

	os.Setenv("CLEANUP_INTERVAL", "not-a-duration")
	result := getCleanupInterval()
	assert.Equal(t, 5*time.Minute, result, "should fall back to default for invalid duration")
}

func TestGetCleanupInterval_EnvVarEmpty(t *testing.T) {
	// Save original and set empty value
	origVal := os.Getenv("CLEANUP_INTERVAL")
	defer func() {
		if origVal != "" {
			os.Setenv("CLEANUP_INTERVAL", origVal)
		} else {
			os.Unsetenv("CLEANUP_INTERVAL")
		}
	}()

	os.Setenv("CLEANUP_INTERVAL", "")
	result := getCleanupInterval()
	assert.Equal(t, 5*time.Minute, result, "should fall back to default for empty string")
}

// Note: getDebugSessionRetentionPeriod tests are in cleanup_task_retention_test.go

// ============================================================================
// Tests for getDebugSessionApprovalTimeout
// ============================================================================

func TestGetDebugSessionApprovalTimeout_Default(t *testing.T) {
	origVal := os.Getenv("DEBUG_SESSION_APPROVAL_TIMEOUT")
	os.Unsetenv("DEBUG_SESSION_APPROVAL_TIMEOUT")
	defer func() {
		if origVal != "" {
			os.Setenv("DEBUG_SESSION_APPROVAL_TIMEOUT", origVal)
		}
	}()

	result := getDebugSessionApprovalTimeout()
	assert.Equal(t, 24*time.Hour, result, "default approval timeout should be 24h")
}

func TestGetDebugSessionApprovalTimeout_EnvVarValid(t *testing.T) {
	origVal := os.Getenv("DEBUG_SESSION_APPROVAL_TIMEOUT")
	defer func() {
		if origVal != "" {
			os.Setenv("DEBUG_SESSION_APPROVAL_TIMEOUT", origVal)
		} else {
			os.Unsetenv("DEBUG_SESSION_APPROVAL_TIMEOUT")
		}
	}()

	tests := []struct {
		envValue string
		expected time.Duration
	}{
		{"1h", 1 * time.Hour},
		{"12h", 12 * time.Hour},
		{"48h", 48 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.envValue, func(t *testing.T) {
			os.Setenv("DEBUG_SESSION_APPROVAL_TIMEOUT", tc.envValue)
			result := getDebugSessionApprovalTimeout()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetDebugSessionApprovalTimeout_EnvVarInvalid(t *testing.T) {
	origVal := os.Getenv("DEBUG_SESSION_APPROVAL_TIMEOUT")
	defer func() {
		if origVal != "" {
			os.Setenv("DEBUG_SESSION_APPROVAL_TIMEOUT", origVal)
		} else {
			os.Unsetenv("DEBUG_SESSION_APPROVAL_TIMEOUT")
		}
	}()

	os.Setenv("DEBUG_SESSION_APPROVAL_TIMEOUT", "not-valid")
	result := getDebugSessionApprovalTimeout()
	assert.Equal(t, 24*time.Hour, result, "should fall back to default for invalid duration")
}
