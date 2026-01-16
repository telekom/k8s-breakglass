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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
)

func TestParseRetainFor(t *testing.T) {
	log := zap.NewNop().Sugar()

	tests := []struct {
		name     string
		value    string
		expected time.Duration
	}{
		{
			name:     "empty string returns default",
			value:    "",
			expected: DefaultRetainForDuration,
		},
		{
			name:     "valid duration 1h",
			value:    "1h",
			expected: time.Hour,
		},
		{
			name:     "valid duration 720h",
			value:    "720h",
			expected: 720 * time.Hour,
		},
		{
			name:     "valid duration with minutes",
			value:    "30m",
			expected: 30 * time.Minute,
		},
		{
			name:     "invalid format returns default",
			value:    "invalid",
			expected: DefaultRetainForDuration,
		},
		{
			name:     "zero duration returns default",
			value:    "0s",
			expected: DefaultRetainForDuration,
		},
		{
			name:     "negative duration returns default",
			value:    "-1h",
			expected: DefaultRetainForDuration,
		},
		{
			name:     "complex duration",
			value:    "2h30m",
			expected: 2*time.Hour + 30*time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := v1alpha1.BreakglassSessionSpec{RetainFor: tt.value}
			result := ParseRetainFor(spec, log)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMaxValidFor(t *testing.T) {
	log := zap.NewNop().Sugar()

	tests := []struct {
		name     string
		value    string
		expected time.Duration
	}{
		{
			name:     "empty string returns default",
			value:    "",
			expected: DefaultValidForDuration,
		},
		{
			name:     "valid duration 2h",
			value:    "2h",
			expected: 2 * time.Hour,
		},
		{
			name:     "valid duration 30m",
			value:    "30m",
			expected: 30 * time.Minute,
		},
		{
			name:     "invalid format returns default",
			value:    "not-a-duration",
			expected: DefaultValidForDuration,
		},
		{
			name:     "zero duration returns default",
			value:    "0h",
			expected: DefaultValidForDuration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := v1alpha1.BreakglassSessionSpec{MaxValidFor: tt.value}
			result := ParseMaxValidFor(spec, log)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseEscalationMaxValidFor(t *testing.T) {
	log := zap.NewNop().Sugar()

	tests := []struct {
		name     string
		value    string
		expected time.Duration
	}{
		{
			name:     "empty string returns default",
			value:    "",
			expected: DefaultValidForDuration,
		},
		{
			name:     "valid duration 4h",
			value:    "4h",
			expected: 4 * time.Hour,
		},
		{
			name:     "invalid format returns default",
			value:    "bad",
			expected: DefaultValidForDuration,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := v1alpha1.BreakglassEscalationSpec{MaxValidFor: tt.value}
			result := ParseEscalationMaxValidFor(spec, log)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseApprovalTimeout(t *testing.T) {
	log := zap.NewNop().Sugar()
	defaultTimeout := time.Hour

	tests := []struct {
		name     string
		value    string
		expected time.Duration
	}{
		{
			name:     "empty string returns 1h default",
			value:    "",
			expected: defaultTimeout,
		},
		{
			name:     "valid duration 2h",
			value:    "2h",
			expected: 2 * time.Hour,
		},
		{
			name:     "valid duration 15m",
			value:    "15m",
			expected: 15 * time.Minute,
		},
		{
			name:     "invalid format returns default",
			value:    "invalid-timeout",
			expected: defaultTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := v1alpha1.BreakglassEscalationSpec{ApprovalTimeout: tt.value}
			result := ParseApprovalTimeout(spec, log)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseDurationOrDefault(t *testing.T) {
	log := zap.NewNop().Sugar()
	customDefault := 5 * time.Minute

	tests := []struct {
		name         string
		value        string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{
			name:         "empty returns custom default",
			value:        "",
			defaultValue: customDefault,
			expected:     customDefault,
		},
		{
			name:         "valid duration returns parsed",
			value:        "10m",
			defaultValue: customDefault,
			expected:     10 * time.Minute,
		},
		{
			name:         "invalid returns custom default",
			value:        "garbage",
			defaultValue: customDefault,
			expected:     customDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseDurationOrDefault(tt.value, tt.defaultValue, "TestField", log)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseDurationWithNilLogger(t *testing.T) {
	// Ensure nil logger doesn't panic
	spec := v1alpha1.BreakglassSessionSpec{RetainFor: "invalid"}
	result := ParseRetainFor(spec, nil)
	assert.Equal(t, DefaultRetainForDuration, result)

	spec2 := v1alpha1.BreakglassSessionSpec{MaxValidFor: "1h"}
	result2 := ParseMaxValidFor(spec2, nil)
	assert.Equal(t, time.Hour, result2)
}
