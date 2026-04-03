// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetCachePropagationDelay(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected time.Duration
	}{
		{
			name:     "empty_uses_default",
			envValue: "",
			expected: 2 * time.Second,
		},
		{
			name:     "integer_milliseconds",
			envValue: "500",
			expected: 500 * time.Millisecond,
		},
		{
			name:     "duration_string_seconds",
			envValue: "3s",
			expected: 3 * time.Second,
		},
		{
			name:     "duration_string_milliseconds",
			envValue: "1500ms",
			expected: 1500 * time.Millisecond,
		},
		{
			name:     "invalid_falls_back_to_default",
			envValue: "not-a-number",
			expected: 2 * time.Second,
		},
		{
			name:     "zero_integer_falls_back_to_default",
			envValue: "0",
			expected: 2 * time.Second,
		},
		{
			name:     "negative_integer_falls_back_to_default",
			envValue: "-100",
			expected: 2 * time.Second,
		},
		{
			name:     "zero_duration_falls_back_to_default",
			envValue: "0s",
			expected: 2 * time.Second,
		},
		{
			name:     "negative_duration_falls_back_to_default",
			envValue: "-1s",
			expected: 2 * time.Second,
		},
		{
			name:     "whitespace_padded_integer",
			envValue: "  1000  ",
			expected: 1 * time.Second,
		},
		{
			name:     "whitespace_padded_duration",
			envValue: "  5s  ",
			expected: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("E2E_CACHE_PROPAGATION_DELAY", tt.envValue)
			got := getCachePropagationDelay()
			assert.Equal(t, tt.expected, got)
		})
	}
}
