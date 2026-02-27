// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestResolveStringConfig(t *testing.T) {
	tests := []struct {
		name         string
		cliValue     string
		configValue  string
		defaultValue string
		want         string
	}{
		{"cli wins over config and default", "cli", "cfg", "def", "cli"},
		{"config wins over default when cli empty", "", "cfg", "def", "cfg"},
		{"default used when cli and config empty", "", "", "def", "def"},
		{"all empty returns empty", "", "", "", ""},
		{"cli empty string ignored", "", "cfg", "", "cfg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveStringConfig(tt.cliValue, tt.configValue, tt.defaultValue)
			if got != tt.want {
				t.Errorf("resolveStringConfig(%q, %q, %q) = %q, want %q",
					tt.cliValue, tt.configValue, tt.defaultValue, got, tt.want)
			}
		})
	}
}

func float64Ptr(v float64) *float64 { return &v }

func TestResolveOTelSamplingRate(t *testing.T) {
	tests := []struct {
		name         string
		cliValue     float64
		configValue  *float64
		defaultValue float64
		want         float64
	}{
		{"cli explicit 0.5 wins", 0.5, float64Ptr(0.8), 1.0, 0.5},
		{"cli explicit 0 (disable sampling) is preserved", 0.0, float64Ptr(0.8), 1.0, 0.0},
		{"cli sentinel -1 falls through to config", -1, float64Ptr(0.8), 1.0, 0.8},
		{"cli sentinel -1 and config 0 disables sampling", -1, float64Ptr(0), 1.0, 0.0},
		{"cli sentinel -1 and no config uses default", -1, nil, 0.5, 0.5},
		{"cli explicit 1.0 wins over config", 1.0, float64Ptr(0.5), 0.5, 1.0},
		{"all defaults (no config set)", -1, nil, 1.0, 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveOTelSamplingRate(tt.cliValue, tt.configValue, tt.defaultValue)
			if got != tt.want {
				t.Errorf("resolveOTelSamplingRate(%v, %v, %v) = %v, want %v",
					tt.cliValue, tt.configValue, tt.defaultValue, got, tt.want)
			}
		})
	}
}
