// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package helpers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKeycloakInternalURL(t *testing.T) {
	// Save original env vars and restore after test
	origInternalURL := os.Getenv("KEYCLOAK_INTERNAL_URL")
	origIssuerURL := os.Getenv("KEYCLOAK_ISSUER_URL")
	origIssuerHost := os.Getenv("KEYCLOAK_ISSUER_HOST")
	origServiceHostname := os.Getenv("KEYCLOAK_SERVICE_HOSTNAME")
	defer func() {
		os.Setenv("KEYCLOAK_INTERNAL_URL", origInternalURL)
		os.Setenv("KEYCLOAK_ISSUER_URL", origIssuerURL)
		os.Setenv("KEYCLOAK_ISSUER_HOST", origIssuerHost)
		os.Setenv("KEYCLOAK_SERVICE_HOSTNAME", origServiceHostname)
	}()

	tests := []struct {
		name            string
		issuerURL       string
		issuerHost      string
		serviceHostname string
		expected        string
	}{
		{
			name:     "default_fallback",
			expected: "https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443",
		},
		{
			name:            "from_service_hostname",
			serviceHostname: "custom-keycloak.namespace.svc.cluster.local",
			expected:        "https://custom-keycloak.namespace.svc.cluster.local:8443",
		},
		{
			name:       "from_issuer_host",
			issuerHost: "keycloak.system:8443",
			expected:   "https://keycloak.system:8443",
		},
		{
			name:      "from_issuer_url_takes_priority",
			issuerURL: "https://my-keycloak.example.com:8443",
			expected:  "https://my-keycloak.example.com:8443",
		},
		{
			name:            "issuer_url_overrides_others",
			issuerURL:       "https://priority-keycloak:8443",
			issuerHost:      "host-keycloak:8443",
			serviceHostname: "service-keycloak.svc",
			expected:        "https://priority-keycloak:8443",
		},
		{
			name:            "issuer_host_overrides_service_hostname",
			issuerHost:      "issuer-host-keycloak:8443",
			serviceHostname: "service-keycloak.svc",
			expected:        "https://issuer-host-keycloak:8443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars first (including KEYCLOAK_INTERNAL_URL which takes priority)
			os.Unsetenv("KEYCLOAK_INTERNAL_URL")
			os.Unsetenv("KEYCLOAK_ISSUER_URL")
			os.Unsetenv("KEYCLOAK_ISSUER_HOST")
			os.Unsetenv("KEYCLOAK_SERVICE_HOSTNAME")

			// Set test-specific env vars
			if tt.issuerURL != "" {
				os.Setenv("KEYCLOAK_ISSUER_URL", tt.issuerURL)
			}
			if tt.issuerHost != "" {
				os.Setenv("KEYCLOAK_ISSUER_HOST", tt.issuerHost)
			}
			if tt.serviceHostname != "" {
				os.Setenv("KEYCLOAK_SERVICE_HOSTNAME", tt.serviceHostname)
			}

			result := GetKeycloakInternalURL()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetKeycloakServiceAccountClientID(t *testing.T) {
	// Save original env vars and restore after test
	origGroupSync := os.Getenv("KEYCLOAK_GROUP_SYNC_CLIENT_ID")
	origServiceAccount := os.Getenv("KEYCLOAK_SERVICE_ACCOUNT_CLIENT_ID")
	defer func() {
		os.Setenv("KEYCLOAK_GROUP_SYNC_CLIENT_ID", origGroupSync)
		os.Setenv("KEYCLOAK_SERVICE_ACCOUNT_CLIENT_ID", origServiceAccount)
	}()

	tests := []struct {
		name              string
		groupSyncClientID string
		serviceAccountID  string
		expected          string
	}{
		{
			name:     "default_fallback",
			expected: "breakglass-group-sync",
		},
		{
			name:             "from_service_account_env",
			serviceAccountID: "custom-service-account",
			expected:         "custom-service-account",
		},
		{
			name:              "from_group_sync_env",
			groupSyncClientID: "custom-group-sync",
			expected:          "custom-group-sync",
		},
		{
			name:              "group_sync_takes_priority",
			groupSyncClientID: "priority-group-sync",
			serviceAccountID:  "fallback-service-account",
			expected:          "priority-group-sync",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars first
			os.Unsetenv("KEYCLOAK_GROUP_SYNC_CLIENT_ID")
			os.Unsetenv("KEYCLOAK_SERVICE_ACCOUNT_CLIENT_ID")

			// Set test-specific env vars
			if tt.groupSyncClientID != "" {
				os.Setenv("KEYCLOAK_GROUP_SYNC_CLIENT_ID", tt.groupSyncClientID)
			}
			if tt.serviceAccountID != "" {
				os.Setenv("KEYCLOAK_SERVICE_ACCOUNT_CLIENT_ID", tt.serviceAccountID)
			}

			result := GetKeycloakServiceAccountClientID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetKeycloakServiceAccountSecret(t *testing.T) {
	// Save original env vars and restore after test
	origGroupSync := os.Getenv("KEYCLOAK_GROUP_SYNC_CLIENT_SECRET")
	origServiceAccount := os.Getenv("KEYCLOAK_SERVICE_ACCOUNT_SECRET")
	defer func() {
		os.Setenv("KEYCLOAK_GROUP_SYNC_CLIENT_SECRET", origGroupSync)
		os.Setenv("KEYCLOAK_SERVICE_ACCOUNT_SECRET", origServiceAccount)
	}()

	tests := []struct {
		name                 string
		groupSyncSecret      string
		serviceAccountSecret string
		expected             string
	}{
		{
			name:     "default_fallback",
			expected: "breakglass-group-sync-secret",
		},
		{
			name:                 "from_service_account_env",
			serviceAccountSecret: "custom-service-secret",
			expected:             "custom-service-secret",
		},
		{
			name:            "from_group_sync_env",
			groupSyncSecret: "custom-group-sync-secret",
			expected:        "custom-group-sync-secret",
		},
		{
			name:                 "group_sync_takes_priority",
			groupSyncSecret:      "priority-group-sync-secret",
			serviceAccountSecret: "fallback-service-secret",
			expected:             "priority-group-sync-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars first
			os.Unsetenv("KEYCLOAK_GROUP_SYNC_CLIENT_SECRET")
			os.Unsetenv("KEYCLOAK_SERVICE_ACCOUNT_SECRET")

			// Set test-specific env vars
			if tt.groupSyncSecret != "" {
				os.Setenv("KEYCLOAK_GROUP_SYNC_CLIENT_SECRET", tt.groupSyncSecret)
			}
			if tt.serviceAccountSecret != "" {
				os.Setenv("KEYCLOAK_SERVICE_ACCOUNT_SECRET", tt.serviceAccountSecret)
			}

			result := GetKeycloakServiceAccountSecret()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetKeycloakURL(t *testing.T) {
	// Save original env vars and restore after test
	origURL := os.Getenv("KEYCLOAK_URL")
	origHost := os.Getenv("KEYCLOAK_HOST")
	defer func() {
		os.Setenv("KEYCLOAK_URL", origURL)
		os.Setenv("KEYCLOAK_HOST", origHost)
	}()

	tests := []struct {
		name         string
		keycloakURL  string
		keycloakHost string
		expected     string
	}{
		{
			name:     "default_fallback",
			expected: "http://localhost:8180",
		},
		{
			name:         "from_keycloak_host",
			keycloakHost: "https://localhost:8443",
			expected:     "https://localhost:8443",
		},
		{
			name:        "from_keycloak_url",
			keycloakURL: "https://keycloak.example.com",
			expected:    "https://keycloak.example.com",
		},
		{
			name:         "keycloak_url_takes_priority",
			keycloakURL:  "https://priority-keycloak.com",
			keycloakHost: "https://fallback-keycloak.com",
			expected:     "https://priority-keycloak.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars first
			os.Unsetenv("KEYCLOAK_URL")
			os.Unsetenv("KEYCLOAK_HOST")

			// Set test-specific env vars
			if tt.keycloakURL != "" {
				os.Setenv("KEYCLOAK_URL", tt.keycloakURL)
			}
			if tt.keycloakHost != "" {
				os.Setenv("KEYCLOAK_HOST", tt.keycloakHost)
			}

			result := GetKeycloakURL()
			assert.Equal(t, tt.expected, result)
		})
	}
}
