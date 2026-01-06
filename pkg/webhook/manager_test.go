package webhook

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/cli"
)

// TestParseWebhookBindAddress tests the parsing of webhook bind address from config.
// This validates the host:port parsing logic at the start of Setup().
func TestParseWebhookBindAddress(t *testing.T) {
	tests := []struct {
		name         string
		bindAddr     string
		expectedHost string
		expectedPort int
	}{
		{
			name:         "standard address",
			bindAddr:     "0.0.0.0:9443",
			expectedHost: "0.0.0.0",
			expectedPort: 9443,
		},
		{
			name:         "localhost with custom port",
			bindAddr:     "127.0.0.1:8443",
			expectedHost: "127.0.0.1",
			expectedPort: 8443,
		},
		{
			name:         "empty host with port",
			bindAddr:     ":9443",
			expectedHost: "",
			expectedPort: 9443,
		},
		{
			name:         "invalid port falls back to default",
			bindAddr:     "0.0.0.0:invalid",
			expectedHost: "0.0.0.0",
			expectedPort: 9443, // default
		},
		{
			name:         "missing colon uses defaults",
			bindAddr:     "0.0.0.0",
			expectedHost: "0.0.0.0",
			expectedPort: 9443, // default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := parseBindAddress(tt.bindAddr)
			assert.Equal(t, tt.expectedHost, host)
			assert.Equal(t, tt.expectedPort, port)
		})
	}
}

// parseBindAddress extracts host and port from bind address string.
// This helper function mirrors the logic in Setup() for testability.
func parseBindAddress(bindAddr string) (string, int) {
	webhookHost := "0.0.0.0"
	webhookPort := 9443
	if parts := strings.Split(bindAddr, ":"); len(parts) == 2 {
		webhookHost = parts[0]
		if port, err := strconv.Atoi(parts[1]); err == nil {
			webhookPort = port
		}
	}
	return webhookHost, webhookPort
}

// TestWebhookConfigValidation tests validation of webhook configuration options
func TestWebhookConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *cli.WebhookConfig
		enableCertGen bool
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config with cert generation enabled",
			config: &cli.WebhookConfig{
				BindAddr: "0.0.0.0:9443",
				CertPath: "/certs",
			},
			enableCertGen: true,
			expectError:   false,
		},
		{
			name: "valid config with external certs",
			config: &cli.WebhookConfig{
				BindAddr: "0.0.0.0:9443",
				CertPath: "/certs",
				CertName: "tls.crt",
				CertKey:  "tls.key",
			},
			enableCertGen: false,
			expectError:   false,
		},
		{
			name: "no cert path and cert generation disabled",
			config: &cli.WebhookConfig{
				BindAddr: "0.0.0.0:9443",
				CertPath: "",
			},
			enableCertGen: false,
			expectError:   true,
			errorContains: "no webhook certificate path",
		},
		{
			name: "metrics secure without cert path and cert generation disabled",
			config: &cli.WebhookConfig{
				BindAddr:      "0.0.0.0:9443",
				CertPath:      "/certs",
				CertName:      "tls.crt",
				CertKey:       "tls.key",
				MetricsAddr:   ":8443",
				MetricsSecure: true,
			},
			enableCertGen: false,
			expectError:   true,
			errorContains: "unable to configure webhook metrics server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookConfig(tt.config, tt.enableCertGen)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// validateWebhookConfig validates webhook configuration.
// This helper function extracts the validation logic from Setup() for testability.
func validateWebhookConfig(wc *cli.WebhookConfig, enableCertGeneration bool) error {
	// Validate cert configuration
	if !enableCertGeneration && wc.CertPath == "" {
		return fmt.Errorf("no webhook certificate path provided and cert generation is disabled; no webhooks will be configured")
	}

	// Validate metrics secure configuration
	if wc.MetricsAddr != "" && wc.MetricsSecure {
		if wc.MetricsCertPath == "" && !enableCertGeneration {
			return fmt.Errorf("unable to configure webhook metrics server - webhooks-metrics-cert-path: %s, secure: %t, cert-generation: %t",
				wc.MetricsCertPath, wc.MetricsSecure, enableCertGeneration)
		}
	}

	return nil
}
