package config_test

import (
	"os"
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name                 string
		configContent        string
		envVar               string
		expectedListenAddr   string
		expectedOIDCPrefixes []string
		expectError          bool
	}{
		{
			name: "valid config with OIDC prefixes",
			configContent: `
server:
  listenAddress: ":8080"
kubernetes:
  context: "test-context"
  oidcPrefixes:
    - "keycloak:"
    - "oidc:"
authorizationServer:
  url: "http://localhost:8080"
  jwksEndpoint: "certs"
frontend:
  oidcAuthority: "http://localhost:8080"
  oidcClientID: "test-client"
  baseURL: "http://localhost:3000"
mail:
  host: "localhost"
  port: 587
`,
			expectedListenAddr:   ":8080",
			expectedOIDCPrefixes: []string{"keycloak:", "oidc:"},
			expectError:          false,
		},
		{
			name: "valid config without OIDC prefixes",
			configContent: `
server:
  listenAddress: ":9090"
kubernetes:
  context: "test-context"
authorizationServer:
  url: "http://localhost:8080"
  jwksEndpoint: "certs"
frontend:
  oidcAuthority: "http://localhost:8080"
  oidcClientID: "test-client"
  baseURL: "http://localhost:3000"
mail:
  host: "localhost"
  port: 587
`,
			expectedListenAddr:   ":9090",
			expectedOIDCPrefixes: nil,
			expectError:          false,
		},
		{
			name: "minimal config",
			configContent: `
server:
  listenAddress: ":3000"
authorizationServer:
  url: "http://localhost:8080"
  jwksEndpoint: "certs"
frontend:
  oidcAuthority: "http://localhost:8080"
  oidcClientID: "test-client"
  baseURL: "http://localhost:3000"
mail:
  host: "localhost"
  port: 587
`,
			expectedListenAddr: ":3000",
			expectError:        false,
		},
		{
			name:          "invalid YAML",
			configContent: `invalid: yaml: content [`,
			expectError:   true,
		},
		{
			name:        "file not found",
			envVar:      "/nonexistent/path/config.yaml",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file if content is provided
			var tempFile *os.File
			var err error

			if tt.configContent != "" {
				tempFile, err = os.CreateTemp("", "test-config-*.yaml")
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer func() { _ = os.Remove(tempFile.Name()) }()
				defer func() { _ = tempFile.Close() }()

				if _, err := tempFile.WriteString(tt.configContent); err != nil {
					t.Fatalf("Failed to write to temp file: %v", err)
				}

				// Set environment variable to point to temp file
				if err := os.Setenv("BREAKGLASS_CONFIG_PATH", tempFile.Name()); err != nil {
					t.Fatalf("Failed to set env var: %v", err)
				}
			} else if tt.envVar != "" {
				// Set environment variable to specific path
				if err := os.Setenv("BREAKGLASS_CONFIG_PATH", tt.envVar); err != nil {
					t.Fatalf("Failed to set env var: %v", err)
				}
			} else {
				// Clear environment variable to test default behavior
				if err := os.Unsetenv("BREAKGLASS_CONFIG_PATH"); err != nil {
					t.Fatalf("Failed to unset env var: %v", err)
				}
			}

			// Clean up environment variable after test
			defer func() {
				if tt.configContent != "" || tt.envVar != "" {
					_ = os.Unsetenv("BREAKGLASS_CONFIG_PATH")
				}
			}()

			// Test the Load function
			cfg, err := config.Load()

			if tt.expectError {
				if err == nil {
					t.Errorf("Load() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Load() unexpected error: %v", err)
				return
			}

			// Verify expected values
			if cfg.Server.ListenAddress != tt.expectedListenAddr {
				t.Errorf("Load() listenAddress = %v, want %v", cfg.Server.ListenAddress, tt.expectedListenAddr)
			}

			if tt.expectedOIDCPrefixes != nil {
				if len(cfg.Kubernetes.OIDCPrefixes) != len(tt.expectedOIDCPrefixes) {
					t.Errorf("Load() OIDCPrefixes length = %v, want %v", len(cfg.Kubernetes.OIDCPrefixes), len(tt.expectedOIDCPrefixes))
				} else {
					for i, prefix := range tt.expectedOIDCPrefixes {
						if cfg.Kubernetes.OIDCPrefixes[i] != prefix {
							t.Errorf("Load() OIDCPrefixes[%d] = %v, want %v", i, cfg.Kubernetes.OIDCPrefixes[i], prefix)
						}
					}
				}
			} else if len(cfg.Kubernetes.OIDCPrefixes) != 0 {
				t.Errorf("Load() OIDCPrefixes = %v, want empty", cfg.Kubernetes.OIDCPrefixes)
			}
		})
	}
}

func TestLoadDefaultPath(t *testing.T) {
	// Test default config path when no environment variable is set
	_ = os.Unsetenv("BREAKGLASS_CONFIG_PATH")

	// This should try to load ./config.yaml which likely doesn't exist
	_, err := config.Load()

	// We expect an error since the default config file doesn't exist
	if err == nil {
		t.Errorf("Load() with default path expected error but got none")
	}
}
