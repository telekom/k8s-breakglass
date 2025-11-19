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
frontend:
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
frontend:
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
frontend:
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
			var configPath string

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

				// Pass temp file path to Load function directly
				configPath = tempFile.Name()
			} else if tt.envVar != "" {
				// Use the provided path for non-existent file test
				configPath = tt.envVar
			}
			// else: use default path by passing empty string

			// Test the Load function
			var cfg config.Config
			if configPath != "" {
				cfg, err = config.Load(configPath)
			} else {
				cfg, err = config.Load()
			}

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
