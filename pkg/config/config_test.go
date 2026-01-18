package config_test

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

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
func TestCachedLoader(t *testing.T) {
	// Create a temp config file
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	initialContent := `
frontend:
  baseURL: "http://initial.example.com"
kubernetes:
  userIdentifierClaim: "email"
`
	if _, err := tmpFile.WriteString(initialContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Create cached loader with short check interval for testing
	loader := config.NewCachedLoader(tmpFile.Name(), 10*time.Millisecond)

	// First load should read from disk
	cfg1, err := loader.Get()
	if err != nil {
		t.Fatalf("First Get() failed: %v", err)
	}
	if cfg1.Frontend.BaseURL != "http://initial.example.com" {
		t.Errorf("Expected baseURL 'http://initial.example.com', got %q", cfg1.Frontend.BaseURL)
	}

	// Second load should return cached value (no disk read)
	cfg2, err := loader.Get()
	if err != nil {
		t.Fatalf("Second Get() failed: %v", err)
	}
	if cfg2.Frontend.BaseURL != "http://initial.example.com" {
		t.Errorf("Expected cached baseURL, got %q", cfg2.Frontend.BaseURL)
	}

	// Wait for check interval to pass
	time.Sleep(20 * time.Millisecond)

	// Update the file
	updatedContent := `
frontend:
  baseURL: "http://updated.example.com"
kubernetes:
  userIdentifierClaim: "preferred_username"
`
	if err := os.WriteFile(tmpFile.Name(), []byte(updatedContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for check interval
	time.Sleep(20 * time.Millisecond)

	// Third load should detect file change and reload
	cfg3, err := loader.Get()
	if err != nil {
		t.Fatalf("Third Get() failed: %v", err)
	}
	if cfg3.Frontend.BaseURL != "http://updated.example.com" {
		t.Errorf("Expected updated baseURL 'http://updated.example.com', got %q", cfg3.Frontend.BaseURL)
	}
	if cfg3.Kubernetes.UserIdentifierClaim != "preferred_username" {
		t.Errorf("Expected userIdentifierClaim 'preferred_username', got %q", cfg3.Kubernetes.UserIdentifierClaim)
	}
}

func TestCachedLoaderConcurrency(t *testing.T) {
	// Create a temp config file
	tmpFile, err := os.CreateTemp("", "config-concurrent-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
frontend:
  baseURL: "http://concurrent.example.com"
`
	if err := os.WriteFile(tmpFile.Name(), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := config.NewCachedLoader(tmpFile.Name(), 5*time.Millisecond)

	// Run concurrent reads
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg, err := loader.Get()
			if err != nil {
				errors <- err
				return
			}
			if cfg.Frontend.BaseURL != "http://concurrent.example.com" {
				errors <- fmt.Errorf("unexpected baseURL: %s", cfg.Frontend.BaseURL)
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestGetUserIdentifierClaim(t *testing.T) {
	tests := []struct {
		name     string
		config   config.Config
		expected string // as string for comparison
	}{
		{
			name:     "default when empty",
			config:   config.Config{},
			expected: "email",
		},
		{
			name: "explicit email claim",
			config: config.Config{
				Kubernetes: config.Kubernetes{
					UserIdentifierClaim: "email",
				},
			},
			expected: "email",
		},
		{
			name: "preferred_username claim",
			config: config.Config{
				Kubernetes: config.Kubernetes{
					UserIdentifierClaim: "preferred_username",
				},
			},
			expected: "preferred_username",
		},
		{
			name: "sub claim",
			config: config.Config{
				Kubernetes: config.Kubernetes{
					UserIdentifierClaim: "sub",
				},
			},
			expected: "sub",
		},
		{
			name: "invalid claim defaults to email",
			config: config.Config{
				Kubernetes: config.Kubernetes{
					UserIdentifierClaim: "invalid_claim",
				},
			},
			expected: "email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetUserIdentifierClaim()
			if string(result) != tt.expected {
				t.Errorf("GetUserIdentifierClaim() = %v, want %v", result, tt.expected)
			}
		})
	}
}
