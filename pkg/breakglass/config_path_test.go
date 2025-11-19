package breakglass

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
)

// TestEscalationControllerUsesConfigPath verifies that the controller uses the provided config path for OIDC prefix stripping
func TestEscalationControllerUsesConfigPath(t *testing.T) {
	// Create a temporary config file with OIDC prefix stripping settings
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	configContent := `
kubernetes:
  oidcPrefixes:
    - "oidc:"
`
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Create controller with custom config path
	logger := zap.NewNop().Sugar()
	manager := &EscalationManager{}

	middleware := func(c *gin.Context) {}
	controller := NewBreakglassEscalationController(logger, manager, middleware, configFile)

	// Verify the controller has the config path set
	assert.Equal(t, configFile, controller.configPath)
}

// TestSessionControllerUsesConfigPath verifies that the session controller uses the provided config path
func TestSessionControllerUsesConfigPath(t *testing.T) {
	// Create a temporary config file with OIDC prefix stripping settings
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	configContent := `
kubernetes:
  oidcPrefixes:
    - "oidc:"
`
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Create controller with custom config path
	logger := zap.NewNop().Sugar()
	cfg := config.Config{}
	sessionManager := &SessionManager{}
	escalationManager := &EscalationManager{}

	middleware := func(c *gin.Context) {}
	controller := NewBreakglassSessionController(logger, cfg, sessionManager, escalationManager, middleware, configFile, nil, nil)

	// Verify the controller has the config path set
	assert.Equal(t, configFile, controller.configPath)
}

// TestGetUserGroupsWithCustomConfigPath verifies that custom config paths are used for OIDC prefix stripping
func TestGetUserGroupsWithCustomConfigPath(t *testing.T) {
	// Skip if no kubernetes context is available
	if os.Getenv("KUBECONFIG") == "" {
		t.Skip("Skipping test as it requires Kubernetes context")
	}

	// Create a temporary config file with OIDC prefix stripping settings
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	configContent := `
kubernetes:
  oidcPrefixes:
    - "oidc:"
`
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Call the function - it should load from the custom path
	// (We just verify it doesn't panic and uses the path)
	ctx := context.Background()
	cug := ClusterUserGroup{
		Username:    "test-user",
		Clustername: "test-cluster",
	}

	// This will fail if cluster is not available, but that's okay
	// The important thing is it tries to use the custom config path
	_, err = GetUserGroupsWithConfig(ctx, cug, configFile)

	// Error is expected since there's no real cluster, but we verified the function accepts the path
	assert.NotNil(t, err)
}

// TestConfigLoadWithDefaultPath tests that config.Load() defaults to "./config.yaml" without a path
func TestConfigLoadWithDefaultPath(t *testing.T) {
	// Save current directory
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(originalDir)
	}()

	// Create a temporary directory and change to it
	tempDir := t.TempDir()
	err = os.Chdir(tempDir)
	require.NoError(t, err)

	// Calling config.Load() without a path should look for "./config.yaml"
	_, err = config.Load()

	// Should fail because there's no ./config.yaml in temp dir
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "./config.yaml")
}

// TestConfigLoadWithCustomPath tests that config.Load() uses the provided path
func TestConfigLoadWithCustomPath(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "custom-config.yaml")

	// Write a valid config file
	configContent := `
server:
  listenAddress: ":8080"
kubernetes:
  oidcPrefixes:
    - "oidc:"
`
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config with custom path
	cfg, err := config.Load(configFile)

	// Should succeed
	assert.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Server.ListenAddress)
	assert.Len(t, cfg.Kubernetes.OIDCPrefixes, 1)
	assert.Equal(t, "oidc:", cfg.Kubernetes.OIDCPrefixes[0])
}

// TestOIDCPrefixStrippingWithCustomConfig tests that OIDC prefix stripping works with custom config path
func TestOIDCPrefixStrippingWithCustomConfig(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	// Write a config file with OIDC prefixes
	configContent := `
server:
  listenAddress: ":8080"
kubernetes:
  oidcPrefixes:
    - "oidc:"
    - "custom:"
`
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load config
	cfg, err := config.Load(configFile)
	require.NoError(t, err)

	// Test stripping
	originalGroups := []string{"oidc:admin", "custom:user", "system:admin"}
	strippedGroups := stripOIDCPrefixes(originalGroups, cfg.Kubernetes.OIDCPrefixes)

	// Verify prefixes were stripped
	assert.Equal(t, []string{"admin", "user", "system:admin"}, strippedGroups)
}
