// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
)

// TestEscalationControllerUsesConfigPath verifies that the controller uses the provided config path for OIDC prefix stripping.
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

func TestPlatformEscalationCachedConfig(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "config.yaml")
	write := func(content string, seconds int64) {
		t.Helper()
		require.NoError(t, os.WriteFile(filename, []byte(content), 0600))
		timestamp := time.Unix(1700000000+seconds, 0)
		require.NoError(t, os.Chtimes(filename, timestamp, timestamp))
	}
	loader := config.NewCachedLoader(filename, time.Nanosecond)
	manager := NewEscalationManagerWithClient(nil, nil, WithConfigLoader(loader))
	WithConfigLoader(nil)(manager)
	require.Same(t, loader, manager.configLoader, "nil option does not remove the shared cache")
	assertPrefixes := func(expected string) {
		t.Helper()
		cfg, err := manager.getConfig()
		require.NoError(t, err)
		require.Equal(t, []string{expected}, cfg.Kubernetes.OIDCPrefixes)
	}
	write("kubernetes:\n  oidcPrefixes: [\"first:\"]\n", 0)
	assertPrefixes("first:")
	write("kubernetes: [", 1)
	assertPrefixes("first:")
	write("kubernetes:\n  oidcPrefixes: [\"recovered:\"]\n", 1)
	assertPrefixes("recovered:")
	require.NoError(t, os.Remove(filename))
	assertPrefixes("recovered:")
}
