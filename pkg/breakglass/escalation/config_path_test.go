// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
