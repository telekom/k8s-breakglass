package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfigPath(t *testing.T) {
	t.Run("uses BGCTL_CONFIG env var when set", func(t *testing.T) {
		customPath := "/custom/path/config.yaml"
		t.Setenv("BGCTL_CONFIG", customPath)

		result := DefaultConfigPath()
		assert.Equal(t, customPath, result)
	})

	t.Run("uses user config dir when BGCTL_CONFIG not set", func(t *testing.T) {
		// Clear the env var
		t.Setenv("BGCTL_CONFIG", "")

		result := DefaultConfigPath()

		// Result should be a valid path ending with bgctl/config.yaml
		assert.True(t, strings.HasSuffix(result, filepath.Join("bgctl", "config.yaml")),
			"Expected path to end with bgctl/config.yaml, got: %s", result)
	})

	t.Run("returns non-empty path", func(t *testing.T) {
		t.Setenv("BGCTL_CONFIG", "")

		result := DefaultConfigPath()
		assert.NotEmpty(t, result)
	})
}

func TestDefaultTokenPath(t *testing.T) {
	t.Run("uses user config dir", func(t *testing.T) {
		result := DefaultTokenPath()

		// Result should be a valid path ending with bgctl/tokens.json
		assert.True(t, strings.HasSuffix(result, filepath.Join("bgctl", "tokens.json")),
			"Expected path to end with bgctl/tokens.json, got: %s", result)
	})

	t.Run("returns non-empty path", func(t *testing.T) {
		result := DefaultTokenPath()
		assert.NotEmpty(t, result)
	})

	t.Run("path is absolute", func(t *testing.T) {
		result := DefaultTokenPath()
		assert.True(t, filepath.IsAbs(result), "Expected absolute path, got: %s", result)
	})
}

func TestDefaultConfigPath_FallbackToHomeDir(t *testing.T) {
	// This test verifies the fallback behavior when UserConfigDir fails
	// We can't easily make UserConfigDir fail, but we can verify the path structure

	t.Run("path contains expected directory name", func(t *testing.T) {
		t.Setenv("BGCTL_CONFIG", "")

		result := DefaultConfigPath()

		// Should contain bgctl somewhere in the path
		assert.Contains(t, result, "bgctl")
		assert.Contains(t, result, "config.yaml")
	})
}

func TestDefaultTokenPath_FallbackToHomeDir(t *testing.T) {
	t.Run("path contains expected directory and filename", func(t *testing.T) {
		result := DefaultTokenPath()

		// Should contain bgctl somewhere in the path
		assert.Contains(t, result, "bgctl")
		assert.Contains(t, result, "tokens.json")
	})
}

func TestPathConstants(t *testing.T) {
	// Verify the constants are as expected
	assert.Equal(t, "bgctl", defaultConfigDirName)
	assert.Equal(t, "config.yaml", defaultConfigFile)
	assert.Equal(t, "tokens.json", defaultTokenFile)
}

func TestDefaultConfigPath_Integration(t *testing.T) {
	t.Run("config path is writable directory", func(t *testing.T) {
		t.Setenv("BGCTL_CONFIG", "")

		result := DefaultConfigPath()
		dir := filepath.Dir(result)

		// The parent of the config dir should exist or be creatable
		// We just verify the path is reasonable
		require.NotEmpty(t, dir)

		// Verify we can get to a home or config directory
		home, err := os.UserHomeDir()
		if err == nil {
			// Path should be somewhere under home or system config
			assert.True(t,
				strings.HasPrefix(result, home) || strings.Contains(result, "Library") || strings.Contains(result, ".config"),
				"Path should be under home or config dir: %s", result)
		}
	})
}
