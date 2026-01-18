/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCompletionCommand(t *testing.T) {
	cmd := NewCompletionCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "completion [bash|zsh|fish|powershell]", cmd.Use)
	assert.Contains(t, cmd.Short, "completion")
}

func TestCompletionCommand_UnsupportedShell(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"completion", "unsupported"})
	err := rootCmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported shell")
}

func TestCompletionCommand_Bash(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"completion", "bash"})
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "bash completion")
}

func TestCompletionCommand_Zsh(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"completion", "zsh"})
	err := rootCmd.Execute()

	require.NoError(t, err)
	// Zsh completion scripts contain compdef
	assert.True(t, len(buf.String()) > 0)
}

func TestCompletionCommand_Fish(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"completion", "fish"})
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.True(t, len(buf.String()) > 0)
}

func TestCompletionCommand_Powershell(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"completion", "powershell"})
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.True(t, len(buf.String()) > 0)
}

func TestCompletionCommand_RequiresArg(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"completion"})
	err := rootCmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg")
}

func TestNewConfigCommand(t *testing.T) {
	cmd := NewConfigCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "config", cmd.Use)
	assert.Contains(t, cmd.Short, "configuration")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	var names []string
	for _, sub := range subcommands {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "init")
	assert.Contains(t, names, "view")
	assert.Contains(t, names, "get-contexts")
	assert.Contains(t, names, "use-context")
}

func TestConfigInitCommand_RequiresServer(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"config", "init"})
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	err := rootCmd.Execute()

	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "server")
}

func TestConfigInitCommand_RequiresOIDC(t *testing.T) {
	buf := &bytes.Buffer{}
	tempFile := "/tmp/test-bgctl-config-" + t.Name() + ".yaml"
	defer os.Remove(tempFile)

	rootCmd := NewRootCommand(Config{
		ConfigPath:   tempFile,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"config", "init", "--server", "https://example.com"})
	err := rootCmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc-authority")
}

func TestConfigInitCommand_Success(t *testing.T) {
	buf := &bytes.Buffer{}
	tempFile := "/tmp/test-bgctl-config-" + t.Name() + ".yaml"
	defer os.Remove(tempFile)

	rootCmd := NewRootCommand(Config{
		ConfigPath:   tempFile,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"config", "init",
		"--server", "https://breakglass.example.com",
		"--oidc-authority", "https://auth.example.com",
		"--oidc-client-id", "test-client",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Initialized config")

	// Verify file was created
	_, err = os.Stat(tempFile)
	require.NoError(t, err)
}

func TestConfigInitCommand_NoOverwrite(t *testing.T) {
	buf := &bytes.Buffer{}
	tempFile := "/tmp/test-bgctl-config-" + t.Name() + ".yaml"

	// Create existing file
	err := os.WriteFile(tempFile, []byte("existing: config"), 0o600)
	require.NoError(t, err)
	defer os.Remove(tempFile)

	rootCmd := NewRootCommand(Config{
		ConfigPath:   tempFile,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"config", "init",
		"--server", "https://breakglass.example.com",
		"--oidc-authority", "https://auth.example.com",
		"--oidc-client-id", "test-client",
	})
	err = rootCmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestConfigInitCommand_ForceOverwrite(t *testing.T) {
	buf := &bytes.Buffer{}
	tempFile := "/tmp/test-bgctl-config-" + t.Name() + ".yaml"

	// Create existing file
	err := os.WriteFile(tempFile, []byte("existing: config"), 0o600)
	require.NoError(t, err)
	defer os.Remove(tempFile)

	rootCmd := NewRootCommand(Config{
		ConfigPath:   tempFile,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"config", "init",
		"--server", "https://breakglass.example.com",
		"--oidc-authority", "https://auth.example.com",
		"--oidc-client-id", "test-client",
		"--force",
	})
	err = rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "Initialized config")
}

func TestNewAuthCommand(t *testing.T) {
	cmd := NewAuthCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "auth", cmd.Use)

	// Verify subcommands
	subcommands := cmd.Commands()
	var names []string
	for _, sub := range subcommands {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "login")
	assert.Contains(t, names, "status")
	assert.Contains(t, names, "logout")
}

func TestNewSessionCommand(t *testing.T) {
	cmd := NewSessionCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "session", cmd.Use)

	// Verify subcommands
	subcommands := cmd.Commands()
	var names []string
	for _, sub := range subcommands {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "list")
	assert.Contains(t, names, "request")
	assert.Contains(t, names, "approve")
	assert.Contains(t, names, "reject")
}

func TestNewEscalationCommand(t *testing.T) {
	cmd := NewEscalationCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "escalation", cmd.Use)
}

func TestNewDebugCommand(t *testing.T) {
	cmd := NewDebugCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "debug", cmd.Use)
}

func TestNewUpdateCommand(t *testing.T) {
	cmd := NewUpdateCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "update", cmd.Use)

	// Verify subcommands
	subcommands := cmd.Commands()
	var names []string
	for _, sub := range subcommands {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "check")
	assert.Contains(t, names, "rollback")
}

func TestRootCommand_PersistentFlags(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		OutputWriter: buf,
	})

	// Verify persistent flags exist
	flags := rootCmd.PersistentFlags()
	require.NotNil(t, flags.Lookup("config"))
	require.NotNil(t, flags.Lookup("context"))
	require.NotNil(t, flags.Lookup("output"))
	require.NotNil(t, flags.Lookup("server"))
	require.NotNil(t, flags.Lookup("token"))
	require.NotNil(t, flags.Lookup("non-interactive"))
}

func TestRootCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "bgctl")
	assert.Contains(t, buf.String(), "config")
	assert.Contains(t, buf.String(), "auth")
	assert.Contains(t, buf.String(), "session")
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.NotEmpty(t, cfg.ConfigPath)
	assert.NotNil(t, cfg.OutputWriter)
}

func TestRuntimeState_OutputFormat(t *testing.T) {
	tests := []struct {
		name            string
		outputOverride  string
		cfgOutputFormat string
		expectedFormat  string
	}{
		{
			name:           "default format",
			expectedFormat: "table",
		},
		{
			name:           "override format",
			outputOverride: "json",
			expectedFormat: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &runtimeState{
				outputFormat: tt.outputOverride,
			}
			assert.Equal(t, tt.expectedFormat, rt.OutputFormat())
		})
	}
}

func TestRuntimeState_Writer(t *testing.T) {
	t.Run("custom writer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rt := &runtimeState{writer: buf}
		assert.Equal(t, buf, rt.Writer())
	})

	t.Run("default to stdout", func(t *testing.T) {
		rt := &runtimeState{}
		assert.Equal(t, os.Stdout, rt.Writer())
	})
}

func TestRuntimeState_ResolveContextName(t *testing.T) {
	t.Run("override takes precedence", func(t *testing.T) {
		rt := &runtimeState{contextOverride: "my-context"}
		assert.Equal(t, "my-context", rt.ResolveContextName())
	})

	t.Run("empty when no config", func(t *testing.T) {
		rt := &runtimeState{}
		assert.Equal(t, "", rt.ResolveContextName())
	})
}

// TestServerTokenBypassConfig verifies that --server and --token flags bypass config file requirement
func TestServerTokenBypassConfig(t *testing.T) {
	t.Run("help works without config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		rootCmd.SetArgs([]string{"--help"})
		err := rootCmd.Execute()

		require.NoError(t, err)
		assert.Contains(t, buf.String(), "Breakglass CLI")
	})

	t.Run("session list with server and token should not require config file", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		// This should NOT fail with "no such file or directory" error for config
		// It will fail with connection error which is expected, but the error should
		// NOT be about missing config file
		rootCmd.SetArgs([]string{
			"--server", "https://test.example.com",
			"--token", "test-token-123",
			"session", "list",
		})
		err := rootCmd.Execute()

		// We expect an error, but it should be a connection error, not a config file error
		if err != nil {
			// Should NOT contain config file errors
			assert.NotContains(t, err.Error(), "no such file or directory")
			assert.NotContains(t, err.Error(), "config path is required")
		}
	})

	t.Run("escalation list with server and token should not require config file", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		rootCmd.SetArgs([]string{
			"--server", "https://test.example.com",
			"--token", "test-token-123",
			"escalation", "list",
		})
		err := rootCmd.Execute()

		// We expect an error, but it should be a connection error, not a config file error
		if err != nil {
			// Should NOT contain config file errors
			assert.NotContains(t, err.Error(), "no such file or directory")
			assert.NotContains(t, err.Error(), "config path is required")
		}
	})

	t.Run("debug session list with server and token should not require config file", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		rootCmd.SetArgs([]string{
			"--server", "https://test.example.com",
			"--token", "test-token-123",
			"debug", "session", "list",
		})
		err := rootCmd.Execute()

		// We expect an error, but it should be a connection error, not a config file error
		if err != nil {
			// Should NOT contain config file errors
			assert.NotContains(t, err.Error(), "no such file or directory")
			assert.NotContains(t, err.Error(), "config path is required")
		}
	})

	t.Run("without server or token, config file is required", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		rootCmd.SetArgs([]string{"session", "list"})
		err := rootCmd.Execute()

		// Without --server and --token, config file error is expected
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("server without token still requires config file", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		rootCmd.SetArgs([]string{
			"--server", "https://test.example.com",
			"session", "list",
		})
		err := rootCmd.Execute()

		// Without --token, config file error is expected (need token from config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("token without server still requires config file", func(t *testing.T) {
		buf := &bytes.Buffer{}
		rootCmd := NewRootCommand(Config{
			ConfigPath:   "/nonexistent/path/to/config.yaml",
			OutputWriter: buf,
		})
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)

		rootCmd.SetArgs([]string{
			"--token", "test-token-123",
			"session", "list",
		})
		err := rootCmd.Execute()

		// Without --server, config file error is expected (need server from config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})
}
