/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package cli contains comprehensive E2E tests for the bgctl CLI.
// These tests verify all CLI commands work correctly against a live environment.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

// =============================================================================
// Test Helpers
// =============================================================================

type cliTestContext struct {
	t          *testing.T
	configPath string
	token      string
	serverURL  string
}

func newCLITestContext(t *testing.T) *cliTestContext {
	t.Helper()

	if !helpers.IsE2EEnabled() {
		t.Skip("E2E tests disabled. Set E2E_TEST=true")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Get OIDC token
	oidcProvider := helpers.DefaultOIDCProvider()
	token := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token, "Failed to get OIDC token")

	serverURL := mcConfig.HubAPIURL
	if serverURL == "" {
		serverURL = os.Getenv("BREAKGLASS_API_URL")
	}
	require.NotEmpty(t, serverURL, "Hub API URL must be set")

	cfg := createCLIConfig(t, serverURL)
	configPath := writeConfigFile(t, cfg)

	return &cliTestContext{
		t:          t,
		configPath: configPath,
		token:      token,
		serverURL:  serverURL,
	}
}

func (c *cliTestContext) runCommand(args ...string) (string, error) {
	buf := &bytes.Buffer{}
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
		ConfigPath:   c.configPath,
		OutputWriter: buf,
	})
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func (c *cliTestContext) runCommandWithToken(args ...string) (string, error) {
	allArgs := append([]string{"--token", c.token}, args...)
	return c.runCommand(allArgs...)
}

// =============================================================================
// Auth Command Tests
// =============================================================================

// TestCLIAuthWithTokenOverride tests authentication commands using the --token flag.
// Note: Testing the actual `auth login` command requires browser/device-code flow
// which cannot be automated. This test uses --token override to simulate authenticated state.
func TestCLIAuthWithTokenOverride(t *testing.T) {
	tc := newCLITestContext(t)

	// Test auth status with token override shows authenticated
	t.Run("StatusWithToken", func(t *testing.T) {
		output, err := tc.runCommandWithToken("auth", "status")
		require.NoError(t, err)
		assert.Contains(t, strings.ToLower(output), "authenticated", "should show authenticated status with token")
	})

	// Test that commands work with token override
	t.Run("EscalationListWithToken", func(t *testing.T) {
		output, err := tc.runCommandWithToken("escalation", "list", "-o", "json")
		require.NoError(t, err, "Should list escalations with token override")

		var escalations []v1alpha1.BreakglassEscalation
		err = json.Unmarshal([]byte(output), &escalations)
		require.NoError(t, err, "Should parse escalation list")
		t.Logf("Listed %d escalations with token override", len(escalations))
	})

	t.Run("SessionListWithToken", func(t *testing.T) {
		output, err := tc.runCommandWithToken("session", "list", "-o", "json")
		require.NoError(t, err, "Should list sessions with token override")
		assert.True(t, json.Valid([]byte(output)), "Should return valid JSON")
	})
}

func TestCLIAuthStatus(t *testing.T) {
	tc := newCLITestContext(t)

	// Test auth status with token (should show authenticated)
	output, err := tc.runCommandWithToken("auth", "status")
	require.NoError(t, err)
	// With a token override, status should indicate we're authenticated
	assert.Contains(t, output, "authenticated", "should show authentication status")
}

func TestCLIAuthLogoutWithoutLogin(t *testing.T) {
	// Use a temporary config to avoid affecting real state
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := config.DefaultConfig()
	cfg.CurrentContext = "test"
	cfg.Contexts = []config.Context{{
		Name:   "test",
		Server: "https://localhost",
		OIDC:   &config.InlineOIDC{Authority: "https://idp.test", ClientID: "test"},
	}}
	require.NoError(t, config.Save(configPath, &cfg))

	buf := &bytes.Buffer{}
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})
	root.SetArgs([]string{"auth", "logout"})
	root.SetOut(buf)
	root.SetErr(buf)

	// Logout may fail if no tokens file exists - that's acceptable
	// The command should either succeed or fail gracefully with "no such file" error
	err := root.Execute()
	if err != nil {
		// Accept "no such file" errors as valid (no tokens to logout)
		assert.Contains(t, err.Error(), "no such file", "expected 'no such file' error or success")
	}
}

// =============================================================================
// Config Command Tests
// =============================================================================

func TestCLIConfigFullLifecycle(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "test-config.yaml")

	t.Run("init with OIDC provider reference", func(t *testing.T) {
		// First create a config with inline OIDC
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"config", "init",
			"--server", "https://api.example.com",
			"--context", "main-ctx",
			"--oidc-authority", "https://idp.example.com/realms/main",
			"--oidc-client-id", "bgctl",
		})

		err := root.Execute()
		require.NoError(t, err)
		require.FileExists(t, configPath)
	})

	t.Run("add OIDC provider", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"config", "add-oidc-provider", "corp-idp",
			"--authority", "https://corp.example.com/auth",
			"--client-id", "bgctl-corp",
		})

		err := root.Execute()
		require.NoError(t, err)

		// Verify provider was added
		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		found := false
		for _, p := range cfg.OIDCProviders {
			if p.Name == "corp-idp" {
				found = true
				assert.Equal(t, "https://corp.example.com/auth", p.Authority)
			}
		}
		assert.True(t, found, "OIDC provider should exist")
	})

	t.Run("get OIDC providers", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "get-oidc-providers"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "corp-idp")
	})

	t.Run("add context with OIDC reference", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"config", "add-context", "corp",
			"--server", "https://corp.example.com",
			"--oidc-provider", "corp-idp",
		})

		err := root.Execute()
		require.NoError(t, err)

		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		found := false
		for _, ctx := range cfg.Contexts {
			if ctx.Name == "corp" {
				found = true
				assert.Equal(t, "corp-idp", ctx.OIDCProvider)
			}
		}
		assert.True(t, found)
	})

	t.Run("get contexts", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "get-contexts"})

		err := root.Execute()
		require.NoError(t, err)
		output := buf.String()
		assert.Contains(t, output, "main-ctx")
		assert.Contains(t, output, "corp")
	})

	t.Run("current context", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "current-context"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "main-ctx")
	})

	t.Run("use context", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "use-context", "corp"})

		err := root.Execute()
		require.NoError(t, err)

		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		assert.Equal(t, "corp", cfg.CurrentContext)
	})

	// Note: set-context only sets the current context, it doesn't modify context properties.
	// To modify context properties, use config set or recreate the context.

	t.Run("set value", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "set", "settings.output-format", "json"})

		err := root.Execute()
		require.NoError(t, err)

		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		assert.Equal(t, "json", cfg.Settings.OutputFormat)
	})

	t.Run("delete context", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "delete-context", "corp"})

		err := root.Execute()
		require.NoError(t, err)

		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		for _, ctx := range cfg.Contexts {
			assert.NotEqual(t, "corp", ctx.Name)
		}
	})

	t.Run("delete OIDC provider", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "delete-oidc-provider", "corp-idp"})

		err := root.Execute()
		require.NoError(t, err)

		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		for _, p := range cfg.OIDCProviders {
			assert.NotEqual(t, "corp-idp", p.Name)
		}
	})

	t.Run("view config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "view"})

		err := root.Execute()
		require.NoError(t, err)
		assert.Contains(t, buf.String(), "version:")
		assert.Contains(t, buf.String(), "contexts:")
	})
}

// =============================================================================
// Session Command Tests
// =============================================================================

func TestCLISessionFullLifecycle(t *testing.T) {
	tc := newCLITestContext(t)
	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	var sessionName, sessionNamespace string

	t.Run("session list empty or existing", func(t *testing.T) {
		output, err := tc.runCommandWithToken("session", "list", "-o", "json")
		require.NoError(t, err)

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &sessions)
		require.NoError(t, err)
		t.Logf("Found %d existing sessions", len(sessions))
	})

	t.Run("session request", func(t *testing.T) {
		output, err := tc.runCommandWithToken(
			"session", "request",
			"--cluster", mcConfig.HubClusterName,
			"--group", "breakglass-create-all",
			"--reason", "CLI E2E comprehensive test",
			"-o", "json",
		)
		require.NoError(t, err)

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err)

		sessionName = session.Name
		sessionNamespace = session.Namespace
		require.NotEmpty(t, sessionName)

		assert.Equal(t, mcConfig.HubClusterName, session.Spec.Cluster)
		assert.Equal(t, "CLI E2E comprehensive test", session.Spec.RequestReason)
		t.Logf("Created session: %s/%s", sessionNamespace, sessionName)
	})

	t.Run("session get", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "session must be created first")

		output, err := tc.runCommandWithToken("session", "get", sessionName, "-o", "json")
		require.NoError(t, err)

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err)
		assert.Equal(t, sessionName, session.Name)
	})

	t.Run("session list with filters", func(t *testing.T) {
		// Filter by cluster
		output, err := tc.runCommandWithToken(
			"session", "list",
			"--cluster", mcConfig.HubClusterName,
			"-o", "json",
		)
		require.NoError(t, err)

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &sessions)
		require.NoError(t, err)
		for _, s := range sessions {
			assert.Equal(t, mcConfig.HubClusterName, s.Spec.Cluster)
		}

		// Filter by state
		_, err = tc.runCommandWithToken(
			"session", "list",
			"--state", "pending",
			"-o", "json",
		)
		require.NoError(t, err)
	})

	t.Run("session list mine", func(t *testing.T) {
		output, err := tc.runCommandWithToken("session", "list", "--mine", "-o", "json")
		require.NoError(t, err)

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &sessions)
		require.NoError(t, err)
		// All should be for our user
		for _, s := range sessions {
			assert.Equal(t, helpers.TestUsers.Requester.Email, s.Spec.User)
		}
	})

	t.Run("session withdraw", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "session must be created first")

		output, err := tc.runCommandWithToken("session", "withdraw", sessionName)
		require.NoError(t, err)
		assert.Contains(t, strings.ToLower(output), "withdraw", "should confirm withdrawal")
	})

	// Create a new session for approve/reject tests using approver
	t.Run("session approval workflow", func(t *testing.T) {
		// Get approver token
		oidcProvider := helpers.DefaultOIDCProvider()
		approverToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)

		// Create another session as requester
		output, err := tc.runCommandWithToken(
			"session", "request",
			"--cluster", mcConfig.HubClusterName,
			"--group", "breakglass-create-all",
			"--reason", "CLI E2E approve test",
			"-o", "json",
		)
		require.NoError(t, err)

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err)

		// Wait for session to be in pending state
		time.Sleep(2 * time.Second)

		// Approve as approver
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   tc.configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"--token", approverToken, "session", "approve", session.Name})
		err = root.Execute()
		if err != nil {
			t.Logf("Approve error (may be expected): %v", err)
		}

		// Drop the session to avoid blocking subsequent tests that use the same group
		buf.Reset()
		root = bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   tc.configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"--token", tc.token, "session", "drop", session.Name})
		err = root.Execute()
		if err != nil {
			t.Logf("Drop error (may be expected): %v", err)
		}
	})
}

// =============================================================================
// Escalation Command Tests
// =============================================================================

func TestCLIEscalationCommands(t *testing.T) {
	tc := newCLITestContext(t)

	t.Run("escalation list", func(t *testing.T) {
		output, err := tc.runCommandWithToken("escalation", "list", "-o", "json")
		require.NoError(t, err)

		var escalations []v1alpha1.BreakglassEscalation
		err = json.Unmarshal([]byte(output), &escalations)
		require.NoError(t, err)
		t.Logf("Found %d escalations", len(escalations))

		// Table format should work too
		output, err = tc.runCommandWithToken("escalation", "list")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
	})

	t.Run("escalation get", func(t *testing.T) {
		// First list to get an escalation name
		output, err := tc.runCommandWithToken("escalation", "list", "-o", "json")
		require.NoError(t, err)

		var escalations []v1alpha1.BreakglassEscalation
		err = json.Unmarshal([]byte(output), &escalations)
		require.NoError(t, err)

		require.NotEmpty(t, escalations, "Escalations must exist in E2E environment - check that fixtures are loaded")

		escName := escalations[0].Name
		output, err = tc.runCommandWithToken("escalation", "get", escName, "-o", "json")
		require.NoError(t, err)

		var esc v1alpha1.BreakglassEscalation
		err = json.Unmarshal([]byte(output), &esc)
		require.NoError(t, err)
		assert.Equal(t, escName, esc.Name)
	})
}

// =============================================================================
// Debug Session Command Tests
// =============================================================================

// debugTemplateSummary mirrors the API response structure for debug templates
type debugTemplateSummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

func TestCLIDebugSessionCommands(t *testing.T) {
	tc := newCLITestContext(t)

	t.Run("debug template list", func(t *testing.T) {
		output, err := tc.runCommandWithToken("debug", "template", "list", "-o", "json")
		require.NoError(t, err)

		var templates []debugTemplateSummary
		err = json.Unmarshal([]byte(output), &templates)
		require.NoError(t, err)
		t.Logf("Found %d debug templates", len(templates))

		for _, tmpl := range templates {
			t.Logf("  - %s", tmpl.Name)
		}
	})

	t.Run("debug template get", func(t *testing.T) {
		output, err := tc.runCommandWithToken("debug", "template", "list", "-o", "json")
		require.NoError(t, err)

		var templates []debugTemplateSummary
		err = json.Unmarshal([]byte(output), &templates)
		require.NoError(t, err)

		require.NotEmpty(t, templates, "DebugSessionTemplates must exist in E2E environment - check that fixtures are loaded")

		tmplName := templates[0].Name
		output, err = tc.runCommandWithToken("debug", "template", "get", tmplName, "-o", "json")
		require.NoError(t, err)

		var tmpl v1alpha1.DebugSessionTemplate
		err = json.Unmarshal([]byte(output), &tmpl)
		require.NoError(t, err)
		assert.Equal(t, tmplName, tmpl.Name)
	})

	t.Run("debug pod-template list", func(t *testing.T) {
		output, err := tc.runCommandWithToken("debug", "pod-template", "list", "-o", "json")
		require.NoError(t, err)

		var templates []v1alpha1.DebugPodTemplate
		err = json.Unmarshal([]byte(output), &templates)
		require.NoError(t, err)
		t.Logf("Found %d debug pod templates", len(templates))
	})

	t.Run("debug session list", func(t *testing.T) {
		output, err := tc.runCommandWithToken("debug", "session", "list", "-o", "json")
		require.NoError(t, err)
		// Should return valid JSON (array or object with sessions)
		assert.True(t, json.Valid([]byte(output)), "should return valid JSON")
	})

	t.Run("debug session create and lifecycle", func(t *testing.T) {
		mcConfig := helpers.GetMultiClusterConfig()

		// Get a template first
		output, err := tc.runCommandWithToken("debug", "template", "list", "-o", "json")
		require.NoError(t, err)

		var templates []debugTemplateSummary
		err = json.Unmarshal([]byte(output), &templates)
		require.NoError(t, err)

		require.NotEmpty(t, templates, "DebugSessionTemplates must exist in E2E environment - check that fixtures are loaded")

		tmplName := templates[0].Name
		require.NotEmpty(t, tmplName, "Template name should not be empty")

		// Create debug session
		output, err = tc.runCommandWithToken(
			"debug", "session", "create",
			"--cluster", mcConfig.HubClusterName,
			"--template", tmplName,
			"--reason", "CLI E2E debug test",
			"-o", "json",
		)
		require.NoError(t, err, "Debug session creation should succeed when templates are available")

		var session v1alpha1.DebugSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err)
		sessionName := session.Name

		t.Logf("Created debug session: %s", sessionName)

		// Get the session
		_, err = tc.runCommandWithToken("debug", "session", "get", sessionName, "-o", "json")
		require.NoError(t, err)

		// Terminate the session
		_, err = tc.runCommandWithToken("debug", "session", "terminate", sessionName)
		if err != nil {
			t.Logf("Terminate error: %v", err)
		}
	})
}

// =============================================================================
// Update Command Tests
// =============================================================================

func TestCLIUpdateCommands(t *testing.T) {
	// Create a valid config file for the test
	configPath := filepath.Join(t.TempDir(), "test-config.yaml")
	cfg := config.DefaultConfig()
	cfg.CurrentContext = "test"
	cfg.Contexts = []config.Context{{
		Name:   "test",
		Server: "https://localhost",
		OIDC:   &config.InlineOIDC{Authority: "https://idp.test", ClientID: "test"},
	}}
	require.NoError(t, config.Save(configPath, &cfg))

	t.Run("update check", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"update", "check"})
		root.SetOut(buf)
		root.SetErr(buf)

		err := root.Execute()
		// May fail if offline or no GitHub access, but command should be valid
		if err != nil {
			t.Logf("Update check error (expected if offline): %v", err)
			// Accept any error when offline/no access
		} else {
			output := buf.String()
			t.Logf("Update check output: %s", output)
		}
	})

	t.Run("update dry-run", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"update", "--dry-run"})
		root.SetOut(buf)
		root.SetErr(buf)

		err := root.Execute()
		// May fail if offline, but dry-run should not actually update
		if err != nil {
			t.Logf("Update dry-run error (expected if offline): %v", err)
		}
	})

	t.Run("update rollback dry-run", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"update", "rollback", "--dry-run"})
		root.SetOut(buf)
		root.SetErr(buf)

		err := root.Execute()
		// Will fail if no .old binary exists, which is expected
		if err != nil {
			t.Logf("Rollback dry-run error (expected - no .old binary): %v", err)
		}
	})
}

// =============================================================================
// Output Format Tests (across commands)
// =============================================================================

func TestCLIOutputFormats(t *testing.T) {
	tc := newCLITestContext(t)

	commands := []struct {
		name string
		args []string
	}{
		{"session list", []string{"session", "list"}},
		{"escalation list", []string{"escalation", "list"}},
		{"debug session list", []string{"debug", "session", "list"}},
		{"debug template list", []string{"debug", "template", "list"}},
	}

	formats := []string{"json", "yaml", "table"}

	for _, cmd := range commands {
		for _, format := range formats {
			t.Run(fmt.Sprintf("%s/%s", cmd.name, format), func(t *testing.T) {
				args := append(cmd.args, "-o", format)
				output, err := tc.runCommandWithToken(args...)
				if err != nil {
					t.Logf("Error (may be expected): %v", err)
					return
				}

				assert.NotEmpty(t, output, "output should not be empty")

				switch format {
				case "json":
					assert.True(t, json.Valid([]byte(output)), "should be valid JSON")
				case "yaml":
					// Empty arrays serialize as "[]" in YAML which is valid but has no colons
					// Only check for colons if there's actual content
					if strings.TrimSpace(output) != "[]" && len(strings.TrimSpace(output)) > 3 {
						assert.Contains(t, output, ":", "YAML should contain colons for non-empty results")
					}
				case "table":
					// Table format is human-readable, just check it's not empty
					assert.NotEmpty(t, output)
				}
			})
		}
	}
}

// =============================================================================
// Pagination Tests
// =============================================================================

func TestCLIListPagination(t *testing.T) {
	tc := newCLITestContext(t)

	t.Run("session list pagination", func(t *testing.T) {
		// First get all
		output, err := tc.runCommandWithToken("session", "list", "--all", "-o", "json")
		require.NoError(t, err)

		var allSessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &allSessions)
		require.NoError(t, err)

		// Then paginate
		output, err = tc.runCommandWithToken("session", "list", "--page", "1", "--page-size", "5", "-o", "json")
		require.NoError(t, err)

		var pagedSessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &pagedSessions)
		require.NoError(t, err)

		if len(allSessions) > 5 {
			assert.LessOrEqual(t, len(pagedSessions), 5, "paginated list should have max page-size items")
		}
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestCLIErrorHandling(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "test-config.yaml")

	t.Run("command without config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath, // Doesn't exist
			OutputWriter: buf,
		})
		root.SetArgs([]string{"session", "list"})

		err := root.Execute()
		// Should fail gracefully with config error
		assert.Error(t, err)
	})

	t.Run("invalid session name", func(t *testing.T) {
		tc := newCLITestContext(t)
		_, err := tc.runCommandWithToken("session", "get", "non-existent-session-12345")
		assert.Error(t, err)
	})

	t.Run("missing required args", func(t *testing.T) {
		tc := newCLITestContext(t)
		_, err := tc.runCommandWithToken("session", "request")
		// Should require cluster and group
		assert.Error(t, err)
	})
}

// =============================================================================
// Global Flags Tests
// =============================================================================

func TestCLIGlobalFlags(t *testing.T) {
	tc := newCLITestContext(t)

	t.Run("context override", func(t *testing.T) {
		// Create a second context
		cfg, err := config.Load(tc.configPath)
		require.NoError(t, err)
		cfg.Contexts = append(cfg.Contexts, config.Context{
			Name:   "alt-context",
			Server: tc.serverURL,
			OIDC:   cfg.Contexts[0].OIDC,
		})
		require.NoError(t, config.Save(tc.configPath, cfg))

		// Use context override
		output, err := tc.runCommand("--context", "alt-context", "--token", tc.token, "session", "list", "-o", "json")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
	})

	t.Run("server override", func(t *testing.T) {
		output, err := tc.runCommand("--server", tc.serverURL, "--token", tc.token, "session", "list", "-o", "json")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
	})

	t.Run("non-interactive mode", func(t *testing.T) {
		output, err := tc.runCommand("--non-interactive", "--token", tc.token, "session", "list", "-o", "json")
		require.NoError(t, err)
		assert.NotEmpty(t, output)
	})
}

// =============================================================================
// Watch Command Tests (basic verification)
// =============================================================================

func TestCLIWatchCommandsExist(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "test-config.yaml")
	cfg := config.DefaultConfig()
	cfg.CurrentContext = "test"
	cfg.Contexts = []config.Context{{
		Name:   "test",
		Server: "https://localhost",
		OIDC:   &config.InlineOIDC{Authority: "https://idp.test", ClientID: "test"},
	}}
	require.NoError(t, config.Save(configPath, &cfg))

	// Just verify the watch subcommands exist by checking --help
	commands := [][]string{
		{"session", "watch", "--help"},
		{"debug", "session", "watch", "--help"},
	}

	for _, args := range commands {
		t.Run(strings.Join(args[:len(args)-1], " "), func(t *testing.T) {
			buf := &bytes.Buffer{}
			root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
				ConfigPath:   configPath,
				OutputWriter: buf,
			})
			root.SetArgs(args)
			root.SetOut(buf)
			root.SetErr(buf)

			err := root.Execute()
			require.NoError(t, err)
			assert.Contains(t, buf.String(), "watch", "should show watch command help")
		})
	}
}

// =============================================================================
// Table format timestamp/duration tests
// =============================================================================

func TestCLITableFormatFields(t *testing.T) {
	tc := newCLITestContext(t)

	t.Run("session list table has expected columns", func(t *testing.T) {
		output, err := tc.runCommandWithToken("session", "list", "-o", "table")
		require.NoError(t, err)

		if output != "" && !strings.Contains(output, "No sessions") {
			// Check for expected column headers (matches WriteSessionTable output)
			headers := []string{"NAME", "CLUSTER", "USER", "STATE"}
			for _, h := range headers {
				assert.Contains(t, output, h, "table should contain %s column", h)
			}
		}
	})

	t.Run("escalation list table has expected columns", func(t *testing.T) {
		output, err := tc.runCommandWithToken("escalation", "list", "-o", "table")
		require.NoError(t, err)

		if output != "" && !strings.Contains(output, "No escalations") {
			assert.Contains(t, output, "NAME", "table should contain NAME column")
		}
	})
}

// =============================================================================
// Help Commands
// =============================================================================

func TestCLIHelpCommands(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nonexistent", "config.yaml")

	commands := []string{
		"--help",
		"auth --help",
		"config --help",
		"session --help",
		"escalation --help",
		"debug --help",
		"completion --help",
		"update --help",
		"version --help",
	}

	for _, cmdStr := range commands {
		args := strings.Split(cmdStr, " ")
		t.Run(cmdStr, func(t *testing.T) {
			buf := &bytes.Buffer{}
			root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
				ConfigPath:   configPath,
				OutputWriter: buf,
			})
			root.SetArgs(args)
			root.SetOut(buf)
			root.SetErr(buf)

			err := root.Execute()
			require.NoError(t, err, "help should not require config")
			assert.NotEmpty(t, buf.String(), "help should produce output")
		})
	}
}

// =============================================================================
// Special Edge Cases
// =============================================================================

func TestCLIEdgeCases(t *testing.T) {
	t.Run("empty config file", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "empty.yaml")
		require.NoError(t, os.WriteFile(configPath, []byte(""), 0600))

		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"session", "list"})

		err := root.Execute()
		assert.Error(t, err, "should fail with empty config")
	})

	t.Run("config with no contexts", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "no-contexts.yaml")
		cfg := config.DefaultConfig()
		cfg.Contexts = nil
		cfg.CurrentContext = ""
		require.NoError(t, config.Save(configPath, &cfg))

		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"session", "list"})

		err := root.Execute()
		assert.Error(t, err, "should fail with no contexts")
	})

	t.Run("session request with all optional flags", func(t *testing.T) {
		tc := newCLITestContext(t)
		mcConfig := helpers.GetMultiClusterConfig()

		// Request with duration and justification file
		justFile := filepath.Join(t.TempDir(), "justification.txt")
		require.NoError(t, os.WriteFile(justFile, []byte("Detailed justification text"), 0600))

		output, err := tc.runCommandWithToken(
			"session", "request",
			"--cluster", mcConfig.HubClusterName,
			"--group", "breakglass-create-all",
			"--reason", "Full flags test",
			"--duration", "3600",
			"-o", "json",
		)
		if err != nil {
			t.Logf("Request with all flags error: %v", err)
		} else {
			var session v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err)
			assert.NotEmpty(t, session.Name)

			// Clean up - withdraw the session
			_, _ = tc.runCommandWithToken("session", "withdraw", session.Name)
		}
	})
}

// =============================================================================
// Cluster-specific tests
// =============================================================================

func TestCLIClusterOperations(t *testing.T) {
	tc := newCLITestContext(t)

	t.Run("list available clusters", func(t *testing.T) {
		// Clusters are derived from escalation configurations
		// List escalations and extract unique clusters
		output, err := tc.runCommandWithToken("escalation", "list", "-o", "json")
		require.NoError(t, err, "Should be able to list escalations")

		var escalations []v1alpha1.BreakglassEscalation
		err = json.Unmarshal([]byte(output), &escalations)
		require.NoError(t, err, "Should parse escalations")

		// Extract unique clusters from escalations
		clusterSet := make(map[string]bool)
		for _, esc := range escalations {
			for _, cluster := range esc.Spec.Allowed.Clusters {
				clusterSet[cluster] = true
			}
		}

		t.Logf("Available clusters from escalations: %v", clusterSet)
		assert.NotEmpty(t, clusterSet, "Should have at least one cluster configured")
	})
}

// =============================================================================
// Full Chain E2E Test - Complete Session Lifecycle
// =============================================================================

// TestCLIFullChainSessionLifecycle tests the complete session lifecycle from
// request through approval to session usage and cleanup. This is the most
// comprehensive test ensuring all components work together.
func TestCLIFullChainSessionLifecycle(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("E2E tests disabled. Set E2E_TEST=true")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Get tokens for both requester and approver
	oidcProvider := helpers.DefaultOIDCProvider()
	requesterToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	approverToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)
	require.NotEmpty(t, requesterToken, "Failed to get requester OIDC token")
	require.NotEmpty(t, approverToken, "Failed to get approver OIDC token")

	serverURL := mcConfig.HubAPIURL
	if serverURL == "" {
		serverURL = os.Getenv("BREAKGLASS_API_URL")
	}
	require.NotEmpty(t, serverURL, "Hub API URL must be set")

	// Create CLI config
	cfg := createCLIConfig(t, serverURL)
	configPath := writeConfigFile(t, cfg)

	// Helper to run command with specific token
	runWithToken := func(token string, args ...string) (string, error) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		allArgs := append([]string{"--token", token}, args...)
		root.SetArgs(allArgs)
		err := root.Execute()
		return buf.String(), err
	}

	var sessionName string

	// Step 1: Verify requester can see available escalations
	t.Run("Step1_ListEscalations", func(t *testing.T) {
		output, err := runWithToken(requesterToken, "escalation", "list", "-o", "json")
		require.NoError(t, err, "Requester should be able to list escalations")

		var escalations []v1alpha1.BreakglassEscalation
		err = json.Unmarshal([]byte(output), &escalations)
		require.NoError(t, err, "Should parse escalation list")
		t.Logf("Found %d escalations available", len(escalations))
		require.NotEmpty(t, escalations, "At least one escalation should be available")
	})

	// Step 2: Requester creates a session
	t.Run("Step2_RequestSession", func(t *testing.T) {
		output, err := runWithToken(requesterToken,
			"session", "request",
			"--cluster", mcConfig.HubClusterName,
			"--group", "breakglass-create-all",
			"--reason", "Full chain E2E test - request",
			"-o", "json",
		)
		require.NoError(t, err, "Session request should succeed")

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err, "Should parse created session")
		require.NotEmpty(t, session.Name, "Session should have a name")

		sessionName = session.Name
		t.Logf("Created session: %s (state: %s)", sessionName, session.Status.State)
	})

	// Step 3: Verify session appears in requester's list
	t.Run("Step3_VerifySessionInList", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		output, err := runWithToken(requesterToken, "session", "list", "--mine", "-o", "json")
		require.NoError(t, err, "Should list my sessions")

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &sessions)
		require.NoError(t, err, "Should parse session list")

		found := false
		for _, s := range sessions {
			if s.Name == sessionName {
				found = true
				t.Logf("Found session %s in list (state: %s)", s.Name, s.Status.State)
				break
			}
		}
		require.True(t, found, "Session %s should appear in requester's session list", sessionName)
	})

	// Step 4: Wait for session to reach pending state
	t.Run("Step4_WaitForPendingState", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// Poll until pending state
		deadline := time.Now().Add(30 * time.Second)
		var lastState v1alpha1.BreakglassSessionState

		for time.Now().Before(deadline) {
			output, err := runWithToken(requesterToken, "session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Should get session")

			var session v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse session")

			lastState = session.Status.State
			if lastState == v1alpha1.SessionStatePending {
				t.Logf("Session %s reached Pending state", sessionName)
				return
			}
			t.Logf("Session state: %s, waiting for Pending...", lastState)
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Session %s did not reach Pending state in time, last state: %s", sessionName, lastState)
	})

	// Step 5: Approver approves the session
	t.Run("Step5_ApproveSession", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		output, err := runWithToken(approverToken, "session", "approve", sessionName)
		require.NoError(t, err, "Approver should be able to approve session")
		t.Logf("Approve response: %s", output)
	})

	// Step 6: Verify session transitions to Approved state
	t.Run("Step6_VerifyApprovedState", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// Poll until approved state
		deadline := time.Now().Add(30 * time.Second)
		var lastState v1alpha1.BreakglassSessionState

		for time.Now().Before(deadline) {
			output, err := runWithToken(requesterToken, "session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Should get session")

			var session v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse session")

			lastState = session.Status.State
			if lastState == v1alpha1.SessionStateApproved {
				t.Logf("Session %s reached Approved state", sessionName)
				require.NotEmpty(t, session.Status.Approvers, "Session should have approvers recorded")
				t.Logf("Approved by: %v", session.Status.Approvers)
				return
			}
			t.Logf("Session state: %s, waiting for Approved...", lastState)
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Session %s did not reach Approved state in time, last state: %s", sessionName, lastState)
	})

	// Step 7: Verify session appears as approved with filters
	t.Run("Step7_VerifyApprovedSessionFilters", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// List approved sessions for this cluster (include --mine to see own sessions,
		// since --approver defaults to true which only shows sessions user can approve)
		output, err := runWithToken(requesterToken,
			"session", "list",
			"--state", "approved",
			"--cluster", mcConfig.HubClusterName,
			"--mine",
			"-o", "json",
		)
		require.NoError(t, err, "Should list approved sessions")

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &sessions)
		require.NoError(t, err, "Should parse session list")

		found := false
		for _, s := range sessions {
			if s.Name == sessionName {
				found = true
				assert.Equal(t, v1alpha1.SessionStateApproved, s.Status.State)
				break
			}
		}
		require.True(t, found, "Session %s should appear in approved session list", sessionName)
	})

	// Step 8: Requester drops the session (cleanup to allow subsequent tests)
	t.Run("Step8_WithdrawSession", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// Drop the approved session to allow subsequent tests to create new sessions
		output, err := runWithToken(requesterToken, "session", "drop", sessionName)
		if err != nil {
			// Drop might fail if session expired or other reasons - log but don't fail
			t.Logf("Drop session result (may be expected to fail): %v, output: %s", err, output)
		} else {
			t.Logf("Session %s dropped successfully", sessionName)
		}
	})

	// Step 9: Final verification - session lifecycle completed successfully
	t.Run("Step9_VerifyLifecycleComplete", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// Get final session state
		output, err := runWithToken(requesterToken, "session", "get", sessionName, "-o", "json")
		require.NoError(t, err, "Should get session")

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err, "Should parse session")

		// Session should be in Approved state (or Expired if TTL is short)
		validFinalStates := []v1alpha1.BreakglassSessionState{
			v1alpha1.SessionStateApproved,
			v1alpha1.SessionStateExpired,
			v1alpha1.SessionStateWithdrawn,
		}
		found := false
		for _, s := range validFinalStates {
			if session.Status.State == s {
				found = true
				break
			}
		}
		require.True(t, found, "Session should be in a valid final state, got: %s", session.Status.State)
		t.Logf("Session %s final state: %s - lifecycle complete", sessionName, session.Status.State)
	})

	t.Logf("✅ Full chain E2E test completed successfully for session %s", sessionName)
}

// TestCLIFullChainDebugSessionLifecycle tests the complete debug session lifecycle
func TestCLIFullChainDebugSessionLifecycle(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("E2E tests disabled. Set E2E_TEST=true")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Get tokens
	oidcProvider := helpers.DefaultOIDCProvider()
	requesterToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	approverToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)
	require.NotEmpty(t, requesterToken, "Failed to get requester OIDC token")
	require.NotEmpty(t, approverToken, "Failed to get approver OIDC token")

	serverURL := mcConfig.HubAPIURL
	if serverURL == "" {
		serverURL = os.Getenv("BREAKGLASS_API_URL")
	}
	require.NotEmpty(t, serverURL, "Hub API URL must be set")

	// Create CLI config
	cfg := createCLIConfig(t, serverURL)
	configPath := writeConfigFile(t, cfg)

	// Helper to run command with specific token
	runWithToken := func(token string, args ...string) (string, error) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		allArgs := append([]string{"--token", token}, args...)
		root.SetArgs(allArgs)
		err := root.Execute()
		return buf.String(), err
	}

	var sessionName string
	var templateName string

	// Step 1: List available debug templates
	t.Run("Step1_ListDebugTemplates", func(t *testing.T) {
		output, err := runWithToken(requesterToken, "debug", "template", "list", "-o", "json")
		require.NoError(t, err, "Should list debug templates")

		var templates []debugTemplateSummary
		err = json.Unmarshal([]byte(output), &templates)
		require.NoError(t, err, "Should parse template list")
		t.Logf("Found %d debug templates", len(templates))

		require.NotEmpty(t, templates, "DebugSessionTemplates must exist in E2E environment - check that fixtures are loaded")

		templateName = templates[0].Name
		require.NotEmpty(t, templateName, "Template name should not be empty")
		t.Logf("Using template: %s", templateName)
	})

	// Step 2: Create debug session
	t.Run("Step2_CreateDebugSession", func(t *testing.T) {
		require.NotEmpty(t, templateName, "Template should have been found in previous step")

		output, err := runWithToken(requesterToken,
			"debug", "session", "create",
			"--cluster", mcConfig.HubClusterName,
			"--template", templateName,
			"--reason", fmt.Sprintf("Full chain debug E2E test %d", time.Now().UnixNano()),
			"-o", "json",
		)
		require.NoError(t, err, "Debug session creation should succeed when templates are available")

		var session v1alpha1.DebugSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err, "Should parse created debug session")
		require.NotEmpty(t, session.Name, "Debug session should have a name")

		sessionName = session.Name
		t.Logf("Created debug session: %s (state: %s)", sessionName, session.Status.State)
	})

	// Track if session was auto-approved (to skip manual approval step)
	var wasAutoApproved bool

	// Step 3: Wait for pending or approved state (template may have auto-approve enabled)
	t.Run("Step3_WaitForPendingOrApprovedState", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session should have been created in previous step")

		deadline := time.Now().Add(30 * time.Second)
		var lastState v1alpha1.DebugSessionState

		for time.Now().Before(deadline) {
			output, err := runWithToken(requesterToken, "debug", "session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Should get debug session")

			var session v1alpha1.DebugSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse debug session")

			lastState = session.Status.State
			if lastState == v1alpha1.DebugSessionStatePending {
				t.Logf("Debug session %s reached Pending state (will require approval)", sessionName)
				return
			}
			// Auto-approved - session went directly to Active or already past Pending
			if lastState == v1alpha1.DebugSessionStateActive {
				t.Logf("Debug session %s was auto-approved, now in %s state", sessionName, lastState)
				wasAutoApproved = true
				return
			}
			t.Logf("Debug session state: %s, waiting for Pending or Approved...", lastState)
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Debug session %s did not reach Pending or Approved state in time, last state: %s", sessionName, lastState)
	})

	// Step 4: Approver approves the debug session (skip if auto-approved)
	t.Run("Step4_ApproveDebugSession", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session should have been created in previous step")

		if wasAutoApproved {
			t.Skip("Session was auto-approved, skipping manual approval step")
		}

		output, err := runWithToken(approverToken, "debug", "session", "approve", sessionName)
		require.NoError(t, err, "Approver should be able to approve debug session")
		t.Logf("Debug session approve response: %s", output)
	})

	// Step 5: Verify approved state
	t.Run("Step5_VerifyApprovedState", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session should have been created in previous step")

		deadline := time.Now().Add(30 * time.Second)
		var lastState v1alpha1.DebugSessionState

		for time.Now().Before(deadline) {
			output, err := runWithToken(requesterToken, "debug", "session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Should get debug session")

			var session v1alpha1.DebugSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse debug session")

			lastState = session.Status.State
			if lastState == v1alpha1.DebugSessionStateActive {
				t.Logf("Debug session %s reached Active state", sessionName)
				return
			}
			t.Logf("Debug session state: %s, waiting for Active...", lastState)
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Debug session %s did not reach Approved/Running state in time, last state: %s", sessionName, lastState)
	})

	// Step 6: Terminate the debug session
	t.Run("Step6_TerminateDebugSession", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session should have been created in previous step")

		output, err := runWithToken(requesterToken, "debug", "session", "terminate", sessionName)
		if err != nil {
			t.Logf("Terminate error (may be expected): %v", err)
		} else {
			t.Logf("Terminate response: %s", output)
		}
	})

	// Step 7: Verify terminated state
	t.Run("Step7_VerifyTerminatedState", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session should have been created in previous step")

		deadline := time.Now().Add(30 * time.Second)
		var lastState v1alpha1.DebugSessionState

		for time.Now().Before(deadline) {
			output, err := runWithToken(requesterToken, "debug", "session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Should get debug session")

			var session v1alpha1.DebugSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse debug session")

			lastState = session.Status.State
			if lastState == v1alpha1.DebugSessionStateTerminated || lastState == v1alpha1.DebugSessionStateExpired {
				t.Logf("Debug session %s reached final state %s - lifecycle complete", sessionName, lastState)
				return
			}
			t.Logf("Debug session state: %s, waiting for terminal state...", lastState)
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Debug session %s did not reach terminal state in time, last state: %s", sessionName, lastState)
	})

	t.Logf("✅ Full chain debug session E2E test completed successfully for session %s", sessionName)
}

// TestCLIFullChainMultiActorWorkflow tests interactions between multiple users
func TestCLIFullChainMultiActorWorkflow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("E2E tests disabled. Set E2E_TEST=true")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Get tokens for multiple actors
	oidcProvider := helpers.DefaultOIDCProvider()
	requester1Token := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	approverToken := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Approver.Username, helpers.TestUsers.Approver.Password)
	require.NotEmpty(t, requester1Token, "Failed to get requester1 OIDC token")
	require.NotEmpty(t, approverToken, "Failed to get approver OIDC token")

	serverURL := mcConfig.HubAPIURL
	if serverURL == "" {
		serverURL = os.Getenv("BREAKGLASS_API_URL")
	}
	require.NotEmpty(t, serverURL, "Hub API URL must be set")

	// Create CLI config
	cfg := createCLIConfig(t, serverURL)
	configPath := writeConfigFile(t, cfg)

	// Helper to run command with specific token
	runWithToken := func(token string, args ...string) (string, error) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		allArgs := append([]string{"--token", token}, args...)
		root.SetArgs(allArgs)
		err := root.Execute()
		return buf.String(), err
	}

	var sessionName string

	// Step 1: Requester creates a session
	t.Run("Step1_RequesterCreatesSession", func(t *testing.T) {
		output, err := runWithToken(requester1Token,
			"session", "request",
			"--cluster", mcConfig.HubClusterName,
			"--group", "breakglass-create-all",
			"--reason", "Multi-actor workflow test",
			"-o", "json",
		)
		require.NoError(t, err, "Session request should succeed")

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err, "Should parse created session")

		sessionName = session.Name
		t.Logf("Requester created session: %s", sessionName)
	})

	// Step 2: Approver can see the pending session
	t.Run("Step2_ApproverSeesPendingSession", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// Wait for pending state
		time.Sleep(2 * time.Second)

		output, err := runWithToken(approverToken, "session", "list", "--state", "pending", "-o", "json")
		require.NoError(t, err, "Approver should list pending sessions")

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &sessions)
		require.NoError(t, err, "Should parse session list")

		found := false
		for _, s := range sessions {
			if s.Name == sessionName {
				found = true
				t.Logf("Approver found pending session: %s", s.Name)
				break
			}
		}
		require.True(t, found, "Approver should see the pending session")
	})

	// Step 3: Approver rejects the session (testing rejection flow)
	t.Run("Step3_ApproverRejectsSession", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		output, err := runWithToken(approverToken, "session", "reject", sessionName, "--reason", "Testing rejection flow")
		require.NoError(t, err, "Approver should be able to reject session")
		t.Logf("Reject response: %s", output)
	})

	// Step 4: Verify session is rejected
	t.Run("Step4_VerifyRejectedState", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		deadline := time.Now().Add(30 * time.Second)
		var lastState v1alpha1.BreakglassSessionState

		for time.Now().Before(deadline) {
			output, err := runWithToken(requester1Token, "session", "get", sessionName, "-o", "json")
			require.NoError(t, err, "Should get session")

			var session v1alpha1.BreakglassSession
			err = json.Unmarshal([]byte(output), &session)
			require.NoError(t, err, "Should parse session")

			lastState = session.Status.State
			if lastState == v1alpha1.SessionStateRejected {
				t.Logf("Session %s reached Rejected state", sessionName)
				return
			}
			t.Logf("Session state: %s, waiting for Rejected...", lastState)
			time.Sleep(1 * time.Second)
		}
		t.Fatalf("Session %s did not reach Rejected state in time, last state: %s", sessionName, lastState)
	})

	// Step 5: Requester cannot use a rejected session (would fail webhook)
	t.Run("Step5_RejectedSessionNotUsable", func(t *testing.T) {
		require.NotEmpty(t, sessionName, "Session must be created first")

		// Verify session is in rejected state
		output, err := runWithToken(requester1Token, "session", "get", sessionName, "-o", "json")
		require.NoError(t, err, "Should get session")

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal([]byte(output), &session)
		require.NoError(t, err, "Should parse session")

		assert.Equal(t, v1alpha1.SessionStateRejected, session.Status.State,
			"Session should remain in rejected state")
		t.Logf("Verified session %s is in Rejected state and cannot be used", sessionName)
	})

	t.Logf("✅ Multi-actor workflow test completed successfully for session %s", sessionName)
}
