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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

// TestCLIMultiCluster tests CLI operations across hub and spoke clusters
// This test requires the multi-cluster environment to be set up via kind-setup-multi.sh
func TestCLIMultiCluster(t *testing.T) {
	if !helpers.IsMultiClusterEnabled() {
		t.Skip("Multi-cluster tests disabled. Set E2E_MULTI_CLUSTER=true and run e2e/kind-setup-multi.sh")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Verify multi-cluster environment is available
	require.NotEmpty(t, mcConfig.HubAPIURL, "Hub API URL must be set")
	require.NotEmpty(t, mcConfig.HubClusterName, "Hub cluster name must be set")
	require.NotEmpty(t, mcConfig.SpokeAClusterName, "Spoke A cluster name must be set")
	require.NotEmpty(t, mcConfig.SpokeBClusterName, "Spoke B cluster name must be set")

	// Get OIDC token for employee user
	oidcProvider := helpers.DefaultOIDCProvider()
	token := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)
	require.NotEmpty(t, token, "Failed to get OIDC token")

	// Create CLI config with hub server
	cfg := createCLIConfig(t, mcConfig.HubAPIURL)
	configPath := writeConfigFile(t, cfg)

	t.Run("list clusters", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"--token", token, "escalation", "list-clusters", "-o", "json"})

		err := root.Execute()
		require.NoError(t, err)

		var clusters []string
		err = json.Unmarshal(buf.Bytes(), &clusters)
		require.NoError(t, err)

		// Should see all three clusters registered
		require.Contains(t, clusters, mcConfig.HubClusterName)
		require.Contains(t, clusters, mcConfig.SpokeAClusterName)
		require.Contains(t, clusters, mcConfig.SpokeBClusterName)
	})

	t.Run("request session on spoke-a", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"--token", token,
			"session", "request",
			"--cluster", mcConfig.SpokeAClusterName,
			"--group", "breakglass-admin",
			"--reason", "CLI test on spoke-a",
			"-o", "json",
		})

		err := root.Execute()
		require.NoError(t, err)

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal(buf.Bytes(), &session)
		require.NoError(t, err)

		require.Equal(t, mcConfig.SpokeAClusterName, session.Spec.Cluster)
		require.Equal(t, helpers.TestUsers.Requester.Email, session.Spec.User)

		t.Logf("Created session: %s on cluster: %s", session.Name, session.Spec.Cluster)
	})

	t.Run("request session on spoke-b", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"--token", token,
			"session", "request",
			"--cluster", mcConfig.SpokeBClusterName,
			"--group", "breakglass-admin",
			"--reason", "CLI test on spoke-b",
			"-o", "json",
		})

		err := root.Execute()
		require.NoError(t, err)

		var session v1alpha1.BreakglassSession
		err = json.Unmarshal(buf.Bytes(), &session)
		require.NoError(t, err)

		require.Equal(t, mcConfig.SpokeBClusterName, session.Spec.Cluster)
		require.Equal(t, helpers.TestUsers.Requester.Email, session.Spec.User)

		t.Logf("Created session: %s on cluster: %s", session.Name, session.Spec.Cluster)
	})

	t.Run("list all sessions across clusters", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"--token", token, "session", "list", "-o", "json"})

		err := root.Execute()
		require.NoError(t, err)

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal(buf.Bytes(), &sessions)
		require.NoError(t, err)

		// Should see sessions from both spoke clusters
		foundSpokeA := false
		foundSpokeB := false
		for _, s := range sessions {
			if s.Spec.Cluster == mcConfig.SpokeAClusterName {
				foundSpokeA = true
			}
			if s.Spec.Cluster == mcConfig.SpokeBClusterName {
				foundSpokeB = true
			}
		}

		t.Logf("Found %d total sessions (spoke-a: %v, spoke-b: %v)", len(sessions), foundSpokeA, foundSpokeB)
	})

	t.Run("filter sessions by cluster", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"--token", token,
			"session", "list",
			"--cluster", mcConfig.SpokeAClusterName,
			"-o", "json",
		})

		err := root.Execute()
		require.NoError(t, err)

		var sessions []v1alpha1.BreakglassSession
		err = json.Unmarshal(buf.Bytes(), &sessions)
		require.NoError(t, err)

		// All returned sessions should be for spoke-a
		for _, s := range sessions {
			require.Equal(t, mcConfig.SpokeAClusterName, s.Spec.Cluster,
				"Session %s should be for cluster %s", s.Name, mcConfig.SpokeAClusterName)
		}

		t.Logf("Found %d sessions on cluster %s", len(sessions), mcConfig.SpokeAClusterName)
	})
}

// TestCLIDebugSessionsMultiCluster tests debug session operations across clusters
func TestCLIDebugSessionsMultiCluster(t *testing.T) {
	if !helpers.IsMultiClusterEnabled() {
		t.Skip("Multi-cluster tests disabled. Set E2E_MULTI_CLUSTER=true")
	}

	ctx := context.Background()
	mcConfig := helpers.GetMultiClusterConfig()

	// Get OIDC token
	oidcProvider := helpers.DefaultOIDCProvider()
	token := oidcProvider.GetToken(t, ctx, helpers.TestUsers.Requester.Username, helpers.TestUsers.Requester.Password)

	cfg := createCLIConfig(t, mcConfig.HubAPIURL)
	configPath := writeConfigFile(t, cfg)

	t.Run("list debug templates", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"--token", token, "debug", "template", "list", "-o", "json"})

		err := root.Execute()
		require.NoError(t, err)

		var templates []v1alpha1.DebugSessionTemplate
		err = json.Unmarshal(buf.Bytes(), &templates)
		require.NoError(t, err)

		t.Logf("Found %d debug templates", len(templates))
		for _, tmpl := range templates {
			t.Logf("  - %s", tmpl.Name)
		}
	})

	t.Run("request debug session on spoke-a", func(t *testing.T) {
		// Ensure we have a debug template - fixtures must be loaded in E2E setup
		hubClient := helpers.GetClientForCluster(t, mcConfig.HubKubeconfig)
		var templates v1alpha1.DebugSessionTemplateList
		err := hubClient.List(ctx, &templates, client.InNamespace(helpers.GetTestNamespace()))
		require.NoError(t, err, "Should list debug templates")
		require.NotEmpty(t, templates.Items, "DebugSessionTemplates must exist in E2E environment - check that fixtures are loaded")

		templateName := templates.Items[0].Name

		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"--token", token,
			"debug", "session", "request",
			"--cluster", mcConfig.SpokeAClusterName,
			"--template", templateName,
			"--reason", "CLI debug test on spoke-a",
			"-o", "json",
		})

		err = root.Execute()
		require.NoError(t, err)

		var session v1alpha1.DebugSession
		err = json.Unmarshal(buf.Bytes(), &session)
		require.NoError(t, err)

		require.Equal(t, mcConfig.SpokeAClusterName, session.Spec.Cluster)
		require.Equal(t, templateName, session.Spec.TemplateRef)

		t.Logf("Created debug session: %s on cluster: %s", session.Name, session.Spec.Cluster)
	})

	t.Run("list debug sessions across clusters", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"--token", token, "debug", "session", "list", "-o", "json"})

		err := root.Execute()
		require.NoError(t, err)

		// Note: API returns DebugSessionSummary, not full DebugSession objects
		var rawResponse json.RawMessage
		err = json.Unmarshal(buf.Bytes(), &rawResponse)
		require.NoError(t, err)

		t.Logf("Debug sessions response: %s", string(rawResponse))
	})
}

// TestCLIVersionWithoutConfig ensures version works without any configuration
func TestCLIVersionWithoutConfig(t *testing.T) {
	// Use non-existent config path
	nonExistentPath := filepath.Join(t.TempDir(), "nonexistent", "config.yaml")

	buf := &bytes.Buffer{}
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
		ConfigPath:   nonExistentPath,
		OutputWriter: buf,
	})
	root.SetArgs([]string{"version"})

	err := root.Execute()
	require.NoError(t, err, "version command should work without config")

	output := buf.String()
	require.Contains(t, output, "bgctl")
	require.Contains(t, output, "commit:")
	require.Contains(t, output, "built:")

	t.Logf("Version output: %s", output)
}

// TestCLIVersionFormats tests different version output formats
func TestCLIVersionFormats(t *testing.T) {
	nonExistentPath := filepath.Join(t.TempDir(), "nonexistent", "config.yaml")

	tests := []struct {
		name         string
		args         []string
		validateFunc func(t *testing.T, output []byte)
	}{
		{
			name: "default text format",
			args: []string{"version"},
			validateFunc: func(t *testing.T, output []byte) {
				s := string(output)
				require.Contains(t, s, "bgctl")
				require.Contains(t, s, "commit:")
			},
		},
		{
			name: "json format",
			args: []string{"version", "-o", "json"},
			validateFunc: func(t *testing.T, output []byte) {
				var versionInfo map[string]interface{}
				err := json.Unmarshal(output, &versionInfo)
				require.NoError(t, err)
				require.Contains(t, versionInfo, "version")
				require.Contains(t, versionInfo, "gitCommit")
				require.Contains(t, versionInfo, "buildDate")
				require.Contains(t, versionInfo, "goVersion")
				require.Contains(t, versionInfo, "platform")
			},
		},
		{
			name: "yaml format",
			args: []string{"version", "-o", "yaml"},
			validateFunc: func(t *testing.T, output []byte) {
				s := string(output)
				require.Contains(t, s, "version:")
				require.Contains(t, s, "gitcommit:")
				require.Contains(t, s, "builddate:")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
				ConfigPath:   nonExistentPath,
				OutputWriter: buf,
			})
			root.SetArgs(tt.args)

			err := root.Execute()
			require.NoError(t, err)

			tt.validateFunc(t, buf.Bytes())
		})
	}
}

// TestCLICompletionWithoutConfig ensures completion works without configuration
func TestCLICompletionWithoutConfig(t *testing.T) {
	nonExistentPath := filepath.Join(t.TempDir(), "nonexistent", "config.yaml")

	shells := []string{"bash", "zsh", "fish", "powershell"}

	for _, shell := range shells {
		t.Run(shell, func(t *testing.T) {
			buf := &bytes.Buffer{}
			root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
				ConfigPath:   nonExistentPath,
				OutputWriter: buf,
			})
			root.SetArgs([]string{"completion", shell})

			err := root.Execute()
			require.NoError(t, err, "completion for %s should work without config", shell)

			output := buf.String()
			require.NotEmpty(t, output, "completion output should not be empty")
			t.Logf("Generated %d bytes of %s completion", len(output), shell)
		})
	}
}

// createCLIConfig creates a basic CLI configuration
func createCLIConfig(t *testing.T, serverURL string) config.Config {
	t.Helper()

	return config.Config{
		Version:        "v1",
		CurrentContext: "default",
		Contexts: []config.Context{
			{
				Name:   "default",
				Server: serverURL,
				OIDC: &config.InlineOIDC{
					Authority: fmt.Sprintf("https://%s/realms/%s",
						os.Getenv("KEYCLOAK_HOST"),
						helpers.GetKeycloakMainRealm()),
					ClientID: helpers.GetKeycloakClientID(),
				},
			},
		},
		Settings: config.Settings{
			OutputFormat: "json",
			PageSize:     50,
		},
	}
}

// writeConfigFile writes config to a temporary file
func writeConfigFile(t *testing.T, cfg config.Config) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, config.Save(path, &cfg))
	return path
}

// TestCLIConfigOperations tests config-related CLI commands
func TestCLIConfigOperations(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "test-config.yaml")

	t.Run("init config", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"config", "init",
			"--server", "https://api.example.com",
			"--context", "test-ctx",
			"--oidc-authority", "https://idp.example.com/realms/test",
			"--oidc-client-id", "bgctl",
		})

		err := root.Execute()
		require.NoError(t, err)

		// Verify config file was created
		require.FileExists(t, configPath)
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

		output := buf.String()
		// Config view outputs YAML by default
		require.Contains(t, output, "version:")
		require.Contains(t, output, "contexts:")
	})

	t.Run("add context", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{
			"config", "add-context", "prod",
			"--server", "https://prod.example.com",
			"--oidc-authority", "https://idp.example.com/realms/prod",
			"--oidc-client-id", "bgctl",
		})

		err := root.Execute()
		require.NoError(t, err)

		// Verify new context was added
		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		require.Len(t, cfg.Contexts, 2)

		found := false
		for _, ctx := range cfg.Contexts {
			if ctx.Name == "prod" {
				found = true
				require.Equal(t, "https://prod.example.com", ctx.Server)
			}
		}
		require.True(t, found, "prod context should exist")
	})

	t.Run("use context", func(t *testing.T) {
		buf := &bytes.Buffer{}
		root := bgctlcmd.NewRootCommand(bgctlcmd.Config{
			ConfigPath:   configPath,
			OutputWriter: buf,
		})
		root.SetArgs([]string{"config", "use-context", "prod"})

		err := root.Execute()
		require.NoError(t, err)

		// Verify current context was changed
		cfg, err := config.Load(configPath)
		require.NoError(t, err)
		require.Equal(t, "prod", cfg.CurrentContext)
	})
}
