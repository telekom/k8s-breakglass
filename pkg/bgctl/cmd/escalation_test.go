/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEscalationCommandStructure(t *testing.T) {
	cmd := NewEscalationCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "escalation", cmd.Use)
	assert.Contains(t, cmd.Short, "escalation")

	// Check subcommands exist
	subCmds := cmd.Commands()
	subCmdNames := make([]string, len(subCmds))
	for i, c := range subCmds {
		subCmdNames[i] = c.Name()
	}
	assert.Contains(t, subCmdNames, "list")
	assert.Contains(t, subCmdNames, "get")
	assert.Contains(t, subCmdNames, "list-clusters")
}

func TestEscalationListCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"escalation", "list", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "list")
}

func TestEscalationGetCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"escalation", "get", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "get")
}

func TestEscalationListClustersCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"escalation", "list-clusters", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "list-clusters")
}

// writeTestConfigForEscalation creates a temporary config file for testing
func writeTestConfigForEscalation(t *testing.T, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := config.DefaultConfig()
	cfg.CurrentContext = "test"
	cfg.Contexts = []config.Context{
		{
			Name:   "test",
			Server: serverURL,
			OIDC: &config.InlineOIDC{
				Authority: "https://idp.example.com/realms/test",
				ClientID:  "bgctl",
			},
		},
	}
	require.NoError(t, config.Save(path, &cfg))
	return path
}

// Mock server for integration-style tests
func setupMockEscalationServer(t *testing.T) *httptest.Server {
	escalations := []v1alpha1.BreakglassEscalation{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "test-escalation-1"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "admin",
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-a", "cluster-b"},
					Groups:   []string{"developers"},
				},
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"approvers"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "test-escalation-2"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "viewer",
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{"cluster-b", "cluster-c"},
					Groups:   []string{"readers"},
				},
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"admin@example.com"},
				},
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/breakglassEscalations":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(escalations)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestEscalationListCommand_WithMockServer(t *testing.T) {
	server := setupMockEscalationServer(t)
	defer server.Close()

	configPath := writeTestConfigForEscalation(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"escalation", "list",
		"-o", "json",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)

	var result []v1alpha1.BreakglassEscalation
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Len(t, result, 2)
	assert.Equal(t, "test-escalation-1", result[0].Name)
}

func TestEscalationListClustersCommand_WithMockServer(t *testing.T) {
	server := setupMockEscalationServer(t)
	defer server.Close()

	configPath := writeTestConfigForEscalation(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"escalation", "list-clusters",
		"-o", "json",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)

	var result []string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	// Should contain unique clusters: cluster-a, cluster-b, cluster-c
	assert.Len(t, result, 3)
	assert.Contains(t, result, "cluster-a")
	assert.Contains(t, result, "cluster-b")
	assert.Contains(t, result, "cluster-c")
}

func TestEscalationListClustersCommand_TableOutput(t *testing.T) {
	server := setupMockEscalationServer(t)
	defer server.Close()

	configPath := writeTestConfigForEscalation(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"escalation", "list-clusters",
		"-o", "table",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	// Table output should contain cluster names (one per line, no header)
	assert.Contains(t, output, "cluster-a")
	assert.Contains(t, output, "cluster-b")
	assert.Contains(t, output, "cluster-c")
}
