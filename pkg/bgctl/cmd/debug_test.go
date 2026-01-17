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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugCommandStructure(t *testing.T) {
	cmd := NewDebugCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "debug", cmd.Use)
	assert.Contains(t, cmd.Short, "debug")

	// Check subcommands exist
	subCmds := cmd.Commands()
	subCmdNames := make([]string, len(subCmds))
	for i, c := range subCmds {
		subCmdNames[i] = c.Name()
	}
	assert.Contains(t, subCmdNames, "session")
	assert.Contains(t, subCmdNames, "template")
	assert.Contains(t, subCmdNames, "pod-template")
	assert.Contains(t, subCmdNames, "kubectl")
}

func TestDebugSessionListCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"debug", "session", "list", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "list")
}

func TestDebugSessionWatchCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"debug", "session", "watch", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "watch")
	assert.Contains(t, buf.String(), "interval")
}

func TestDebugKubectlCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"debug", "kubectl", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "kubectl")
}

func TestDebugKubectlInjectCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"debug", "kubectl", "inject", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "inject")
	assert.Contains(t, output, "namespace")
	assert.Contains(t, output, "pod")
	assert.Contains(t, output, "image")
}

func TestDebugKubectlCopyPodCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"debug", "kubectl", "copy-pod", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "copy-pod")
	assert.Contains(t, output, "namespace")
	assert.Contains(t, output, "pod")
}

func TestDebugKubectlNodeDebugCommand_Help(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   "/tmp/nonexistent-test-config.yaml",
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{"debug", "kubectl", "node-debug", "--help"})
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "node-debug")
	assert.Contains(t, output, "node")
}

// writeTestConfigForDebug creates a temporary config file for testing
func writeTestConfigForDebug(t *testing.T, serverURL string) string {
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

// Mock server for debug session tests
func setupMockDebugServer(t *testing.T) *httptest.Server {
	now := time.Now()
	startsAt := metav1.NewTime(now)
	expiresAt := metav1.NewTime(now.Add(2 * time.Hour))

	debugSessions := client.DebugSessionListResponse{
		Sessions: []client.DebugSessionSummary{
			{
				Name:         "debug-session-1",
				TemplateRef:  "template-1",
				Cluster:      "cluster-a",
				RequestedBy:  "user@example.com",
				State:        v1alpha1.DebugSessionStateActive,
				StartsAt:     &startsAt,
				ExpiresAt:    &expiresAt,
				Participants: 2,
				AllowedPods:  5,
			},
		},
		Total: 1,
	}

	templates := struct {
		Templates []client.DebugSessionTemplateSummary `json:"templates"`
	}{
		Templates: []client.DebugSessionTemplateSummary{
			{
				Name:             "template-1",
				DisplayName:      "Debug Template",
				Mode:             "workload",
				TargetNamespace:  "debug-ns",
				RequiresApproval: true,
			},
		},
	}

	podTemplates := struct {
		Templates []client.DebugPodTemplateSummary `json:"templates"`
	}{
		Templates: []client.DebugPodTemplateSummary{
			{
				Name:        "pod-template-1",
				DisplayName: "Pod Template",
				Description: "Test pod template",
				Containers:  1,
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/debugSessions":
			_ = json.NewEncoder(w).Encode(debugSessions)
		case "/api/debugSessions/templates":
			_ = json.NewEncoder(w).Encode(templates)
		case "/api/debugSessions/podTemplates":
			_ = json.NewEncoder(w).Encode(podTemplates)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestDebugSessionListCommand_WithMockServer(t *testing.T) {
	server := setupMockDebugServer(t)
	defer server.Close()

	configPath := writeTestConfigForDebug(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "session", "list",
		"-o", "json",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)

	var result []client.DebugSessionSummary
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Len(t, result, 1)
	assert.Equal(t, "debug-session-1", result[0].Name)
}

func TestDebugSessionListCommand_WideFormat(t *testing.T) {
	server := setupMockDebugServer(t)
	defer server.Close()

	configPath := writeTestConfigForDebug(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "session", "list",
		"-o", "wide",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	// Wide format should include all columns
	assert.Contains(t, output, "TEMPLATE")
	assert.Contains(t, output, "PARTICIPANTS")
	assert.Contains(t, output, "ALLOWED_PODS")
}

func TestDebugTemplateListCommand_WithMockServer(t *testing.T) {
	server := setupMockDebugServer(t)
	defer server.Close()

	configPath := writeTestConfigForDebug(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "template", "list",
		"-o", "json",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)

	var result []client.DebugSessionTemplateSummary
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Len(t, result, 1)
	assert.Equal(t, "template-1", result[0].Name)
}

func TestDebugPodTemplateListCommand_WithMockServer(t *testing.T) {
	server := setupMockDebugServer(t)
	defer server.Close()

	configPath := writeTestConfigForDebug(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "pod-template", "list",
		"-o", "json",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)

	var result []client.DebugPodTemplateSummary
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Len(t, result, 1)
	assert.Equal(t, "pod-template-1", result[0].Name)
}
