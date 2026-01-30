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

	templateClusters := client.TemplateClustersResponse{
		TemplateName:        "template-1",
		TemplateDisplayName: "Debug Template",
		Clusters: []client.AvailableClusterDetail{
			{
				Name:        "cluster-a",
				DisplayName: "Cluster A",
				Environment: "production",
				Location:    "eu-west-1",
				BindingRef: &client.BindingReference{
					Name:      "prod-binding",
					Namespace: "debug-ns",
				},
				Approval: &client.ApprovalInfo{
					Required:       true,
					ApproverGroups: []string{"approvers"},
				},
				NamespaceConstraints: &client.NamespaceConstraintsResponse{
					DefaultNamespace:   "debug-default",
					AllowUserNamespace: true,
					AllowedPatterns:    []string{"debug-*", "test-*"},
				},
				Impersonation: &client.ImpersonationSummary{
					Enabled:        true,
					ServiceAccount: "debug-sa",
					Namespace:      "system",
				},
				RequiredAuxResourceCategories: []string{"logging", "monitoring"},
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/debugSessions":
			_ = json.NewEncoder(w).Encode(debugSessions)
		case r.URL.Path == "/api/debugSessions/templates":
			_ = json.NewEncoder(w).Encode(templates)
		case r.URL.Path == "/api/debugSessions/templates/template-1/clusters":
			_ = json.NewEncoder(w).Encode(templateClusters)
		case r.URL.Path == "/api/debugSessions/podTemplates":
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

func TestDebugTemplateListCommand_TableFormatShowsNote(t *testing.T) {
	server := setupMockDebugServer(t)
	defer server.Close()

	configPath := writeTestConfigForDebug(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	// Table format without --all should show the note about filtered templates
	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "template", "list",
		"-o", "table",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	// Should contain the note about using --all to see all templates
	assert.Contains(t, output, "Note:")
	assert.Contains(t, output, "--all")
}

func TestDebugTemplateListCommand_AllFlagNoNote(t *testing.T) {
	server := setupMockDebugServer(t)
	defer server.Close()

	configPath := writeTestConfigForDebug(t, server.URL)
	buf := &bytes.Buffer{}
	rootCmd := NewRootCommand(Config{
		ConfigPath:   configPath,
		OutputWriter: buf,
	})

	// With --all flag, the note should NOT be shown
	rootCmd.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "template", "list",
		"-o", "table",
		"--all",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	// Should NOT contain the note when --all is used
	assert.NotContains(t, output, "Note:")
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

func TestDebugTemplateClustersCommand_WithMockServer(t *testing.T) {
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
		"debug", "template", "clusters", "template-1",
		"-o", "json",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)

	var result client.TemplateClustersResponse
	require.NoError(t, json.Unmarshal(buf.Bytes(), &result))
	assert.Equal(t, "template-1", result.TemplateName)
	assert.Len(t, result.Clusters, 1)

	cluster := result.Clusters[0]
	assert.Equal(t, "cluster-a", cluster.Name)
	assert.Equal(t, "production", cluster.Environment)

	// Verify binding reference is returned
	require.NotNil(t, cluster.BindingRef)
	assert.Equal(t, "prod-binding", cluster.BindingRef.Name)
	assert.Equal(t, "debug-ns", cluster.BindingRef.Namespace)

	// Verify namespace constraints are returned
	require.NotNil(t, cluster.NamespaceConstraints)
	assert.Equal(t, "debug-default", cluster.NamespaceConstraints.DefaultNamespace)
	assert.True(t, cluster.NamespaceConstraints.AllowUserNamespace)
	assert.Contains(t, cluster.NamespaceConstraints.AllowedPatterns, "debug-*")
	assert.Contains(t, cluster.NamespaceConstraints.AllowedPatterns, "test-*")

	// Verify impersonation is returned
	require.NotNil(t, cluster.Impersonation)
	assert.True(t, cluster.Impersonation.Enabled)
	assert.Equal(t, "debug-sa", cluster.Impersonation.ServiceAccount)
	assert.Equal(t, "system", cluster.Impersonation.Namespace)

	// Verify approval is returned
	require.NotNil(t, cluster.Approval)
	assert.True(t, cluster.Approval.Required)
	assert.Contains(t, cluster.Approval.ApproverGroups, "approvers")

	// Verify required auxiliary resource categories
	assert.Contains(t, cluster.RequiredAuxResourceCategories, "logging")
	assert.Contains(t, cluster.RequiredAuxResourceCategories, "monitoring")
}

func TestDebugTemplateClustersCommand_TableFormat(t *testing.T) {
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
		"debug", "template", "clusters", "template-1",
		"-o", "table",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "cluster-a")
	assert.Contains(t, output, "production")
	// Regular table format shows binding count, not binding names
	assert.Contains(t, output, "BINDINGS")
	assert.Contains(t, output, "MAX_DURATION")
	assert.Contains(t, output, "APPROVAL")
}

func TestDebugTemplateClustersCommand_WideFormat(t *testing.T) {
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
		"debug", "template", "clusters", "template-1",
		"-o", "wide",
	})
	err := rootCmd.Execute()

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "cluster-a")
	assert.Contains(t, output, "production")
	// Wide format shows binding names
	assert.Contains(t, output, "prod-binding")
}
