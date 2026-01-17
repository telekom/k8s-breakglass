/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

// TestCLIKubectlDebugInject tests the kubectl debug inject command via CLI
func TestCLIKubectlDebugInject(t *testing.T) {
	// Mock server that handles the inject request
	requestReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/debugSessions/test-session/injectEphemeralContainer" && r.Method == http.MethodPost {
			requestReceived = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":       true,
				"containerName": "debug",
				"podName":       "test-pod",
				"namespace":     "default",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	buf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, server.URL)
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "kubectl", "inject", "test-session",
		"--namespace", "default",
		"--pod", "test-pod",
		"--image", "alpine:3.20",
		"-o", "json",
	})

	err := root.Execute()
	require.NoError(t, err)
	require.True(t, requestReceived, "inject request should have been received by server")
}

// TestCLIKubectlDebugCopyPod tests the kubectl debug copy-pod command via CLI
func TestCLIKubectlDebugCopyPod(t *testing.T) {
	requestReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/debugSessions/test-session/createPodCopy" && r.Method == http.MethodPost {
			requestReceived = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":   true,
				"debugPod":  "test-pod-debug-abc123",
				"namespace": "default",
				"sourcePod": "test-pod",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	buf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, server.URL)
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "kubectl", "copy-pod", "test-session",
		"--namespace", "default",
		"--pod", "test-pod",
		"-o", "json",
	})

	err := root.Execute()
	require.NoError(t, err)
	require.True(t, requestReceived, "copy-pod request should have been received by server")
}

// TestCLIKubectlDebugNodeDebug tests the kubectl debug node-debug command via CLI
func TestCLIKubectlDebugNodeDebug(t *testing.T) {
	requestReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/debugSessions/test-session/createNodeDebugPod" && r.Method == http.MethodPost {
			requestReceived = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":   true,
				"debugPod":  "node-debug-abc123",
				"nodeName":  "worker-node-1",
				"namespace": "debug-system",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	buf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, server.URL)
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"debug", "kubectl", "node-debug", "test-session",
		"--node", "worker-node-1",
		"-o", "json",
	})

	err := root.Execute()
	require.NoError(t, err)
	require.True(t, requestReceived, "node-debug request should have been received by server")
}

// TestCLIKubectlDebugInject_RequiredFlags tests that required flags are enforced
func TestCLIKubectlDebugInject_RequiredFlags(t *testing.T) {
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, "http://localhost:8080")
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetErr(errBuf)
	// Missing required flags: --namespace, --pod, --image
	root.SetArgs([]string{
		"--server", "http://localhost:8080",
		"--token", "test-token",
		"debug", "kubectl", "inject", "test-session",
	})

	err := root.Execute()
	require.Error(t, err)
	// Should fail due to missing required flags
	require.Contains(t, err.Error(), "required flag")
}

// TestCLIKubectlDebugCopyPod_RequiredFlags tests that required flags are enforced
func TestCLIKubectlDebugCopyPod_RequiredFlags(t *testing.T) {
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, "http://localhost:8080")
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetErr(errBuf)
	// Missing required flags: --namespace, --pod
	root.SetArgs([]string{
		"--server", "http://localhost:8080",
		"--token", "test-token",
		"debug", "kubectl", "copy-pod", "test-session",
	})

	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag")
}

// TestCLIKubectlDebugNodeDebug_RequiredFlags tests that required flags are enforced
func TestCLIKubectlDebugNodeDebug_RequiredFlags(t *testing.T) {
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, "http://localhost:8080")
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetErr(errBuf)
	// Missing required flag: --node
	root.SetArgs([]string{
		"--server", "http://localhost:8080",
		"--token", "test-token",
		"debug", "kubectl", "node-debug", "test-session",
	})

	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag")
}

// TestCLIKubectlDebugInject_MissingSessionArg tests that session name argument is required
func TestCLIKubectlDebugInject_MissingSessionArg(t *testing.T) {
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	configPath := writeTestConfigForKubectl(t, "http://localhost:8080")
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetErr(errBuf)
	// Missing session name argument
	root.SetArgs([]string{
		"--server", "http://localhost:8080",
		"--token", "test-token",
		"debug", "kubectl", "inject",
		"--namespace", "default",
		"--pod", "test-pod",
		"--image", "alpine",
	})

	err := root.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "accepts 1 arg")
}

// writeTestConfigForKubectl creates a temporary config file for testing
func writeTestConfigForKubectl(t *testing.T, serverURL string) string {
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
