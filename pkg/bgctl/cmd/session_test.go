package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSessionListCommand_listsSessions_whenRuntimeProvided(t *testing.T) {
	t.Parallel()

	// Given
	buf := &bytes.Buffer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/breakglassSessions", r.URL.Path)
		require.Equal(t, "prod-cluster", r.URL.Query().Get("cluster"))
		require.Equal(t, "alice@example.com", r.URL.Query().Get("user"))
		require.Equal(t, "admins", r.URL.Query().Get("group"))
		require.Equal(t, "true", r.URL.Query().Get("mine"))
		require.Equal(t, "true", r.URL.Query().Get("approvedByMe"))
		require.Equal(t, "true", r.URL.Query().Get("activeOnly"))
		require.Equal(t, "pending,approved", r.URL.Query().Get("state"))
		_, approverPresent := r.URL.Query()["approver"]
		require.False(t, approverPresent)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode([]breakglassv1alpha1.BreakglassSession{{
			ObjectMeta: metav1.ObjectMeta{Name: "session-1"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster: "prod-cluster",
				User:    "alice@example.com",
			},
		}}))
	}))
	defer server.Close()

	root := NewRootCommand(Config{OutputWriter: buf})
	root.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"--output", "json",
		"session", "list",
		"--cluster", "prod-cluster",
		"--user", "alice@example.com",
		"--group", "admins",
		"--mine",
		"--approved-by-me",
		"--active",
		"--state", "pending,approved",
	})

	// When
	err := root.Execute()

	// Then
	require.NoError(t, err)
	var sessions []breakglassv1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(buf.Bytes(), &sessions))
	require.Len(t, sessions, 1)
	require.Equal(t, "session-1", sessions[0].Name)
}

func TestSessionGetCommand_getsSession_whenNameProvided(t *testing.T) {
	t.Parallel()

	// Given
	buf := &bytes.Buffer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/breakglassSessions/session-123", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"session": breakglassv1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session-123"},
				Spec:       breakglassv1alpha1.BreakglassSessionSpec{User: "alice@example.com"},
			},
		}))
	}))
	defer server.Close()

	root := NewRootCommand(Config{OutputWriter: buf})
	root.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"--output", "json",
		"session", "get", "session-123",
	})

	// When
	err := root.Execute()

	// Then
	require.NoError(t, err)
	var session breakglassv1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(buf.Bytes(), &session))
	require.Equal(t, "session-123", session.Name)
	require.Equal(t, "alice@example.com", session.Spec.User)
}

func TestSessionRequestCommand_requestsSession_whenFlagsValid(t *testing.T) {
	t.Parallel()

	// Given
	buf := &bytes.Buffer{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/breakglassSessions", r.URL.Path)

		var req struct {
			Cluster          string `json:"cluster"`
			User             string `json:"user"`
			Group            string `json:"group"`
			Reason           string `json:"reason"`
			DurationSeconds  int64  `json:"duration"`
			ScheduledStartAt string `json:"scheduledStartTime"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, "prod-cluster", req.Cluster)
		require.Equal(t, "alice@example.com", req.User)
		require.Equal(t, "admins", req.Group)
		require.Equal(t, "incident-123", req.Reason)
		require.EqualValues(t, 3600, req.DurationSeconds)
		require.Equal(t, "2026-06-29T10:00:00Z", req.ScheduledStartAt)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session-new"},
			Spec: breakglassv1alpha1.BreakglassSessionSpec{
				Cluster:      req.Cluster,
				User:         req.User,
				GrantedGroup: req.Group,
			},
		}))
	}))
	defer server.Close()

	root := NewRootCommand(Config{OutputWriter: buf})
	root.SetArgs([]string{
		"--server", server.URL,
		"--token", "test-token",
		"--output", "json",
		"session", "request",
		"--cluster", "prod-cluster",
		"--group", "admins",
		"--user", "alice@example.com",
		"--reason", "incident-123",
		"--duration", "3600",
		"--scheduled-start", "2026-06-29T10:00:00Z",
	})

	// When
	err := root.Execute()

	// Then
	require.NoError(t, err)
	var session breakglassv1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(buf.Bytes(), &session))
	require.Equal(t, "session-new", session.Name)
	require.Equal(t, "admins", session.Spec.GrantedGroup)
}

func TestConfigViewCommand_writesConfig_whenConfigExists(t *testing.T) {
	t.Parallel()

	// Given
	buf := &bytes.Buffer{}
	configPath := filepath.Join(t.TempDir(), "bgctl.yaml")
	require.NoError(t, config.Save(configPath, &config.Config{
		Version:        config.VersionV1,
		CurrentContext: "prod",
		Contexts: []config.Context{{
			Name:   "prod",
			Server: "https://breakglass.example.com",
			OIDC: &config.InlineOIDC{
				Authority: "https://idp.example.com",
				ClientID:  "bgctl",
			},
		}},
	}))

	root := NewRootCommand(Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetArgs([]string{"config", "view"})

	// When
	err := root.Execute()

	// Then
	require.NoError(t, err)
	output := buf.String()
	require.Contains(t, output, "current-context: prod")
	require.Contains(t, output, "server: https://breakglass.example.com")
}

func TestBuildClientWithoutConfig(t *testing.T) {
	rt := &runtimeState{
		configPath:     filepath.Join(os.TempDir(), "nonexistent-config.yaml"),
		serverOverride: "",
		tokenOverride:  "",
	}

	_, err := buildClient(context.Background(), rt)
	require.Error(t, err)
	require.Contains(t, err.Error(), "config")
}
