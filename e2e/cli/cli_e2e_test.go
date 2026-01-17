package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	bgctlcmd "github.com/telekom/k8s-breakglass/pkg/bgctl/cmd"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func TestCLIListSessions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/breakglassSessions" {
			_ = json.NewEncoder(w).Encode([]v1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "session-1",
						CreationTimestamp: metav1.NewTime(time.Now().Add(-time.Hour)),
					},
					Spec: v1alpha1.BreakglassSessionSpec{
						Cluster:      "cluster-1",
						User:         "user@example.com",
						GrantedGroup: "breakglass-admin",
					},
					Status: v1alpha1.BreakglassSessionStatus{
						State:     v1alpha1.SessionStatePending,
						ExpiresAt: metav1.NewTime(time.Now().Add(time.Hour)),
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	buf := &bytes.Buffer{}
	configPath := writeTestConfig(t, server.URL)
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetArgs([]string{"--server", server.URL, "--token", "test", "session", "list", "-o", "json"})
	require.NoError(t, root.Execute())

	var sessions []v1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(buf.Bytes(), &sessions))
	require.Len(t, sessions, 1)
	require.Equal(t, "session-1", sessions[0].Name)
}

func TestCLIDebugSessionList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/debugSessions" {
			_ = json.NewEncoder(w).Encode(client.DebugSessionListResponse{
				Sessions: []client.DebugSessionSummary{
					{
						Name:        "debug-1",
						TemplateRef: "template-1",
						Cluster:     "cluster-1",
						RequestedBy: "user@example.com",
						State:       v1alpha1.DebugSessionStatePending,
					},
				},
				Total: 1,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	buf := &bytes.Buffer{}
	configPath := writeTestConfig(t, server.URL)
	root := bgctlcmd.NewRootCommand(bgctlcmd.Config{ConfigPath: configPath, OutputWriter: buf})
	root.SetArgs([]string{"--server", server.URL, "--token", "test", "debug", "session", "list", "-o", "json"})
	require.NoError(t, root.Execute())

	var sessions []client.DebugSessionSummary
	require.NoError(t, json.Unmarshal(buf.Bytes(), &sessions))
	require.Len(t, sessions, 1)
	require.Equal(t, "debug-1", sessions[0].Name)
}

func writeTestConfig(t *testing.T, serverURL string) string {
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
