package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewSessionCommand_Subcommands(t *testing.T) {
	cmd := NewSessionCommand()
	assert.Equal(t, "session", cmd.Use)

	var names []string
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "list")
	assert.Contains(t, names, "get")
	assert.Contains(t, names, "request")
	assert.Contains(t, names, "approve")
	assert.Contains(t, names, "reject")
	assert.Contains(t, names, "withdraw")
	assert.Contains(t, names, "drop")
	assert.Contains(t, names, "cancel")
	assert.Contains(t, names, "watch")
}

func TestSessionListCommand_DefaultFlags(t *testing.T) {
	cmd := newSessionListCommand()

	mine, _ := cmd.Flags().GetBool("mine")
	approver, _ := cmd.Flags().GetBool("approver")
	approvedByMe, _ := cmd.Flags().GetBool("approved-by-me")
	activeOnly, _ := cmd.Flags().GetBool("active")

	assert.False(t, mine)
	assert.True(t, approver)
	assert.False(t, approvedByMe)
	assert.False(t, activeOnly)
}

func TestSessionApproverOption(t *testing.T) {
	t.Run("unset flag omits option", func(t *testing.T) {
		cmd := newSessionListCommand()
		approver, _ := cmd.Flags().GetBool("approver")

		assert.Nil(t, sessionApproverOption(cmd, approver))
	})

	t.Run("explicit true sets option true", func(t *testing.T) {
		cmd := newSessionListCommand()
		assert.NoError(t, cmd.ParseFlags([]string{"--approver=true"}))
		approver, _ := cmd.Flags().GetBool("approver")

		option := sessionApproverOption(cmd, approver)
		if assert.NotNil(t, option) {
			assert.True(t, *option)
		}
	})

	t.Run("explicit false sets option false", func(t *testing.T) {
		cmd := newSessionListCommand()
		assert.NoError(t, cmd.ParseFlags([]string{"--approver=false"}))
		approver, _ := cmd.Flags().GetBool("approver")

		option := sessionApproverOption(cmd, approver)
		if assert.NotNil(t, option) {
			assert.False(t, *option)
		}
	})
}

func TestSessionWatchCommand_DefaultFlags(t *testing.T) {
	cmd := newSessionWatchCommand()

	interval, _ := cmd.Flags().GetDuration("interval")
	approver, _ := cmd.Flags().GetBool("approver")
	activeOnly, _ := cmd.Flags().GetBool("active")
	showFull, _ := cmd.Flags().GetBool("show-full")

	assert.Equal(t, 2*time.Second, interval)
	assert.True(t, approver)
	assert.False(t, activeOnly)
	assert.False(t, showFull)
}

func TestSessionWatchCommand_RejectsNonPositiveInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval string
	}{
		{
			name:     "zero",
			interval: "0",
		},
		{
			name:     "negative",
			interval: "-1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := NewRootCommand(Config{OutputWriter: &bytes.Buffer{}})
			root.SetArgs([]string{
				"--server", "https://breakglass.example.com",
				"--token", "test-token",
				"session", "watch",
				"--interval=" + tt.interval,
			})

			err := root.Execute()

			require.Error(t, err)
			require.Contains(t, err.Error(), "interval must be greater than 0")
		})
	}
}

func TestSessionWatchCommand_ShowFullRespectsOutputFormat(t *testing.T) {
	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "watch-session-1"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "cluster-a",
			User:    "user@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	tests := []struct {
		name       string
		outputFlag string
		want       string
		notWant    string
	}{
		{
			name:    "show-full with default output emits JSON",
			want:    `"name": "watch-session-1"`,
			notWant: "name: watch-session-1",
		},
		{
			name:       "show-full with -o table emits JSON",
			outputFlag: "table",
			want:       `"name": "watch-session-1"`,
			notWant:    "name: watch-session-1",
		},
		{
			name:       "show-full with -o wide emits JSON",
			outputFlag: "wide",
			want:       `"name": "watch-session-1"`,
			notWant:    "name: watch-session-1",
		},
		{
			name:       "show-full with -o yaml outputs YAML",
			outputFlag: "yaml",
			want:       "name: watch-session-1",
			notWant:    `"name": "watch-session-1"`,
		},
		{
			name:       "show-full with -o json outputs JSON",
			outputFlag: "json",
			want:       `"name": "watch-session-1"`,
			notWant:    "name: watch-session-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/api/breakglassSessions", r.URL.Path)
				requestCount++
				if requestCount == 1 {
					w.Header().Set("Content-Type", "application/json")
					require.NoError(t, json.NewEncoder(w).Encode([]breakglassv1alpha1.BreakglassSession{session}))
					return
				}
				http.Error(w, "server stopping", http.StatusServiceUnavailable)
			}))
			defer server.Close()

			buf := &bytes.Buffer{}
			root := NewRootCommand(Config{OutputWriter: buf})
			args := []string{"--server", server.URL, "--token", "test-token"}
			if tt.outputFlag != "" {
				args = append(args, "--output", tt.outputFlag)
			}
			args = append(args, "session", "watch", "--show-full", "--interval", "1ms")
			root.SetArgs(args)

			err := root.Execute()

			require.Error(t, err)
			out := buf.String()
			require.NotEmpty(t, out)
			require.Contains(t, out, tt.want)
			require.NotContains(t, out, tt.notWant)
		})
	}
}

func TestSessionWatchCommand_ReturnsWriterErrors(t *testing.T) {
	writerErr := errors.New("writer failed")
	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "watch-session-1"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "cluster-a",
			User:    "user@example.com",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateApproved,
		},
	}

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "show-full explicit structured output",
			args: []string{"--output", "json", "session", "watch", "--show-full"},
		},
		{
			name: "show-full default output",
			args: []string{"session", "watch", "--show-full"},
		},
		{
			name: "tabular output",
			args: []string{"session", "watch"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "/api/breakglassSessions", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				require.NoError(t, json.NewEncoder(w).Encode([]breakglassv1alpha1.BreakglassSession{session}))
			}))
			defer server.Close()

			args := append([]string{
				"--server", server.URL,
				"--token", "test-token",
			}, tt.args...)
			root := NewRootCommand(Config{OutputWriter: errorWriter{err: writerErr}})
			root.SetArgs(args)

			err := root.Execute()

			require.ErrorIs(t, err, writerErr)
		})
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func TestSessionWatchCommand_ShowFullRejectsUnsupportedOutputFormat(t *testing.T) {
	root := NewRootCommand(Config{OutputWriter: &bytes.Buffer{}})
	root.SetArgs([]string{
		"--server", "https://breakglass.example.com",
		"--token", "test-token",
		"--output", "xml",
		"session", "watch",
		"--show-full",
	})

	err := root.Execute()

	require.Error(t, err)
	require.Contains(t, err.Error(), `unsupported output format: "xml"`)
}
