// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// runInject runs `bgctl debug kubectl inject` against a fake hub whose session
// has the given ephemeral-container policy (nil: session GET fails) and whose
// inject endpoint answers with injectStatus. It returns the securityContext
// the hub received and the command error.
func runInject(t *testing.T, policy *breakglassv1alpha1.EphemeralContainersConfig, injectStatus int, extraArgs ...string) (*corev1.SecurityContext, string, error) {
	t.Helper()
	var received *corev1.SecurityContext
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/debugSessions/s1":
			if policy == nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "boom"})
				return
			}
			_ = json.NewEncoder(w).Encode(client.DebugSessionDetailResponse{DebugSession: breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "s1"},
				Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
					KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: policy},
				}},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/api/debugSessions/s1/injectEphemeralContainer":
			var req client.InjectEphemeralContainerRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			received = req.SecurityContext
			w.WriteHeader(injectStatus)
			if injectStatus != http.StatusOK {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "debug operation is not allowed"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "ok"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	errBuf := &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: writeTestConfigForDebug(t, server.URL), OutputWriter: &bytes.Buffer{}})
	root.SetErr(errBuf)
	root.SetArgs(append([]string{
		"--server", server.URL, "--token", "t",
		"debug", "kubectl", "inject", "s1", "--namespace", "ns", "--pod", "p", "--image", "busybox", "-o", "json",
	}, extraArgs...))
	err := root.Execute()
	return received, errBuf.String(), err
}

func TestInjectSecurityContextDefaults(t *testing.T) {
	restricted := &corev1.SecurityContext{
		RunAsNonRoot:             ptr.To(true),
		RunAsUser:                ptr.To(int64(65534)),
		AllowPrivilegeEscalation: ptr.To(false),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	tests := []struct {
		name   string
		policy *breakglassv1alpha1.EphemeralContainersConfig
		args   []string
		want   *corev1.SecurityContext
	}{
		{
			name:   "template requires non-root: restricted defaults",
			policy: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, RequireNonRoot: true},
			want:   restricted,
		},
		{
			name:   "template allows root: only no privilege escalation",
			policy: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true},
			want:   &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false)},
		},
		{
			name: "session unreadable: base default only",
			want: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false)},
		},
		{
			name:   "flags override defaults",
			policy: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, RequireNonRoot: true},
			args:   []string{"--run-as-user", "1000", "--run-as-group", "2000", "--add-capabilities", "net_raw,CAP_NET_ADMIN"},
			want: &corev1.SecurityContext{
				RunAsNonRoot:             ptr.To(true),
				RunAsUser:                ptr.To(int64(1000)),
				RunAsGroup:               ptr.To(int64(2000)),
				AllowPrivilegeEscalation: ptr.To(false),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_RAW", "NET_ADMIN"}},
				SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
		},
		{
			name:   "opt-out sends nothing",
			policy: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, RequireNonRoot: true},
			args:   []string{"--default-security-context=false"},
		},
		{
			name:   "opt-out keeps explicit flags",
			policy: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, RequireNonRoot: true},
			args:   []string{"--default-security-context=false", "--run-as-non-root", "--drop-capabilities", "ALL"},
			want:   &corev1.SecurityContext{RunAsNonRoot: ptr.To(true), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, stderr, err := runInject(t, tt.policy, http.StatusOK, tt.args...)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			if tt.policy == nil {
				assert.Contains(t, stderr, "could not read session s1")
			}
		})
	}
}

func TestInjectSecurityContextFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sc.yaml")
	require.NoError(t, os.WriteFile(path, []byte("runAsUser: 1234\nrunAsNonRoot: true\nreadOnlyRootFilesystem: true\n"), 0o600))
	policy := &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, RequireNonRoot: true}

	got, _, err := runInject(t, policy, http.StatusOK, "--security-context-file", path)
	require.NoError(t, err)
	assert.Equal(t, &corev1.SecurityContext{
		RunAsUser: ptr.To(int64(1234)), RunAsNonRoot: ptr.To(true), ReadOnlyRootFilesystem: ptr.To(true),
	}, got, "file is sent verbatim without defaults")

	require.NoError(t, os.WriteFile(path, []byte("runAsUsr: 1\n"), 0o600))
	_, _, err = runInject(t, policy, http.StatusOK, "--security-context-file", path)
	require.ErrorContains(t, err, "parse --security-context-file")

	_, _, err = runInject(t, policy, http.StatusOK, "--security-context-file", path, "--run-as-user", "1")
	require.ErrorContains(t, err, "none of the others can be")
}

func TestInjectRejectionExplainsPolicy(t *testing.T) {
	policy := &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, RequireNonRoot: true, MaxCapabilities: []string{"NET_RAW"}}
	_, _, err := runInject(t, policy, http.StatusForbidden, "--run-as-user", "0")
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "request failed (403): debug operation is not allowed")
	assert.Contains(t, msg, "requireNonRoot=true")
	assert.Contains(t, msg, "maxCapabilities=[NET_RAW]")
	assert.Contains(t, msg, `"runAsUser":0`)
	assert.Contains(t, msg, "--security-context-file")

	_, _, err = runInject(t, policy, http.StatusBadRequest)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "template policy", "only policy rejections get the hint")
}
