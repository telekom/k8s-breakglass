// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordingReaderStub struct {
	opened int
}

func (r *recordingReaderStub) OpenRecording(_ context.Context, _ *breakglassv1alpha1.DebugSession) (io.ReadCloser, string, error) {
	r.opened++
	return io.NopCloser(strings.NewReader("version https://asciinema.org/a\n")), "application/x-asciicast", nil
}

func recordingFixture(enabled bool) (*breakglassv1alpha1.DebugSession, *breakglassv1alpha1.DebugSessionTemplate) {
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-one", Namespace: "breakglass"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "prod", TemplateRef: "netshoot"},
	}, &breakglassv1alpha1.DebugSessionTemplate{
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: enabled, RecordingRetention: "30d"},
		},
	}
}

func TestInjectTerminalRecordingContract(t *testing.T) {
	ds, template := recordingFixture(true)
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "debug", Image: "example/debug"}}}
	if err := injectTerminalRecording(spec, ds, template, "registry.example/recorder@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("inject terminal recording: %v", err)
	}
	if len(spec.Containers) != 2 || spec.Containers[1].Name != "terminal-recorder" {
		t.Fatalf("expected recorder sidecar, got %#v", spec.Containers)
	}
	if len(spec.Volumes) != 1 || spec.Volumes[0].Name != terminalRecordingVolumeName {
		t.Fatalf("expected private recording volume, got %#v", spec.Volumes)
	}
	for _, env := range spec.Containers[1].Env {
		if env.Name == "AUTHORIZATION" || env.Name == "TOKEN" {
			t.Fatalf("secret-like environment variable copied to sidecar: %s", env.Name)
		}
	}
	if len(spec.Containers[0].VolumeMounts) != 0 {
		t.Fatal("workload container must not have access to the recording artifact volume")
	}
	if !recordingEnvValue(spec.Containers[1].Env, TerminalRecordingRedactionEnv, "true") {
		t.Fatal("expected recording redaction marker on sidecar")
	}
}

func recordingEnvValue(env []corev1.EnvVar, name, want string) bool {
	for _, item := range env {
		if item.Name == name && item.Value == want {
			return true
		}
	}
	return false
}

func TestInjectTerminalRecordingFailsClosed(t *testing.T) {
	ds, template := recordingFixture(true)
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "debug"}}}
	if err := injectTerminalRecording(spec, ds, template, ""); err == nil {
		t.Fatal("expected missing sidecar image to fail")
	}
	template.Spec.Audit.RecordingRetention = "not-a-duration"
	if err := injectTerminalRecording(spec, ds, template, "example/recorder:v1"); err == nil {
		t.Fatal("expected invalid retention to fail")
	}
	template.Spec.Audit.RecordingRetention = "30d"
	spec.Containers = nil
	if err := injectTerminalRecording(spec, ds, template, "example/recorder:v1"); err == nil {
		t.Fatal("expected pod without workload container to fail")
	}
}

func TestRecordingRetentionDuration(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int64
	}{
		{"90d", int64(90 * 24 * 60 * 60)},
		{"2w", int64(14 * 24 * 60 * 60)},
		{"1d12h", int64(36 * 60 * 60)},
		{"1w2d3h", int64(219 * 60 * 60)},
		{"1h", int64(60 * 60)},
	} {
		d, err := recordingRetentionDuration(tc.value)
		if err != nil || int64(d.Seconds()) != tc.want {
			t.Errorf("retention %q = %v, %v", tc.value, d, err)
		}
	}
	if _, err := recordingRetentionDuration("0d"); err == nil {
		t.Fatal("expected non-positive retention to fail")
	}
	reserved := &corev1.PodSpec{Containers: []corev1.Container{{Name: "terminal-recorder"}}}
	if err := injectTerminalRecording(reserved, &breakglassv1alpha1.DebugSession{}, recordingFixtureTemplate(), "registry.example/recorder@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("expected user-owned recorder container name to fail closed")
	}
	reserved = &corev1.PodSpec{Containers: []corev1.Container{{Name: "debug"}}, Volumes: []corev1.Volume{{Name: terminalRecordingVolumeName}}}
	if err := injectTerminalRecording(reserved, &breakglassv1alpha1.DebugSession{}, recordingFixtureTemplate(), "registry.example/recorder@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("expected user-owned recorder volume name to fail closed")
	}
}

func recordingFixtureTemplate() *breakglassv1alpha1.DebugSessionTemplate {
	return &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true, RecordingRetention: "30d"},
	}}
}

func TestRecordingReplayAvailableRequiresReadyBoundedUnexpiredArtifact(t *testing.T) {
	ready := &breakglassv1alpha1.TerminalRecordingStatus{
		Enabled: true,
		State:   breakglassv1alpha1.TerminalRecordingStateReady,
		Artifact: &breakglassv1alpha1.TerminalRecordingArtifact{
			URI:       "opaque/object-key",
			SizeBytes: 10,
			ExpiresAt: func() *metav1.Time { value := metav1.NewTime(time.Now().Add(time.Hour)); return &value }(),
		},
	}
	if !recordingReplayAvailable(ready) {
		t.Fatal("expected ready recording to be replayable")
	}
	ready.State = breakglassv1alpha1.TerminalRecordingStateRecording
	if recordingReplayAvailable(ready) {
		t.Fatal("recording must not be replayable before finalization")
	}
	ready.State = breakglassv1alpha1.TerminalRecordingStateReady
	ready.Artifact.SizeBytes = -1
	if recordingReplayAvailable(ready) {
		t.Fatal("negative artifact size must be rejected")
	}
}

func TestRecordingReplayUsesSessionAuthorizationAndStreamsExternalArtifact(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "recorded-session",
			Namespace: "default",
			Labels:    map[string]string{DebugSessionLabelKey: "recorded-session"},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "prod",
			RequestedBy: "owner@example.com",
			TemplateRef: "template",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			Recording: &breakglassv1alpha1.TerminalRecordingStatus{
				Enabled: true,
				State:   breakglassv1alpha1.TerminalRecordingStateReady,
				Artifact: &breakglassv1alpha1.TerminalRecordingArtifact{
					URI:       "opaque/object-key",
					SizeBytes: 35,
				},
			},
		},
	}
	_, controller := setupTestRouter(t, session)
	reader := &recordingReaderStub{}
	controller.WithRecordingReplayReader(reader)

	ownerRouter := setupAuthenticatedDebugSessionRouter(t, controller, "owner@example.com", "", nil)
	ownerRequest := httptest.NewRequest(http.MethodGet, "/api/debugSessions/recorded-session/recording/replay?namespace=default", nil)
	ownerResponse := httptest.NewRecorder()
	ownerRouter.ServeHTTP(ownerResponse, ownerRequest)
	if ownerResponse.Code != http.StatusOK || !strings.Contains(ownerResponse.Body.String(), "asciinema") {
		t.Fatalf("authorized replay failed: status=%d body=%q", ownerResponse.Code, ownerResponse.Body.String())
	}

	otherRouter := setupAuthenticatedDebugSessionRouter(t, controller, "other@example.com", "", nil)
	otherRequest := httptest.NewRequest(http.MethodGet, "/api/debugSessions/recorded-session/recording/replay?namespace=default", nil)
	otherResponse := httptest.NewRecorder()
	otherRouter.ServeHTTP(otherResponse, otherRequest)
	if otherResponse.Code != http.StatusForbidden {
		t.Fatalf("unauthorized replay should be forbidden: status=%d body=%q", otherResponse.Code, otherResponse.Body.String())
	}
	if reader.opened != 1 {
		t.Fatalf("unauthorized replay must not open the artifact: opened=%d", reader.opened)
	}
}

func TestRecordingCleanupRetainsFinalizedLifecycleWithoutDeletingArtifact(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-session", Namespace: "default"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "prod", TemplateRef: "missing-template", RequestedBy: "owner@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateTerminated,
			Recording: &breakglassv1alpha1.TerminalRecordingStatus{
				Enabled:   true,
				State:     breakglassv1alpha1.TerminalRecordingStateFinalizing,
				Retention: "1h",
				Artifact:  &breakglassv1alpha1.TerminalRecordingArtifact{URI: "opaque/object-key"},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), fakeClient, nil)
	if _, err := controller.handleCleanup(context.Background(), session); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	latest := &breakglassv1alpha1.DebugSession{}
	if err := fakeClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), latest); err != nil {
		t.Fatalf("load cleaned session: %v", err)
	}
	if latest.Status.Recording.State != breakglassv1alpha1.TerminalRecordingStateRetained || latest.Status.Recording.CompletedAt == nil || latest.Status.Recording.Artifact.ExpiresAt == nil {
		t.Fatalf("cleanup did not retain finalized recording: %#v", latest.Status.Recording)
	}
}

func TestSafeRecordingFailureRedactsSecretsAndBoundsLength(t *testing.T) {
	got := safeRecordingFailure("sidecar rejected Authorization: Bearer super-secret-token")
	if got == "" || got == "sidecar rejected Authorization: Bearer super-secret-token" {
		t.Fatalf("secret was not redacted: %q", got)
	}
	for _, input := range []string{
		"Authorization: Bearer abc123",
		"Authorization: Basic dXNlcjpwYXNz",
		"Authorization: ******",
		"Bearer oauth-secret",
		"access_token=oauth-secret",
		"access-token: oauth-secret",
	} {
		for _, secret := range []string{"abc123", "dXNlcjpwYXNz", "oauth-secret"} {
			if got := safeRecordingFailure(input); strings.Contains(got, secret) {
				t.Fatalf("credential was not redacted: %q", got)
			}
		}
	}
	long := safeRecordingFailure("token=" + string(make([]byte, 1024)))
	if len(long) > 515 {
		t.Fatalf("failure was not bounded: %d", len(long))
	}
}
