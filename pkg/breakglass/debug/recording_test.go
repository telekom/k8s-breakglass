// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"strings"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

func TestBuildPodSpecInjectsTerminalRecording(t *testing.T) {
	ds, template := recordingFixture(true)
	podTemplate := &breakglassv1alpha1.DebugPodTemplate{
		Spec: breakglassv1alpha1.DebugPodTemplateSpec{
			Template: &breakglassv1alpha1.DebugPodSpec{
				Spec: breakglassv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{{Name: "debug", Image: "example/debug"}},
				},
			},
		},
	}
	controller := &DebugSessionController{
		log:                    zap.NewNop().Sugar(),
		terminalRecordingImage: "registry.example/recorder@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	result, err := controller.buildPodSpec(ds, template, podTemplate)
	if err != nil {
		t.Fatalf("build pod spec: %v", err)
	}
	if len(result.PodSpec.Containers) != 2 || result.PodSpec.Containers[1].Name != "terminal-recorder" {
		t.Fatalf("expected production pod rendering to inject recorder sidecar, got %#v", result.PodSpec.Containers)
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
	if err := injectTerminalRecording(spec, ds, template, "example/recorder@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err == nil {
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

func TestSafeRecordingFailureRedactsSecretsAndBoundsLength(t *testing.T) {
	got := safeRecordingFailure("sidecar rejected Authorization: Bearer super-secret-token")
	if got == "" || got == "sidecar rejected Authorization: Bearer super-secret-token" {
		t.Fatalf("secret was not redacted: %q", got)
	}
	for _, input := range []string{"Authorization: Basic dXNlcjpwYXNz", "access_token=oauth-secret"} {
		if got := safeRecordingFailure(input); strings.Contains(got, "dXNlcjpwYXNz") || strings.Contains(got, "oauth-secret") {
			t.Fatalf("credential was not redacted: %q", got)
		}
	}
	long := safeRecordingFailure("token=" + string(make([]byte, 1024)))
	if len(long) > 515 {
		t.Fatalf("failure was not bounded: %d", len(long))
	}
}
