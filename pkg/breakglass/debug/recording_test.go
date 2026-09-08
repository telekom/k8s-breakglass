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
	_, template := recordingFixture(true)
	if err := injectTerminalRecording(template); err == nil || !strings.Contains(err.Error(), "terminal-byte transport") {
		t.Fatalf("expected unavailable transport to fail closed, got %v", err)
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
		log: zap.NewNop().Sugar(),
	}
	result, err := controller.buildPodSpec(ds, template, podTemplate)
	if err == nil || !strings.Contains(err.Error(), "terminal-byte transport") {
		t.Fatalf("expected production pod rendering to fail closed, got result=%#v err=%v", result, err)
	}
}

func TestInjectTerminalRecordingFailsClosed(t *testing.T) {
	_, template := recordingFixture(true)
	if err := injectTerminalRecording(template); err == nil {
		t.Fatal("expected terminal recording to fail closed")
	}
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
	long := safeRecordingFailure(strings.Repeat("x", 1024))
	if len(long) != 515 {
		t.Fatalf("failure was not bounded: %d", len(long))
	}
}
