// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/remotecommand"
)

type testTerminalExecutor struct {
	input  []byte
	output []byte
	err    error
}

type blockingTerminalExecutor struct{}

func (blockingTerminalExecutor) Stream(remotecommand.StreamOptions) error { return nil }

func (blockingTerminalExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	if _, err := options.Stdout.Write([]byte("before-expiry")); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

type testTerminalRecordingConnection struct{}

func (testTerminalRecordingConnection) Binding() TerminalRecordingConnectionBinding {
	return TerminalRecordingConnectionBinding{SessionUID: "session", TargetPodUID: "pod", Epoch: "epoch", Generation: "generation", RuntimeBindingDigest: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Second)}
}
func (testTerminalRecordingConnection) Validate(context.Context) error { return nil }
func (testTerminalRecordingConnection) Close(context.Context) error    { return nil }

func (e *testTerminalExecutor) Stream(_ remotecommand.StreamOptions) error { return nil }

func (e *testTerminalExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	input, err := io.ReadAll(options.Stdin)
	if err != nil {
		return err
	}
	e.input = append([]byte(nil), input...)
	if len(e.output) > 0 {
		if _, err := options.Stdout.Write(e.output); err != nil {
			return err
		}
	}
	return e.err
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

func TestRejectUnsupportedTerminalRecordingContract(t *testing.T) {
	_, template := recordingFixture(true)
	if err := rejectUnsupportedTerminalRecording(template); err == nil || !strings.Contains(err.Error(), "spec.audit.enableTerminalRecording") || !strings.Contains(err.Error(), "terminal-byte transport") {
		t.Fatalf("expected unavailable transport to fail closed, got %v", err)
	}
}

func TestBuildPodSpecRejectsUnsupportedTerminalRecording(t *testing.T) {
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

func TestRejectUnsupportedTerminalRecordingAllowsDisabled(t *testing.T) {
	_, template := recordingFixture(false)
	if err := rejectUnsupportedTerminalRecording(template); err != nil {
		t.Fatalf("disabled terminal recording should remain supported: %v", err)
	}
}

func TestStreamTerminalRecordsBothDirectionsAndFinalizesHashChain(t *testing.T) {
	executor := &testTerminalExecutor{output: []byte("target-output")}
	recorder := NewTerminalRecorder(1024)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	result, err := StreamTerminal(context.Background(), executor, strings.NewReader("user-input"), &stdout, &stderr, recorder)
	if err != nil {
		t.Fatalf("StreamTerminal() error = %v", err)
	}
	if string(executor.input) != "user-input" {
		t.Fatalf("executor input = %q, want user-input", executor.input)
	}
	if stdout.String() != "target-output" {
		t.Fatalf("stdout = %q, want target-output", stdout.String())
	}
	if result.SHA256 == "" || len(result.Bytes) == 0 {
		t.Fatalf("finalized recording missing bytes or digest: %#v", result)
	}
	if _, err := recorder.Finalize(); err != nil {
		t.Fatalf("idempotent Finalize() error = %v", err)
	}
	if err := recorder.Write(TerminalRecordingOutput, []byte("late")); err == nil {
		t.Fatal("Write() after Finalize() succeeded")
	}
}

func TestStreamTerminalPreservesPartialRecordingWhenExecutorFails(t *testing.T) {
	executor := &testTerminalExecutor{output: []byte("partial-output"), err: errors.New("remote command failed")}
	recorder := NewTerminalRecorder(1024)
	var stdout bytes.Buffer

	result, err := StreamTerminal(context.Background(), executor, strings.NewReader("input"), &stdout, nil, recorder)
	if err == nil || !strings.Contains(err.Error(), "remote command failed") {
		t.Fatalf("StreamTerminal() error = %v, want executor failure", err)
	}
	if stdout.String() != "partial-output" {
		t.Fatalf("stdout = %q, want partial-output", stdout.String())
	}
	if len(result.Bytes) == 0 || result.SHA256 == "" {
		t.Fatalf("partial recording was discarded: %#v", result)
	}
}

func TestStreamTerminalWithLeaseStopsAtBindingExpiryAndKeepsEvidence(t *testing.T) {
	aborted := make(chan struct{})
	recorder := NewTerminalRecorder(1024)
	var stdout bytes.Buffer
	recording, err := streamTerminalWithLease(context.Background(), testTerminalRecordingConnection{}, time.Now().Add(20*time.Millisecond), blockingTerminalExecutor{}, nil, &stdout, &stdout, recorder, func() { close(aborted) })
	if err == nil || !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("streamTerminalWithLease() error = %v, want expiry cancellation", err)
	}
	select {
	case <-aborted:
	default:
		t.Fatal("HTTP transport was not aborted on expiry")
	}
	if stdout.String() != "before-expiry" || len(recording.Bytes) == 0 {
		t.Fatalf("expiry discarded partial output: stdout=%q recording=%d", stdout.String(), len(recording.Bytes))
	}
}

func TestTerminalRecorderFailsClosedAtByteLimit(t *testing.T) {
	recorder := NewTerminalRecorder(terminalRecordingFrameHeaderSize + 3)
	if err := recorder.Write(TerminalRecordingInput, []byte("abc")); err != nil {
		t.Fatalf("first Write() error = %v", err)
	}
	if err := recorder.Write(TerminalRecordingOutput, []byte("d")); err == nil {
		t.Fatal("Write() beyond the byte limit succeeded")
	}
	result, err := recorder.Finalize()
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if len(result.Bytes) != terminalRecordingFrameHeaderSize+3 {
		t.Fatalf("finalized bytes = %d, want %d", len(result.Bytes), terminalRecordingFrameHeaderSize+3)
	}
}
