//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/recording"
)

// Recorded terminal throughput floor (#1761), checked for streams of at least
// 4 MiB. Per-write live authorization moved about 20 KiB/s in Kind; a cached
// check moves MiB/s.
const minRecordedTerminalRate = 256 << 10 // bytes per second

// Must match pkg/breakglass/debug (test-only fault injection, e2e_fault).
const failOutputAdmissionEnv = "BREAKGLASS_E2E_FAIL_TERMINAL_OUTPUT_ADMISSION"

// TestDebugSessionTerminalRecordingCompletenessE2E checks #1760 and #1761 on a
// real controller: a several-MiB stream whose command exits right after its
// output is delivered and recorded byte for byte at a usable rate, and a
// revocation in the middle of continuous output cuts it within the documented
// bound and publishes the recording incomplete.
func TestDebugSessionTerminalRecordingCompletenessE2E(t *testing.T) {
	maxBytes, err := strconv.ParseInt(os.Getenv("E2E_RECORDING_MAX_BYTES"), 10, 64)
	require.NoError(t, err, "run e2e/fixtures/artifacts/setup.sh first")
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	ensureAuditPipeline(t, ctx, s)
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)

	t.Run("large stream is delivered and recorded completely", func(t *testing.T) {
		session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
		refreshToken(ctx, requester)
		// Half the recording limit leaves room for framing; 8 MiB at most.
		size := min(int64(8<<20), maxBytes/2)
		const marker = "END-OF-OUTPUT"
		cid := uuid.NewString()
		var first, last time.Time
		// The command exits right after its output: whatever is still in
		// flight then must be drained, delivered and recorded.
		result := streamRecorded(t, ctx, requester, helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command:       []string{"sh", "-c", fmt.Sprintf("head -c %d /dev/zero | tr '\\0' a; echo; echo %s", size, marker)},
			CorrelationID: cid,
			Interact: func(output <-chan string, _ io.Writer) error {
				for range output {
					if last = time.Now(); first.IsZero() {
						first = last
					}
				}
				return nil
			},
		}, 10*time.Minute)
		// From the first to the last output chunk: excludes setup and retries.
		elapsed := last.Sub(first)
		rate := float64(size) / max(elapsed.Seconds(), 0.001)
		t.Logf("measured: %d bytes in %v = %.0f KiB/s (floor %d KiB/s from 4 MiB)", size, elapsed.Round(time.Millisecond), rate/1024, minRecordedTerminalRate>>10)
		require.Equal(t, int64(strings.Count(result.Output, "a")), size, "every output byte reached the client")
		require.Contains(t, result.Output, marker)
		require.Equal(t, "completed", result.Status)

		replayed := replayOutput(t, ctx, requester, session, result.RecordingID)
		require.Equal(t, result.Output, replayed, "the recording holds exactly the delivered output")
		if size >= 4<<20 {
			require.GreaterOrEqual(t, rate, float64(minRecordedTerminalRate), "recorded terminal throughput (#1761)")
		}
	})

	t.Run("revocation cuts continuous output within the bound", func(t *testing.T) {
		session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
		refreshToken(ctx, requester)
		cid := uuid.NewString()
		var revokedAt, lastOutput time.Time
		// About 80 KiB/s, so even the 1 MiB recording limit of the
		// multi-cluster lanes is far away when the session is terminated.
		result := streamRecorded(t, ctx, requester, helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command:       []string{"sh", "-c", `while :; do head -c 4096 /dev/zero | tr '\0' r; sleep 0.05; done`},
			CorrelationID: cid,
			Interact: func(output <-chan string, _ io.Writer) error {
				seen := 0
				for chunk := range output {
					if seen += len(chunk); seen >= 64<<10 {
						break
					}
				}
				if err := requester.TerminateDebugSession(ctx, t, session.Name); err != nil {
					return err
				}
				revokedAt = time.Now()
				for range output {
					lastOutput = time.Now()
				}
				return nil
			},
		}, 5*time.Minute)
		require.False(t, revokedAt.IsZero(), "the session was terminated mid-stream")
		cut := lastOutput.Sub(revokedAt)
		t.Logf("measured: last output %v after the revocation was acknowledged (documented bound: 1s after it is visible to live reads, plus one admitted write and transport latency)", cut.Round(time.Millisecond))
		require.NotEqual(t, "completed", result.Status)
		require.Less(t, cut, 3*time.Second, "revocation cuts the output within the bound")
		finalized := finalizedEvent(t, ctx, cid)
		require.Equal(t, false, finalized.Details["complete"])
		require.Equal(t, "session_authority_changed", finalized.Details["abortReason"])
	})
}

// TestDebugSessionTerminalRecordingAdmissionFaultE2E reproduces #1760 on a
// real controller: the e2e_fault build (e2e/build-ha-image.sh) fails one
// output admission in the middle of a stream while the session stays valid.
// The stream must end and be published incomplete; before #1760 the output was
// silently dropped and the clean exit published it as complete.
// It restarts the controller, so CI runs it in its own step.
func TestDebugSessionTerminalRecordingAdmissionFaultE2E(t *testing.T) {
	if os.Getenv("E2E_TERMINAL_ADMISSION_FAULT") != "true" {
		t.Skip("restarts the controller with the e2e_fault build; set E2E_TERMINAL_ADMISSION_FAULT=true")
	}
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	ensureAuditPipeline(t, ctx, s)
	image := os.Getenv("E2E_FAULT_IMAGE")
	if image == "" {
		image = "breakglass:e2e-fault"
	}
	// The 20th output write of every stream is refused once.
	updateController(t, s, func(d *appsv1.Deployment) {
		c := &d.Spec.Template.Spec.Containers[0]
		c.Image, c.ImagePullPolicy = image, corev1.PullIfNotPresent
		env := make([]corev1.EnvVar, 0, len(c.Env)+1)
		for _, e := range c.Env {
			if e.Name != failOutputAdmissionEnv {
				env = append(env, e)
			}
		}
		c.Env = append(env, corev1.EnvVar{Name: failOutputAdmissionEnv, Value: "20"})
	})
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)
	session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
	refreshToken(ctx, requester)
	const size, marker = 1 << 20, "END-OF-OUTPUT"
	cid := uuid.NewString()
	result := streamRecorded(t, ctx, requester, helpers.TerminalStreamRequest{
		Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
		Command:       []string{"sh", "-c", fmt.Sprintf("echo start; head -c %d /dev/zero | tr '\\0' f; echo; echo %s", size, marker)},
		Interact:      drainOutput,
		CorrelationID: cid,
	}, 5*time.Minute)
	t.Logf("delivered %d of %d output bytes, status %q", strings.Count(result.Output, "f"), size, result.Status)
	require.Less(t, strings.Count(result.Output, "f"), size, "the refused admission dropped output")
	require.NotContains(t, result.Output, marker)
	require.Equal(t, "incomplete", result.Status, "a stream that dropped output is never complete")
	finalized := finalizedEvent(t, ctx, cid)
	require.Equal(t, false, finalized.Details["complete"])
	require.Equal(t, "authority_check_failed", finalized.Details["abortReason"], "a failed read, not a revocation")
	// Everything the client saw is in the evidence.
	require.True(t, strings.HasPrefix(replayOutput(t, ctx, requester, session, result.RecordingID), result.Output))
}

// drainOutput keeps stdin open until the stream ends, like a user watching
// output: a TTY exec whose input ends at once may end before it ran.
func drainOutput(output <-chan string, _ io.Writer) error {
	for range output {
	}
	return nil
}

// refreshToken starts a stream with a fresh token: streams bypass the
// client's 401 refresh.
func refreshToken(ctx context.Context, client *helpers.APIClient) {
	if token := client.RefreshToken(ctx); token != "" {
		client.AuthToken = token
	}
}

// streamRecorded runs one recorded stream, retrying only the refusal of a
// session's first stream while its credential generation is published (503).
func streamRecorded(t *testing.T, ctx context.Context, client *helpers.APIClient, request helpers.TerminalStreamRequest, timeout time.Duration) helpers.TerminalStreamResult {
	t.Helper()
	streamCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		result, err := client.StreamRecordedTerminal(streamCtx, request)
		require.NoError(t, err)
		if result.StatusCode != http.StatusServiceUnavailable || attempt >= 10 {
			require.Equal(t, http.StatusOK, result.StatusCode, result.Body)
			return result
		}
		select {
		case <-streamCtx.Done():
			t.Fatalf("stream refused until timeout: %s", result.Body)
		case <-time.After(2 * time.Second):
		}
	}
}

// replayOutput returns the output frames of a published recording; it also
// verifies the hash chain.
func replayOutput(t *testing.T, ctx context.Context, client *helpers.APIClient, session *breakglassv1alpha1.DebugSession, recordingID string) string {
	t.Helper()
	require.NotEmpty(t, recordingID)
	path := "/api/debugSessions/" + url.PathEscape(session.Name) + "/terminal/" + url.PathEscape(recordingID) + "?namespace=" + url.QueryEscape(session.Namespace)
	status, body, err := client.GetRaw(ctx, path)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, string(body))
	parsed, err := recording.Parse(bytes.NewReader(body))
	require.NoError(t, err)
	var output strings.Builder
	for _, frame := range parsed.Frames {
		if frame.Direction == 'o' {
			output.Write(frame.Payload)
		}
	}
	return output.String()
}

func finalizedEvent(t *testing.T, ctx context.Context, cid string) helpers.ReceivedAuditEvent {
	t.Helper()
	var finalized helpers.ReceivedAuditEvent
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		events, err := helpers.AuditEventsByCorrelation(ctx, cid)
		require.NoError(c, err)
		found := false
		for _, event := range events {
			if event.Type == "debug_session.terminal_recording_finalized" {
				finalized, found = event, true
			}
		}
		require.True(c, found, "the finalized event is delivered: %+v", events)
	}, time.Minute, 2*time.Second)
	t.Logf("finalized: recordingId=%v complete=%v abortReason=%v bytes=%v", finalized.Details["recordingId"], finalized.Details["complete"], finalized.Details["abortReason"], finalized.Details["bytes"])
	return finalized
}
