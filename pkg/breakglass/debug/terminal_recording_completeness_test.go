// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/httpstream" //nolint:staticcheck // client-go spdy.Upgrader still returns this package's Connection
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// clientGoCopyExecutor streams like client-go's SPDY executor: a failed stdin
// or stdout copy is only logged, the rest of the output is discarded, and the
// command still ends cleanly (#1760).
type clientGoCopyExecutor struct {
	chunks    int
	readInput bool
	// before runs before output chunk i is written.
	before func(i int)
}

const clientGoChunk = "chunk\n"

func (clientGoCopyExecutor) Stream(remotecommand.StreamOptions) error { return nil }
func (e clientGoCopyExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	if e.readInput {
		_, _ = io.Copy(io.Discard, options.Stdin) // logged only
	}
	for i := 0; i < e.chunks; i++ {
		if e.before != nil {
			e.before(i)
		}
		if _, err := options.Stdout.Write([]byte(clientGoChunk)); err != nil {
			break // logged only; the remaining output is discarded
		}
	}
	return nil
}

// recordedOutput returns the payload of the recording's output frames.
func recordedOutput(t *testing.T, recording TerminalRecording) string {
	t.Helper()
	var out strings.Builder
	for data := recording.Bytes; len(data) > 0; {
		require.GreaterOrEqual(t, len(data), terminalRecordingFrameHeaderSize)
		length := int(binary.BigEndian.Uint64(data[10:18]))
		if data[1] == terminalRecordingDirectionOutput {
			out.Write(data[terminalRecordingFrameHeaderSize : terminalRecordingFrameHeaderSize+length])
		}
		data = data[terminalRecordingFrameHeaderSize+length:]
	}
	return out.String()
}

// failingAt fails the nth call (1-based) with err; every other call passes.
func failingAt(n int, err error) func(context.Context) error {
	var calls atomic.Int64
	return func(context.Context) error {
		if calls.Add(1) == int64(n) {
			return err
		}
		return nil
	}
}

func streamForTest(executor remotecommand.Executor, stdin io.Reader, stdout io.Writer) (TerminalRecording, error) {
	return streamTerminalWithLease(context.Background(), testTerminalRecordingConnection{}, time.Now().Add(time.Minute), executor, stdin, stdout, stdout, nil, NewTerminalRecorder(1<<20), func() {})
}

// #1760: one failed admission inside the output copy used to stop the output
// for the rest of the stream while the clean exit published it as complete.
func TestStreamEndsWhenOutputAdmissionFails(t *testing.T) {
	var delivered bytes.Buffer
	guard := authorizedRecordingWriter{ctx: context.Background(), writer: &delivered,
		authorize: failingAt(3, errors.New("read terminal session authority: context deadline exceeded"))}
	recording, err := streamForTest(clientGoCopyExecutor{chunks: 10}, nil, guard)
	require.Error(t, err, "a stream that dropped output must not end cleanly")
	require.Equal(t, "session_authority_changed", terminalRecordingAbortReason(err))
	require.Equal(t, strings.Repeat(clientGoChunk, 2), delivered.String())
	require.True(t, strings.HasPrefix(recordedOutput(t, recording), delivered.String()), "every delivered byte is recorded")
}

func TestStreamEndsWhenOutputDeliveryFails(t *testing.T) {
	var delivered bytes.Buffer
	client := &failingWriter{writer: &delivered, failAt: 2}
	recording, err := streamForTest(clientGoCopyExecutor{chunks: 10}, nil, client)
	require.Error(t, err)
	require.Equal(t, "transport_failed", terminalRecordingAbortReason(err))
	require.Equal(t, clientGoChunk, delivered.String())
	require.True(t, strings.HasPrefix(recordedOutput(t, recording), delivered.String()))
}

func TestStreamEndsWhenInputAdmissionFails(t *testing.T) {
	guard := authorizedRecordingReader{ctx: context.Background(), reader: strings.NewReader("typed"),
		authorize: failingAt(2, errors.New("read terminal stream claim: context deadline exceeded"))}
	_, err := streamForTest(clientGoCopyExecutor{chunks: 1, readInput: true}, guard, io.Discard)
	require.Error(t, err, "input dropped by a failed admission must end the stream")
	require.Equal(t, "lease_changed", terminalRecordingAbortReason(err))
}

// A client that closes its input ends stdin cleanly, not the stream.
func TestStreamToleratesInputEOF(t *testing.T) {
	var delivered bytes.Buffer
	_, err := streamForTest(clientGoCopyExecutor{chunks: 2, readInput: true}, strings.NewReader("typed"), &delivered)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat(clientGoChunk, 2), delivered.String())
}

type failingWriter struct {
	writer io.Writer
	failAt int
	calls  int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls >= w.failAt {
		return 0, errors.New("write: broken pipe")
	}
	return w.writer.Write(p)
}

// fakeExecutor returns err after optionally marking the final status seen.
type fakeExecutor struct {
	status *atomic.Bool
	seen   bool
	err    error
}

func (fakeExecutor) Stream(remotecommand.StreamOptions) error { return nil }
func (e fakeExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	_, _ = options.Stdout.Write([]byte("partial"))
	if e.seen {
		e.status.Store(true)
	}
	return e.err
}

// #1761: a transport torn down after the command exited reads EOF on every
// stream, so the SPDY executor reports the lost tail as a clean end.
func TestStatusCheckedExecutorFailsStreamWithoutFinalStatus(t *testing.T) {
	exitErr := errors.New("command terminated with exit code 1")
	for _, tt := range []struct {
		name   string
		seen   bool
		err    error
		want   error
		reason string
	}{
		{"torn down without status", false, nil, errTerminalOutputTruncated, "output_truncated"},
		{"ended with success status", true, nil, nil, ""},
		{"executor error wins", false, exitErr, exitErr, "stream_failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status := &atomic.Bool{}
			executor := statusCheckedExecutor{Executor: fakeExecutor{status: status, seen: tt.seen, err: tt.err}, status: status}
			_, err := streamForTest(executor, nil, io.Discard)
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
			require.Equal(t, tt.reason, terminalRecordingAbortReason(err))
		})
	}
}

type fakeHTTPStream struct {
	httpstream.Stream
	reader  io.Reader
	headers http.Header
}

func (s fakeHTTPStream) Read(p []byte) (int, error) { return s.reader.Read(p) }

type fakeHTTPConnection struct {
	httpstream.Connection
	payload map[string]string
}

func (c fakeHTTPConnection) CreateStream(headers http.Header) (httpstream.Stream, error) {
	return fakeHTTPStream{reader: strings.NewReader(c.payload[headers.Get(corev1.StreamType)]), headers: headers}, nil
}

func TestStatusTrackingConnectionWatchesOnlyTheErrorStream(t *testing.T) {
	read := func(payload map[string]string, streamType string) bool {
		seen := &atomic.Bool{}
		connection := statusTrackingConnection{Connection: fakeHTTPConnection{payload: payload}, seen: seen}
		headers := http.Header{}
		headers.Set(corev1.StreamType, streamType)
		stream, err := connection.CreateStream(headers)
		require.NoError(t, err)
		_, err = io.ReadAll(stream)
		require.NoError(t, err)
		return seen.Load()
	}
	require.True(t, read(map[string]string{corev1.StreamTypeError: `{"status":"Success"}`}, corev1.StreamTypeError))
	require.False(t, read(map[string]string{corev1.StreamTypeError: ""}, corev1.StreamTypeError), "an empty error stream is no status")
	require.False(t, read(map[string]string{corev1.StreamTypeStdout: "output"}, corev1.StreamTypeStdout), "output is no status")
}

// countingConnection counts live checks and fails them while revoked.
type countingConnection struct {
	testTerminalRecordingConnection
	calls   atomic.Int64
	revoked atomic.Bool
	delay   time.Duration
}

func (c *countingConnection) Validate(context.Context) error {
	c.calls.Add(1)
	time.Sleep(c.delay)
	if c.revoked.Load() {
		return errors.New("terminal session authority changed")
	}
	return nil
}

func TestTerminalAuthorityReusesARecentLiveCheck(t *testing.T) {
	ctx := context.Background()
	live := &countingConnection{}
	authority := newTerminalAuthority(live, 200*time.Millisecond)
	for range 1000 {
		require.NoError(t, authority.Admit(ctx))
	}
	require.EqualValues(t, 1, live.calls.Load(), "1000 writes within the bound need one live check")
	time.Sleep(250 * time.Millisecond)
	require.NoError(t, authority.Admit(ctx))
	require.EqualValues(t, 2, live.calls.Load(), "an expired check is renewed live")
	require.NoError(t, authority.Validate(ctx))
	require.EqualValues(t, 3, live.calls.Load(), "Validate is always live")
}

func TestTerminalAuthorityStrictModeChecksEveryAdmission(t *testing.T) {
	live := &countingConnection{}
	authority := newTerminalAuthority(live, 0)
	for range 5 {
		require.NoError(t, authority.Admit(context.Background()))
	}
	require.EqualValues(t, 5, live.calls.Load())
}

func TestTerminalAuthorityFailedCheckStopsCachedAdmission(t *testing.T) {
	ctx := context.Background()
	live := &countingConnection{}
	authority := newTerminalAuthority(live, time.Hour)
	require.NoError(t, authority.Admit(ctx))
	live.revoked.Store(true)
	require.Error(t, authority.Validate(ctx), "the watcher's live check sees the revocation")
	require.Error(t, authority.Admit(ctx), "no admission on a check older than a failed one")
	live.revoked.Store(false)
	require.NoError(t, authority.Admit(ctx), "a later successful live check admits again")
}

// Concurrent stale admissions share one live check instead of each reading.
func TestTerminalAuthoritySerializesLiveChecks(t *testing.T) {
	live := &countingConnection{delay: 50 * time.Millisecond}
	authority := newTerminalAuthority(live, time.Minute)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { require.NoError(t, authority.Admit(context.Background())) })
	}
	wg.Wait()
	require.EqualValues(t, 1, live.calls.Load())
}

// The documented revocation bound: after a revocation becomes visible to live
// reads, admission stops within maxAge of the last successful check's start.
func TestTerminalAuthorityRevocationBound(t *testing.T) {
	const maxAge = 300 * time.Millisecond
	live := &countingConnection{delay: 20 * time.Millisecond}
	authority := newTerminalAuthority(live, maxAge)
	require.NoError(t, authority.Admit(context.Background()))
	time.Sleep(100 * time.Millisecond)
	revokedAt := time.Now()
	live.revoked.Store(true)
	var lastAdmitted time.Time
	for authority.Admit(context.Background()) == nil {
		lastAdmitted = time.Now()
		time.Sleep(time.Millisecond)
	}
	cutAfter := time.Since(revokedAt)
	t.Logf("admission stopped %v after the revocation (bound %v)", cutAfter, maxAge)
	require.Less(t, lastAdmitted.Sub(revokedAt), maxAge, "nothing is admitted later than maxAge after the revocation")
	require.Less(t, cutAfter, maxAge+live.delay+100*time.Millisecond)
}

// #1760 at the route: a failed admission inside the output copy publishes the
// recording incomplete with an audited reason, in strict and in cached mode.
func TestTerminalRouteMarksDroppedOutputIncomplete(t *testing.T) {
	for _, strict := range []bool{true, false} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			now := metav1.Now()
			expiresAt := metav1.NewTime(now.Add(time.Hour))
			execAllowed := true
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiresAt,
					ResolvedTemplate:     &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}},
					Participants:         []breakglassv1alpha1.DebugSessionParticipant{{User: "alice", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now}},
					AllowedPods:          []breakglassv1alpha1.AllowedPodRef{{Namespace: "target", Name: "pod", UID: "pod-uid"}},
					AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: &execAllowed},
				},
			}
			service, cli := terminalArtifactFixture(t, session)
			failNext := &atomic.Bool{}
			auditEvents := NewMockAuditEmitter(true)
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).
				WithAPIReader(cli).
				WithTerminalRecordingArtifacts(service).
				WithTerminalRecordingConnections(flakyRouteProvider{failNext: failNext}).
				WithTerminalRecordingStrictAuthorization(strict).
				WithAuditService(auditEvents)
			controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error) {
				return &rest.Config{}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, "cluster-uid", nil
			}
			controller.terminalExecutorFactory = func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error) {
				return clientGoCopyExecutor{chunks: 6, before: func(i int) {
					if i == 3 {
						// One slow live read; cached mode meets it once the
						// last check is older than the bound.
						failNext.Store(true)
						if !strict {
							time.Sleep(terminalAuthorityMaxAge + 100*time.Millisecond)
						}
					}
				}}, nil
			}
			server := httptest.NewServer(debugSessionAPITestRouter(t, controller, "alice", "", nil))
			defer server.Close()
			response, err := http.Post(server.URL+"/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh", "application/octet-stream", strings.NewReader(""))
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, http.StatusOK, response.StatusCode)
			// When the watcher meets the failure first it cuts the response
			// before its trailers.
			output, err := io.ReadAll(response.Body)
			if strict {
				require.NoError(t, err)
				require.Equal(t, "incomplete", response.Trailer.Get("X-Breakglass-Recording-Status"))
				require.Less(t, len(output), 6*len(clientGoChunk), "the failed admission dropped output")
			}
			require.NotEqual(t, "completed", response.Trailer.Get("X-Breakglass-Recording-Status"))
			// A cut response can return before the handler finalized.
			var finalized *audit.Event
			require.Eventually(t, func() bool {
				for _, event := range auditEvents.GetEvents() {
					if event.Type == audit.EventDebugSessionTerminalRecordingFinalized {
						finalized = event
					}
				}
				return finalized != nil
			}, 5*time.Second, 20*time.Millisecond)
			require.Equal(t, false, finalized.Details["complete"])
			require.Equal(t, "lease_changed", finalized.Details["abortReason"])
		})
	}
}
