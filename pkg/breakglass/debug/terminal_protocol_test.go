// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/recording"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func framed(t *testing.T, frames ...func(io.Writer) error) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	for _, frame := range frames {
		require.NoError(t, frame(&buf))
	}
	return &buf
}

func stdinFrame(data string) func(io.Writer) error {
	return func(w io.Writer) error { return EncodeTerminalFrame(w, TerminalFrameStdin, []byte(data)) }
}

func resizeFrame(data string) func(io.Writer) error {
	return func(w io.Writer) error { return EncodeTerminalFrame(w, TerminalFrameResize, []byte(data)) }
}

func TestDecodeFramedTerminalInput(t *testing.T) {
	body := framed(t, stdinFrame("ab"), resizeFrame(`{"Width":100,"Height":30}`), stdinFrame("c"))
	stdin, sizes := decodeFramedTerminalInput(context.Background(), body, func(err error) { t.Errorf("unexpected abort: %v", err) })
	data, err := io.ReadAll(stdin)
	require.NoError(t, err)
	require.Equal(t, "abc", string(data))
	require.Equal(t, &remotecommand.TerminalSize{Width: 100, Height: 30}, sizes.Next())
	require.Nil(t, sizes.Next(), "the queue ends with the body")

	for name, body := range map[string]*bytes.Buffer{
		"unknown type": framed(t, func(w io.Writer) error { return EncodeTerminalFrame(w, 9, nil) }),
		"zero size":    framed(t, resizeFrame(`{"Width":0,"Height":30}`)),
		"bad json":     framed(t, resizeFrame(`nope`)),
		"oversized":    bytes.NewBuffer([]byte{0, 0xff, 0xff, 0xff, 0xff}),
		"truncated":    bytes.NewBuffer([]byte{0, 0, 0, 0, 4, 'a'}),
	} {
		t.Run(name, func(t *testing.T) {
			aborted := make(chan error, 1)
			stdin, _ := decodeFramedTerminalInput(context.Background(), body, func(err error) { aborted <- err })
			_, err := io.ReadAll(stdin)
			require.Error(t, err, "malformed input must fail the stream closed")
			require.Error(t, <-aborted, "the stream owner is told to stop")
		})
	}
	require.Error(t, EncodeTerminalFrame(io.Discard, TerminalFrameStdin, make([]byte, MaxTerminalInputFrame+1)))
}

// resizingTerminalExecutor acknowledges the first size it takes, so the test
// can pace input from the moment the size was recorded.
type resizingTerminalExecutor struct{ resized chan struct{} }

func (resizingTerminalExecutor) Stream(remotecommand.StreamOptions) error { return nil }
func (e resizingTerminalExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	if _, err := io.WriteString(options.Stdout, "prompt"); err != nil {
		return err
	}
	size := options.TerminalSizeQueue.Next()
	if size == nil {
		return io.ErrUnexpectedEOF
	}
	close(e.resized)
	input, err := io.ReadAll(options.Stdin)
	if err != nil {
		return err
	}
	_, err = options.Stdout.Write(input)
	return err
}

// stdinIgnoringExecutor models an executor that never reports stdin errors
// and exits successfully once its context ends.
type stdinIgnoringExecutor struct{}

func (stdinIgnoringExecutor) Stream(remotecommand.StreamOptions) error { return nil }
func (stdinIgnoringExecutor) StreamWithContext(ctx context.Context, options remotecommand.StreamOptions) error {
	if _, err := io.WriteString(options.Stdout, "prompt"); err != nil {
		return err
	}
	go func() { _, _ = io.Copy(io.Discard, options.Stdin) }()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
	}
	return nil
}

func TestTerminalRouteFramedProtocolRecordsResizeAndTiming(t *testing.T) {
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
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).
		WithTerminalRecordingArtifacts(service).WithTerminalRecordingMaxBytes(4096).WithTerminalRecordingConnections(terminalRecordingRouteProvider{})
	controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error) {
		return &rest.Config{}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, "cluster-uid", nil
	}
	resized := make(chan struct{})
	var executor remotecommand.Executor = resizingTerminalExecutor{resized: resized}
	controller.terminalExecutorFactory = func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error) {
		return executor, nil
	}
	server := httptest.NewServer(debugSessionAPITestRouter(t, controller, "alice", "", nil))
	defer server.Close()
	endpoint := server.URL + "/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh"

	unsupported, err := http.NewRequest(http.MethodPost, endpoint, http.NoBody)
	require.NoError(t, err)
	unsupported.Header.Set(TerminalProtocolHeader, "framed.v9")
	response, err := http.DefaultClient.Do(unsupported)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.NoError(t, response.Body.Close())

	input, inputWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, endpoint, input)
	require.NoError(t, err)
	req.Header.Set(TerminalProtocolHeader, TerminalProtocolFramed)
	go func() {
		_ = EncodeTerminalFrame(inputWriter, TerminalFrameResize, []byte(`{"Width":132,"Height":43}`))
		<-resized
		time.Sleep(100 * time.Millisecond)
		_ = EncodeTerminalFrame(inputWriter, TerminalFrameStdin, []byte("typed"))
		_ = inputWriter.Close()
	}()
	response, err = (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	output, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, "prompttyped", string(output))
	require.Equal(t, "completed", response.Trailer.Get("X-Breakglass-Recording-Status"))

	replay, err := http.Get(server.URL + "/api/v1/debugSessions/session/terminal/" + response.Trailer.Get("X-Breakglass-Recording-ID") + "?namespace=hub")
	require.NoError(t, err)
	defer replay.Body.Close()
	rec, err := recording.Parse(replay.Body)
	require.NoError(t, err)
	require.Equal(t, response.Trailer.Get("X-Breakglass-Recording-SHA256"), rec.SHA256)
	var directions []byte
	for _, frame := range rec.Frames {
		directions = append(directions, frame.Direction)
		require.EqualValues(t, TerminalRecordingFormatVersion, frame.Version)
	}
	require.Equal(t, "orio", string(directions), "output, resize, input, echo")
	require.JSONEq(t, `{"width":132,"height":43}`, string(rec.Frames[1].Payload))
	require.Equal(t, "typed", string(rec.Frames[2].Payload))
	require.GreaterOrEqual(t, rec.Frames[2].Offset-rec.Frames[1].Offset, 100*time.Millisecond)

	// A malformed frame must stop an executor that ignores stdin errors and
	// leave the evidence incomplete.
	executor = stdinIgnoringExecutor{}
	input, inputWriter = io.Pipe()
	req, err = http.NewRequest(http.MethodPost, endpoint, input)
	require.NoError(t, err)
	req.Header.Set(TerminalProtocolHeader, TerminalProtocolFramed)
	go func() {
		_ = EncodeTerminalFrame(inputWriter, 7, nil)
		_ = inputWriter.Close()
	}()
	started := time.Now()
	// The aborted stream may cut the connection before any response.
	if response, err = (&http.Client{Timeout: 10 * time.Second}).Do(req); err == nil {
		_, _ = io.ReadAll(response.Body)
		_ = response.Body.Close()
		require.NotEqual(t, "completed", response.Trailer.Get("X-Breakglass-Recording-Status"))
	}
	require.Less(t, time.Since(started), 4*time.Second, "a malformed frame stops the stream")
	require.Eventually(t, func() bool {
		records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
		if err != nil || len(records) != 2 {
			return false
		}
		for _, record := range records {
			if record.SHA256 != rec.SHA256 {
				return record.Recording != nil && !record.Recording.Complete
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond, "malformed input never yields a complete recording")
}
