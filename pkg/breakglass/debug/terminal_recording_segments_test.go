// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func TestSegmentedRecorderBoundsMemoryAndChainsSegments(t *testing.T) {
	type flush struct {
		data []byte
		head [sha256.Size]byte
	}
	var flushes []flush
	var buffered int
	recorder := NewSegmentedTerminalRecorder(1<<20, 200, func(data []byte, head [sha256.Size]byte) error {
		flushes = append(flushes, flush{bytes.Clone(data), head})
		return nil
	})
	for i := 0; i < 10; i++ {
		require.NoError(t, recorder.Write(TerminalRecordingOutput, []byte("0123456789")))
		buffered = max(buffered, recorder.bytes.Len())
	}
	result, err := recorder.Finalize()
	require.NoError(t, err)
	// Each frame is header + 10 bytes; a segment is flushed before the frame
	// that follows >= 200 buffered bytes.
	require.LessOrEqual(t, buffered, 200+terminalRecordingFrameHeaderSize+10, "memory is bounded by one segment plus one frame")
	require.Greater(t, len(flushes), 1)
	require.Empty(t, result.Bytes)

	var all []byte
	for _, f := range flushes {
		require.NotEmpty(t, f.data)
		require.Zero(t, len(f.data)%(terminalRecordingFrameHeaderSize+10), "segments are frame aligned")
		all = append(all, f.data...)
		lastFrame := all[len(all)-(terminalRecordingFrameHeaderSize+10):]
		require.Equal(t, sha256.Sum256(lastFrame), f.head, "each flush carries the chain head of its last frame")
	}
	require.EqualValues(t, len(all), result.Size)
	require.EqualValues(t, 10, result.Frames)
	require.Equal(t, sha256Hex(string(all)), result.SHA256)

	again, err := recorder.Finalize()
	require.NoError(t, err)
	require.Equal(t, result, again, "finalize is idempotent")
}

func TestSegmentedRecorderFlushFailureFailsClosed(t *testing.T) {
	boom := errors.New("backend down")
	var calls int
	recorder := NewSegmentedTerminalRecorder(1<<20, 1, func([]byte, [sha256.Size]byte) error { calls++; return boom })
	require.NoError(t, recorder.Write(TerminalRecordingOutput, []byte("x")), "buffered below one segment")
	require.ErrorIs(t, recorder.Write(TerminalRecordingOutput, []byte("y")), boom, "a frame that needs a failed flush is refused")
	require.ErrorIs(t, recorder.Write(TerminalRecordingOutput, []byte("z")), boom, "no further bytes pass once evidence cannot be persisted")
	_, err := recorder.Finalize()
	require.ErrorIs(t, err, boom)
	require.Equal(t, 2, calls, "the failed flush, then one final retry")
}

func TestSegmentedRecorderFinalRetryCommitsOnlyDeliveredFrames(t *testing.T) {
	boom := errors.New("backend blip")
	var committed [][]byte
	failures := 1
	recorder := NewSegmentedTerminalRecorder(1<<20, 1, func(data []byte, _ [sha256.Size]byte) error {
		if failures > 0 {
			failures--
			return boom
		}
		committed = append(committed, bytes.Clone(data))
		return nil
	})
	require.NoError(t, recorder.Write(TerminalRecordingOutput, []byte("delivered")))
	require.ErrorIs(t, recorder.Write(TerminalRecordingOutput, []byte("refused")), boom)
	result, err := recorder.Finalize()
	require.ErrorIs(t, err, boom, "the stream still counts as failed")
	require.Len(t, committed, 1, "the delivered tail is committed by the final retry")
	require.Contains(t, string(committed[0]), "delivered")
	require.NotContains(t, string(committed[0]), "refused", "a refused frame never enters the evidence")
	require.EqualValues(t, len(committed[0]), result.Size)
	require.ErrorIs(t, recorder.FlushError(), boom)
}

// failingPutStore fails puts number failFrom..failTo (1-based).
type failingPutStore struct {
	storage.Store
	puts             atomic.Int32
	failFrom, failTo int32
}

func (s *failingPutStore) PutIfAbsent(ctx context.Context, object storage.Object, source io.Reader) (storage.Metadata, error) {
	if n := s.puts.Add(1); n >= s.failFrom && n <= s.failTo {
		return storage.Metadata{}, errors.New("backend unavailable")
	}
	return s.Store.PutIfAbsent(ctx, object, source)
}

func (s *failingPutStore) InventoryKey(ctx context.Context, key string) ([]storage.Version, error) {
	return s.Store.(storage.KeyInventory).InventoryKey(ctx, key)
}

func segmentedSession() *breakglassv1alpha1.DebugSession {
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	execAllowed := true
	return &breakglassv1alpha1.DebugSession{
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
}

// postSegmentedTerminal runs one terminal stream against a controller with
// incremental flush enabled on a store whose puts failFrom..failTo fail. The
// target prints "prompt", then echoes its input.
func postSegmentedTerminal(t *testing.T, failFrom, failTo int32) (http.Header, string, *backend.Service, *MockAuditEmitter, *breakglassv1alpha1.DebugSession) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	session := segmentedSession()
	service, cli := terminalArtifactFixtureWithStore(t, session, func(s storage.Store) storage.Store {
		return &failingPutStore{Store: s, failFrom: failFrom, failTo: failTo}
	})
	events := NewMockAuditEmitter(true)
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).
		WithTerminalRecordingArtifacts(service).WithTerminalRecordingMaxBytes(1 << 20).
		WithTerminalRecordingSegmentBytes(1).WithTerminalRecordingConnections(terminalRecordingRouteProvider{}).WithAuditService(events)
	controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error) {
		return &rest.Config{}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, "cluster-uid", nil
	}
	controller.terminalExecutorFactory = func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error) {
		return interactiveTerminalExecutor{}, nil
	}
	server := httptest.NewServer(debugSessionAPITestRouter(t, controller, "alice", "", nil))
	t.Cleanup(server.Close)
	response, err := http.Post(server.URL+"/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh", "application/octet-stream", strings.NewReader("input"))
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return response.Trailer.Clone(), string(body), service, events, session
}

func TestSegmentedRecordingPublishesRegularArtifact(t *testing.T) {
	trailer, body, service, events, session := postSegmentedTerminal(t, 1<<30, 1<<30)
	require.Equal(t, "promptinput", body)
	require.Equal(t, "completed", trailer.Get("X-Breakglass-Recording-Status"))
	records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.True(t, records[0].Recording.Complete)
	require.Equal(t, records[0].SHA256, trailer.Get("X-Breakglass-Recording-SHA256"))
	types := []audit.EventType{}
	for _, e := range events.GetEvents() {
		types = append(types, e.Type)
	}
	require.Equal(t, []audit.EventType{audit.EventDebugSessionTerminalRecordingStarted, audit.EventDebugSessionTerminalRecordingFinalized}, types)
}

// failedStages returns the stages of terminal_recording_failed events and
// checks that no backend error text reaches audit.
func failedStages(t *testing.T, events *MockAuditEmitter) []any {
	t.Helper()
	stages := []any{}
	for _, e := range events.GetEvents() {
		if e.Type == audit.EventDebugSessionTerminalRecordingFailed {
			stages = append(stages, e.Details["stage"])
			require.NotContains(t, fmt.Sprint(e.Details), "unavailable", "backend error text is not leaked into audit")
		}
	}
	return stages
}

func TestSegmentedRecordingBackendFailureFailsClosedAndIsAudited(t *testing.T) {
	// Segment 0 and manifest 0 ("prompt") are written, then the backend dies.
	trailer, body, service, events, session := postSegmentedTerminal(t, 3, 1<<30)
	require.Equal(t, "prompt", body, "output that cannot be recorded never reaches the client")
	require.NotEqual(t, "completed", trailer.Get("X-Breakglass-Recording-Status"))
	records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
	require.NoError(t, err)
	require.Empty(t, records, "nothing is published while the backend is down")
	require.Equal(t, []any{"flush", "finalize"}, failedStages(t, events))
}

func TestSegmentedRecordingFlushFailurePublishesCommittedPrefixAsIncomplete(t *testing.T) {
	// The flush of the input frame fails, and so does its final retry; the
	// backend is back for publication.
	trailer, body, service, events, session := postSegmentedTerminal(t, 3, 4)
	require.Equal(t, "prompt", body)
	require.Equal(t, "incomplete", trailer.Get("X-Breakglass-Recording-Status"))
	records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
	require.NoError(t, err)
	require.Len(t, records, 1)
	require.False(t, records[0].Recording.Complete)
	require.Equal(t, records[0].SHA256, trailer.Get("X-Breakglass-Recording-SHA256"))
	require.Equal(t, []any{"flush"}, failedStages(t, events))
	for _, e := range events.GetEvents() {
		if e.Type == audit.EventDebugSessionTerminalRecordingFinalized {
			require.Equal(t, records[0].Recording.Frames, e.Details["frames"], "audit reports what was published")
			require.Equal(t, records[0].Size, e.Details["bytes"])
		}
	}
}

func TestAuditRecoveredTerminalRecording(t *testing.T) {
	events := NewMockAuditEmitter(true)
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), nil, nil, nil).WithAuditService(events)
	record := backend.Record{Namespace: "hub", SessionName: "session", SessionUID: "session-uid", ArtifactID: "dsa-1"}
	controller.AuditRecoveredTerminalRecording(context.Background(), record, backend.PublicRecord{SHA256: strings.Repeat("a", 64), Size: 51, Recording: &backend.RecordingMetadata{FormatVersion: 2, Frames: 1, PodName: "pod", Operation: "exec"}})
	got := events.GetEvents()
	require.Len(t, got, 1)
	require.Equal(t, audit.EventDebugSessionTerminalRecordingFinalized, got[0].Type)
	require.Equal(t, "system", got[0].Actor.User)
	require.Equal(t, "session-uid", got[0].Target.UID)
	require.Equal(t, true, got[0].Details["recovered"])
	require.Equal(t, false, got[0].Details["complete"])
	require.Equal(t, "dsa-1", got[0].Details["recordingId"])
	require.Equal(t, strings.Repeat("a", 64), got[0].Details["sha256"])
}
