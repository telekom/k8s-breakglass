// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
		data  []byte
		head  [sha256.Size]byte
		final bool
	}
	var flushes []flush
	var buffered int
	recorder := NewSegmentedTerminalRecorder(1<<20, 200, func(data []byte, head [sha256.Size]byte, final bool) error {
		flushes = append(flushes, flush{bytes.Clone(data), head, final})
		return nil
	})
	for i := 0; i < 10; i++ {
		require.NoError(t, recorder.Write(TerminalRecordingOutput, []byte("0123456789")))
		buffered = max(buffered, recorder.bytes.Len())
	}
	result, err := recorder.Finalize()
	require.NoError(t, err)
	// Each frame is header + 10 bytes; a segment closes once >= 200 bytes buffered.
	require.LessOrEqual(t, buffered, 200+terminalRecordingFrameHeaderSize+10, "memory is bounded by one segment")
	require.Greater(t, len(flushes), 1)
	require.True(t, flushes[len(flushes)-1].final)
	require.Empty(t, result.Bytes)

	var all []byte
	for _, f := range flushes {
		require.Zero(t, len(f.data)%(terminalRecordingFrameHeaderSize+10), "segments are frame aligned")
		all = append(all, f.data...)
	}
	require.EqualValues(t, len(all), result.Size)
	require.EqualValues(t, 10, result.Frames)
	require.Equal(t, sha256Hex(string(all)), result.SHA256)
	lastFrame := all[len(all)-(terminalRecordingFrameHeaderSize+10):]
	require.Equal(t, sha256.Sum256(lastFrame), flushes[len(flushes)-1].head, "final flush carries the chain head")

	again, err := recorder.Finalize()
	require.NoError(t, err)
	require.Equal(t, result, again, "finalize is idempotent")
}

func TestSegmentedRecorderFlushFailureFailsClosed(t *testing.T) {
	boom := errors.New("backend down")
	recorder := NewSegmentedTerminalRecorder(1<<20, 1, func([]byte, [sha256.Size]byte, bool) error { return boom })
	err := recorder.Write(TerminalRecordingOutput, []byte("x"))
	require.ErrorIs(t, err, boom)
	require.ErrorIs(t, recorder.Write(TerminalRecordingOutput, []byte("y")), boom, "no further bytes pass once evidence cannot be persisted")
	_, err = recorder.Finalize()
	require.ErrorIs(t, err, boom)
}

type failingPutStore struct {
	storage.Store
	puts      atomic.Int32
	failAfter int32
}

func (s *failingPutStore) PutIfAbsent(ctx context.Context, object storage.Object, source io.Reader) (storage.Metadata, error) {
	if s.puts.Add(1) > s.failAfter {
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
// incremental flush enabled on a store that fails after failAfter puts.
func postSegmentedTerminal(t *testing.T, failAfter int32) (http.Header, *backend.Service, *MockAuditEmitter, *breakglassv1alpha1.DebugSession) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	session := segmentedSession()
	service, cli := terminalArtifactFixtureWithStore(t, session, func(s storage.Store) storage.Store {
		return &failingPutStore{Store: s, failAfter: failAfter}
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
	_, _ = io.Copy(io.Discard, response.Body)
	require.NoError(t, response.Body.Close())
	return response.Trailer.Clone(), service, events, session
}

func TestSegmentedRecordingPublishesRegularArtifact(t *testing.T) {
	trailer, service, events, session := postSegmentedTerminal(t, 1<<20)
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

func TestSegmentedRecordingBackendFailureFailsClosedAndIsAudited(t *testing.T) {
	// Allow the first segment and its manifest (2 puts), then the backend dies.
	trailer, service, events, session := postSegmentedTerminal(t, 2)
	require.NotEqual(t, "completed", trailer.Get("X-Breakglass-Recording-Status"))
	records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
	require.NoError(t, err)
	require.Empty(t, records, "no complete recording is advertised when the backend failed")
	stages := []any{}
	for _, e := range events.GetEvents() {
		if e.Type == audit.EventDebugSessionTerminalRecordingFailed {
			stages = append(stages, e.Details["stage"])
			require.NotContains(t, e.Details, "error", "backend error text is not leaked into audit")
			require.NotContains(t, e.Details, "unavailable")
		}
	}
	require.Contains(t, stages, "flush")
}
