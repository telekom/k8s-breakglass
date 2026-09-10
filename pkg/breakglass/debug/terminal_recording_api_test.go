// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type terminalRecordingTestStore struct {
	mu       sync.Mutex
	data     map[string][]byte
	metadata map[string]artifactstorage.Metadata
	deleted  []string
}

type terminalRecordingRouteConnection struct {
	binding TerminalRecordingConnectionBinding
}

func (c terminalRecordingRouteConnection) Binding() TerminalRecordingConnectionBinding {
	return c.binding
}
func (terminalRecordingRouteConnection) Validate(context.Context) error { return nil }
func (terminalRecordingRouteConnection) Close(context.Context) error    { return nil }

type terminalRecordingRouteProvider struct{}

func (terminalRecordingRouteProvider) AcquireTerminalRecordingConnection(_ context.Context, binding TerminalRecordingConnectionBinding) (TerminalRecordingConnection, error) {
	binding.Epoch, binding.Generation = "epoch", "generation"
	return terminalRecordingRouteConnection{binding: binding}, nil
}

func newTerminalRecordingTestStore() *terminalRecordingTestStore {
	return &terminalRecordingTestStore{data: map[string][]byte{}, metadata: map[string]artifactstorage.Metadata{}}
}

func (s *terminalRecordingTestStore) Backend() string           { return "test-terminal-recording" }
func (s *terminalRecordingTestStore) BackendInstanceID() string { return "test-instance" }
func (s *terminalRecordingTestStore) PutIfAbsent(_ context.Context, object artifactstorage.Object, source io.Reader) (artifactstorage.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.metadata[object.Key]; ok {
		return artifactstorage.Metadata{}, artifactstorage.ErrAlreadyExists
	}
	b, err := io.ReadAll(source)
	if err != nil {
		return artifactstorage.Metadata{}, err
	}
	metadata := artifactstorage.Metadata{BackendInstanceID: s.BackendInstanceID(), Key: object.Key, VersionID: "v1", RuntimeBindingDigest: object.RuntimeBindingDigest, Size: object.Size, SHA256: object.SHA256, ModifiedAt: time.Now().UTC()}
	s.data[object.Key], s.metadata[object.Key] = b, metadata
	return metadata, nil
}
func (s *terminalRecordingTestStore) OpenVersion(_ context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (io.ReadCloser, artifactstorage.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, ok := s.metadata[object.Key]
	if !ok || metadata.VersionID != expected.VersionID || metadata.RuntimeBindingDigest != expected.RuntimeBindingDigest {
		return nil, artifactstorage.Metadata{}, artifactstorage.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(s.data[object.Key])), metadata, nil
}
func (s *terminalRecordingTestStore) StatVersion(_ context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (artifactstorage.Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, ok := s.metadata[object.Key]
	if !ok || metadata.VersionID != expected.VersionID || metadata.RuntimeBindingDigest != expected.RuntimeBindingDigest {
		return artifactstorage.Metadata{}, artifactstorage.ErrNotFound
	}
	return metadata, nil
}
func (s *terminalRecordingTestStore) Inventory(context.Context, artifactstorage.Object) ([]artifactstorage.Version, error) {
	return nil, nil
}
func (s *terminalRecordingTestStore) DeleteVersion(_ context.Context, object artifactstorage.Object, version artifactstorage.Version) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, ok := s.metadata[object.Key]
	if !ok || metadata.VersionID != version.VersionID || metadata.RuntimeBindingDigest != version.RuntimeBindingDigest {
		return artifactstorage.ErrNotFound
	}
	delete(s.metadata, object.Key)
	delete(s.data, object.Key)
	s.deleted = append(s.deleted, object.Key)
	return nil
}

func TestPersistTerminalRecordingPinsStoreAndLeaseMetadata(t *testing.T) {
	store := newTerminalRecordingTestStore()
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: types.UID("session-uid")}, Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{RecordingRetention: "1h"}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}
	recording := TerminalRecording{Bytes: []byte("framed-bytes"), SHA256: sha256Hex("framed-bytes")}
	binding := TerminalRecordingConnectionBinding{SessionUID: "session-uid", TargetPodUID: "pod-uid", Epoch: "epoch-1", Generation: "generation-1", RuntimeBindingDigest: strings.Repeat("a", 64)}
	ref, metadata, err := persistTerminalRecording(context.Background(), store, session, pod, "exec", "shell", binding, time.Now().UTC(), recording)
	require.NoError(t, err)
	require.Equal(t, store.BackendInstanceID(), ref.BackendInstanceID)
	require.Equal(t, binding.RuntimeBindingDigest, ref.RuntimeBindingDigest)
	require.Equal(t, int64(len(recording.Bytes)), ref.Size)
	reader, _, err := store.OpenVersion(context.Background(), terminalRecordingObject(ref), metadata)
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Equal(t, recording.Bytes, got)
}

func TestRegisteredTerminalRouteStreamsAndPublishesRecording(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := newTerminalRecordingTestStore()
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	execAllowed := true
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:                breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt:            &expiresAt,
			ResolvedTemplate:     &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}},
			Participants:         []breakglassv1alpha1.DebugSessionParticipant{{User: "alice", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now}},
			AllowedPods:          []breakglassv1alpha1.AllowedPodRef{{Namespace: "target", Name: "pod", UID: "pod-uid"}},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: &execAllowed},
		},
	}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(session).Build()
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).
		WithAPIReader(cli).
		WithTerminalRecordingStore(store).
		WithTerminalRecordingConnections(terminalRecordingRouteProvider{})
	controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, error) {
		return &rest.Config{}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, nil
	}
	controller.terminalExecutorFactory = func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error) {
		return interactiveTerminalExecutor{}, nil
	}
	router := debugSessionAPITestRouter(t, controller, "alice", "", nil)
	server := httptest.NewServer(router)
	defer server.Close()
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh", input)
	require.NoError(t, err)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	response, err := httpClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	prompt := make([]byte, len("prompt"))
	_, err = io.ReadFull(response.Body, prompt)
	require.NoError(t, err)
	require.Equal(t, "prompt", string(prompt))
	// The prompt must arrive before the request body is supplied or closed.
	_, err = io.WriteString(inputWriter, "input")
	require.NoError(t, err)
	require.NoError(t, inputWriter.Close())
	rest, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "input", string(rest))
	require.NotEmpty(t, response.Trailer.Get("X-Breakglass-Recording-ID"))
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), stored))
	require.Len(t, stored.Status.KubectlDebugStatus.TerminalRecordings, 1)
	require.Equal(t, "pod-uid", stored.Status.KubectlDebugStatus.TerminalRecordings[0].PodUID)
}

func TestCleanupExpiredTerminalRecordingsDeletesExactVersionAndKeepsLive(t *testing.T) {
	store := newTerminalRecordingTestStore()
	old := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Status: breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{}}}
	binding := strings.Repeat("b", 64)
	put := func(t *testing.T, key string, expires time.Time) breakglassv1alpha1.TerminalRecordingRef {
		t.Helper()
		recording := TerminalRecording{Bytes: []byte(key), SHA256: sha256Hex(key)}
		session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: old.UID}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: key, UID: types.UID(key)}}
		ref, _, err := persistTerminalRecording(context.Background(), store, session, pod, "exec", "shell", TerminalRecordingConnectionBinding{RuntimeBindingDigest: binding}, time.Now().Add(-time.Hour), recording)
		require.NoError(t, err)
		return ref
	}
	// Use a real persisted reference so cleanup exercises StatVersion/DeleteVersion.
	expired := put(t, "expired", time.Now().Add(-time.Minute))
	expired.ExpiresAt = metav1.NewTime(time.Now().Add(-time.Minute))
	live := put(t, "live", time.Now().Add(time.Hour))
	live.ExpiresAt = metav1.NewTime(time.Now().Add(time.Hour))
	old.Status.KubectlDebugStatus.TerminalRecordings = []breakglassv1alpha1.TerminalRecordingRef{expired, live}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(old).WithObjects(old).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithLiveReader(cli).WithTerminalRecordingStore(store)
	require.NoError(t, controller.cleanupExpiredTerminalRecordings(context.Background(), old))
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(old), stored))
	require.Len(t, stored.Status.KubectlDebugStatus.TerminalRecordings, 1)
	require.Equal(t, live.ID, stored.Status.KubectlDebugStatus.TerminalRecordings[0].ID)
	require.Len(t, store.deleted, 1)
}

func TestCleanupExpiredTerminalRecordingsConvergesAfterPriorDelete(t *testing.T) {
	store := newTerminalRecordingTestStore()
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")}, Status: breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{}}}
	ref, _, err := persistTerminalRecording(context.Background(), store, session, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, "exec", "shell", TerminalRecordingConnectionBinding{RuntimeBindingDigest: strings.Repeat("d", 64)}, time.Now().Add(-time.Hour), TerminalRecording{Bytes: []byte("evidence"), SHA256: sha256Hex("evidence")})
	require.NoError(t, err)
	ref.ExpiresAt = metav1.NewTime(time.Now().Add(-time.Minute))
	version := artifactstorage.Version{VersionID: ref.VersionID, RuntimeBindingDigest: ref.RuntimeBindingDigest, Size: ref.Size, SHA256: ref.SHA256}
	require.NoError(t, store.DeleteVersion(context.Background(), terminalRecordingObject(ref), version))
	session.Status.KubectlDebugStatus.TerminalRecordings = []breakglassv1alpha1.TerminalRecordingRef{ref}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(session).Build()
	controller := NewDebugSessionController(zap.NewNop().Sugar(), cli, nil).WithLiveReader(cli).WithTerminalRecordingStore(store)
	require.NoError(t, controller.cleanupExpiredTerminalRecordings(context.Background(), session))
	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), stored))
	require.Empty(t, stored.Status.KubectlDebugStatus)
}

func TestMergeKubectlDebugStatusRetainsTerminalRecordings(t *testing.T) {
	ref := breakglassv1alpha1.TerminalRecordingRef{ID: "recording", SHA256: strings.Repeat("c", 64)}
	merged := mergeKubectlDebugStatus(&breakglassv1alpha1.KubectlDebugStatus{}, &breakglassv1alpha1.KubectlDebugStatus{}, &breakglassv1alpha1.KubectlDebugStatus{TerminalRecordings: []breakglassv1alpha1.TerminalRecordingRef{ref}})
	require.Len(t, merged.TerminalRecordings, 1)
	require.Equal(t, ref.ID, merged.TerminalRecordings[0].ID)
}

func TestClearKubectlDebugResourcesRetainsRecordingInventory(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{
		EphemeralContainersInjected: []breakglassv1alpha1.EphemeralContainerRef{{PodName: "pod"}},
		TerminalRecordings:          []breakglassv1alpha1.TerminalRecordingRef{{ID: "recording"}},
	}}
	clearKubectlDebugResources(status)
	require.NotNil(t, status.KubectlDebugStatus)
	require.Len(t, status.KubectlDebugStatus.TerminalRecordings, 1)
	require.Empty(t, status.KubectlDebugStatus.EphemeralContainersInjected)
}

// interactiveTerminalExecutor follows the real protocol order: output first,
// then read input. A buffered HTTP transport deadlocks this exchange.
type interactiveTerminalExecutor struct{}

func (interactiveTerminalExecutor) Stream(remotecommand.StreamOptions) error { return nil }
func (interactiveTerminalExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	if _, err := io.WriteString(options.Stdout, "prompt"); err != nil {
		return err
	}
	input, err := io.ReadAll(options.Stdin)
	if err != nil {
		return err
	}
	_, err = options.Stdout.Write(input)
	return err
}

func TestRecordingInputLimitDoesNotForwardUnrecordedBytes(t *testing.T) {
	recorder := NewTerminalRecorder(terminalRecordingFrameHeaderSize + 2)
	input := &recordingReader{reader: strings.NewReader("unrecorded command"), recorder: recorder, direction: TerminalRecordingInput}
	var target bytes.Buffer
	_, err := io.Copy(&target, input)
	require.Error(t, err)
	require.Empty(t, target.Bytes())
}
