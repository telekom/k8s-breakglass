// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type terminalRecordingTestStore struct {
	mu       sync.Mutex
	data     map[string][]byte
	metadata map[string]artifactstorage.Metadata
	deleted  []string
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

func TestMergeKubectlDebugStatusRetainsTerminalRecordings(t *testing.T) {
	ref := breakglassv1alpha1.TerminalRecordingRef{ID: "recording", SHA256: strings.Repeat("c", 64)}
	merged := mergeKubectlDebugStatus(&breakglassv1alpha1.KubectlDebugStatus{}, &breakglassv1alpha1.KubectlDebugStatus{}, &breakglassv1alpha1.KubectlDebugStatus{TerminalRecordings: []breakglassv1alpha1.TerminalRecordingRef{ref}})
	require.Len(t, merged.TerminalRecordings, 1)
	require.Equal(t, ref.ID, merged.TerminalRecordings[0].ID)
}
