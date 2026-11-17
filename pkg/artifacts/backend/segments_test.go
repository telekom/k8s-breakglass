//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
)

const testFrameSize = 51 // v2Frames: 50 byte header + 1 byte payload

type segmentFixture struct {
	service *Service
	store   *local.Store
	repo    *memoryRepository
	record  Record
	frames  []byte
}

func newSegmentFixture(t *testing.T, frames int) segmentFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	config := local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: true, ArtifactRoot: filepath.Join(root, "objects"), StagingRoot: filepath.Join(root, "staging"), InstanceID: "segments-instance", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), ServingReplicas: 1, AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate, EncryptionAcknowledged: true, SnapshotPolicy: local.SnapshotsProhibited}
	require.NoError(t, os.Mkdir(config.ArtifactRoot, 0700))
	require.NoError(t, os.Mkdir(config.StagingRoot, 0700))
	require.NoError(t, local.ProvisionSentinels(config))
	store, err := local.Open(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	offsets := make([]uint64, frames)
	directions := strings.Repeat("o", frames)
	for i := range offsets {
		offsets[i] = uint64(i)
	}
	meta := &RecordingMetadata{FormatVersion: 2, PodNamespace: "ns", PodName: "pod", PodUID: "puid", LeaseUID: "l", LeaseEpoch: "1", Generation: "1", Operation: "exec", StartedAt: time.Unix(10, 0), StreamExpiresAt: time.Unix(50, 0)}
	record := Record{Namespace: "ns", SessionName: "session", SessionUID: "suid", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "seg-uid", TargetClusterUID: "c", TargetIdentityDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), PlanDigest: strings.Repeat("c", 64), Recipe: TerminalRecordingRecipe, RecipeVersion: 1, ExpiresAt: time.Unix(200, 0), MaxBytes: 1 << 20, OperationEpoch: 1, Recording: meta, State: StatePending, Generation: 1}
	repo := &memoryRepository{record: record}
	return segmentFixture{service: newServiceForTest(t, repo, store, allowAuthorizer{}), store: store, repo: repo, record: record, frames: v2Frames(offsets, directions)}
}

// flush writes the frames in segments of perSegment frames and returns the
// writer plus the chain head after the last flushed frame.
func (f segmentFixture) flush(t *testing.T, perSegment, count int, final bool) {
	t.Helper()
	w := f.service.NewSegmentWriter(f.record)
	for start := 0; start < count; start += perSegment {
		end := min(start+perSegment, count)
		head := sha256.Sum256(f.frames[(end-1)*testFrameSize : end*testFrameSize])
		require.NoError(t, w.Append(context.Background(), f.frames[start*testFrameSize:end*testFrameSize], head, final && end == count))
	}
}

func (f segmentFixture) replaceSegment(t *testing.T, index int, content []byte) {
	t.Helper()
	ctx := context.Background()
	key, err := f.service.segmentObjectKey(f.record, "segment", index)
	require.NoError(t, err)
	require.NoError(t, f.service.deleteSegmentObject(ctx, f.record, "segment", index))
	require.NoError(t, f.service.putSegmentObject(ctx, f.record, key, content))
}

func TestSegmentsCrashKeepsCommittedPrefixVerifiable(t *testing.T) {
	f := newSegmentFixture(t, 7)
	// No final flag: simulates a controller killed mid-stream after 3 segments.
	f.flush(t, 3, 7, false)
	manifest, size, err := f.service.VerifyRecordingSegments(context.Background(), f.record)
	require.NoError(t, err)
	require.Len(t, manifest.Segments, 3)
	require.EqualValues(t, 7*testFrameSize, size)
	require.False(t, manifest.Final)
	require.Equal(t, 2, manifest.Seq)

	// A segment written right before the crash, without its manifest, is not committed.
	key, err := f.service.segmentObjectKey(f.record, "segment", 3)
	require.NoError(t, err)
	require.NoError(t, f.service.putSegmentObject(context.Background(), f.record, key, []byte("uncommitted")))
	_, size, err = f.service.VerifyRecordingSegments(context.Background(), f.record)
	require.NoError(t, err)
	require.EqualValues(t, 7*testFrameSize, size)
}

func TestSegmentsDetectTruncationAndTampering(t *testing.T) {
	ctx := context.Background()
	for name, tamper := range map[string]func(*testing.T, segmentFixture){
		"truncated segment": func(t *testing.T, f segmentFixture) {
			f.replaceSegment(t, 1, f.frames[3*testFrameSize:4*testFrameSize])
		},
		"modified payload": func(t *testing.T, f segmentFixture) {
			changed := bytes.Clone(f.frames[3*testFrameSize : 6*testFrameSize])
			changed[testFrameSize-1] ^= 0xff
			f.replaceSegment(t, 1, changed)
		},
		"missing tail segment": func(t *testing.T, f segmentFixture) {
			require.NoError(t, f.service.deleteSegmentObject(ctx, f.record, "segment", 2))
		},
		"segments swapped": func(t *testing.T, f segmentFixture) {
			f.replaceSegment(t, 0, f.frames[3*testFrameSize:6*testFrameSize])
			f.replaceSegment(t, 1, f.frames[0:3*testFrameSize])
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSegmentFixture(t, 9)
			f.flush(t, 3, 9, true)
			_, _, err := f.service.VerifyRecordingSegments(ctx, f.record)
			require.NoError(t, err)
			tamper(t, f)
			_, _, err = f.service.VerifyRecordingSegments(ctx, f.record)
			require.Error(t, err)
		})
	}
}

func TestSegmentsRejectWrongChainHead(t *testing.T) {
	f := newSegmentFixture(t, 3)
	w := f.service.NewSegmentWriter(f.record)
	require.NoError(t, w.Append(context.Background(), f.frames, sha256.Sum256([]byte("forged")), true))
	_, _, err := f.service.VerifyRecordingSegments(context.Background(), f.record)
	require.ErrorIs(t, err, ErrConflict)
}

func TestFinalizeFromSegmentsPublishesRecoversAndCleansUp(t *testing.T) {
	ctx := context.Background()
	f := newSegmentFixture(t, 7)
	f.flush(t, 3, 7, false) // crashed stream: recovered with Complete=false
	meta := *f.record.Recording
	meta.FinishedAt = time.Unix(60, 0)
	published, err := f.service.FinalizeRecordingFromSegments(ctx, f.record, meta)
	require.NoError(t, err)
	require.Equal(t, StateAvailable, published.State)
	require.EqualValues(t, 7*testFrameSize, published.Size)
	require.EqualValues(t, 7, published.Recording.Frames)
	require.False(t, published.Recording.Complete)

	reader, _, err := f.service.DownloadRecording(ctx, f.repo.record, func(context.Context) error { return nil })
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
	require.Equal(t, f.frames, got)

	for _, kind := range []string{"segment", "manifest"} {
		key, err := f.service.segmentObjectKey(f.record, kind, 0)
		require.NoError(t, err)
		versions, err := f.store.InventoryKey(ctx, key)
		require.NoError(t, err)
		require.Empty(t, versions, "%s objects are removed after publication", kind)
	}
}

func TestCleanupRemovesUnpublishedSegments(t *testing.T) {
	ctx := context.Background()
	f := newSegmentFixture(t, 4)
	f.flush(t, 2, 4, false)
	require.NoError(t, f.service.Cleanup(ctx, f.repo.record, StateExpired))
	key, err := f.service.segmentObjectKey(f.record, "manifest", 0)
	require.NoError(t, err)
	versions, err := f.store.InventoryKey(ctx, key)
	require.NoError(t, err)
	require.Empty(t, versions)
	require.Equal(t, StateExpired, f.repo.record.State)
}
