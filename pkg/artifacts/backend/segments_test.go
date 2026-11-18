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

// flush writes the frames in segments of perSegment frames.
func (f segmentFixture) flush(t *testing.T, perSegment, count int) *SegmentWriter {
	t.Helper()
	w := f.service.NewSegmentWriter(f.record)
	for start := 0; start < count; start += perSegment {
		end := min(start+perSegment, count)
		head := sha256.Sum256(f.frames[(end-1)*testFrameSize : end*testFrameSize])
		require.NoError(t, w.Append(context.Background(), f.frames[start*testFrameSize:end*testFrameSize], head))
	}
	return w
}

func (f segmentFixture) replaceSegment(t *testing.T, index int, content []byte) {
	t.Helper()
	ctx := context.Background()
	key, err := f.service.segmentObjectKey(f.record, "segment", index)
	require.NoError(t, err)
	require.NoError(t, f.service.deleteSegmentObject(ctx, f.record, "segment", index))
	require.NoError(t, f.service.putSegmentObject(ctx, f.record, key, content))
}

func (f segmentFixture) objects(t *testing.T, kind string) int {
	t.Helper()
	n, err := f.service.segmentObjectCount(context.Background(), f.record, kind)
	require.NoError(t, err)
	return n
}

func TestSegmentsCrashKeepsCommittedPrefixVerifiable(t *testing.T) {
	f := newSegmentFixture(t, 7)
	// A controller killed mid-stream after 3 segments.
	f.flush(t, 3, 7)
	manifest, err := f.service.VerifyRecordingSegments(context.Background(), f.record)
	require.NoError(t, err)
	require.Equal(t, 3, manifest.Segments)
	require.EqualValues(t, 7*testFrameSize, manifest.Size)
	require.Equal(t, 2, manifest.Seq)

	// A segment written right before the crash, without its manifest, is not committed.
	key, err := f.service.segmentObjectKey(f.record, "segment", 3)
	require.NoError(t, err)
	require.NoError(t, f.service.putSegmentObject(context.Background(), f.record, key, []byte("uncommitted")))
	manifest, err = f.service.VerifyRecordingSegments(context.Background(), f.record)
	require.NoError(t, err)
	require.EqualValues(t, 7*testFrameSize, manifest.Size)
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
		"modified last frame": func(t *testing.T, f segmentFixture) {
			changed := bytes.Clone(f.frames[6*testFrameSize : 9*testFrameSize])
			changed[len(changed)-1] ^= 0xff
			f.replaceSegment(t, 2, changed)
		},
		"trailing bytes on the last segment": func(t *testing.T, f segmentFixture) {
			f.replaceSegment(t, 2, append(bytes.Clone(f.frames[6*testFrameSize:9*testFrameSize]), "junk"...))
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
			f.flush(t, 3, 9)
			_, err := f.service.VerifyRecordingSegments(ctx, f.record)
			require.NoError(t, err)
			tamper(t, f)
			_, err = f.service.VerifyRecordingSegments(ctx, f.record)
			require.Error(t, err)
			meta := *f.record.Recording
			meta.FinishedAt = time.Unix(60, 0)
			_, err = f.service.FinalizeRecordingFromSegments(ctx, f.record, meta)
			require.Error(t, err, "publication applies the same checks")
			require.Equal(t, StatePending, f.repo.record.State, "nothing is published")
		})
	}
}

func TestSegmentsRejectWrongChainHead(t *testing.T) {
	f := newSegmentFixture(t, 3)
	w := f.service.NewSegmentWriter(f.record)
	require.NoError(t, w.Append(context.Background(), f.frames, sha256.Sum256([]byte("forged"))))
	_, err := f.service.VerifyRecordingSegments(context.Background(), f.record)
	require.ErrorIs(t, err, ErrConflict)
	meta := *f.record.Recording
	meta.FinishedAt = time.Unix(60, 0)
	_, err = w.Finalize(context.Background(), meta)
	require.ErrorIs(t, err, ErrConflict, "the stream's own finalize checks the head too")
}

func TestSegmentAppendIsFencedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	f := newSegmentFixture(t, 4)
	w := f.flush(t, 2, 2)
	// A retried write of identical bytes (after an ambiguous failure) succeeds.
	key, err := f.service.segmentObjectKey(f.record, "segment", 1)
	require.NoError(t, err)
	require.NoError(t, f.service.putSegmentObject(ctx, f.record, key, f.frames[2*testFrameSize:4*testFrameSize]))
	require.NoError(t, w.Append(ctx, f.frames[2*testFrameSize:4*testFrameSize], sha256.Sum256(f.frames[3*testFrameSize:4*testFrameSize])))
	require.Equal(t, 2, f.objects(t, "manifest"))

	// Once the reservation left Pending (cleanup, publication), nothing more is written.
	f.repo.record.State = StateDeleting
	require.ErrorIs(t, w.Append(ctx, f.frames[:testFrameSize], sha256.Sum256(f.frames[:testFrameSize])), ErrConflict)
	require.Equal(t, 2, f.objects(t, "segment"))
}

func TestFinalizeFromSegmentsPublishesRecoversAndCleansUp(t *testing.T) {
	ctx := context.Background()
	f := newSegmentFixture(t, 7)
	f.flush(t, 3, 7) // crashed stream: recovered with Complete=false
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
	require.Zero(t, f.objects(t, "segment"), "segments are removed after publication")
	require.Zero(t, f.objects(t, "manifest"), "manifests are removed after publication")

	// A second publication attempt (a racing handler) only recovers the result.
	again, err := f.service.FinalizeRecordingFromSegments(ctx, f.record, meta)
	require.NoError(t, err)
	require.Equal(t, published.SHA256, again.SHA256)
}

func TestRecoverAbandonedRecordingWaitsForTheGrace(t *testing.T) {
	ctx := context.Background()
	f := newSegmentFixture(t, 4)
	f.flush(t, 2, 4)
	// The service clock is 50s past the stream's expiry.
	_, recovered, err := f.service.RecoverAbandonedRecording(ctx, f.repo.record, time.Minute)
	require.NoError(t, err)
	require.False(t, recovered, "the stream's handler may still be publishing")
	require.Equal(t, StatePending, f.repo.record.State)

	published, recovered, err := f.service.RecoverAbandonedRecording(ctx, f.repo.record, 10*time.Second)
	require.NoError(t, err)
	require.True(t, recovered)
	require.False(t, published.Recording.Complete, "recovered evidence is incomplete")
	require.True(t, published.Recording.FinishedAt.Equal(f.record.Recording.StreamExpiresAt))
	require.Equal(t, StateAvailable, f.repo.record.State)
}

func TestRecoverAbandonedRecordingWithoutSegmentsChangesNothing(t *testing.T) {
	f := newSegmentFixture(t, 1)
	_, recovered, err := f.service.RecoverAbandonedRecording(context.Background(), f.repo.record, 0)
	require.NoError(t, err)
	require.False(t, recovered)
	require.Equal(t, StatePending, f.repo.record.State)
}

func TestCleanupRemovesUnpublishedSegments(t *testing.T) {
	ctx := context.Background()
	for name, setup := range map[string]func(*testing.T, segmentFixture){
		"committed segments": func(t *testing.T, f segmentFixture) { f.flush(t, 2, 4) },
		// A crash between the first segment and its manifest.
		"segment without manifest": func(t *testing.T, f segmentFixture) {
			key, err := f.service.segmentObjectKey(f.record, "segment", 0)
			require.NoError(t, err)
			require.NoError(t, f.service.putSegmentObject(ctx, f.record, key, f.frames[:testFrameSize]))
		},
		"corrupt manifest": func(t *testing.T, f segmentFixture) {
			f.flush(t, 2, 2)
			key, err := f.service.segmentObjectKey(f.record, "manifest", 1)
			require.NoError(t, err)
			require.NoError(t, f.service.putSegmentObject(ctx, f.record, key, []byte("{not json")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSegmentFixture(t, 4)
			setup(t, f)
			require.NoError(t, f.service.Cleanup(ctx, f.repo.record, StateExpired))
			require.Zero(t, f.objects(t, "segment"))
			require.Zero(t, f.objects(t, "manifest"))
			require.Equal(t, StateExpired, f.repo.record.State)
		})
	}
}
