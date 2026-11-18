// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

// Incremental terminal evidence. The artifact store is create-only, so a
// running stream persists frame-aligned segments as separate objects and,
// after every segment, a new numbered manifest object with the segment count,
// the total size and the SHA-256 chain head. The frame hash chain commits to
// every byte before the head, so the manifest stays constant-size. The latest
// manifest is the commit point: after a controller crash everything it covers
// is readable and verifiable; bytes after it are unproven and ignored.

// errNoSegments reports that a reservation has no committed segments (the
// feature was off, or the stream ended before its first flush).
var errNoSegments = fmt.Errorf("%w: no committed recording segments", storage.ErrNotFound)

const (
	// MaxRecordingSegments bounds object count per recording.
	MaxRecordingSegments = 4096
	segmentManifestMax   = 4 << 10
)

// SegmentManifest is the committed prefix of a recording.
type SegmentManifest struct {
	Version  int   `json:"version"`
	Seq      int   `json:"seq"`
	Segments int   `json:"segments"`
	Size     int64 `json:"size"`
	// ChainHead is the hex SHA-256 of the last frame in the last segment.
	ChainHead string `json:"chainHead"`
}

func (service *Service) segmentObjectKey(record Record, kind string, n int) (string, error) {
	if record.ArtifactUID == "" {
		return "", errors.New("artifact UID is required for storage key")
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "breakglass-recording-segment-v1:%s:%s:%d", kind, record.ArtifactUID, n))
	return hex.EncodeToString(sum[:]), nil
}

// putSegmentObject is idempotent: an object already holding exactly data (a
// retry after an ambiguous write) counts as written.
func (service *Service) putSegmentObject(ctx context.Context, record Record, key string, data []byte) error {
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	_, err := service.store.PutIfAbsent(ctx, storage.Object{Key: key, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: int64(len(data)), SHA256: digest}, bytes.NewReader(data))
	if errors.Is(err, storage.ErrAlreadyExists) {
		existing, _, found, inventoryErr := service.inventorySegmentObject(ctx, record, key)
		if inventoryErr == nil && found && existing.Size == int64(len(data)) && existing.SHA256 == digest {
			return nil
		}
	}
	return err
}

// SegmentWriter appends segments for one reservation. It is not safe for
// concurrent use; the recorder serializes calls.
type SegmentWriter struct {
	service  *Service
	record   Record
	manifest SegmentManifest
}

// NewSegmentWriter starts an empty segment sequence for a pending recording.
func (service *Service) NewSegmentWriter(reservation Record) *SegmentWriter {
	return &SegmentWriter{service: service, record: reservation, manifest: SegmentManifest{Version: 1, Seq: -1}}
}

// Append persists data (frame-aligned; empty only for a manifest-only final
// commit, which is skipped) and then a manifest committing to it. A failure
// leaves the previous manifest as the committed prefix, and the same call may
// be retried.
func (w *SegmentWriter) Append(ctx context.Context, data []byte, chainHead [32]byte) error {
	if len(data) == 0 {
		return nil
	}
	if w.manifest.Segments >= MaxRecordingSegments {
		return fmt.Errorf("%w: recording exceeds %d segments", ErrInvalid, MaxRecordingSegments)
	}
	// Fence: a reservation that was published, revoked or cleaned up takes no
	// more objects, which nothing would ever find and remove again.
	// ponytail: check-then-write; a cleanup between the two leaves at most one
	// unreachable segment.
	current, err := w.service.Recording(ctx, w.record.Namespace, w.record.SessionName, w.record.ArtifactID)
	if err != nil {
		return err
	}
	if current.ArtifactUID != w.record.ArtifactUID || current.State != StatePending {
		return fmt.Errorf("%w: recording reservation is no longer pending", ErrConflict)
	}
	next := w.manifest
	next.Seq++
	next.Segments++
	next.Size += int64(len(data))
	next.ChainHead = hex.EncodeToString(chainHead[:])
	key, err := w.service.segmentObjectKey(w.record, "segment", next.Segments-1)
	if err != nil {
		return err
	}
	if err := w.service.putSegmentObject(ctx, w.record, key, data); err != nil {
		return fmt.Errorf("persist recording segment %d: %w", next.Segments-1, err)
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	key, err = w.service.segmentObjectKey(w.record, "manifest", next.Seq)
	if err != nil {
		return err
	}
	if err := w.service.putSegmentObject(ctx, w.record, key, encoded); err != nil {
		return fmt.Errorf("persist recording manifest %d: %w", next.Seq, err)
	}
	w.manifest = next
	return nil
}

// Finalize publishes what this writer committed, without rediscovering it.
func (w *SegmentWriter) Finalize(ctx context.Context, metadata RecordingMetadata) (PublicRecord, error) {
	if w.manifest.Segments == 0 {
		return PublicRecord{}, errNoSegments
	}
	return w.service.finalizeFromManifest(ctx, w.record, w.manifest, metadata)
}

func (service *Service) inventorySegmentObject(ctx context.Context, record Record, key string) (storage.Object, storage.Version, bool, error) {
	inventory, ok := service.store.(storage.KeyInventory)
	if !ok {
		return storage.Object{}, storage.Version{}, false, storage.ErrAmbiguous
	}
	versions, err := inventory.InventoryKey(ctx, key)
	if err != nil {
		return storage.Object{}, storage.Version{}, false, err
	}
	var found []storage.Version
	for _, version := range versions {
		if !version.DeleteMarker {
			found = append(found, version)
		}
	}
	switch len(found) {
	case 0:
		return storage.Object{}, storage.Version{}, false, nil
	case 1:
		v := found[0]
		if v.RuntimeBindingDigest != record.RuntimeBindingDigest || v.Size < 1 {
			return storage.Object{}, storage.Version{}, false, storage.ErrConflict
		}
		return storage.Object{Key: key, RuntimeBindingDigest: v.RuntimeBindingDigest, Size: v.Size, SHA256: v.SHA256}, v, true, nil
	default:
		return storage.Object{}, storage.Version{}, false, storage.ErrAmbiguous
	}
}

func (service *Service) openSegmentObject(ctx context.Context, record Record, key string) (io.ReadCloser, error) {
	object, version, found, err := service.inventorySegmentObject(ctx, record, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, storage.ErrNotFound
	}
	metadata, err := service.store.StatVersion(ctx, object, storage.Metadata{BackendInstanceID: service.store.BackendInstanceID(), Key: key, VersionID: version.VersionID, RuntimeBindingDigest: object.RuntimeBindingDigest, Size: object.Size, SHA256: object.SHA256, ETag: version.ETag, ProviderChecksum: version.ProviderChecksum, ModifiedAt: version.ModifiedAt})
	if err != nil {
		return nil, err
	}
	reader, _, err := service.store.OpenVersion(ctx, object, metadata)
	return reader, err
}

// segmentObjectCount returns how many objects of kind exist from index 0 on.
// Segments and manifests are written in index order and deleted highest
// first, so they always form a prefix. ponytail: linear probe, bounded by
// MaxRecordingSegments; crash recovery and retention cleanup only.
func (service *Service) segmentObjectCount(ctx context.Context, record Record, kind string) (int, error) {
	for n := 0; n <= MaxRecordingSegments; n++ {
		key, err := service.segmentObjectKey(record, kind, n)
		if err != nil {
			return 0, err
		}
		_, _, found, err := service.inventorySegmentObject(ctx, record, key)
		if err != nil {
			return 0, err
		}
		if !found {
			return n, nil
		}
	}
	return 0, fmt.Errorf("%w: more than %d recording %s objects", ErrConflict, MaxRecordingSegments, kind)
}

// latestSegmentManifest reads the highest-numbered manifest.
func (service *Service) latestSegmentManifest(ctx context.Context, record Record) (SegmentManifest, error) {
	count, err := service.segmentObjectCount(ctx, record, "manifest")
	if err != nil {
		return SegmentManifest{}, err
	}
	if count == 0 {
		return SegmentManifest{}, errNoSegments
	}
	seq := count - 1
	key, err := service.segmentObjectKey(record, "manifest", seq)
	if err != nil {
		return SegmentManifest{}, err
	}
	reader, err := service.openSegmentObject(ctx, record, key)
	if err != nil {
		return SegmentManifest{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(reader, segmentManifestMax))
	_ = reader.Close()
	if readErr != nil {
		return SegmentManifest{}, readErr
	}
	var manifest SegmentManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Version != 1 || manifest.Seq != seq || manifest.Segments < 1 || manifest.Segments > MaxRecordingSegments || manifest.Size < 1 || !digestValid(manifest.ChainHead) {
		return SegmentManifest{}, fmt.Errorf("%w: invalid recording manifest %d", ErrConflict, seq)
	}
	return manifest, nil
}

// segmentStream concatenates the manifest's segments and fails unless they
// add up to exactly the committed size.
type segmentStream struct {
	ctx      context.Context
	service  *Service
	record   Record
	manifest SegmentManifest
	next     int
	current  io.ReadCloser
	read     int64
}

func (s *segmentStream) Read(p []byte) (int, error) {
	for {
		if s.current == nil {
			if s.next >= s.manifest.Segments {
				if s.read != s.manifest.Size {
					return 0, fmt.Errorf("%w: recording segments do not match their manifest", ErrConflict)
				}
				return 0, io.EOF
			}
			key, err := s.service.segmentObjectKey(s.record, "segment", s.next)
			if err != nil {
				return 0, err
			}
			reader, err := s.service.openSegmentObject(s.ctx, s.record, key)
			if err != nil {
				return 0, fmt.Errorf("open recording segment %d: %w", s.next, err)
			}
			s.current = reader
		}
		n, err := s.current.Read(p)
		s.read += int64(n)
		if s.read > s.manifest.Size {
			return 0, fmt.Errorf("%w: recording segments exceed their manifest", ErrConflict)
		}
		if errors.Is(err, io.EOF) {
			_ = s.current.Close()
			s.current = nil
			s.next++
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *segmentStream) Close() error {
	if s.current != nil {
		return s.current.Close()
	}
	return nil
}

// VerifyRecordingSegments checks the latest committed manifest: the segments
// must add up to its size, form one valid frame hash chain, and end at its
// chain head.
func (service *Service) VerifyRecordingSegments(ctx context.Context, reservation Record) (SegmentManifest, error) {
	manifest, err := service.latestSegmentManifest(ctx, reservation)
	if err != nil {
		return SegmentManifest{}, err
	}
	if manifest.Size > reservation.MaxBytes {
		return SegmentManifest{}, fmt.Errorf("%w: recording exceeds its size limit", ErrInvalid)
	}
	stream := &segmentStream{ctx: ctx, service: service, record: reservation, manifest: manifest}
	defer func() { _ = stream.Close() }()
	if _, err := validateRecordingFramesWithHead(ctx, stream, manifest.Size, manifest.ChainHead); err != nil {
		return SegmentManifest{}, err
	}
	// Read to EOF so the size check above also rejects trailing bytes.
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return SegmentManifest{}, err
	}
	return manifest, nil
}

// FinalizeRecordingFromSegments publishes the latest committed manifest of a
// pending recording as the regular single recording artifact. The artifact
// controller uses it, with metadata.Complete=false, to recover a stream whose
// controller died. A recording that is no longer pending is only recovered.
func (service *Service) FinalizeRecordingFromSegments(ctx context.Context, reservation Record, metadata RecordingMetadata) (PublicRecord, error) {
	current, err := service.Recording(ctx, reservation.Namespace, reservation.SessionName, reservation.ArtifactID)
	if err != nil {
		return PublicRecord{}, err
	}
	if current.State != StatePending {
		return service.RecoverRecording(ctx, reservation)
	}
	manifest, err := service.latestSegmentManifest(ctx, reservation)
	if err != nil {
		return PublicRecord{}, err
	}
	return service.finalizeFromManifest(ctx, reservation, manifest, metadata)
}

// RecoverAbandonedRecording publishes the committed segments of a pending
// recording as incomplete evidence once its stream expired more than grace
// ago (the stream's own handler can no longer publish). It reports false when
// nothing was due or nothing was committed.
func (service *Service) RecoverAbandonedRecording(ctx context.Context, record Record, grace time.Duration) (PublicRecord, bool, error) {
	if record.Recipe != TerminalRecordingRecipe || record.State != StatePending || record.Recording == nil || service.now().Before(record.Recording.StreamExpiresAt.Add(grace)) {
		return PublicRecord{}, false, nil
	}
	// The caller's copy may be stale: only a still pending recording is
	// recovered here, so a handler's own publication is never reported as one.
	current, err := service.Recording(ctx, record.Namespace, record.SessionName, record.ArtifactID)
	if err != nil {
		return PublicRecord{}, false, err
	}
	if current.ArtifactUID != record.ArtifactUID || current.State != StatePending {
		return PublicRecord{}, false, nil
	}
	recovered := *record.Recording
	recovered.Complete, recovered.FinishedAt = false, recovered.StreamExpiresAt
	published, err := service.FinalizeRecordingFromSegments(ctx, record, recovered)
	if errors.Is(err, errNoSegments) {
		return PublicRecord{}, false, nil
	}
	if err != nil {
		return PublicRecord{}, false, err
	}
	return published, true, nil
}

// finalizeFromManifest streams the manifest's segments into FinalizeRecording,
// which stages them once and checks the frame chain and its head before
// anything is published. Segments are removed afterwards (best effort;
// Cleanup removes leftovers at retention expiry).
func (service *Service) finalizeFromManifest(ctx context.Context, reservation Record, manifest SegmentManifest, metadata RecordingMetadata) (PublicRecord, error) {
	if !digestValid(manifest.ChainHead) {
		return PublicRecord{}, fmt.Errorf("%w: recording manifest has no chain head", ErrConflict)
	}
	if manifest.Size > reservation.MaxBytes {
		return PublicRecord{}, fmt.Errorf("%w: recording exceeds its size limit", ErrInvalid)
	}
	stream := &segmentStream{ctx: ctx, service: service, record: reservation, manifest: manifest}
	defer func() { _ = stream.Close() }()
	published, err := service.finalizeRecording(ctx, reservation, stream, metadata, manifest.ChainHead)
	if err != nil {
		return PublicRecord{}, err
	}
	// Known counts: no rediscovery on the stream's finalize path. One more
	// segment may exist: written, but its manifest failed.
	_ = service.deleteSegmentObjects(ctx, reservation, "segment", manifest.Segments+1)
	_ = service.deleteSegmentObjects(ctx, reservation, "manifest", manifest.Seq+1)
	return published, nil
}

// deleteRecordingSegments removes segments and then manifests, highest index
// first, so a partial run stays discoverable. It does not parse manifests: a
// corrupt one, or a segment written before its first manifest, is removed too.
func (service *Service) deleteRecordingSegments(ctx context.Context, record Record) error {
	if _, ok := service.store.(storage.KeyInventory); !ok || record.ArtifactUID == "" {
		return nil
	}
	for _, kind := range []string{"segment", "manifest"} {
		count, err := service.segmentObjectCount(ctx, record, kind)
		if err != nil {
			return err
		}
		if err := service.deleteSegmentObjects(ctx, record, kind, count); err != nil {
			return err
		}
	}
	return nil
}

// deleteSegmentObjects removes objects count-1..0 of kind; missing ones are skipped.
func (service *Service) deleteSegmentObjects(ctx context.Context, record Record, kind string, count int) error {
	for i := count - 1; i >= 0; i-- {
		if err := service.deleteSegmentObject(ctx, record, kind, i); err != nil {
			return err
		}
	}
	return nil
}

func (service *Service) deleteSegmentObject(ctx context.Context, record Record, kind string, n int) error {
	key, err := service.segmentObjectKey(record, kind, n)
	if err != nil {
		return err
	}
	object, version, found, err := service.inventorySegmentObject(ctx, record, key)
	if err != nil || !found {
		return err
	}
	return service.store.DeleteVersion(ctx, object, version)
}
