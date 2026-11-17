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
	"hash"
	"io"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

// Incremental terminal evidence. The artifact store is create-only, so a
// running stream persists frame-aligned segments as separate objects and,
// after every segment, a new numbered manifest object that lists all segments
// so far plus the SHA-256 chain head. The latest manifest is the commit
// point: after a controller crash everything it lists is readable and
// verifiable; bytes after it are unproven and ignored.

const (
	// MaxRecordingSegments bounds object count per recording.
	MaxRecordingSegments = 4096
	segmentManifestMax   = 1 << 20
)

// SegmentRef commits to one segment object.
type SegmentRef struct {
	Index  int    `json:"index"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// SegmentManifest is the committed prefix of a recording.
type SegmentManifest struct {
	Version  int          `json:"version"`
	Seq      int          `json:"seq"`
	Segments []SegmentRef `json:"segments"`
	// ChainHead is the hex SHA-256 of the last frame in the last segment.
	ChainHead string `json:"chainHead"`
	// Final is set once the stream ended and the recorder flushed everything.
	Final bool `json:"final"`
}

func (service *Service) segmentObjectKey(record Record, kind string, n int) (string, error) {
	if record.ArtifactUID == "" {
		return "", errors.New("artifact UID is required for storage key")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("breakglass-artifact-v1:%s:%s:%d", kind, record.ArtifactUID, n)))
	return hex.EncodeToString(sum[:]), nil
}

func (service *Service) putSegmentObject(ctx context.Context, record Record, key string, data []byte) error {
	sum := sha256.Sum256(data)
	_, err := service.store.PutIfAbsent(ctx, storage.Object{Key: key, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}, bytes.NewReader(data))
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

// Append persists data (frame-aligned, may be empty only for a final
// manifest-only commit) and then a manifest committing to it. A failure leaves
// the previous manifest as the committed prefix.
func (w *SegmentWriter) Append(ctx context.Context, data []byte, chainHead [32]byte, final bool) error {
	next := w.manifest
	next.Segments = append([]SegmentRef(nil), w.manifest.Segments...)
	next.Seq++
	next.Final = final
	next.ChainHead = hex.EncodeToString(chainHead[:])
	if len(data) > 0 {
		if len(next.Segments) >= MaxRecordingSegments {
			return fmt.Errorf("%w: recording exceeds %d segments", ErrInvalid, MaxRecordingSegments)
		}
		index := len(next.Segments)
		key, err := w.service.segmentObjectKey(w.record, "segment", index)
		if err != nil {
			return err
		}
		if err := w.service.putSegmentObject(ctx, w.record, key, data); err != nil {
			return fmt.Errorf("persist recording segment %d: %w", index, err)
		}
		sum := sha256.Sum256(data)
		next.Segments = append(next.Segments, SegmentRef{Index: index, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
	}
	if len(next.Segments) == 0 {
		return fmt.Errorf("%w: recording manifest without segments", ErrInvalid)
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return err
	}
	key, err := w.service.segmentObjectKey(w.record, "manifest", next.Seq)
	if err != nil {
		return err
	}
	if err := w.service.putSegmentObject(ctx, w.record, key, encoded); err != nil {
		return fmt.Errorf("persist recording manifest %d: %w", next.Seq, err)
	}
	w.manifest = next
	return nil
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

func (service *Service) openSegmentObject(ctx context.Context, record Record, key string) (io.ReadCloser, storage.Version, error) {
	object, version, found, err := service.inventorySegmentObject(ctx, record, key)
	if err != nil {
		return nil, storage.Version{}, err
	}
	if !found {
		return nil, storage.Version{}, storage.ErrNotFound
	}
	metadata, err := service.store.StatVersion(ctx, object, storage.Metadata{BackendInstanceID: service.store.BackendInstanceID(), Key: key, VersionID: version.VersionID, RuntimeBindingDigest: object.RuntimeBindingDigest, Size: object.Size, SHA256: object.SHA256, ETag: version.ETag, ProviderChecksum: version.ProviderChecksum, ModifiedAt: version.ModifiedAt})
	if err != nil {
		return nil, storage.Version{}, err
	}
	reader, _, err := service.store.OpenVersion(ctx, object, metadata)
	return reader, version, err
}

// latestSegmentManifest returns the highest-numbered manifest. Manifests are
// probed upward from 0; ponytail: linear probe, bounded by MaxRecordingSegments*2.
func (service *Service) latestSegmentManifest(ctx context.Context, record Record) (SegmentManifest, error) {
	var latest *SegmentManifest
	for seq := 0; seq < 2*MaxRecordingSegments; seq++ {
		key, err := service.segmentObjectKey(record, "manifest", seq)
		if err != nil {
			return SegmentManifest{}, err
		}
		reader, _, err := service.openSegmentObject(ctx, record, key)
		if errors.Is(err, storage.ErrNotFound) {
			break
		}
		if err != nil {
			return SegmentManifest{}, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(reader, segmentManifestMax))
		_ = reader.Close()
		if readErr != nil {
			return SegmentManifest{}, readErr
		}
		var manifest SegmentManifest
		if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Version != 1 || manifest.Seq != seq || len(manifest.Segments) == 0 {
			return SegmentManifest{}, fmt.Errorf("%w: invalid recording manifest %d", ErrConflict, seq)
		}
		latest = &manifest
	}
	if latest == nil {
		return SegmentManifest{}, storage.ErrNotFound
	}
	return *latest, nil
}

// segmentStream concatenates the manifest's segments and fails at the end of
// each segment whose size or SHA-256 differs from the manifest.
type segmentStream struct {
	ctx      context.Context
	service  *Service
	record   Record
	segments []SegmentRef
	next     int
	current  io.ReadCloser
	hash     hash.Hash
	read     int64
}

func (s *segmentStream) Read(p []byte) (int, error) {
	for {
		if s.current == nil {
			if s.next >= len(s.segments) {
				return 0, io.EOF
			}
			ref := s.segments[s.next]
			key, err := s.service.segmentObjectKey(s.record, "segment", ref.Index)
			if err != nil {
				return 0, err
			}
			reader, _, err := s.service.openSegmentObject(s.ctx, s.record, key)
			if err != nil {
				return 0, fmt.Errorf("open recording segment %d: %w", ref.Index, err)
			}
			s.current, s.hash, s.read = reader, sha256.New(), 0
		}
		n, err := s.current.Read(p)
		_, _ = s.hash.Write(p[:n])
		s.read += int64(n)
		if errors.Is(err, io.EOF) {
			ref := s.segments[s.next]
			_ = s.current.Close()
			s.current = nil
			s.next++
			if s.read != ref.Size || hex.EncodeToString(s.hash.Sum(nil)) != ref.SHA256 {
				return n, fmt.Errorf("%w: recording segment %d is truncated or modified", ErrConflict, ref.Index)
			}
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

// VerifyRecordingSegments checks the latest committed manifest: every segment
// must match its committed size and digest, the frames must form one valid
// hash chain, and the chain must end at the manifest's chain head.
func (service *Service) VerifyRecordingSegments(ctx context.Context, reservation Record) (SegmentManifest, int64, error) {
	manifest, err := service.latestSegmentManifest(ctx, reservation)
	if err != nil {
		return SegmentManifest{}, 0, err
	}
	var size int64
	for i, ref := range manifest.Segments {
		if ref.Index != i || ref.Size < 1 {
			return SegmentManifest{}, 0, fmt.Errorf("%w: invalid recording manifest", ErrConflict)
		}
		size += ref.Size
	}
	if size > reservation.MaxBytes {
		return SegmentManifest{}, 0, fmt.Errorf("%w: recording exceeds its size limit", ErrInvalid)
	}
	stream := &segmentStream{ctx: ctx, service: service, record: reservation, segments: manifest.Segments}
	defer func() { _ = stream.Close() }()
	_, head, err := validateRecordingFramesHead(ctx, stream, size)
	if err != nil {
		return SegmentManifest{}, 0, err
	}
	if hex.EncodeToString(head[:]) != manifest.ChainHead {
		return SegmentManifest{}, 0, fmt.Errorf("%w: recording chain head does not match its manifest", ErrConflict)
	}
	return manifest, size, nil
}

// FinalizeRecordingFromSegments verifies the committed segments and publishes
// them as the regular single recording artifact. It is used at the end of a
// stream and, with metadata.Complete=false, to recover a stream whose
// controller died. Segments are removed afterwards (best effort; Cleanup
// removes leftovers at retention expiry).
func (service *Service) FinalizeRecordingFromSegments(ctx context.Context, reservation Record, metadata RecordingMetadata) (PublicRecord, error) {
	if _, _, err := service.VerifyRecordingSegments(ctx, reservation); err != nil {
		return PublicRecord{}, err
	}
	manifest, err := service.latestSegmentManifest(ctx, reservation)
	if err != nil {
		return PublicRecord{}, err
	}
	stream := &segmentStream{ctx: ctx, service: service, record: reservation, segments: manifest.Segments}
	defer func() { _ = stream.Close() }()
	published, err := service.FinalizeRecording(ctx, reservation, stream, metadata)
	if err != nil {
		return PublicRecord{}, err
	}
	_ = service.deleteRecordingSegments(ctx, reservation)
	return published, nil
}

// deleteRecordingSegments removes segments (highest first) and then manifests
// (highest first), so a partial run stays discoverable from the manifests.
func (service *Service) deleteRecordingSegments(ctx context.Context, record Record) error {
	if _, ok := service.store.(storage.KeyInventory); !ok || record.ArtifactUID == "" {
		return nil
	}
	manifest, err := service.latestSegmentManifest(ctx, record)
	if errors.Is(err, storage.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// A segment written just before a crash has no manifest yet: one extra index.
	for i := len(manifest.Segments); i >= 0; i-- {
		if err := service.deleteSegmentObject(ctx, record, "segment", i); err != nil {
			return err
		}
	}
	for seq := manifest.Seq; seq >= 0; seq-- {
		if err := service.deleteSegmentObject(ctx, record, "manifest", seq); err != nil {
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
