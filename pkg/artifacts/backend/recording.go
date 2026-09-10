// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

// ReserveRecording is internal to the authenticated terminal relay. The
// callback validates its actual Pod lease, not the separate cluster lease.
func (service *Service) ReserveRecording(ctx context.Context, record Record, authorize func(context.Context) error) (Record, error) {
	if !validRecording(record.Recording) || record.MaxBytes > MaximumRecordingBytes {
		return Record{}, ErrForbidden
	}
	record.Recipe = TerminalRecordingRecipe
	record.RecipeVersion = 1
	// Terminal evidence preserves authorized stream bytes; this version identifies
	// its framing/metadata policy, not collector credential redaction.
	record.Expected.RedactionProfile = TerminalRecordingRecipe
	record.Expected.RedactionVersion = 1
	copyMetadata := *record.Recording
	copyMetadata.StartedAt = copyMetadata.StartedAt.UTC().Truncate(time.Second)
	copyMetadata.StreamExpiresAt = copyMetadata.StreamExpiresAt.UTC().Truncate(time.Second)
	copyMetadata.FinishedAt = time.Time{}
	copyMetadata.Complete = false
	copyMetadata.Frames = 0
	record.Recording = &copyMetadata
	if !validRecording(record.Recording) {
		return Record{}, ErrForbidden
	}
	return service.reserve(ctx, record, authorize)
}
func validRecording(m *RecordingMetadata) bool {
	return m != nil && m.FormatVersion == 1 && m.PodNamespace != "" && m.PodName != "" && m.PodUID != "" && m.LeaseUID != "" && m.LeaseEpoch != "" && m.Generation != "" && (m.Operation == "exec" || m.Operation == "attach") && !m.StartedAt.IsZero() && m.StreamExpiresAt.After(m.StartedAt)
}
func recordingIdentity(m *RecordingMetadata) *RecordingMetadata {
	if m == nil {
		return nil
	}
	identity := *m
	identity.FinishedAt = time.Time{}
	identity.Complete = false
	identity.Frames = 0
	identity.StartedAt = identity.StartedAt.UTC().Truncate(time.Second)
	identity.StreamExpiresAt = identity.StreamExpiresAt.UTC().Truncate(time.Second)
	return &identity
}
func sameRecording(a, b Record) bool {
	return a.ArtifactUID != "" && a.ArtifactUID == b.ArtifactUID && a.ArtifactID == b.ArtifactID && a.Namespace == b.Namespace && a.SessionName == b.SessionName && a.SessionUID == b.SessionUID && a.TargetClusterUID == b.TargetClusterUID && a.TargetIdentityDigest == b.TargetIdentityDigest && a.PlanDigest == b.PlanDigest && a.RuntimeBindingDigest == b.RuntimeBindingDigest && a.OperationEpoch == b.OperationEpoch && a.ExpiresAt.Equal(b.ExpiresAt) && reflect.DeepEqual(recordingIdentity(a.Recording), recordingIdentity(b.Recording))
}

func (service *Service) Recording(ctx context.Context, namespace, sessionName, artifactID string) (Record, error) {
	record, err := service.repository.Get(ctx, namespace, sessionName, artifactID)
	if err != nil {
		return Record{}, err
	}
	if record.Recipe != TerminalRecordingRecipe || !validRecording(record.Recording) {
		return Record{}, ErrForbidden
	}
	return record, nil
}
func (service *Service) Recordings(ctx context.Context, namespace, sessionName, sessionUID string, authorize func(context.Context) error) ([]PublicRecord, error) {
	if authorize == nil || sessionUID == "" {
		return nil, ErrForbidden
	}
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	records, err := service.repository.ListBySession(ctx, namespace, sessionName, sessionUID)
	if err != nil {
		return nil, err
	}
	if err := authorize(ctx); err != nil {
		return nil, err
	}
	result := make([]PublicRecord, 0, len(records))
	for _, r := range records {
		if r.Namespace == namespace && r.SessionName == sessionName && r.SessionUID == sessionUID && r.Recipe == TerminalRecordingRecipe && r.State == StateAvailable && service.now().Before(r.ExpiresAt) {
			result = append(result, service.Public(r))
		}
	}
	return result, nil
}

// FinalizeRecording retains previously admitted evidence after access expiry.
// No public upload route calls this method. Exact reservation identity and the
// retention deadline, rather than current access permission, fence publication.
func (service *Service) FinalizeRecording(ctx context.Context, reservation Record, source io.Reader, metadata RecordingMetadata) (PublicRecord, error) {
	current, err := service.Recording(ctx, reservation.Namespace, reservation.SessionName, reservation.ArtifactID)
	if err != nil {
		return PublicRecord{}, err
	}
	if !sameRecording(current, reservation) || !reflect.DeepEqual(recordingIdentity(current.Recording), recordingIdentity(&metadata)) {
		return PublicRecord{}, ErrForbidden
	}
	if !service.now().Before(current.ExpiresAt) {
		return PublicRecord{}, ErrExpired
	}
	if current.State != StatePending {
		return service.RecoverRecording(ctx, reservation)
	}
	staged, size, digest, err := service.stage(ctx, source, current.MaxBytes)
	if err != nil {
		return PublicRecord{}, err
	}
	defer func() { _ = staged.Close(); _ = os.Remove(staged.Name()) }()
	frames, err := validateRecordingFrames(ctx, staged, size)
	if err != nil {
		return PublicRecord{}, err
	}
	if metadata.FinishedAt.IsZero() || metadata.FinishedAt.Before(metadata.StartedAt) || metadata.FinishedAt.After(service.now().Add(time.Second)) {
		return PublicRecord{}, ErrForbidden
	}
	metadata.Frames = frames
	metadata.FinishedAt = metadata.FinishedAt.UTC().Truncate(time.Second)
	metadata.StartedAt = metadata.StartedAt.UTC().Truncate(time.Second)
	metadata.StreamExpiresAt = metadata.StreamExpiresAt.UTC().Truncate(time.Second)
	current.Recording = &metadata
	current.Size = size
	current.SHA256 = digest
	current.State = StateUploading
	current.Generation++
	if err := service.persist(ctx, &current, current.Generation-1); err != nil {
		return PublicRecord{}, err
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return PublicRecord{}, err
	}
	key, err := artifactStorageKey(current)
	if err != nil {
		return PublicRecord{}, err
	}
	if !service.now().Before(current.ExpiresAt) {
		return PublicRecord{}, ErrExpired
	}
	_, err = service.store.PutIfAbsent(ctx, storage.Object{Key: key, RuntimeBindingDigest: current.RuntimeBindingDigest, Size: size, SHA256: digest}, staged)
	if err != nil && !errors.Is(err, storage.ErrAlreadyExists) {
		service.restoreUnknown(ctx, current)
		return PublicRecord{}, err
	}
	return service.RecoverRecording(ctx, current)
}

func (service *Service) RecoverRecording(ctx context.Context, reservation Record) (PublicRecord, error) {
	current, err := service.Recording(ctx, reservation.Namespace, reservation.SessionName, reservation.ArtifactID)
	if err != nil {
		return PublicRecord{}, err
	}
	if !sameRecording(current, reservation) || current.CleanupAmbiguous {
		return PublicRecord{}, ErrForbidden
	}
	if !service.now().Before(current.ExpiresAt) {
		return PublicRecord{}, ErrExpired
	}
	if current.State == StateAvailable {
		return service.Public(current), nil
	}
	if current.State != StateUploading && current.State != StateUnknown {
		return PublicRecord{}, ErrConflict
	}
	if current.Size < 42 || !digestValid(current.SHA256) {
		return PublicRecord{}, ErrConflict
	}
	metadata, err := service.resolveMetadata(ctx, current)
	if err != nil {
		return PublicRecord{}, err
	}
	// Inventory may take time; reject retention expiry and lifecycle changes.
	latest, err := service.Recording(ctx, current.Namespace, current.SessionName, current.ArtifactID)
	if err != nil {
		return PublicRecord{}, err
	}
	if !sameRecording(current, latest) || latest.Generation != current.Generation || latest.State != current.State || !service.now().Before(latest.ExpiresAt) {
		return PublicRecord{}, ErrConflict
	}
	current.Metadata = metadata
	current.State = StateAvailable
	current.Generation++
	if err := service.persist(ctx, &current, current.Generation-1); err != nil {
		return PublicRecord{}, err
	}
	return service.Public(current), nil
}

func (service *Service) DownloadRecording(ctx context.Context, reservation Record, authorize func(context.Context) error) (io.ReadCloser, PublicRecord, error) {
	guard := func() error {
		if authorize == nil {
			return ErrForbidden
		}
		if err := authorize(ctx); err != nil {
			return err
		}
		current, err := service.Recording(ctx, reservation.Namespace, reservation.SessionName, reservation.ArtifactID)
		if err != nil {
			return err
		}
		if !sameRecording(current, reservation) || current.State != StateAvailable {
			return ErrForbidden
		}
		if !service.now().Before(current.ExpiresAt) {
			return ErrExpired
		}
		return nil
	}
	if err := guard(); err != nil {
		return nil, PublicRecord{}, err
	}
	current, err := service.Recording(ctx, reservation.Namespace, reservation.SessionName, reservation.ArtifactID)
	if err != nil {
		return nil, PublicRecord{}, err
	}
	metadata, err := service.resolveMetadata(ctx, current)
	if err != nil {
		return nil, PublicRecord{}, err
	}
	key, err := artifactStorageKey(current)
	if err != nil {
		return nil, PublicRecord{}, err
	}
	if err := guard(); err != nil {
		return nil, PublicRecord{}, err
	}
	reader, opened, err := service.store.OpenVersion(ctx, storage.Object{Key: key, RuntimeBindingDigest: current.RuntimeBindingDigest, Size: current.Size, SHA256: current.SHA256}, metadata)
	if err != nil {
		return nil, PublicRecord{}, err
	}
	if opened.BackendInstanceID != metadata.BackendInstanceID || opened.Key != metadata.Key || opened.VersionID != metadata.VersionID || opened.Size != metadata.Size || opened.SHA256 != metadata.SHA256 || opened.RuntimeBindingDigest != metadata.RuntimeBindingDigest {
		_ = reader.Close()
		return nil, PublicRecord{}, ErrConflict
	}
	if err := guard(); err != nil {
		_ = reader.Close()
		return nil, PublicRecord{}, err
	}
	return &recordingReader{ReadCloser: reader, guard: guard}, service.Public(current), nil
}

type recordingReader struct {
	io.ReadCloser
	guard func() error
}

func (r *recordingReader) Read(p []byte) (int, error) {
	if err := r.guard(); err != nil {
		return 0, err
	}
	n, err := r.ReadCloser.Read(p)
	if check := r.guard(); check != nil {
		clear(p[:n])
		return 0, check
	}
	return n, err
}

func validateRecordingFrames(ctx context.Context, source io.Reader, size int64) (int64, error) {
	var previous [32]byte
	var frames int64
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var header [42]byte
		if _, err := io.ReadFull(source, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint64(header[2:10])
		if length > math.MaxInt64 || remaining < 42 {
			return 0, errors.New("invalid terminal recording frame length")
		}
		payloadLength := int64(length)
		if header[0] != 1 || (header[1] != 'i' && header[1] != 'o') || string(header[10:]) != string(previous[:]) || payloadLength > remaining-42 {
			return 0, errors.New("invalid terminal recording frame")
		}
		digest := sha256.New()
		_, _ = digest.Write(header[:])
		if _, err := io.CopyN(digest, source, payloadLength); err != nil {
			return 0, fmt.Errorf("read terminal frame: %w", err)
		}
		copy(previous[:], digest.Sum(nil))
		remaining -= 42 + payloadLength
		frames++
	}
	if frames == 0 {
		return 0, errors.New("terminal recording is empty")
	}
	return frames, nil
}
