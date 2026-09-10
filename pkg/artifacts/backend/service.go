// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package backend implements the provider-independent diagnostic artifact
// lifecycle. Kubernetes persistence and session authorization are injected so
// the service never has to expose provider configuration to an API caller.
package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
)

var (
	ErrForbidden = errors.New("artifact access is forbidden")
	ErrConflict  = errors.New("artifact lifecycle conflict")
	ErrExpired   = errors.New("artifact access has expired")
	ErrReplay    = errors.New("artifact upload has already been consumed")
)

// State is monotonic. Unknown means the provider result is ambiguous and may
// only be resolved by inventory; it is never treated as available.
type State string

const (
	StatePending   State = "Pending"
	StateUploading State = "Uploading"
	StateAvailable State = "Available"
	StateDeleting  State = "Deleting"
	StateDeleted   State = "Deleted"
	StateExpired   State = "Expired"
	StateRevoked   State = "Revoked"
	StateUnknown   State = "Unknown"
)

// Record is the storage-neutral durable representation used by Repository.
// Provider keys and credentials are deliberately absent; the backend derives
// the object key from ID and the configured store instance.
type Record struct {
	Namespace            string
	SessionName          string
	SessionUID           string
	ArtifactID           string
	TargetClusterUID     string
	TargetIdentityDigest string
	RuntimeBindingDigest string
	PlanDigest           string
	Recipe               string
	RecipeVersion        int
	Expected             archive.Expected
	ExpiresAt            time.Time
	MaxBytes             int64
	OperationEpoch       uint64
	UploadJTI            string
	UploadJTIHash        string
	State                State
	Generation           int64
	Size                 int64
	SHA256               string
	Metadata             storage.Metadata
	CleanupAmbiguous     bool
	ResourceVersion      string
}

// PublicRecord is safe to return to an API client. It contains no provider
// URL, bucket, object key, version ID, credential reference, or token.
type PublicRecord struct {
	ArtifactID    string    `json:"artifactID"`
	Recipe        string    `json:"recipe"`
	RecipeVersion int       `json:"recipeVersion"`
	State         State     `json:"state"`
	Size          int64     `json:"size,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// Repository is a durable CAS store. Update must fail with ErrConflict (or a
// wrapped equivalent) when expectedGeneration is stale.
type Repository interface {
	Get(context.Context, string, string, string) (Record, error)
	Update(context.Context, Record, int64) error
	ListBySession(context.Context, string, string, string) ([]Record, error)
}

// SessionBinding is checked against the live session on every operation.
type SessionBinding struct {
	Namespace            string
	Name                 string
	UID                  string
	TargetClusterUID     string
	TargetIdentityDigest string
	OperationEpoch       uint64
}

// SessionAuthorizer must read the live session/target state and fail closed
// for expired, revoked, deleted, or UID-mismatched sessions.
type SessionAuthorizer interface {
	AuthorizeArtifact(context.Context, SessionBinding) error
}

// Service validates the archive and coordinates durable state with one
// configured storage backend.
type Service struct {
	repository Repository
	store      storage.Store
	authorizer SessionAuthorizer
	tokens     *token.Keyring
	stagingDir string
	now        func() time.Time
}

type Config struct {
	Repository Repository
	Store      storage.Store
	Authorizer SessionAuthorizer
	Tokens     *token.Keyring
	StagingDir string
	Now        func() time.Time
}

func New(config Config) (*Service, error) {
	if config.Repository == nil || config.Store == nil || config.Authorizer == nil || config.Tokens == nil {
		return nil, errors.New("artifact backend repository, store, authorizer, and token keyring are required")
	}
	if config.StagingDir == "" {
		return nil, errors.New("artifact backend staging directory is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{repository: config.Repository, store: config.Store, authorizer: config.Authorizer, tokens: config.Tokens, stagingDir: config.StagingDir, now: config.Now}, nil
}

func (service *Service) Public(record Record) PublicRecord {
	return PublicRecord{ArtifactID: record.ArtifactID, Recipe: record.Recipe, RecipeVersion: record.RecipeVersion, State: record.State, Size: record.Size, SHA256: record.SHA256, ExpiresAt: record.ExpiresAt.UTC()}
}

// List returns metadata only after the live session binding has been checked.
// Terminal records remain visible as audit evidence, while provider details
// stay inside the storage layer.
func (service *Service) List(ctx context.Context, namespace, sessionName string, binding SessionBinding) ([]PublicRecord, error) {
	if binding.Namespace != namespace || binding.Name != sessionName {
		return nil, ErrForbidden
	}
	if err := service.authorizer.AuthorizeArtifact(ctx, binding); err != nil {
		return nil, err
	}
	records, err := service.repository.ListBySession(ctx, namespace, sessionName, binding.UID)
	if err != nil {
		return nil, ErrForbidden
	}
	result := make([]PublicRecord, 0, len(records))
	for _, record := range records {
		if record.SessionUID != binding.UID || record.TargetClusterUID != binding.TargetClusterUID || record.TargetIdentityDigest != binding.TargetIdentityDigest || record.OperationEpoch != binding.OperationEpoch {
			continue
		}
		result = append(result, service.Public(record))
	}
	return result, nil
}

// Upload verifies the one-time token, live binding, archive contract, and
// digest before publishing one create-only object.
func (service *Service) Upload(ctx context.Context, encodedToken string, route string, source io.Reader) (PublicRecord, error) {
	if ctx == nil || source == nil {
		return PublicRecord{}, ErrForbidden
	}
	claims, err := service.tokens.Verify(encodedToken, service.now().UTC())
	if err != nil || claims.Route != route {
		return PublicRecord{}, ErrForbidden
	}
	record, err := service.repository.Get(ctx, claims.SessionNamespace, claims.SessionName, claims.ArtifactID)
	if err != nil {
		return PublicRecord{}, ErrForbidden
	}
	if err := service.authorize(ctx, record, claims.SessionUID, claims.TargetIdentityDigest, claims.OperationEpoch); err != nil {
		return PublicRecord{}, err
	}
	if record.UploadJTI != claims.JTI && record.UploadJTIHash != jtiHash(claims.JTI) {
		return PublicRecord{}, ErrForbidden
	}
	if record.State == StateAvailable {
		return PublicRecord{}, ErrReplay
	}
	if record.State != StatePending {
		return PublicRecord{}, ErrConflict
	}
	if record.ExpiresAt.IsZero() || !service.now().Before(record.ExpiresAt) {
		return PublicRecord{}, ErrExpired
	}
	record.State = StateUploading
	record.Generation++
	if err := service.repository.Update(ctx, record, record.Generation-1); err != nil {
		return PublicRecord{}, err
	}

	staged, size, digest, err := service.stage(ctx, source, record.MaxBytes)
	if err != nil {
		service.restorePending(ctx, record)
		return PublicRecord{}, err
	}
	defer func() { _ = staged.Close(); _ = os.Remove(staged.Name()) }()
	validation, err := archive.Validate(ctx, staged, size, record.Expected, archive.Limits{MaxCompressedBytes: record.MaxBytes})
	if err != nil {
		service.restorePending(ctx, record)
		return PublicRecord{}, fmt.Errorf("validate diagnostic artifact: %w", err)
	}
	if validation.CompressedSHA256 != digest {
		service.restorePending(ctx, record)
		return PublicRecord{}, errors.New("validated artifact digest changed during staging")
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		service.restoreUnknown(ctx, record)
		return PublicRecord{}, fmt.Errorf("rewind staged diagnostic artifact: %w", err)
	}
	metadata, err := service.store.PutIfAbsent(ctx, storage.Object{Key: record.ArtifactID, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: size, SHA256: digest}, staged)
	if err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			metadata, err = service.reconcileObject(ctx, record, size, digest)
		}
		if err != nil {
			service.restoreUnknown(ctx, record)
			return PublicRecord{}, err
		}
	}
	record.State = StateAvailable
	record.Generation++
	record.Size = size
	record.SHA256 = digest
	record.Metadata = metadata
	if err := service.repository.Update(ctx, record, record.Generation-1); err != nil {
		return PublicRecord{}, fmt.Errorf("persist available diagnostic artifact: %w", err)
	}
	return service.Public(record), nil
}

func jtiHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// Download authorizes against the live session before resolving an exact
// provider version and returning bytes.
func (service *Service) Download(ctx context.Context, namespace, sessionName, artifactID string, binding SessionBinding) (io.ReadCloser, PublicRecord, error) {
	record, err := service.repository.Get(ctx, namespace, sessionName, artifactID)
	if err != nil {
		return nil, PublicRecord{}, ErrForbidden
	}
	if record.Namespace != namespace || record.SessionName != sessionName || record.ArtifactID != artifactID {
		return nil, PublicRecord{}, ErrForbidden
	}
	if record.TargetClusterUID != "" && binding.TargetClusterUID != record.TargetClusterUID {
		return nil, PublicRecord{}, ErrForbidden
	}
	if err := service.authorize(ctx, record, binding.UID, binding.TargetIdentityDigest, binding.OperationEpoch); err != nil {
		return nil, PublicRecord{}, err
	}
	if record.State != StateAvailable || record.ExpiresAt.IsZero() || !service.now().Before(record.ExpiresAt) {
		return nil, PublicRecord{}, ErrExpired
	}
	metadata, err := service.resolveMetadata(ctx, record)
	if err != nil {
		return nil, PublicRecord{}, err
	}
	reader, _, err := service.store.OpenVersion(ctx, storage.Object{Key: record.ArtifactID, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: record.Size, SHA256: record.SHA256}, metadata)
	if err != nil {
		return nil, PublicRecord{}, err
	}
	return reader, service.Public(record), nil
}

// Cleanup marks a record for deletion and removes only versions whose stored
// identity matches the immutable record. Absence is treated as complete only
// after two independent inventories.
func (service *Service) Cleanup(ctx context.Context, record Record, terminal State) error {
	if terminal != StateExpired && terminal != StateRevoked && terminal != StateDeleted {
		return errors.New("artifact cleanup terminal state is invalid")
	}
	if record.State == StateDeleted {
		return nil
	}
	if record.State != StateDeleting {
		record.State = StateDeleting
		record.Generation++
		if err := service.repository.Update(ctx, record, record.Generation-1); err != nil {
			return err
		}
	}
	object := storage.Object{Key: record.ArtifactID, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: record.Size, SHA256: record.SHA256}
	if record.Size < 1 || record.SHA256 == "" {
		record.State = terminal
		record.Generation++
		return service.repository.Update(ctx, record, record.Generation-1)
	}
	for observation := 0; observation < 2; observation++ {
		versions, err := service.store.Inventory(ctx, object)
		if err != nil {
			record.State = StateUnknown
			record.CleanupAmbiguous = true
			record.Generation++
			_ = service.repository.Update(ctx, record, record.Generation-1)
			return err
		}
		found := false
		for _, version := range versions {
			if version.DeleteMarker {
				continue
			}
			if version.RuntimeBindingDigest != object.RuntimeBindingDigest || version.Size != object.Size || version.SHA256 != object.SHA256 {
				record.State = StateUnknown
				record.CleanupAmbiguous = true
				record.Generation++
				_ = service.repository.Update(ctx, record, record.Generation-1)
				return ErrConflict
			}
			found = true
			if err := service.store.DeleteVersion(ctx, object, version); err != nil {
				return err
			}
		}
		if found {
			continue
		}
	}
	record.State = terminal
	record.Generation++
	record.CleanupAmbiguous = false
	return service.repository.Update(ctx, record, record.Generation-1)
}

func (service *Service) authorize(ctx context.Context, record Record, sessionUID, targetDigest string, epoch uint64) error {
	if record.SessionUID != sessionUID || record.TargetIdentityDigest != targetDigest || record.OperationEpoch != epoch {
		return ErrForbidden
	}
	return service.authorizer.AuthorizeArtifact(ctx, SessionBinding{Namespace: record.Namespace, Name: record.SessionName, UID: sessionUID, TargetClusterUID: record.TargetClusterUID, TargetIdentityDigest: targetDigest, OperationEpoch: epoch})
}

func (service *Service) restorePending(ctx context.Context, record Record) {
	record.State = StatePending
	record.Generation++
	_ = service.repository.Update(ctx, record, record.Generation-1)
}

func (service *Service) restoreUnknown(ctx context.Context, record Record) {
	record.State = StateUnknown
	record.Generation++
	_ = service.repository.Update(ctx, record, record.Generation-1)
}

func (service *Service) stage(ctx context.Context, source io.Reader, maxBytes int64) (*os.File, int64, string, error) {
	if maxBytes < 1 || maxBytes > archive.MaxCollectorArchiveBytes {
		return nil, 0, "", errors.New("artifact maximum size is outside the bounded contract")
	}
	file, err := os.CreateTemp(service.stagingDir, "breakglass-artifact-")
	if err != nil {
		return nil, 0, "", fmt.Errorf("create diagnostic artifact staging file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()
	hash := sha256.New()
	read, err := copyContext(ctx, io.MultiWriter(file, hash), io.LimitReader(source, maxBytes+1))
	if err != nil {
		return nil, 0, "", fmt.Errorf("stage diagnostic artifact: %w", err)
	}
	if read < 1 || read > maxBytes {
		return nil, 0, "", errors.New("diagnostic artifact exceeds its configured size limit")
	}
	if err := file.Sync(); err != nil {
		return nil, 0, "", fmt.Errorf("sync diagnostic artifact staging file: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, 0, "", fmt.Errorf("rewind diagnostic artifact staging file: %w", err)
	}
	cleanup = false
	return file, read, hex.EncodeToString(hash.Sum(nil)), nil
}

func (service *Service) resolveMetadata(ctx context.Context, record Record) (storage.Metadata, error) {
	if record.Metadata.VersionID != "" {
		object := storage.Object{Key: record.ArtifactID, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: record.Size, SHA256: record.SHA256}
		metadata, err := service.store.StatVersion(ctx, object, record.Metadata)
		if err == nil {
			return metadata, nil
		}
	}
	object := storage.Object{Key: record.ArtifactID, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: record.Size, SHA256: record.SHA256}
	versions, err := service.store.Inventory(ctx, object)
	if err != nil {
		return storage.Metadata{}, err
	}
	for _, version := range versions {
		if version.DeleteMarker || version.RuntimeBindingDigest != object.RuntimeBindingDigest || version.Size != object.Size || version.SHA256 != object.SHA256 {
			continue
		}
		metadata, statErr := service.store.StatVersion(ctx, object, storage.Metadata{BackendInstanceID: service.store.BackendInstanceID(), Key: object.Key, VersionID: version.VersionID, RuntimeBindingDigest: object.RuntimeBindingDigest, Size: object.Size, SHA256: object.SHA256, ETag: version.ETag, ProviderChecksum: version.ProviderChecksum, ModifiedAt: version.ModifiedAt})
		if statErr == nil {
			return metadata, nil
		}
	}
	return storage.Metadata{}, storage.ErrNotFound
}

func (service *Service) reconcileObject(ctx context.Context, record Record, size int64, digest string) (storage.Metadata, error) {
	return service.resolveMetadata(ctx, Record{ArtifactID: record.ArtifactID, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: size, SHA256: digest})
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	if ctx == nil {
		return 0, errors.New("artifact staging context is required")
	}
	buffer := make([]byte, 32<<10)
	var total int64
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}
