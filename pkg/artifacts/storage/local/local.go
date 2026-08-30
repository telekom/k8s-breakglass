//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package local implements the explicit single-replica RWO artifact backend.
// The 0700 roots must be private to the dedicated serving process. Privileged
// processes and other processes with the configured UID are outside this trust
// boundary. Paths are descriptor-relative, publication is atomic and
// create-only, and every read verifies the exact stored version before
// returning bytes.
package local

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/internal/strictjson"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"golang.org/x/sys/unix"
)

const (
	rootMode        = 0700
	sentinelMode    = 0400
	objectMode      = 0600
	headerSize      = 2048
	headerPrefix    = "BGARTL1\n"
	headerLengthPos = len(headerPrefix)
	headerJSONPos   = headerLengthPos + 4
	temporaryPrefix = "tmp-"
	probePrefix     = ".probe-"
	deletionPrefix  = ".delete-"
)

// Store holds descriptor-opened roots and their runtime device/inode fence.
// It is valid only while the configured PVC remains mounted at those roots.
type Store struct {
	config        Config
	artifactRoot  *os.File
	stagingRoot   *os.File
	instanceID    string
	artifactStat  unix.Stat_t
	stagingStat   unix.Stat_t
	operations    fileOperations
	capacityMu    sync.Mutex
	reservedBytes int64
	mutationMu    sync.RWMutex
	ambiguous     bool
}

type fileOperations struct {
	link                 func(int, string, int, string, int) error
	unlink               func(int, string, int) error
	syncDirectory        func(*os.File) error
	availableBytes       func(*os.File) (int64, error)
	closeFile            func(*os.File) error
	renameNoReplace      func(*os.File, string, *os.File, string) error
	beforeIdentityUnlink func(*os.File, string)
	afterIdentityCheck   func(*os.File, string)
}

func defaultFileOperations() fileOperations {
	return fileOperations{
		link: unix.Linkat, unlink: unix.Unlinkat, syncDirectory: syncDirectory,
		availableBytes: availableBytes, closeFile: func(file *os.File) error { return file.Close() },
		renameNoReplace:      renameNoReplace,
		beforeIdentityUnlink: func(*os.File, string) {},
		afterIdentityCheck:   func(*os.File, string) {},
	}
}

type diskHeader struct {
	Schema               string    `json:"schema"`
	BackendInstanceID    string    `json:"backend_instance_id"`
	Key                  string    `json:"key"`
	VersionID            string    `json:"version_id"`
	RuntimeBindingDigest string    `json:"runtime_binding_sha256"`
	Size                 int64     `json:"size"`
	SHA256               string    `json:"sha256"`
	ETag                 string    `json:"etag"`
	ProviderChecksum     string    `json:"provider_checksum"`
	ModifiedAt           time.Time `json:"modified_at"`
}

// ProvisionSentinels is the controller-owned provisioning step. Open never
// creates a missing sentinel, so an empty or repointed volume fails closed.
func ProvisionSentinels(config Config) (result error) {
	validated, err := config.validate()
	if err != nil {
		return err
	}
	artifactRoot, artifactStat, err := openRoot(validated.ArtifactRoot, validated)
	if err != nil {
		return fmt.Errorf("open local artifact root for provisioning: %w", err)
	}
	defer func() { result = errors.Join(result, artifactRoot.Close()) }()
	stagingRoot, stagingStat, err := openRoot(validated.StagingRoot, validated)
	if err != nil {
		return fmt.Errorf("open local staging root for provisioning: %w", err)
	}
	defer func() { result = errors.Join(result, stagingRoot.Close()) }()
	if artifactStat.Dev != stagingStat.Dev {
		return errors.New("local artifact and staging roots are not on the same filesystem")
	}
	for _, root := range []*os.File{artifactRoot, stagingRoot} {
		if err := provisionSentinel(root, validated); err != nil {
			return err
		}
	}
	return nil
}

// Open verifies the provisioned roots and sentinel, removes only recognized
// stale staging links, and executes the publication/fsync/locking probe.
func Open(config Config) (*Store, error) {
	validated, err := config.validate()
	if err != nil {
		return nil, err
	}
	artifactRoot, artifactStat, err := openRoot(validated.ArtifactRoot, validated)
	if err != nil {
		return nil, fmt.Errorf("open local artifact root: %w", err)
	}
	stagingRoot, stagingStat, err := openRoot(validated.StagingRoot, validated)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open local staging root: %w", err), artifactRoot.Close())
	}
	store := &Store{
		config: validated, artifactRoot: artifactRoot, stagingRoot: stagingRoot,
		instanceID:   backendInstanceID(validated.InstanceID),
		artifactStat: *artifactStat, stagingStat: *stagingStat,
		operations: defaultFileOperations(),
	}
	if artifactStat.Dev != stagingStat.Dev {
		return nil, errors.Join(errors.New("local artifact and staging roots are not on the same filesystem"), store.Close())
	}
	if err := verifySentinel(artifactRoot, validated); err != nil {
		return nil, errors.Join(fmt.Errorf("verify local artifact sentinel: %w", err), store.Close())
	}
	if err := verifySentinel(stagingRoot, validated); err != nil {
		return nil, errors.Join(fmt.Errorf("verify local staging sentinel: %w", err), store.Close())
	}
	if err := store.removeStaleTemporaryFiles(); err != nil {
		return nil, errors.Join(err, store.Close())
	}
	if err := store.probe(); err != nil {
		return nil, errors.Join(fmt.Errorf("probe local artifact storage: %w", err), store.Close())
	}
	return store, nil
}

func (store *Store) Backend() string { return artifactstorage.BackendLocal }

func (store *Store) BackendInstanceID() string {
	if store == nil {
		return ""
	}
	return store.instanceID
}

// Close releases the descriptor fence. Callers must stop serving before
// closing the store.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	var result error
	if store.artifactRoot != nil {
		result = errors.Join(result, store.artifactRoot.Close())
		store.artifactRoot = nil
	}
	if store.stagingRoot != nil {
		result = errors.Join(result, store.stagingRoot.Close())
		store.stagingRoot = nil
	}
	return result
}

func (store *Store) PutIfAbsent(ctx context.Context, object artifactstorage.Object, source io.Reader) (metadata artifactstorage.Metadata, result error) {
	var empty artifactstorage.Metadata
	if err := store.ready(object); err != nil {
		return empty, err
	}
	if ctx == nil || source == nil {
		return empty, errors.New("local artifact source and context are required")
	}
	store.mutationMu.RLock()
	err := store.ambiguityError()
	var existing artifactstorage.Metadata
	var found bool
	if err == nil {
		existing, found, err = store.existingBeforePut(ctx, object)
	}
	store.mutationMu.RUnlock()
	if err != nil {
		return empty, err
	}
	if found {
		return existing, artifactstorage.ErrAlreadyExists
	}
	releaseCapacity, err := store.reserveCapacity(object.Size)
	if err != nil {
		return empty, err
	}
	defer releaseCapacity()
	metadata = metadataFor(store.instanceID, object, store.config.Now().UTC())
	if metadata.ModifiedAt.IsZero() {
		return empty, errors.New("local artifact clock returned a zero timestamp")
	}
	header, err := marshalHeader(metadata)
	if err != nil {
		return empty, err
	}
	temporaryName, temporary, err := createTemporary(store.stagingRoot)
	if err != nil {
		return empty, fmt.Errorf("create local artifact staging file: %w", err)
	}
	temporaryStat, err := statDescriptor(temporary)
	if err != nil || temporaryStat.Nlink != 1 || temporaryStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return empty, errors.Join(errors.New("local artifact staging descriptor is unsafe"), err,
			errorContext("close unsafe local artifact staging file", temporary.Close()))
	}
	removeTemporary := true
	publishedName := ""
	publicationMayBeDurable := false
	mutationLocked := false
	defer func() {
		var cleanupErr error
		if result != nil && publishedName != "" && !publicationMayBeDurable {
			cleanupErr = errors.Join(cleanupErr, store.removeBoundName(
				store.artifactRoot, publishedName, temporaryStat, 2, 2, "publication rollback",
			))
		}
		if removeTemporary {
			removed, unlinkErr := store.unlinkIfIdentity(store.stagingRoot, temporaryName, temporaryStat, 1, 2)
			if unlinkErr != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("rollback local artifact staging file: %w", unlinkErr))
			} else if !removed {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("local artifact staging rollback changed before removal: %w", artifactstorage.ErrAmbiguous))
			}
			if removed {
				if syncErr := store.operations.syncDirectory(store.stagingRoot); syncErr != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("fsync local artifact staging parent after rollback: %w", syncErr))
				}
			}
		}
		if closeErr := store.operations.closeFile(temporary); closeErr != nil {
			result = errors.Join(result, fmt.Errorf("close local artifact staging file: %w", closeErr))
		}
		if mutationLocked {
			if publishedName != "" && cleanupErr != nil {
				store.ambiguous = true
				cleanupErr = errors.Join(cleanupErr, store.ambiguityError())
			}
			store.mutationMu.Unlock()
		}
		result = errors.Join(result, cleanupErr)
	}()
	if err := writeObject(ctx, temporary, header, source, object); err != nil {
		return empty, err
	}
	if err := temporary.Sync(); err != nil {
		return empty, fmt.Errorf("fsync local artifact staging file: %w", err)
	}
	if err := contextError(ctx); err != nil {
		return empty, err
	}
	if err := store.verifyRuntimeFence(); err != nil {
		return empty, err
	}
	store.mutationMu.Lock()
	mutationLocked = true
	if err := store.ambiguityError(); err != nil {
		return empty, err
	}
	name := objectName(object.Key)
	if err := linkAt(store.operations.link, store.stagingRoot, temporaryName, store.artifactRoot, name); err != nil {
		if errors.Is(err, unix.EEXIST) {
			winner, found, reconcileErr := store.existingBeforePut(ctx, object)
			if reconcileErr != nil {
				return empty, reconcileErr
			}
			if !found {
				return empty, fmt.Errorf("local artifact publication winner disappeared: %w", artifactstorage.ErrAmbiguous)
			}
			return winner, artifactstorage.ErrAlreadyExists
		}
		return empty, fmt.Errorf("publish local artifact without replacement: %w", err)
	}
	publishedName = name
	if err := store.verifyPublishedIdentity(temporary, temporaryStat, name, 2); err != nil {
		return empty, err
	}
	// Once fsync starts, failure leaves durability unknown. Keep the exact
	// publication so a retry can reconcile it.
	publicationMayBeDurable = true
	if err := store.operations.syncDirectory(store.artifactRoot); err != nil {
		return empty, fmt.Errorf("fsync local artifact parent after publication: %w", err)
	}
	removed, err := store.unlinkIfIdentity(store.stagingRoot, temporaryName, temporaryStat, 2, 2)
	if err != nil {
		return empty, fmt.Errorf("unlink published local artifact staging name: %w", err)
	}
	if !removed {
		return empty, fmt.Errorf("local artifact staging name changed before unlink: %w", artifactstorage.ErrAmbiguous)
	}
	removeTemporary = false
	if err := store.operations.syncDirectory(store.stagingRoot); err != nil {
		return empty, fmt.Errorf("fsync local artifact staging parent after publication: %w", err)
	}
	if err := store.verifyPublishedIdentity(temporary, temporaryStat, name, 1); err != nil {
		return empty, err
	}
	return metadata, nil
}

func (store *Store) existingBeforePut(ctx context.Context, object artifactstorage.Object) (artifactstorage.Metadata, bool, error) {
	var empty artifactstorage.Metadata
	file, metadata, err := store.openAndVerify(ctx, object)
	if errors.Is(err, artifactstorage.ErrNotFound) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	if err := file.Close(); err != nil {
		return empty, false, fmt.Errorf("close existing local artifact before create-only retry: %w", err)
	}
	if err := store.operations.syncDirectory(store.artifactRoot); err != nil {
		return empty, false, fmt.Errorf("fsync local artifact parent before retry reconciliation: %w", err)
	}
	return metadata, true, nil
}

func (store *Store) verifyPublishedIdentity(temporary *os.File, original *unix.Stat_t, name string, expectedLinks uint64) error {
	descriptorStat, descriptorErr := statDescriptor(temporary)
	publishedStat, publishedErr := statNameNoFollow(store.artifactRoot, name)
	if descriptorErr == nil && publishedErr == nil && sameFileIdentity(original, descriptorStat) &&
		sameFileIdentity(original, publishedStat) && descriptorStat.Mode&unix.S_IFMT == unix.S_IFREG &&
		publishedStat.Mode&unix.S_IFMT == unix.S_IFREG && linkCount(descriptorStat.Nlink) == expectedLinks &&
		linkCount(publishedStat.Nlink) == expectedLinks {
		return nil
	}
	return fmt.Errorf("local artifact publication identity is ambiguous: %w", artifactstorage.ErrAmbiguous)
}

func (store *Store) unlinkIfIdentity(root *os.File, name string, expected *unix.Stat_t, minimumLinks, maximumLinks uint64) (bool, error) {
	store.operations.beforeIdentityUnlink(root, name)
	actual, err := statNameNoFollow(root, name)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	links := linkCount(actual.Nlink)
	if !sameFileIdentity(actual, expected) || links < minimumLinks || links > maximumLinks {
		return false, nil
	}
	store.operations.afterIdentityCheck(root, name)
	actual, err = statNameNoFollow(root, name)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	links = linkCount(actual.Nlink)
	if !sameFileIdentity(actual, expected) || links < minimumLinks || links > maximumLinks {
		return false, nil
	}
	if err := unlinkAt(store.operations.unlink, root, name); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (store *Store) OpenVersion(ctx context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (io.ReadCloser, artifactstorage.Metadata, error) {
	var empty artifactstorage.Metadata
	if err := store.ready(object); err != nil {
		return nil, empty, err
	}
	store.mutationMu.RLock()
	defer store.mutationMu.RUnlock()
	if err := store.ambiguityError(); err != nil {
		return nil, empty, err
	}
	file, actual, err := store.openAndVerify(ctx, object)
	if err != nil {
		return nil, empty, err
	}
	if !metadataEqual(actual, expected) {
		return nil, empty, errors.Join(artifactstorage.ErrConflict, file.Close())
	}
	if _, err := file.Seek(headerSize, io.SeekStart); err != nil {
		return nil, empty, errors.Join(fmt.Errorf("seek local artifact content: %w", err), file.Close())
	}
	if err := contextError(ctx); err != nil {
		return nil, empty, errors.Join(err, file.Close())
	}
	return &boundedReadCloser{Reader: &contextReader{ctx: ctx, reader: io.LimitReader(file, object.Size)}, closer: file}, actual, nil
}

func (store *Store) StatVersion(ctx context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (metadata artifactstorage.Metadata, result error) {
	var empty artifactstorage.Metadata
	if err := store.ready(object); err != nil {
		return empty, err
	}
	store.mutationMu.RLock()
	defer store.mutationMu.RUnlock()
	if err := store.ambiguityError(); err != nil {
		return empty, err
	}
	file, actual, err := store.openAndVerify(ctx, object)
	if err != nil {
		return empty, err
	}
	defer func() { result = errors.Join(result, errorContext("close local artifact after stat", file.Close())) }()
	if !metadataEqual(actual, expected) {
		return empty, artifactstorage.ErrConflict
	}
	return actual, nil
}

func (store *Store) Inventory(ctx context.Context, object artifactstorage.Object) (versions []artifactstorage.Version, result error) {
	if err := store.ready(object); err != nil {
		return nil, err
	}
	store.mutationMu.RLock()
	defer store.mutationMu.RUnlock()
	if err := store.ambiguityError(); err != nil {
		return nil, err
	}
	file, metadata, err := store.openAndVerify(ctx, object)
	if errors.Is(err, artifactstorage.ErrNotFound) {
		if syncErr := store.operations.syncDirectory(store.artifactRoot); syncErr != nil {
			return nil, fmt.Errorf("fsync local artifact parent before absence proof: %w", syncErr)
		}
		return []artifactstorage.Version{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		result = errors.Join(result, errorContext("close local artifact after inventory", file.Close()))
	}()
	if err := store.operations.syncDirectory(store.artifactRoot); err != nil {
		return nil, fmt.Errorf("fsync local artifact parent before inventory proof: %w", err)
	}
	return []artifactstorage.Version{versionFromMetadata(metadata)}, nil
}

func (store *Store) DeleteVersion(ctx context.Context, object artifactstorage.Object, version artifactstorage.Version) (result error) {
	if err := store.ready(object); err != nil {
		return err
	}
	if ctx == nil || version.DeleteMarker {
		return artifactstorage.ErrConflict
	}
	store.mutationMu.Lock()
	defer store.mutationMu.Unlock()
	if err := store.ambiguityError(); err != nil {
		return err
	}
	file, metadata, err := store.openAndVerify(ctx, object)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.operations.closeFile(file); closeErr != nil {
			result = errors.Join(result, fmt.Errorf("close exact local artifact: %w", closeErr))
		}
	}()
	descriptorStat, err := statDescriptor(file)
	if err != nil {
		return fmt.Errorf("stat exact local artifact before deletion: %w", err)
	}
	if !versionEqual(versionFromMetadata(metadata), version) {
		return artifactstorage.ErrConflict
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := store.verifyRuntimeFence(); err != nil {
		return err
	}
	result = errors.Join(result, store.deleteExactName(objectName(object.Key), descriptorStat))
	return result
}

func (store *Store) deleteExactName(name string, expected *unix.Stat_t) (result error) {
	store.operations.beforeIdentityUnlink(store.artifactRoot, name)
	actual, err := statNameNoFollow(store.artifactRoot, name)
	if err != nil {
		return fmt.Errorf("inspect exact local artifact before deletion: %w", err)
	}
	if !sameFileIdentity(actual, expected) || linkCount(actual.Nlink) != 1 {
		return fmt.Errorf("exact local artifact changed before deletion: %w", artifactstorage.ErrAmbiguous)
	}
	quarantine, err := randomName(deletionPrefix)
	if err != nil {
		return fmt.Errorf("create exact local artifact deletion name: %w", err)
	}
	store.operations.afterIdentityCheck(store.artifactRoot, name)
	if err := store.operations.renameNoReplace(store.artifactRoot, name, store.artifactRoot, quarantine); err != nil {
		return fmt.Errorf("move exact local artifact for deletion: %w", err)
	}

	rollback := true
	defer func() {
		if rollback {
			restoreErr := store.operations.renameNoReplace(store.artifactRoot, quarantine, store.artifactRoot, name)
			if restoreErr != nil {
				store.ambiguous = true
				result = errors.Join(result, fmt.Errorf("restore local artifact after rejected deletion: %w", restoreErr),
					store.ambiguityError())
			}
		}
		result = errors.Join(result, errorContext("fsync local artifact parent after deletion",
			store.operations.syncDirectory(store.artifactRoot)))
	}()

	moved, err := statNameNoFollow(store.artifactRoot, quarantine)
	if err != nil {
		return fmt.Errorf("inspect moved local artifact before deletion: %w", err)
	}
	if !sameFileIdentity(moved, expected) || linkCount(moved.Nlink) != 1 {
		return fmt.Errorf("exact local artifact changed during deletion: %w", artifactstorage.ErrAmbiguous)
	}
	if err := unlinkAt(store.operations.unlink, store.artifactRoot, quarantine); err != nil {
		return fmt.Errorf("unlink exact local artifact version: %w", err)
	}
	rollback = false
	return nil
}

func (store *Store) openAndVerify(ctx context.Context, object artifactstorage.Object) (file *os.File, metadata artifactstorage.Metadata, result error) {
	var empty artifactstorage.Metadata
	if err := store.verifyRuntimeFence(); err != nil {
		return nil, empty, err
	}
	file, stat, err := openRegular(store.artifactRoot, objectName(object.Key), objectMode, store.config)
	if errors.Is(err, unix.ENOENT) {
		return nil, empty, artifactstorage.ErrNotFound
	}
	if err != nil {
		return nil, empty, fmt.Errorf("open exact local artifact: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			if closeErr := file.Close(); closeErr != nil {
				result = errors.Join(result, fmt.Errorf("close local artifact after failed verification: %w", closeErr))
			}
		}
	}()
	if stat.Nlink != 1 || stat.Size < headerSize || stat.Size != headerSize+object.Size {
		return nil, empty, artifactstorage.ErrConflict
	}
	headerBytes := make([]byte, headerSize)
	if err := readFullContext(ctx, file, headerBytes); err != nil {
		return nil, empty, fmt.Errorf("read local artifact metadata: %w", err)
	}
	metadata, err = unmarshalHeader(headerBytes)
	if err != nil || !metadataMatchesObject(metadata, store.instanceID, object) {
		return nil, empty, artifactstorage.ErrConflict
	}
	digest := sha256.New()
	if _, err := copyExact(ctx, digest, file, object.Size); err != nil {
		return nil, empty, err
	}
	if hex.EncodeToString(digest.Sum(nil)) != object.SHA256 {
		return nil, empty, artifactstorage.ErrConflict
	}
	closeOnError = false
	return file, metadata, nil
}

func (store *Store) ready(object artifactstorage.Object) error {
	if store == nil || store.artifactRoot == nil || store.stagingRoot == nil {
		return errors.New("local artifact store is closed")
	}
	if !validObject(object, store.config.MaximumObjectBytes) {
		return errors.New("local artifact object is outside its bounded contract")
	}
	return store.verifyRuntimeFence()
}

func (store *Store) ambiguityError() error {
	if !store.ambiguous {
		return nil
	}
	return fmt.Errorf("local artifact store needs reopen or reconciliation: %w", artifactstorage.ErrAmbiguous)
}

func (store *Store) verifyRuntimeFence() error {
	if store == nil || store.artifactRoot == nil || store.stagingRoot == nil {
		return artifactstorage.ErrBackendDrift
	}
	artifactStat, err := statDescriptor(store.artifactRoot)
	if err != nil || !safeRootStat(artifactStat, store.config) ||
		!sameFileIdentity(artifactStat, &store.artifactStat) {
		return artifactstorage.ErrBackendDrift
	}
	stagingStat, err := statDescriptor(store.stagingRoot)
	if err != nil || !safeRootStat(stagingStat, store.config) ||
		!sameFileIdentity(stagingStat, &store.stagingStat) {
		return artifactstorage.ErrBackendDrift
	}
	return nil
}

func (store *Store) reserveCapacity(size int64) (func(), error) {
	store.capacityMu.Lock()
	defer store.capacityMu.Unlock()
	available, err := store.operations.availableBytes(store.stagingRoot)
	if err != nil {
		return nil, fmt.Errorf("stat local artifact filesystem capacity: %w", err)
	}
	reservation, overflow := addInt64(size, headerSize)
	withReserved, reservedOverflow := addInt64(store.reservedBytes, reservation)
	required, requiredOverflow := addInt64(withReserved, store.config.MinimumFreeBytes)
	if overflow || reservedOverflow || requiredOverflow || available < required {
		return nil, errors.New("local artifact filesystem capacity floor is unavailable")
	}
	store.reservedBytes = withReserved
	var once sync.Once
	return func() {
		once.Do(func() {
			store.capacityMu.Lock()
			store.reservedBytes -= reservation
			store.capacityMu.Unlock()
		})
	}, nil
}

func (store *Store) removeStaleTemporaryFiles() (result error) {
	names, err := store.stagingRoot.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list local artifact staging root: %w", err)
	}
	removed := false
	defer func() {
		if removed {
			if err := syncDirectory(store.stagingRoot); err != nil {
				result = errors.Join(result, fmt.Errorf("fsync local artifact staging root after recovery: %w", err))
			}
		}
	}()
	for _, name := range names {
		if name == sentinelName || !validTemporaryName(name) {
			continue
		}
		file, stat, err := openRegular(store.stagingRoot, name, objectMode, store.config)
		if err != nil {
			return fmt.Errorf("inspect stale local artifact staging file: %w", err)
		}
		if stat.Nlink < 1 || stat.Nlink > 2 {
			return errors.Join(errors.New("stale local artifact staging link count is unsafe"), file.Close())
		}
		links := linkCount(stat.Nlink)
		unlinked, unlinkErr := store.unlinkIfIdentity(store.stagingRoot, name, stat, links, links)
		if unlinked {
			removed = true
		}
		closeErr := store.operations.closeFile(file)
		if unlinkErr != nil || !unlinked || closeErr != nil {
			var identityErr error
			if !unlinked && unlinkErr == nil {
				identityErr = fmt.Errorf("stale local artifact staging file changed before removal: %w", artifactstorage.ErrAmbiguous)
			}
			return errors.Join(errorContext("remove stale local artifact staging file", unlinkErr), identityErr,
				errorContext("close stale local artifact staging file", closeErr))
		}
	}
	result = errors.Join(result, store.removeStaleProbeFiles())
	return result
}

func (store *Store) removeStaleProbeFiles() (result error) {
	names, err := store.artifactRoot.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list local artifact root for stale probes: %w", err)
	}
	removed := false
	defer func() {
		if removed {
			if err := syncDirectory(store.artifactRoot); err != nil {
				result = errors.Join(result, fmt.Errorf("fsync local artifact root after probe recovery: %w", err))
			}
		}
	}()
	for _, name := range names {
		if validDeletionName(name) {
			return fmt.Errorf("unfinished local artifact deletion %q requires reconciliation: %w", name, artifactstorage.ErrAmbiguous)
		}
		if !validProbeName(name) {
			continue
		}
		file, stat, err := openRegular(store.artifactRoot, name, objectMode, store.config)
		if err != nil {
			return fmt.Errorf("inspect stale local artifact probe: %w", err)
		}
		if stat.Nlink < 1 || stat.Nlink > 2 {
			return errors.Join(errors.New("stale local artifact probe link count is unsafe"), file.Close())
		}
		links := linkCount(stat.Nlink)
		unlinked, unlinkErr := store.unlinkIfIdentity(store.artifactRoot, name, stat, links, links)
		if unlinked {
			removed = true
		}
		closeErr := store.operations.closeFile(file)
		if unlinkErr != nil || !unlinked || closeErr != nil {
			var identityErr error
			if !unlinked && unlinkErr == nil {
				identityErr = fmt.Errorf("stale local artifact probe changed before removal: %w", artifactstorage.ErrAmbiguous)
			}
			return errors.Join(errorContext("remove stale local artifact probe", unlinkErr), identityErr,
				errorContext("close stale local artifact probe", closeErr))
		}
	}
	return nil
}

func (store *Store) probe() (result error) {
	temporaryName, temporary, err := createTemporary(store.stagingRoot)
	if err != nil {
		return err
	}
	temporaryStat, err := statDescriptor(temporary)
	if err != nil || temporaryStat.Nlink != 1 || temporaryStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.Join(errors.New("local artifact probe descriptor is unsafe"), err,
			errorContext("close unsafe local artifact probe", temporary.Close()))
	}
	temporaryPresent := true
	defer func() {
		if temporaryPresent {
			result = errors.Join(result, store.removeBoundName(store.stagingRoot, temporaryName, temporaryStat, 1, 2, "staging probe"))
		}
		result = errors.Join(result, store.operations.closeFile(temporary))
	}()
	if err := flock(temporary, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("lock local artifact probe file: %w", err)
	}
	second, _, err := openRegular(store.stagingRoot, temporaryName, objectMode, store.config)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.operations.closeFile(second)) }()
	if err := flock(second, unix.LOCK_EX|unix.LOCK_NB); err == nil {
		return errors.Join(errors.New("local artifact filesystem did not enforce exclusive locking"),
			errorContext("unlock local artifact probe", flock(second, unix.LOCK_UN)))
	} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		return fmt.Errorf("verify local artifact lock exclusion: %w", err)
	}
	if _, err := temporary.Write([]byte("probe")); err != nil {
		return fmt.Errorf("write local artifact probe: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("fsync local artifact probe: %w", err)
	}
	probeName := probePrefix + strings.TrimPrefix(temporaryName, temporaryPrefix)
	if err := linkAt(store.operations.link, store.stagingRoot, temporaryName, store.artifactRoot, probeName); err != nil {
		return fmt.Errorf("publish local artifact probe: %w", err)
	}
	probePresent := true
	defer func() {
		if probePresent {
			result = errors.Join(result, store.removeBoundName(store.artifactRoot, probeName, temporaryStat, 2, 2, "published probe"))
		}
	}()
	if err := store.verifyPublishedIdentity(temporary, temporaryStat, probeName, 2); err != nil {
		return err
	}
	if err := linkAt(store.operations.link, store.stagingRoot, temporaryName, store.artifactRoot, probeName); !errors.Is(err, unix.EEXIST) {
		return errors.New("local artifact filesystem did not enforce create-only publication")
	}
	if err := store.operations.syncDirectory(store.artifactRoot); err != nil {
		return fmt.Errorf("fsync local artifact probe publication: %w", err)
	}
	if err := store.removeBoundName(store.artifactRoot, probeName, temporaryStat, 2, 2, "published probe"); err != nil {
		return err
	}
	probePresent = false
	if err := store.removeBoundName(store.stagingRoot, temporaryName, temporaryStat, 1, 1, "staging probe"); err != nil {
		return err
	}
	temporaryPresent = false
	return nil
}

func (store *Store) removeBoundName(root *os.File, name string, expected *unix.Stat_t, minimumLinks, maximumLinks uint64, description string) error {
	removed, err := store.unlinkIfIdentity(root, name, expected, minimumLinks, maximumLinks)
	if err != nil {
		return fmt.Errorf("remove local artifact %s: %w", description, err)
	}
	if !removed {
		return fmt.Errorf("local artifact %s changed before removal: %w", description, artifactstorage.ErrAmbiguous)
	}
	if err := store.operations.syncDirectory(root); err != nil {
		return fmt.Errorf("fsync local artifact %s parent after removal: %w", description, err)
	}
	return nil
}

func provisionSentinel(root *os.File, config Config) (result error) {
	content := []byte(config.InstanceID + "\n")
	file, _, err := openRegular(root, sentinelName, sentinelMode, config)
	if err == nil {
		defer func() { result = errors.Join(result, file.Close()) }()
		actual, readErr := io.ReadAll(io.LimitReader(file, int64(len(content)+1)))
		if readErr != nil || string(actual) != string(content) {
			return artifactstorage.ErrBackendDrift
		}
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("open local artifact sentinel: %w", err)
	}
	rootFD, err := fileDescriptor(root)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(rootFD, sentinelName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, sentinelMode)
	if err != nil {
		return fmt.Errorf("create local artifact sentinel: %w", err)
	}
	created, err := fileFromDescriptor(fd, sentinelName)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			if unlinkErr := unlinkAt(unix.Unlinkat, root, sentinelName); unlinkErr != nil && !errors.Is(unlinkErr, unix.ENOENT) {
				result = errors.Join(result, fmt.Errorf("rollback local artifact sentinel: %w", unlinkErr))
			} else if unlinkErr == nil {
				result = errors.Join(result, errorContext("fsync local artifact root after sentinel rollback", syncDirectory(root)))
			}
		}
		if closeErr := created.Close(); closeErr != nil {
			result = errors.Join(result, fmt.Errorf("close local artifact sentinel: %w", closeErr))
		}
	}()
	if _, err := created.Write(content); err != nil {
		return fmt.Errorf("write local artifact sentinel: %w", err)
	}
	if err := created.Sync(); err != nil {
		return fmt.Errorf("fsync local artifact sentinel: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return fmt.Errorf("fsync local artifact root after sentinel provisioning: %w", err)
	}
	remove = false
	return nil
}

func verifySentinel(root *os.File, config Config) (result error) {
	file, stat, err := openRegular(root, sentinelName, sentinelMode, config)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	if stat.Nlink != 1 {
		return artifactstorage.ErrBackendDrift
	}
	expected := config.InstanceID + "\n"
	actual, err := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	if err != nil || string(actual) != expected {
		return artifactstorage.ErrBackendDrift
	}
	return nil
}

func openRoot(root string, config Config) (*os.File, *unix.Stat_t, error) {
	components := strings.Split(strings.TrimPrefix(filepath.Clean(root), string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	for _, component := range components {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return nil, nil, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return nil, nil, errors.Join(closeErr, unix.Close(next))
		}
		fd = next
	}
	file, err := fileFromDescriptor(fd, root)
	if err != nil {
		return nil, nil, err
	}
	stat, err := statDescriptor(file)
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if !safeRootStat(stat, config) {
		return nil, nil, errors.Join(errors.New("local artifact root ownership or mode is unsafe"), file.Close())
	}
	return file, stat, nil
}

func openRegular(root *os.File, name string, mode uint32, config Config) (*os.File, *unix.Stat_t, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return nil, nil, errors.New("local artifact leaf name is invalid")
	}
	before, err := statNameNoFollow(root, name)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, nil, errors.New("local artifact path is not a regular file")
	}
	rootFD, err := fileDescriptor(root)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file, err := fileFromDescriptor(fd, name)
	if err != nil {
		return nil, nil, err
	}
	stat, err := statDescriptor(file)
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if !sameFileIdentity(before, stat) || stat.Mode&unix.S_IFMT != unix.S_IFREG || modeBits(stat.Mode&07777) != mode ||
		int(stat.Uid) != config.ExpectedUID || int(stat.Gid) != config.ExpectedGID {
		return nil, nil, errors.Join(errors.New("local artifact file ownership, type, or mode is unsafe"), file.Close())
	}
	return file, stat, nil
}

func statNameNoFollow(root *os.File, name string) (*unix.Stat_t, error) {
	var stat unix.Stat_t
	if root == nil {
		return nil, errors.New("local artifact root descriptor is closed")
	}
	rootFD, err := fileDescriptor(root)
	if err != nil {
		return nil, err
	}
	if err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	return &stat, nil
}

func sameFileIdentity(left, right *unix.Stat_t) bool {
	return left != nil && right != nil && left.Dev == right.Dev && left.Ino == right.Ino
}

func statDescriptor(file *os.File) (*unix.Stat_t, error) {
	var stat unix.Stat_t
	if file == nil {
		return nil, errors.New("local artifact descriptor is closed")
	}
	fd, err := fileDescriptor(file)
	if err != nil {
		return nil, err
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	return &stat, nil
}

func createTemporary(root *os.File) (string, *os.File, error) {
	for attempt := 0; attempt < 4; attempt++ {
		name, err := randomName(temporaryPrefix)
		if err != nil {
			return "", nil, fmt.Errorf("generate local artifact staging name: %w", err)
		}
		rootFD, err := fileDescriptor(root)
		if err != nil {
			return "", nil, err
		}
		fd, err := unix.Openat(rootFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, objectMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		file, err := fileFromDescriptor(fd, name)
		if err != nil {
			return "", nil, err
		}
		return name, file, nil
	}
	return "", nil, errors.New("local artifact staging name collisions exceeded their bound")
}

func randomName(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random), nil
}

func writeObject(ctx context.Context, file *os.File, header []byte, source io.Reader, object artifactstorage.Object) error {
	if err := writeAll(file, header); err != nil {
		return fmt.Errorf("write local artifact metadata: %w", err)
	}
	digest := sha256.New()
	written, err := copyExactToWriters(ctx, file, digest, source, object.Size)
	if err != nil {
		return err
	}
	if written != object.Size || hex.EncodeToString(digest.Sum(nil)) != object.SHA256 {
		return artifactstorage.ErrConflict
	}
	var extra [1]byte
	if read, readErr := source.Read(extra[:]); read != 0 || readErr != io.EOF {
		return errors.New("local artifact source exceeds its declared size")
	}
	return nil
}

func marshalHeader(metadata artifactstorage.Metadata) ([]byte, error) {
	header := diskHeader{
		Schema: "local-artifact/v1", BackendInstanceID: metadata.BackendInstanceID,
		Key: metadata.Key, VersionID: metadata.VersionID, RuntimeBindingDigest: metadata.RuntimeBindingDigest,
		Size: metadata.Size, SHA256: metadata.SHA256, ETag: metadata.ETag,
		ProviderChecksum: metadata.ProviderChecksum, ModifiedAt: metadata.ModifiedAt,
	}
	encoded, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshal local artifact metadata: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > headerSize-headerJSONPos {
		return nil, errors.New("local artifact metadata exceeds its fixed header")
	}
	result := make([]byte, headerSize)
	copy(result, headerPrefix)
	binary.BigEndian.PutUint32(result[headerLengthPos:headerJSONPos], uint32(len(encoded))) // #nosec G115 -- fixed header bound checked above.
	copy(result[headerJSONPos:], encoded)
	return result, nil
}

func unmarshalHeader(value []byte) (artifactstorage.Metadata, error) {
	var metadata artifactstorage.Metadata
	if len(value) != headerSize || string(value[:headerLengthPos]) != headerPrefix {
		return metadata, errors.New("local artifact metadata prefix is invalid")
	}
	length := int(binary.BigEndian.Uint32(value[headerLengthPos:headerJSONPos]))
	if length < 1 || length > headerSize-headerJSONPos || !allZero(value[headerJSONPos+length:]) {
		return metadata, errors.New("local artifact metadata length or padding is invalid")
	}
	var header diskHeader
	if err := strictjson.Decode(value[headerJSONPos:headerJSONPos+length], headerSize-headerJSONPos, &header); err != nil {
		return metadata, fmt.Errorf("decode local artifact metadata: %w", err)
	}
	if header.Schema != "local-artifact/v1" {
		return metadata, errors.New("local artifact metadata schema is invalid")
	}
	return artifactstorage.Metadata{
		BackendInstanceID: header.BackendInstanceID, Key: header.Key, VersionID: header.VersionID,
		RuntimeBindingDigest: header.RuntimeBindingDigest, Size: header.Size, SHA256: header.SHA256,
		ETag: header.ETag, ProviderChecksum: header.ProviderChecksum, ModifiedAt: header.ModifiedAt,
	}, nil
}

func metadataFor(instanceID string, object artifactstorage.Object, modified time.Time) artifactstorage.Metadata {
	versionHash := sha256.Sum256([]byte(instanceID + "\x00" + object.Key + "\x00" +
		object.RuntimeBindingDigest + "\x00" + object.SHA256 + "\x00" + fmt.Sprint(object.Size)))
	version := base64.RawURLEncoding.EncodeToString(versionHash[:])
	return artifactstorage.Metadata{
		BackendInstanceID: instanceID, Key: object.Key, VersionID: version,
		RuntimeBindingDigest: object.RuntimeBindingDigest, Size: object.Size, SHA256: object.SHA256,
		ETag: object.SHA256, ProviderChecksum: object.SHA256, ModifiedAt: modified,
	}
}

func metadataMatchesObject(metadata artifactstorage.Metadata, instanceID string, object artifactstorage.Object) bool {
	return metadata.BackendInstanceID == instanceID && metadata.Key == object.Key &&
		metadata.RuntimeBindingDigest == object.RuntimeBindingDigest && metadata.Size == object.Size &&
		metadata.SHA256 == object.SHA256 && metadata.ETag == object.SHA256 &&
		metadata.ProviderChecksum == object.SHA256 && metadata.VersionID == metadataFor(instanceID, object, metadata.ModifiedAt).VersionID &&
		!metadata.ModifiedAt.IsZero() && metadata.ModifiedAt.Location() == time.UTC
}

func metadataEqual(left, right artifactstorage.Metadata) bool {
	return left.BackendInstanceID == right.BackendInstanceID && left.Key == right.Key &&
		left.VersionID == right.VersionID && left.RuntimeBindingDigest == right.RuntimeBindingDigest &&
		left.Size == right.Size && left.SHA256 == right.SHA256 && left.ETag == right.ETag &&
		left.ProviderChecksum == right.ProviderChecksum && left.ModifiedAt.Equal(right.ModifiedAt)
}

func versionFromMetadata(metadata artifactstorage.Metadata) artifactstorage.Version {
	return artifactstorage.Version{
		VersionID: metadata.VersionID, RuntimeBindingDigest: metadata.RuntimeBindingDigest,
		Size: metadata.Size, SHA256: metadata.SHA256, ETag: metadata.ETag,
		ProviderChecksum: metadata.ProviderChecksum, ModifiedAt: metadata.ModifiedAt,
	}
}

func versionEqual(left, right artifactstorage.Version) bool {
	return left.VersionID == right.VersionID && left.DeleteMarker == right.DeleteMarker &&
		left.RuntimeBindingDigest == right.RuntimeBindingDigest && left.Size == right.Size &&
		left.SHA256 == right.SHA256 && left.ETag == right.ETag && left.ProviderChecksum == right.ProviderChecksum &&
		left.ModifiedAt.Equal(right.ModifiedAt)
}

func validObject(object artifactstorage.Object, maximum int64) bool {
	return validDigest(object.Key) && validDigest(object.RuntimeBindingDigest) && validDigest(object.SHA256) &&
		object.Size > 0 && object.Size <= maximum
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func objectName(key string) string { return "object-" + key }

func validTemporaryName(name string) bool {
	if len(name) != len(temporaryPrefix)+32 || !strings.HasPrefix(name, temporaryPrefix) {
		return false
	}
	_, err := hex.DecodeString(name[len(temporaryPrefix):])
	return err == nil && strings.ToLower(name) == name
}

func validProbeName(name string) bool {
	if len(name) != len(probePrefix)+32 || !strings.HasPrefix(name, probePrefix) {
		return false
	}
	_, err := hex.DecodeString(name[len(probePrefix):])
	return err == nil && strings.ToLower(name) == name
}

func validDeletionName(name string) bool {
	if len(name) != len(deletionPrefix)+32 || !strings.HasPrefix(name, deletionPrefix) {
		return false
	}
	_, err := hex.DecodeString(name[len(deletionPrefix):])
	return err == nil && strings.ToLower(name) == name
}

func backendInstanceID(sentinel string) string {
	digest := sha256.Sum256([]byte("local-artifact-backend/v1\x00" + sentinel))
	return hex.EncodeToString(digest[:])
}

func readFullContext(ctx context.Context, reader io.Reader, target []byte) error {
	offset := 0
	_, err := copyExactToWriters(ctx, writerFunc(func(value []byte) (int, error) {
		written := copy(target[offset:], value)
		offset += written
		return written, nil
	}), nil, reader, int64(len(target)))
	return err
}

type writerFunc func([]byte) (int, error)

func (function writerFunc) Write(value []byte) (int, error) { return function(value) }

func copyExact(ctx context.Context, digest hash.Hash, source io.Reader, size int64) (int64, error) {
	return copyExactToWriters(ctx, digest, nil, source, size)
}

func copyExactToWriters(ctx context.Context, first io.Writer, second io.Writer, source io.Reader, size int64) (int64, error) {
	var written int64
	buffer := make([]byte, 32<<10)
	for written < size {
		if err := contextError(ctx); err != nil {
			return written, err
		}
		want := len(buffer)
		if remaining := size - written; remaining < int64(want) {
			want = int(remaining)
		}
		read, err := source.Read(buffer[:want])
		if read > 0 {
			if err := writeAll(first, buffer[:read]); err != nil {
				return written, err
			}
			if second != nil {
				if err := writeAll(second, buffer[:read]); err != nil {
					return written, err
				}
			}
			written += int64(read)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && written == size {
				return written, nil
			}
			return written, fmt.Errorf("read bounded local artifact bytes: %w", err)
		}
		if read == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("local artifact context is required")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func syncDirectory(directory *os.File) error {
	fd, err := fileDescriptor(directory)
	if err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func availableCapacity(blockSize, availableBlocks uint64) (int64, error) {
	if blockSize == 0 || blockSize > 1<<63-1 || availableBlocks > (1<<63-1)/blockSize {
		return 0, errors.New("local artifact filesystem capacity is invalid")
	}
	return int64(availableBlocks * blockSize), nil // #nosec G115 -- product is bounded by MaxInt64 above.
}

func addInt64(left, right int64) (int64, bool) {
	if right > 0 && left > (1<<63-1)-right {
		return 0, true
	}
	return left + right, false
}

type boundedReadCloser struct {
	io.Reader
	closer io.Closer
}

func (reader *boundedReadCloser) Close() error { return reader.closer.Close() }

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(value []byte) (int, error) {
	if err := contextError(reader.ctx); err != nil {
		return 0, err
	}
	return reader.reader.Read(value)
}

func safeRootStat(stat *unix.Stat_t, config Config) bool {
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR && modeBits(stat.Mode&07777) == rootMode &&
		int(stat.Uid) == config.ExpectedUID && int(stat.Gid) == config.ExpectedGID
}

func fileDescriptor(file *os.File) (int, error) {
	if file == nil {
		return 0, errors.New("local artifact descriptor is closed")
	}
	value := file.Fd()
	if value > ^uintptr(0)>>1 {
		return 0, errors.New("local artifact descriptor exceeds the platform range")
	}
	return int(value), nil // #nosec G115 -- value is checked against the maximum int above.
}

func fileFromDescriptor(fd int, name string) (*os.File, error) {
	if fd < 0 {
		return nil, errors.New("local artifact descriptor is invalid")
	}
	file := os.NewFile(uintptr(fd), name) // #nosec G115 -- non-negative int always fits uintptr.
	if file == nil {
		return nil, errors.Join(errors.New("create local artifact file from descriptor"), unix.Close(fd))
	}
	return file, nil
}

func linkAt(link func(int, string, int, string, int) error, oldRoot *os.File, oldName string, newRoot *os.File, newName string) error {
	oldFD, err := fileDescriptor(oldRoot)
	if err != nil {
		return err
	}
	newFD, err := fileDescriptor(newRoot)
	if err != nil {
		return err
	}
	return link(oldFD, oldName, newFD, newName, 0)
}

func unlinkAt(unlink func(int, string, int) error, root *os.File, name string) error {
	fd, err := fileDescriptor(root)
	if err != nil {
		return err
	}
	return unlink(fd, name, 0)
}

func flock(file *os.File, operation int) error {
	fd, err := fileDescriptor(file)
	if err != nil {
		return err
	}
	return unix.Flock(fd, operation)
}

func linkCount[T ~uint16 | ~uint32 | ~uint64](value T) uint64 {
	return uint64(value)
}

func modeBits[T ~uint16 | ~uint32](value T) uint32 {
	return uint32(value)
}

func errorContext(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
