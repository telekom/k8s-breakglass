// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package local implements the explicit single-replica RWO artifact backend.
// Paths are descriptor-relative, publication is atomic and create-only, and
// every read verifies the exact stored version before returning bytes.
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
)

// Store holds descriptor-opened roots and their runtime device/inode fence.
// It is valid only while the configured PVC remains mounted at those roots.
type Store struct {
	config         Config
	artifactRoot   *os.File
	stagingRoot    *os.File
	instanceID     string
	artifactDevice uint64
	artifactInode  uint64
	stagingDevice  uint64
	stagingInode   uint64
	operations     fileOperations
	capacityMu     sync.Mutex
	reservedBytes  int64
	mutationMu     sync.Mutex
}

type fileOperations struct {
	link                 func(int, string, int, string, int) error
	unlink               func(int, string, int) error
	syncDirectory        func(*os.File) error
	availableBytes       func(*os.File) (int64, error)
	beforeIdentityUnlink func(*os.File, string)
}

func defaultFileOperations() fileOperations {
	return fileOperations{
		link: unix.Linkat, unlink: unix.Unlinkat, syncDirectory: syncDirectory,
		availableBytes: availableBytes, beforeIdentityUnlink: func(*os.File, string) {},
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
func ProvisionSentinels(config Config) error {
	validated, err := config.validate()
	if err != nil {
		return err
	}
	artifactRoot, artifactStat, err := openRoot(validated.ArtifactRoot, validated)
	if err != nil {
		return fmt.Errorf("open local artifact root for provisioning: %w", err)
	}
	defer artifactRoot.Close()
	stagingRoot, stagingStat, err := openRoot(validated.StagingRoot, validated)
	if err != nil {
		return fmt.Errorf("open local staging root for provisioning: %w", err)
	}
	defer stagingRoot.Close()
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
		artifactRoot.Close()
		return nil, fmt.Errorf("open local staging root: %w", err)
	}
	store := &Store{
		config: validated, artifactRoot: artifactRoot, stagingRoot: stagingRoot,
		instanceID:     backendInstanceID(validated.InstanceID),
		artifactDevice: uint64(artifactStat.Dev), artifactInode: uint64(artifactStat.Ino),
		stagingDevice: uint64(stagingStat.Dev), stagingInode: uint64(stagingStat.Ino),
		operations: defaultFileOperations(),
	}
	if artifactStat.Dev != stagingStat.Dev {
		store.Close()
		return nil, errors.New("local artifact and staging roots are not on the same filesystem")
	}
	if err := verifySentinel(artifactRoot, validated); err != nil {
		store.Close()
		return nil, fmt.Errorf("verify local artifact sentinel: %w", err)
	}
	if err := verifySentinel(stagingRoot, validated); err != nil {
		store.Close()
		return nil, fmt.Errorf("verify local staging sentinel: %w", err)
	}
	if err := store.removeStaleTemporaryFiles(); err != nil {
		store.Close()
		return nil, err
	}
	if err := store.probe(); err != nil {
		store.Close()
		return nil, fmt.Errorf("probe local artifact storage: %w", err)
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

func (store *Store) PutIfAbsent(ctx context.Context, object artifactstorage.Object, source io.Reader) (artifactstorage.Metadata, error) {
	var empty artifactstorage.Metadata
	if err := store.ready(object); err != nil {
		return empty, err
	}
	if ctx == nil || source == nil {
		return empty, errors.New("local artifact source and context are required")
	}
	if existing, found, err := store.existingBeforePut(ctx, object); err != nil {
		return empty, err
	} else if found {
		return existing, artifactstorage.ErrAlreadyExists
	}
	releaseCapacity, err := store.reserveCapacity(object.Size)
	if err != nil {
		return empty, err
	}
	defer releaseCapacity()
	metadata := metadataFor(store.instanceID, object, store.config.Now().UTC())
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
		_ = temporary.Close()
		return empty, errors.New("local artifact staging descriptor is unsafe")
	}
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			removed, _ := store.unlinkIfIdentity(store.stagingRoot, temporaryName, temporaryStat, 1, 2)
			if removed {
				_ = store.operations.syncDirectory(store.stagingRoot)
			}
		}
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
	defer store.mutationMu.Unlock()
	name := objectName(object.Key)
	if err := store.operations.link(int(store.stagingRoot.Fd()), temporaryName, int(store.artifactRoot.Fd()), name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return empty, artifactstorage.ErrAlreadyExists
		}
		return empty, fmt.Errorf("publish local artifact without replacement: %w", err)
	}
	if err := store.verifyPublishedIdentity(temporary, temporaryStat, name, 2); err != nil {
		return empty, err
	}
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
		publishedStat.Mode&unix.S_IFMT == unix.S_IFREG && uint64(descriptorStat.Nlink) == expectedLinks &&
		uint64(publishedStat.Nlink) == expectedLinks {
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
	links := uint64(actual.Nlink)
	if !sameFileIdentity(actual, expected) || links < minimumLinks || links > maximumLinks {
		return false, nil
	}
	if err := store.operations.unlink(int(root.Fd()), name, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (store *Store) OpenVersion(ctx context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (io.ReadCloser, artifactstorage.Metadata, error) {
	var empty artifactstorage.Metadata
	file, actual, err := store.openAndVerify(ctx, object)
	if err != nil {
		return nil, empty, err
	}
	if !metadataEqual(actual, expected) {
		file.Close()
		return nil, empty, artifactstorage.ErrConflict
	}
	if _, err := file.Seek(headerSize, io.SeekStart); err != nil {
		file.Close()
		return nil, empty, fmt.Errorf("seek local artifact content: %w", err)
	}
	if err := contextError(ctx); err != nil {
		file.Close()
		return nil, empty, err
	}
	return &boundedReadCloser{Reader: &contextReader{ctx: ctx, reader: io.LimitReader(file, object.Size)}, closer: file}, actual, nil
}

func (store *Store) StatVersion(ctx context.Context, object artifactstorage.Object, expected artifactstorage.Metadata) (artifactstorage.Metadata, error) {
	var empty artifactstorage.Metadata
	file, actual, err := store.openAndVerify(ctx, object)
	if err != nil {
		return empty, err
	}
	if err := file.Close(); err != nil {
		return empty, fmt.Errorf("close local artifact after stat: %w", err)
	}
	if !metadataEqual(actual, expected) {
		return empty, artifactstorage.ErrConflict
	}
	return actual, nil
}

func (store *Store) Inventory(ctx context.Context, object artifactstorage.Object) ([]artifactstorage.Version, error) {
	if err := store.ready(object); err != nil {
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
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close local artifact after inventory: %w", err)
	}
	if err := store.operations.syncDirectory(store.artifactRoot); err != nil {
		return nil, fmt.Errorf("fsync local artifact parent before inventory proof: %w", err)
	}
	return []artifactstorage.Version{versionFromMetadata(metadata)}, nil
}

func (store *Store) DeleteVersion(ctx context.Context, object artifactstorage.Object, version artifactstorage.Version) error {
	if err := store.ready(object); err != nil {
		return err
	}
	if ctx == nil || version.DeleteMarker {
		return artifactstorage.ErrConflict
	}
	store.mutationMu.Lock()
	defer store.mutationMu.Unlock()
	file, metadata, err := store.openAndVerify(ctx, object)
	if err != nil {
		return err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
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
	removed, err := store.unlinkIfIdentity(store.artifactRoot, objectName(object.Key), descriptorStat, 1, 1)
	if err != nil {
		return fmt.Errorf("unlink exact local artifact version: %w", err)
	}
	if !removed {
		return fmt.Errorf("exact local artifact changed before deletion: %w", artifactstorage.ErrAmbiguous)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close exact local artifact after deletion: %w", err)
	}
	closeFile = false
	if err := store.operations.syncDirectory(store.artifactRoot); err != nil {
		return fmt.Errorf("fsync local artifact parent after deletion: %w", err)
	}
	return nil
}

func (store *Store) openAndVerify(ctx context.Context, object artifactstorage.Object) (*os.File, artifactstorage.Metadata, error) {
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
			_ = file.Close()
		}
	}()
	if stat.Nlink != 1 || stat.Size < headerSize || stat.Size != headerSize+object.Size {
		return nil, empty, artifactstorage.ErrConflict
	}
	headerBytes := make([]byte, headerSize)
	if err := readFullContext(ctx, file, headerBytes); err != nil {
		return nil, empty, fmt.Errorf("read local artifact metadata: %w", err)
	}
	metadata, err := unmarshalHeader(headerBytes)
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

func (store *Store) verifyRuntimeFence() error {
	if store == nil || store.artifactRoot == nil || store.stagingRoot == nil {
		return artifactstorage.ErrBackendDrift
	}
	artifactStat, err := statDescriptor(store.artifactRoot)
	if err != nil || !safeRootStat(artifactStat, store.config) ||
		uint64(artifactStat.Dev) != store.artifactDevice || uint64(artifactStat.Ino) != store.artifactInode {
		return artifactstorage.ErrBackendDrift
	}
	stagingStat, err := statDescriptor(store.stagingRoot)
	if err != nil || !safeRootStat(stagingStat, store.config) ||
		uint64(stagingStat.Dev) != store.stagingDevice || uint64(stagingStat.Ino) != store.stagingInode {
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

func (store *Store) removeStaleTemporaryFiles() error {
	names, err := store.stagingRoot.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list local artifact staging root: %w", err)
	}
	removed := false
	for _, name := range names {
		if name == sentinelName || !validTemporaryName(name) {
			continue
		}
		file, stat, err := openRegular(store.stagingRoot, name, objectMode, store.config)
		if err != nil {
			return fmt.Errorf("inspect stale local artifact staging file: %w", err)
		}
		if stat.Nlink < 1 || stat.Nlink > 2 {
			_ = file.Close()
			return errors.New("stale local artifact staging link count is unsafe")
		}
		links := uint64(stat.Nlink)
		unlinked, unlinkErr := store.unlinkIfIdentity(store.stagingRoot, name, stat, links, links)
		closeErr := file.Close()
		if unlinkErr != nil {
			return fmt.Errorf("remove stale local artifact staging file: %w", unlinkErr)
		}
		if !unlinked {
			return fmt.Errorf("stale local artifact staging file changed before removal: %w", artifactstorage.ErrAmbiguous)
		}
		if closeErr != nil {
			return fmt.Errorf("close stale local artifact staging file: %w", closeErr)
		}
		removed = true
	}
	if removed {
		if err := syncDirectory(store.stagingRoot); err != nil {
			return fmt.Errorf("fsync local artifact staging root after recovery: %w", err)
		}
	}
	return store.removeStaleProbeFiles()
}

func (store *Store) removeStaleProbeFiles() error {
	names, err := store.artifactRoot.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list local artifact root for stale probes: %w", err)
	}
	removed := false
	for _, name := range names {
		if !validProbeName(name) {
			continue
		}
		file, stat, err := openRegular(store.artifactRoot, name, objectMode, store.config)
		if err != nil {
			return fmt.Errorf("inspect stale local artifact probe: %w", err)
		}
		if stat.Nlink < 1 || stat.Nlink > 2 {
			_ = file.Close()
			return errors.New("stale local artifact probe link count is unsafe")
		}
		links := uint64(stat.Nlink)
		unlinked, unlinkErr := store.unlinkIfIdentity(store.artifactRoot, name, stat, links, links)
		closeErr := file.Close()
		if unlinkErr != nil {
			return fmt.Errorf("remove stale local artifact probe: %w", unlinkErr)
		}
		if !unlinked {
			return fmt.Errorf("stale local artifact probe changed before removal: %w", artifactstorage.ErrAmbiguous)
		}
		if closeErr != nil {
			return fmt.Errorf("close stale local artifact probe: %w", closeErr)
		}
		removed = true
	}
	if removed {
		if err := syncDirectory(store.artifactRoot); err != nil {
			return fmt.Errorf("fsync local artifact root after probe recovery: %w", err)
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
		_ = temporary.Close()
		return errors.New("local artifact probe descriptor is unsafe")
	}
	temporaryPresent := true
	defer func() {
		if temporaryPresent {
			result = errors.Join(result, store.removeBoundName(store.stagingRoot, temporaryName, temporaryStat, 1, 2, "staging probe"))
		}
		result = errors.Join(result, temporary.Close())
	}()
	if err := unix.Flock(int(temporary.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("lock local artifact probe file: %w", err)
	}
	second, _, err := openRegular(store.stagingRoot, temporaryName, objectMode, store.config)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, second.Close()) }()
	if err := unix.Flock(int(second.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		_ = unix.Flock(int(second.Fd()), unix.LOCK_UN)
		return errors.New("local artifact filesystem did not enforce exclusive locking")
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
	if err := store.operations.link(int(store.stagingRoot.Fd()), temporaryName, int(store.artifactRoot.Fd()), probeName, 0); err != nil {
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
	if err := store.operations.link(int(store.stagingRoot.Fd()), temporaryName, int(store.artifactRoot.Fd()), probeName, 0); !errors.Is(err, unix.EEXIST) {
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

func provisionSentinel(root *os.File, config Config) error {
	content := []byte(config.InstanceID + "\n")
	file, _, err := openRegular(root, sentinelName, sentinelMode, config)
	if err == nil {
		defer file.Close()
		actual, readErr := io.ReadAll(io.LimitReader(file, int64(len(content)+1)))
		if readErr != nil || string(actual) != string(content) {
			return artifactstorage.ErrBackendDrift
		}
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("open local artifact sentinel: %w", err)
	}
	fd, err := unix.Openat(int(root.Fd()), sentinelName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, sentinelMode)
	if err != nil {
		return fmt.Errorf("create local artifact sentinel: %w", err)
	}
	created := os.NewFile(uintptr(fd), sentinelName)
	remove := true
	defer func() {
		_ = created.Close()
		if remove {
			_ = unix.Unlinkat(int(root.Fd()), sentinelName, 0)
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

func verifySentinel(root *os.File, config Config) error {
	file, stat, err := openRegular(root, sentinelName, sentinelMode, config)
	if err != nil {
		return err
	}
	defer file.Close()
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
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, nil, openErr
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), root)
	stat, err := statDescriptor(file)
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !safeRootStat(stat, config) {
		file.Close()
		return nil, nil, errors.New("local artifact root ownership or mode is unsafe")
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
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	stat, err := statDescriptor(file)
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !sameFileIdentity(before, stat) || stat.Mode&unix.S_IFMT != unix.S_IFREG || uint32(stat.Mode&07777) != mode ||
		int(stat.Uid) != config.ExpectedUID || int(stat.Gid) != config.ExpectedGID {
		file.Close()
		return nil, nil, errors.New("local artifact file ownership, type, or mode is unsafe")
	}
	return file, stat, nil
}

func statNameNoFollow(root *os.File, name string) (*unix.Stat_t, error) {
	var stat unix.Stat_t
	if root == nil {
		return nil, errors.New("local artifact root descriptor is closed")
	}
	if err := unix.Fstatat(int(root.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
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
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, err
	}
	return &stat, nil
}

func createTemporary(root *os.File) (string, *os.File, error) {
	for attempt := 0; attempt < 4; attempt++ {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, fmt.Errorf("generate local artifact staging name: %w", err)
		}
		name := temporaryPrefix + hex.EncodeToString(random)
		fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, objectMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, os.NewFile(uintptr(fd), name), nil
	}
	return "", nil, errors.New("local artifact staging name collisions exceeded their bound")
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
	binary.BigEndian.PutUint32(result[headerLengthPos:headerJSONPos], uint32(len(encoded)))
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
		want := int64(len(buffer))
		if remaining := size - written; remaining < want {
			want = remaining
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

func syncDirectory(directory *os.File) error { return unix.Fsync(int(directory.Fd())) }

func availableBytes(directory *os.File) (int64, error) {
	var stats unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &stats); err != nil {
		return 0, err
	}
	blockSize := int64(stats.Bsize)
	availableBlocks := int64(stats.Bavail)
	if blockSize <= 0 || availableBlocks < 0 || availableBlocks > (1<<63-1)/blockSize {
		return 0, errors.New("local artifact filesystem capacity is invalid")
	}
	return availableBlocks * blockSize, nil
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
	return stat != nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR && uint32(stat.Mode&07777) == rootMode &&
		int(stat.Uid) == config.ExpectedUID && int(stat.Gid) == config.ExpectedGID
}
