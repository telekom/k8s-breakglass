//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"golang.org/x/sys/unix"
)

func TestLocalStoreRequiresExplicitProvisionedTopology(t *testing.T) {
	config := localTestConfig(t)
	disabled := config
	disabled.ExplicitlyEnabled = false
	if _, err := Open(disabled); err == nil {
		t.Fatal("Open() accepted implicit local storage")
	}
	if _, err := Open(config); err == nil {
		t.Fatal("Open() provisioned a missing sentinel implicitly")
	}
	untrusted := config
	untrusted.PrivateRootAcknowledged = false
	if _, err := Open(untrusted); err == nil {
		t.Fatal("Open() accepted roots without the private-root trust boundary")
	}
	if err := ProvisionSentinels(config); err != nil {
		t.Fatalf("ProvisionSentinels() error = %v", err)
	}
	store, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if store.Backend() != artifactstorage.BackendLocal || store.BackendInstanceID() == "" {
		t.Fatalf("Open() backend = %q instance = %q", store.Backend(), store.BackendInstanceID())
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for name, mutate := range map[string]func(*Config){
		"replicas": func(value *Config) { value.ServingReplicas = 2 },
		"access":   func(value *Config) { value.AccessMode = "ReadWriteMany" },
		"strategy": func(value *Config) { value.DeploymentStrategy = "RollingUpdate" },
		"encryption": func(value *Config) {
			value.EncryptionAcknowledged = false
		},
		"snapshot": func(value *Config) { value.SnapshotPolicy = "enabled" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := config
			mutate(&invalid)
			if _, err := Open(invalid); err == nil {
				t.Fatal("Open() accepted unsupported local topology")
			}
		})
	}
}

func TestLocalStoreCreateReadInventoryDelete(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := bytes.Repeat([]byte("incompressible-enough\x00"), 70_000)
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("PutIfAbsent() error = %v", err)
	}
	if metadata.BackendInstanceID != store.BackendInstanceID() || metadata.VersionID == "" ||
		metadata.SHA256 != object.SHA256 || metadata.RuntimeBindingDigest != object.RuntimeBindingDigest {
		t.Fatalf("PutIfAbsent() metadata = %#v", metadata)
	}
	if _, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content)); !errors.Is(err, artifactstorage.ErrAlreadyExists) {
		t.Fatalf("duplicate PutIfAbsent() error = %v", err)
	}
	inventory, err := store.Inventory(context.Background(), object)
	if err != nil || len(inventory) != 1 || inventory[0].VersionID != metadata.VersionID {
		t.Fatalf("Inventory() = %#v, error = %v", inventory, err)
	}
	if _, err := store.StatVersion(context.Background(), object, metadata); err != nil {
		t.Fatalf("StatVersion() error = %v", err)
	}
	reader, actual, err := store.OpenVersion(context.Background(), object, metadata)
	if err != nil {
		t.Fatalf("OpenVersion() error = %v", err)
	}
	read, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil || !bytes.Equal(read, content) || !metadataEqual(actual, metadata) {
		t.Fatalf("OpenVersion() bytes=%d metadata=%#v error=%v", len(read), actual, err)
	}

	forged := metadata
	forged.VersionID = strings.Repeat("x", len(forged.VersionID))
	if _, err := store.StatVersion(context.Background(), object, forged); !errors.Is(err, artifactstorage.ErrConflict) {
		t.Fatalf("forged StatVersion() error = %v", err)
	}
	if err := store.DeleteVersion(context.Background(), object, inventory[0]); err != nil {
		t.Fatalf("DeleteVersion() error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(config.ArtifactRoot, objectName(object.Key))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published object remains after deletion: %v", err)
	}
	inventory, err = store.Inventory(context.Background(), object)
	if err != nil || len(inventory) != 0 {
		t.Fatalf("post-delete Inventory() = %#v, error = %v", inventory, err)
	}
	if err := store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata)); !errors.Is(err, artifactstorage.ErrNotFound) {
		t.Fatalf("second DeleteVersion() error = %v", err)
	}
}

func TestLocalStoreDeleteVersionRequiresContext(t *testing.T) {
	store, _ := openLocalTestStore(t)
	defer store.Close()
	object := testObject([]byte("delete-context"))
	if err := store.DeleteVersion(nil, object, artifactstorage.Version{}); err == nil || err.Error() != "local artifact context is required" {
		t.Fatalf("DeleteVersion(nil) error = %v, want context-required error", err)
	}
}

func TestLocalStoreRejectsWrongBytesBoundsAndCancelledStreams(t *testing.T) {
	store, _ := openLocalTestStore(t)
	defer store.Close()
	content := []byte("exact bytes")
	object := testObject(content)
	wrongDigest := object
	wrongDigest.SHA256 = strings.Repeat("f", sha256.Size*2)
	if _, err := store.PutIfAbsent(context.Background(), wrongDigest, bytes.NewReader(content)); !errors.Is(err, artifactstorage.ErrConflict) {
		t.Fatalf("wrong digest PutIfAbsent() error = %v", err)
	}
	tooLong := append(append([]byte(nil), content...), 'x')
	if _, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(tooLong)); err == nil {
		t.Fatal("PutIfAbsent() accepted bytes beyond declared size")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PutIfAbsent(cancelled, object, bytes.NewReader(content)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled PutIfAbsent() error = %v", err)
	}

	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	readContext, stop := context.WithCancel(context.Background())
	reader, _, err := store.OpenVersion(readContext, object, metadata)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	buffer := make([]byte, 1)
	if _, err := reader.Read(buffer); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled artifact read error = %v", err)
	}
	_ = reader.Close()
}

func TestLocalStoreFailsClosedOnSentinelPathAndObjectDrift(t *testing.T) {
	config := localTestConfig(t)
	if err := ProvisionSentinels(config); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(config.ArtifactRoot, sentinelName)
	backup := sentinel + ".backup"
	if err := os.Rename(sentinel, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(backup, sentinel); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config); err == nil {
		t.Fatal("Open() followed a sentinel symlink")
	}
	if err := os.Remove(sentinel); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, sentinel); err != nil {
		t.Fatal(err)
	}
	store, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	content := []byte("artifact")
	object := testObject(content)
	path := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	if err := os.Symlink(config.StagingRoot, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content)); err == nil {
		t.Fatal("PutIfAbsent() accepted an existing symlink")
	}
	if _, err := store.Inventory(context.Background(), object); err == nil {
		t.Fatal("Inventory() followed an object symlink")
	}
}

func TestLocalStoreRecoversOnlyRecognizedStaleNames(t *testing.T) {
	store, config := openLocalTestStore(t)
	content := []byte("persisted")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	staleName := temporaryPrefix + strings.Repeat("a", 32)
	if err := os.Link(filepath.Join(config.ArtifactRoot, objectName(object.Key)), filepath.Join(config.StagingRoot, staleName)); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(config.StagingRoot, "operator-note")
	if err := os.WriteFile(unknown, []byte("do not remove"), objectMode); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(config.ArtifactRoot, probePrefix+strings.Repeat("b", 32))
	if err := os.WriteFile(probe, []byte("probe"), objectMode); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(config)
	if err != nil {
		t.Fatalf("Open() recovery error = %v", err)
	}
	defer reopened.Close()
	for _, removed := range []string{filepath.Join(config.StagingRoot, staleName), probe} {
		if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recognized stale name remains: %s, %v", removed, err)
		}
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown staging file was removed: %v", err)
	}
	if _, err := reopened.StatVersion(context.Background(), object, metadata); err != nil {
		t.Fatalf("published object did not survive recovery: %v", err)
	}
}

func TestLocalStoreStartupRejectsAndPreservesDeletionQuarantine(t *testing.T) {
	config := localTestConfig(t)
	if err := ProvisionSentinels(config); err != nil {
		t.Fatal(err)
	}
	quarantinePath := filepath.Join(config.ArtifactRoot, deletionPrefix+strings.Repeat("d", 32))
	quarantineContent := []byte("unfinished deletion")
	if err := os.WriteFile(quarantinePath, quarantineContent, objectMode); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(config); !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("Open() deletion quarantine error = %v", err)
	}
	actual, err := os.ReadFile(quarantinePath)
	if err != nil {
		t.Fatalf("Open() removed the deletion quarantine: %v", err)
	}
	if !bytes.Equal(actual, quarantineContent) {
		t.Fatalf("Open() changed the deletion quarantine: got %q, want %q", actual, quarantineContent)
	}
}

func TestLocalStoreDetectsContentAndRootModeDrift(t *testing.T) {
	store, config := openLocalTestStore(t)
	content := []byte("immutable")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("X"), headerSize); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if _, err := store.StatVersion(context.Background(), object, metadata); !errors.Is(err, artifactstorage.ErrConflict) {
		t.Fatalf("corrupt StatVersion() error = %v", err)
	}
	if err := os.Chmod(config.StagingRoot, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inventory(context.Background(), object); !errors.Is(err, artifactstorage.ErrBackendDrift) {
		t.Fatalf("root mode drift Inventory() error = %v", err)
	}
	_ = store.Close()
}

func TestLocalStoreConcurrentPublicationIsAtomicAndCreateOnly(t *testing.T) {
	store, _ := openLocalTestStore(t)
	defer store.Close()
	content := bytes.Repeat([]byte("concurrent"), 4096)
	object := testObject(content)
	start := make(chan struct{})
	releaseReaders := make(chan struct{})
	readerStarted := []chan struct{}{make(chan struct{}), make(chan struct{})}
	metadataByAttempt := make([]artifactstorage.Metadata, 2)
	errorsByAttempt := make([]error, 2)
	var wait sync.WaitGroup
	for attempt := range errorsByAttempt {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			metadataByAttempt[attempt], errorsByAttempt[attempt] = store.PutIfAbsent(context.Background(), object, &blockingReader{
				Reader: bytes.NewReader(content), started: readerStarted[attempt], release: releaseReaders,
			})
		}()
	}
	close(start)
	for _, started := range readerStarted {
		<-started
	}
	close(releaseReaders)
	wait.Wait()
	var accepted, collided int
	var acceptedMetadata, collidedMetadata artifactstorage.Metadata
	for attempt, err := range errorsByAttempt {
		switch {
		case err == nil:
			accepted++
			acceptedMetadata = metadataByAttempt[attempt]
		case errors.Is(err, artifactstorage.ErrAlreadyExists):
			collided++
			collidedMetadata = metadataByAttempt[attempt]
		default:
			t.Fatalf("concurrent PutIfAbsent() error = %v", err)
		}
	}
	if accepted != 1 || collided != 1 {
		t.Fatalf("concurrent outcomes: accepted=%d collided=%d", accepted, collided)
	}
	if !metadataEqual(collidedMetadata, acceptedMetadata) {
		t.Fatalf("collision metadata = %#v, want %#v", collidedMetadata, acceptedMetadata)
	}
	inventory, err := store.Inventory(context.Background(), object)
	if err != nil || len(inventory) != 1 {
		t.Fatalf("Inventory() after concurrent publication = %#v, error=%v", inventory, err)
	}
}

func TestLocalStoreConcurrentConflictsKeepOneWinner(t *testing.T) {
	content := []byte("same-size-content-a")
	otherContent := []byte("same-size-content-b")
	if len(content) != len(otherContent) {
		t.Fatal("test content sizes differ")
	}

	tests := []struct {
		name    string
		objects [2]artifactstorage.Object
		content [2][]byte
	}{
		{
			name: "different content",
			objects: [2]artifactstorage.Object{
				testObjectWithKey(content, "shared-content-key"),
				testObjectWithKey(otherContent, "shared-content-key"),
			},
			content: [2][]byte{content, otherContent},
		},
		{
			name: "different binding",
			objects: func() [2]artifactstorage.Object {
				first := testObjectWithKey(content, "shared-binding-key")
				second := first
				digest := sha256.Sum256([]byte("other-runtime-binding"))
				second.RuntimeBindingDigest = hex.EncodeToString(digest[:])
				return [2]artifactstorage.Object{first, second}
			}(),
			content: [2][]byte{content, content},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _ := openLocalTestStore(t)
			defer store.Close()
			releaseReaders := make(chan struct{})
			readerStarted := []chan struct{}{make(chan struct{}), make(chan struct{})}
			metadataByAttempt := make([]artifactstorage.Metadata, 2)
			errorsByAttempt := make([]error, 2)
			var wait sync.WaitGroup
			for attempt := range errorsByAttempt {
				wait.Add(1)
				go func() {
					defer wait.Done()
					metadataByAttempt[attempt], errorsByAttempt[attempt] = store.PutIfAbsent(
						context.Background(), test.objects[attempt], &blockingReader{
							Reader:  bytes.NewReader(test.content[attempt]),
							started: readerStarted[attempt], release: releaseReaders,
						},
					)
				}()
			}
			for _, started := range readerStarted {
				<-started
			}
			close(releaseReaders)
			wait.Wait()

			winner := -1
			var accepted, conflicted int
			for attempt, err := range errorsByAttempt {
				switch {
				case err == nil:
					accepted++
					winner = attempt
				case errors.Is(err, artifactstorage.ErrConflict):
					conflicted++
				default:
					t.Fatalf("PutIfAbsent() error = %v", err)
				}
			}
			if accepted != 1 || conflicted != 1 {
				t.Fatalf("outcomes: accepted=%d conflicted=%d", accepted, conflicted)
			}
			reader, actual, err := store.OpenVersion(context.Background(), test.objects[winner], metadataByAttempt[winner])
			if err != nil {
				t.Fatalf("OpenVersion() error = %v", err)
			}
			stored, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			if readErr != nil || closeErr != nil || !bytes.Equal(stored, test.content[winner]) ||
				!metadataEqual(actual, metadataByAttempt[winner]) {
				t.Fatalf("winner was not stored exactly: bytes=%q metadata=%#v read error=%v close error=%v",
					stored, actual, readErr, closeErr)
			}
		})
	}
}

func TestLocalStorePutRollbackBlocksOperationsAndFailsClosed(t *testing.T) {
	store, config := openLocalTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	content := []byte("failed publication stays hidden")
	object := testObject(content)
	metadata := metadataFor(store.instanceID, object, store.config.Now().UTC())
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	extraLink := filepath.Join(filepath.Dir(config.ArtifactRoot), "failed-publication-link")

	defaultOperations := store.operations
	linkResult := make(chan error, 1)
	store.operations.link = func(oldDirectory int, oldName string, newDirectory int, newName string, flags int) error {
		if err := defaultOperations.link(oldDirectory, oldName, newDirectory, newName, flags); err != nil {
			return err
		}
		linkResult <- os.Link(objectPath, extraLink)
		return nil
	}
	publicationCleanupStarted := make(chan struct{})
	releasePublicationCleanup := make(chan struct{})
	stagingCleanupStarted := make(chan struct{})
	releaseStagingCleanup := make(chan struct{})
	store.operations.beforeIdentityUnlink = func(root *os.File, name string) {
		switch {
		case root == store.artifactRoot && name == objectName(object.Key):
			close(publicationCleanupStarted)
			<-releasePublicationCleanup
		case root == store.stagingRoot && validTemporaryName(name):
			close(stagingCleanupStarted)
			<-releaseStagingCleanup
		}
	}

	putResult := make(chan error, 1)
	go func() {
		_, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
		putResult <- err
	}()
	if err := <-linkResult; err != nil {
		t.Fatalf("create extra publication link: %v", err)
	}
	<-publicationCleanupStarted
	if store.mutationMu.TryRLock() {
		store.mutationMu.RUnlock()
		t.Fatal("read lock was available during publication cleanup")
	}
	if store.mutationMu.TryLock() {
		store.mutationMu.Unlock()
		t.Fatal("write lock was available during publication cleanup")
	}

	type operationResult struct {
		name string
		err  error
	}
	operations := []struct {
		name string
		run  func() error
	}{
		{
			name: "inventory",
			run: func() error {
				_, err := store.Inventory(context.Background(), object)
				return err
			},
		},
		{
			name: "open",
			run: func() error {
				reader, _, err := store.OpenVersion(context.Background(), object, metadata)
				if reader != nil {
					return errors.Join(errors.New("OpenVersion() returned a reader"), reader.Close())
				}
				return err
			},
		},
		{
			name: "stat",
			run: func() error {
				_, err := store.StatVersion(context.Background(), object, metadata)
				return err
			},
		},
		{
			name: "delete",
			run: func() error {
				return store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
			},
		},
		{
			name: "retry put if absent",
			run: func() error {
				_, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
				return err
			},
		},
	}
	started := make(chan struct{}, len(operations))
	results := make(chan operationResult, len(operations))
	for _, operation := range operations {
		go func() {
			started <- struct{}{}
			results <- operationResult{name: operation.name, err: operation.run()}
		}()
	}
	for range operations {
		<-started
	}
	select {
	case result := <-results:
		t.Fatalf("%s returned during publication cleanup: %v", result.name, result.err)
	default:
	}

	close(releasePublicationCleanup)
	<-stagingCleanupStarted
	select {
	case result := <-results:
		t.Fatalf("%s returned during staging cleanup: %v", result.name, result.err)
	default:
	}
	close(releaseStagingCleanup)

	if err := <-putResult; !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("PutIfAbsent() cleanup error = %v", err)
	}
	for range operations {
		result := <-results
		if !errors.Is(result.err, artifactstorage.ErrAmbiguous) {
			t.Errorf("%s after cleanup error = %v", result.name, result.err)
		}
	}
}

func TestLocalStoreCapacityReservationIsAtomicAcrossDistinctKeys(t *testing.T) {
	store, _ := openLocalTestStore(t)
	defer store.Close()
	content := bytes.Repeat([]byte("capacity"), 1024)
	firstObject := testObjectWithKey(content, "first-key")
	secondObject := testObjectWithKey(content, "second-key")
	reservation := int64(len(content) + headerSize)
	store.operations.availableBytes = func(*os.File) (int64, error) { return reservation, nil }
	started := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		_, err := store.PutIfAbsent(context.Background(), firstObject, &blockingReader{
			Reader: bytes.NewReader(content), started: started, release: release,
		})
		firstResult <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first upload did not claim its capacity reservation")
	}
	if _, err := store.PutIfAbsent(context.Background(), secondObject, bytes.NewReader(content)); err == nil ||
		!strings.Contains(err.Error(), "capacity floor") {
		t.Fatalf("second distinct-key PutIfAbsent() error = %v", err)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first PutIfAbsent() error = %v", err)
	}
	firstInventory, err := store.Inventory(context.Background(), firstObject)
	if err != nil || len(firstInventory) != 1 {
		t.Fatalf("first Inventory() = %#v, error=%v", firstInventory, err)
	}
	secondInventory, err := store.Inventory(context.Background(), secondObject)
	if err != nil || len(secondInventory) != 0 {
		t.Fatalf("capacity-denied Inventory() = %#v, error=%v", secondInventory, err)
	}
}

func TestLocalStoreExactRetryReconcilesBeforeCapacityAdmission(t *testing.T) {
	store, _ := openLocalTestStore(t)
	defer store.Close()
	content := []byte("already durable")
	object := testObject(content)
	want, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	store.operations.availableBytes = func(*os.File) (int64, error) { return 0, nil }
	got, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if !errors.Is(err, artifactstorage.ErrAlreadyExists) || !metadataEqual(got, want) {
		t.Fatalf("low-space exact retry metadata=%#v error=%v", got, err)
	}
}

func TestLocalStoreRejectsFIFOAndDeviceSymlinkWithoutOpening(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("special")
	fifoObject := testObjectWithKey(content, "fifo-key")
	fifoPath := filepath.Join(config.ArtifactRoot, objectName(fifoObject.Key))
	if err := unix.Mkfifo(fifoPath, objectMode); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := store.Inventory(ctx, fifoObject)
		finished <- err
	}()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("Inventory() accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("Inventory() blocked while inspecting a FIFO")
	}

	deviceObject := testObjectWithKey(content, "device-key")
	devicePath := filepath.Join(config.ArtifactRoot, objectName(deviceObject.Key))
	if err := os.Symlink("/dev/null", devicePath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inventory(context.Background(), deviceObject); err == nil {
		t.Fatal("Inventory() followed a device symlink")
	}
}

func TestLocalStoreRejectsStagingNameSwapWithoutDeletingUnprovenEntry(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("descriptor identity")
	object := testObject(content)
	defaultOperations := store.operations
	store.operations.link = func(oldDirectory int, oldName string, newDirectory int, newName string, flags int) error {
		if err := unix.Unlinkat(oldDirectory, oldName, 0); err != nil {
			return err
		}
		if err := unix.Symlinkat(config.ArtifactRoot, oldDirectory, oldName); err != nil {
			return err
		}
		return defaultOperations.link(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if _, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content)); err == nil {
		t.Fatal("PutIfAbsent() accepted a substituted staging symlink")
	} else if !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("staging-swap PutIfAbsent() error = %v", err)
	}
	substitutedPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	info, err := os.Lstat(substitutedPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("unproven substituted publication was deleted or followed: info=%v error=%v", info, err)
	}
	if _, err := store.Inventory(context.Background(), object); err == nil {
		t.Fatal("Inventory() accepted the unproven substituted publication")
	}
}

func TestLocalStoreDeleteRefusesSubstitutedPath(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("exact deletion identity")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	savedPath := objectPath + ".saved"
	var hookErr error
	var swap sync.Once
	store.operations.beforeIdentityUnlink = func(root *os.File, name string) {
		if root != store.artifactRoot || name != objectName(object.Key) {
			return
		}
		swap.Do(func() {
			if err := os.Rename(objectPath, savedPath); err != nil {
				hookErr = err
				return
			}
			hookErr = os.WriteFile(objectPath, []byte("replacement"), objectMode)
		})
	}
	err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
	if hookErr != nil {
		t.Fatalf("substitution hook error = %v", hookErr)
	}
	if !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("DeleteVersion() substitution error = %v", err)
	}
	for _, retained := range []string{objectPath, savedPath} {
		if _, statErr := os.Lstat(retained); statErr != nil {
			t.Fatalf("DeleteVersion() removed unproven path %s: %v", retained, statErr)
		}
	}
}

func TestLocalStoreDeleteRefusesNewUnrecognizedHardlink(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("single-link deletion authority")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	extraPath := filepath.Join(filepath.Dir(config.ArtifactRoot), "late-hardlink")
	var hookErr error
	var createLink sync.Once
	store.operations.beforeIdentityUnlink = func(root *os.File, name string) {
		if root == store.artifactRoot && name == objectName(object.Key) {
			createLink.Do(func() { hookErr = os.Link(objectPath, extraPath) })
		}
	}
	err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
	if hookErr != nil {
		t.Fatalf("hardlink hook error = %v", hookErr)
	}
	if !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("DeleteVersion() hardlink error = %v", err)
	}
	for _, retained := range []string{objectPath, extraPath} {
		if _, statErr := os.Lstat(retained); statErr != nil {
			t.Fatalf("DeleteVersion() removed hard-link artifact %s: %v", retained, statErr)
		}
	}
}

func TestLocalStoreDeleteRefusesPostValidationSubstitution(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("post-validation deletion identity")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	savedPath := objectPath + ".validated"
	var hookErr error
	var swap sync.Once
	store.operations.afterIdentityCheck = func(root *os.File, name string) {
		if root != store.artifactRoot || name != objectName(object.Key) {
			return
		}
		swap.Do(func() {
			if err := os.Rename(objectPath, savedPath); err != nil {
				hookErr = err
				return
			}
			hookErr = os.WriteFile(objectPath, []byte("replacement"), objectMode)
		})
	}
	err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
	if hookErr != nil {
		t.Fatalf("post-validation substitution hook error = %v", hookErr)
	}
	if !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("DeleteVersion() post-validation substitution error = %v", err)
	}
	for _, retained := range []string{objectPath, savedPath} {
		if _, statErr := os.Lstat(retained); statErr != nil {
			t.Fatalf("DeleteVersion() removed post-validation path %s: %v", retained, statErr)
		}
	}
	actual, readErr := os.ReadFile(objectPath)
	if readErr != nil || string(actual) != "replacement" {
		t.Fatalf("DeleteVersion() did not restore replacement: bytes=%q error=%v", actual, readErr)
	}
}

func TestLocalStoreDeleteQuarantineMovePreservesDestinationCollision(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("quarantine move collision")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	original, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	collisionContent := []byte("existing quarantine destination")
	defaultRename := store.operations.renameNoReplace
	var collisionPath string
	store.operations.renameNoReplace = func(oldRoot *os.File, oldName string, newRoot *os.File, newName string) error {
		collisionPath = filepath.Join(config.ArtifactRoot, newName)
		if err := os.WriteFile(collisionPath, collisionContent, objectMode); err != nil {
			return err
		}
		return defaultRename(oldRoot, oldName, newRoot, newName)
	}

	err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("DeleteVersion() quarantine collision error = %v", err)
	}
	assertFileContent(t, objectPath, original)
	assertFileContent(t, collisionPath, collisionContent)
}

func TestLocalStoreDeleteRestorePreservesDestinationCollision(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("restore collision")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	artifactContent, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	collisionContent := []byte("existing restored destination")
	unlinkFailure := errors.New("injected quarantine unlink failure")
	store.operations.unlink = func(int, string, int) error { return unlinkFailure }
	defaultRename := store.operations.renameNoReplace
	renames := 0
	var quarantinePath string
	store.operations.renameNoReplace = func(oldRoot *os.File, oldName string, newRoot *os.File, newName string) error {
		renames++
		if renames == 1 {
			quarantinePath = filepath.Join(config.ArtifactRoot, newName)
			return defaultRename(oldRoot, oldName, newRoot, newName)
		}
		if err := os.WriteFile(objectPath, collisionContent, objectMode); err != nil {
			return err
		}
		return defaultRename(oldRoot, oldName, newRoot, newName)
	}

	err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
	if !errors.Is(err, unlinkFailure) || !errors.Is(err, unix.EEXIST) {
		t.Fatalf("DeleteVersion() restoration collision error = %v", err)
	}
	if renames != 2 {
		t.Fatalf("DeleteVersion() rename calls = %d, want 2", renames)
	}
	assertFileContent(t, objectPath, collisionContent)
	assertFileContent(t, quarantinePath, artifactContent)
}

func TestLocalStoreFailsClosedAfterDeleteRollbackFailure(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Store, artifactstorage.Object, artifactstorage.Metadata, []byte) error
	}{
		{
			name: "inventory",
			run: func(store *Store, object artifactstorage.Object, _ artifactstorage.Metadata, _ []byte) error {
				_, err := store.Inventory(context.Background(), object)
				return err
			},
		},
		{
			name: "put if absent",
			run: func(store *Store, object artifactstorage.Object, _ artifactstorage.Metadata, content []byte) error {
				_, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
				return err
			},
		},
		{
			name: "get through open version",
			run: func(store *Store, object artifactstorage.Object, metadata artifactstorage.Metadata, _ []byte) error {
				reader, _, err := store.OpenVersion(context.Background(), object, metadata)
				if reader != nil {
					return errors.Join(errors.New("OpenVersion() returned a reader from an ambiguous store"), reader.Close())
				}
				return err
			},
		},
		{
			name: "get through stat version",
			run: func(store *Store, object artifactstorage.Object, metadata artifactstorage.Metadata, _ []byte) error {
				_, err := store.StatVersion(context.Background(), object, metadata)
				return err
			},
		},
		{
			name: "delete",
			run: func(store *Store, object artifactstorage.Object, metadata artifactstorage.Metadata, _ []byte) error {
				return store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, config := openLocalTestStore(t)
			t.Cleanup(func() { _ = store.Close() })
			content := []byte("hidden after failed rollback")
			object := testObject(content)
			metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
			if err != nil {
				t.Fatal(err)
			}

			defaultOperations := store.operations
			unlinkFailure := errors.New("injected quarantine unlink failure")
			rollbackFailure := errors.New("injected quarantine rollback failure")
			store.operations.unlink = func(int, string, int) error { return unlinkFailure }
			renames := 0
			var quarantinePath string
			rollbackStarted := make(chan struct{})
			releaseRollback := make(chan struct{})
			store.operations.renameNoReplace = func(oldRoot *os.File, oldName string, newRoot *os.File, newName string) error {
				renames++
				if renames == 2 {
					close(rollbackStarted)
					<-releaseRollback
					return rollbackFailure
				}
				quarantinePath = filepath.Join(config.ArtifactRoot, newName)
				return defaultOperations.renameNoReplace(oldRoot, oldName, newRoot, newName)
			}

			deleteResult := make(chan error, 1)
			go func() {
				deleteResult <- store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
			}()
			<-rollbackStarted
			operationStarted := make(chan struct{})
			operationResult := make(chan error, 1)
			go func() {
				close(operationStarted)
				operationResult <- test.run(store, object, metadata, content)
			}()
			<-operationStarted
			select {
			case err := <-operationResult:
				t.Fatalf("operation returned during rollback with error %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			close(releaseRollback)

			err = <-deleteResult
			if !errors.Is(err, unlinkFailure) || !errors.Is(err, rollbackFailure) || !errors.Is(err, artifactstorage.ErrAmbiguous) {
				t.Fatalf("DeleteVersion() rollback error = %v", err)
			}
			if _, err := os.Lstat(filepath.Join(config.ArtifactRoot, objectName(object.Key))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("normal object path after failed rollback error = %v", err)
			}
			if _, err := os.Lstat(quarantinePath); err != nil {
				t.Fatalf("hidden quarantine after failed rollback error = %v", err)
			}

			if err := <-operationResult; !errors.Is(err, artifactstorage.ErrAmbiguous) {
				t.Fatalf("operation after failed rollback error = %v", err)
			}
		})
	}
}

func TestLocalStoreStaleCleanupRefusesSubstitutedPath(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	name := temporaryPrefix + strings.Repeat("d", 32)
	path := filepath.Join(config.StagingRoot, name)
	savedPath := path + ".saved"
	if err := os.WriteFile(path, []byte("stale"), objectMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.stagingRoot.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	var hookErr error
	var swap sync.Once
	store.operations.beforeIdentityUnlink = func(root *os.File, candidate string) {
		if root != store.stagingRoot || candidate != name {
			return
		}
		swap.Do(func() {
			if err := os.Rename(path, savedPath); err != nil {
				hookErr = err
				return
			}
			hookErr = os.WriteFile(path, []byte("replacement"), objectMode)
		})
	}
	err := store.removeStaleTemporaryFiles()
	if hookErr != nil {
		t.Fatalf("substitution hook error = %v", hookErr)
	}
	if !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("removeStaleTemporaryFiles() substitution error = %v", err)
	}
	for _, retained := range []string{path, savedPath} {
		if _, statErr := os.Lstat(retained); statErr != nil {
			t.Fatalf("stale cleanup removed unproven path %s: %v", retained, statErr)
		}
	}
}

func TestLocalStoreProbeCleanupRefusesSubstitutedPath(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	var hookErr error
	var substitutedPath, savedPath string
	var swap sync.Once
	store.operations.beforeIdentityUnlink = func(root *os.File, name string) {
		if root != store.artifactRoot || !validProbeName(name) {
			return
		}
		swap.Do(func() {
			substitutedPath = filepath.Join(config.ArtifactRoot, name)
			savedPath = substitutedPath + ".saved"
			if err := os.Rename(substitutedPath, savedPath); err != nil {
				hookErr = err
				return
			}
			hookErr = os.WriteFile(substitutedPath, []byte("replacement"), objectMode)
		})
	}
	err := store.probe()
	if hookErr != nil {
		t.Fatalf("probe substitution hook error = %v", hookErr)
	}
	if !errors.Is(err, artifactstorage.ErrAmbiguous) {
		t.Fatalf("probe() substitution error = %v", err)
	}
	for _, retained := range []string{substitutedPath, savedPath} {
		if retained == "" {
			t.Fatal("probe cleanup did not reach the injected substitution")
		}
		if _, statErr := os.Lstat(retained); statErr != nil {
			t.Fatalf("probe cleanup removed unproven path %s: %v", retained, statErr)
		}
	}
}

func TestLocalStoreReconcilesAmbiguousPublicationAndDeletion(t *testing.T) {
	store, _ := openLocalTestStore(t)
	defer store.Close()
	content := []byte("commit-before-response-loss")
	object := testObject(content)
	defaultOperations := store.operations
	publicationSyncFailed := false
	store.operations.syncDirectory = func(directory *os.File) error {
		if directory == store.artifactRoot && !publicationSyncFailed {
			publicationSyncFailed = true
			return errors.New("injected publication fsync failure")
		}
		return defaultOperations.syncDirectory(directory)
	}
	if _, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content)); err == nil {
		t.Fatal("PutIfAbsent() hid an injected post-publication fsync failure")
	}
	store.operations = defaultOperations
	inventory, err := store.Inventory(context.Background(), object)
	if err != nil || len(inventory) != 1 || inventory[0].SHA256 != object.SHA256 {
		t.Fatalf("Inventory() did not reconcile committed publication: %#v, error=%v", inventory, err)
	}

	store.operations.syncDirectory = func(directory *os.File) error {
		if directory == store.artifactRoot {
			return errors.New("injected deletion fsync failure")
		}
		return defaultOperations.syncDirectory(directory)
	}
	if err := store.DeleteVersion(context.Background(), object, inventory[0]); err == nil {
		t.Fatal("DeleteVersion() hid an injected post-unlink fsync failure")
	}
	if _, err := store.Inventory(context.Background(), object); err == nil {
		t.Fatal("Inventory() claimed durable absence while parent fsync still failed")
	}
	store.operations = defaultOperations
	inventory, err = store.Inventory(context.Background(), object)
	if err != nil || len(inventory) != 0 {
		t.Fatalf("Inventory() did not resolve ambiguous deletion: %#v, error=%v", inventory, err)
	}
}

func TestLocalStoreAggregatesMutationCleanupErrors(t *testing.T) {
	t.Run("put rollback", func(t *testing.T) {
		store, _ := openLocalTestStore(t)
		defer store.Close()
		content := []byte("rollback errors")
		object := testObject(content)
		object.SHA256 = strings.Repeat("f", sha256.Size*2)
		unlinkFailure := errors.New("injected rollback unlink failure")
		closeFailure := errors.New("injected staging close failure")
		store.operations.unlink = func(int, string, int) error { return unlinkFailure }
		store.operations.closeFile = func(file *os.File) error {
			return errors.Join(file.Close(), closeFailure)
		}
		_, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
		if !errors.Is(err, artifactstorage.ErrConflict) || !errors.Is(err, unlinkFailure) || !errors.Is(err, closeFailure) {
			t.Fatalf("PutIfAbsent() joined error = %v", err)
		}
	})

	t.Run("put rollback sync", func(t *testing.T) {
		store, _ := openLocalTestStore(t)
		defer store.Close()
		content := []byte("rollback sync")
		object := testObject(content)
		object.SHA256 = strings.Repeat("f", sha256.Size*2)
		syncFailure := errors.New("injected staging sync failure")
		defaults := store.operations
		store.operations.syncDirectory = func(directory *os.File) error {
			if directory == store.stagingRoot {
				return syncFailure
			}
			return defaults.syncDirectory(directory)
		}
		_, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
		if !errors.Is(err, artifactstorage.ErrConflict) || !errors.Is(err, syncFailure) {
			t.Fatalf("PutIfAbsent() joined error = %v", err)
		}
	})

	t.Run("delete close and parent sync", func(t *testing.T) {
		store, _ := openLocalTestStore(t)
		defer store.Close()
		content := []byte("delete cleanup errors")
		object := testObject(content)
		metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		closeFailure := errors.New("injected delete close failure")
		syncFailure := errors.New("injected delete parent sync failure")
		store.operations.closeFile = func(file *os.File) error {
			return errors.Join(file.Close(), closeFailure)
		}
		store.operations.syncDirectory = func(*os.File) error { return syncFailure }
		err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
		if !errors.Is(err, closeFailure) || !errors.Is(err, syncFailure) {
			t.Fatalf("DeleteVersion() joined error = %v", err)
		}
	})

	t.Run("delete primary close and parent sync", func(t *testing.T) {
		store, _ := openLocalTestStore(t)
		defer store.Close()
		content := []byte("delete joined primary error")
		object := testObject(content)
		metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		unlinkFailure := errors.New("injected delete unlink failure")
		closeFailure := errors.New("injected delete close failure")
		syncFailure := errors.New("injected delete parent sync failure")
		rollbackFailure := errors.New("injected delete rollback failure")
		defaultRename := store.operations.renameNoReplace
		store.operations.unlink = func(int, string, int) error { return unlinkFailure }
		renames := 0
		store.operations.renameNoReplace = func(oldRoot *os.File, oldName string, newRoot *os.File, newName string) error {
			renames++
			if renames == 2 {
				return rollbackFailure
			}
			return defaultRename(oldRoot, oldName, newRoot, newName)
		}
		store.operations.closeFile = func(file *os.File) error {
			return errors.Join(file.Close(), closeFailure)
		}
		store.operations.syncDirectory = func(*os.File) error { return syncFailure }
		err = store.DeleteVersion(context.Background(), object, versionFromMetadata(metadata))
		if !errors.Is(err, unlinkFailure) || !errors.Is(err, rollbackFailure) ||
			!errors.Is(err, closeFailure) || !errors.Is(err, syncFailure) {
			t.Fatalf("DeleteVersion() joined primary error = %v", err)
		}
	})
}

func TestLocalStoreCapacityFloorDeniesBeforePublication(t *testing.T) {
	config := localTestConfig(t)
	config.MaximumObjectBytes = 1024
	config.MinimumFreeBytes = (1 << 63) - 1 - headerSize - config.MaximumObjectBytes
	if err := ProvisionSentinels(config); err != nil {
		t.Fatal(err)
	}
	store, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	content := []byte("bounded")
	object := testObject(content)
	if _, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content)); err == nil {
		t.Fatal("PutIfAbsent() ignored the configured free-space floor")
	}
	inventory, err := store.Inventory(context.Background(), object)
	if err != nil || len(inventory) != 0 {
		t.Fatalf("capacity-denied object was published: %#v, error=%v", inventory, err)
	}
}

func TestLocalStoreRejectsSymlinkedRootAndRecognizedStaleSymlink(t *testing.T) {
	config := localTestConfig(t)
	if err := ProvisionSentinels(config); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(filepath.Dir(config.ArtifactRoot), "linked-artifacts")
	if err := os.Symlink(config.ArtifactRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	linked := config
	linked.ArtifactRoot = linkedRoot
	if _, err := Open(linked); err == nil {
		t.Fatal("Open() followed a symlinked root component")
	}

	stale := filepath.Join(config.StagingRoot, temporaryPrefix+strings.Repeat("c", 32))
	if err := os.Symlink(config.ArtifactRoot, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config); err == nil {
		t.Fatal("Open() followed or removed a recognized-name staging symlink")
	}
}

func TestLocalStoreRejectsUnrecognizedHardlinkAndWidenedMode(t *testing.T) {
	store, config := openLocalTestStore(t)
	defer store.Close()
	content := []byte("private")
	object := testObject(content)
	metadata, err := store.PutIfAbsent(context.Background(), object, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(config.ArtifactRoot, objectName(object.Key))
	extraLink := filepath.Join(filepath.Dir(config.ArtifactRoot), "unrecognized-hardlink")
	if err := os.Link(objectPath, extraLink); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StatVersion(context.Background(), object, metadata); !errors.Is(err, artifactstorage.ErrConflict) {
		t.Fatalf("hard-link StatVersion() error = %v", err)
	}
	if err := os.Remove(extraLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(objectPath, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StatVersion(context.Background(), object, metadata); err == nil {
		t.Fatal("StatVersion() accepted widened object permissions")
	}
}

func TestLocalConfigRejectsNestedRoots(t *testing.T) {
	config := localTestConfig(t)
	config.StagingRoot = filepath.Join(config.ArtifactRoot, "staging")
	if err := os.Mkdir(config.StagingRoot, rootMode); err != nil {
		t.Fatal(err)
	}
	if _, err := config.validate(); err == nil {
		t.Fatal("Config accepted nested publication roots")
	}
}

func TestDescriptorAndCapacityConversionsRejectInvalidValues(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "closed-descriptor-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fileDescriptor(file); err == nil {
		t.Fatal("fileDescriptor() accepted a closed file")
	}
	if _, err := fileFromDescriptor(-1, "invalid"); err == nil {
		t.Fatal("fileFromDescriptor() accepted a negative descriptor")
	}

	tests := []struct {
		name      string
		blockSize uint64
		blocks    uint64
		valid     bool
	}{
		{name: "valid", blockSize: 4096, blocks: 1024, valid: true},
		{name: "zero block size", blocks: 1},
		{name: "block size overflow", blockSize: 1 << 63, blocks: 1},
		{name: "product overflow", blockSize: 2, blocks: 1 << 62},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := availableCapacity(test.blockSize, test.blocks)
			if (err == nil) != test.valid {
				t.Fatalf("availableCapacity() error = %v, valid want %t", err, test.valid)
			}
		})
	}
}

func localTestConfig(t *testing.T) Config {
	t.Helper()
	parent := t.TempDir()
	parent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		t.Fatal(err)
	}
	artifactRoot := filepath.Join(parent, "artifacts")
	stagingRoot := filepath.Join(parent, "staging")
	if err := os.Mkdir(artifactRoot, rootMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stagingRoot, rootMode); err != nil {
		t.Fatal(err)
	}
	return Config{
		ExplicitlyEnabled: true, PrivateRootAcknowledged: true,
		ArtifactRoot: artifactRoot, StagingRoot: stagingRoot,
		InstanceID: "pvc-test-0123456789abcdef", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(),
		ServingReplicas: 1, AccessMode: AccessModeReadWriteOnce, DeploymentStrategy: StrategyRecreate,
		EncryptionAcknowledged: true, SnapshotPolicy: SnapshotsProhibited,
		MaximumObjectBytes: defaultMaximumObjectBytes, MinimumFreeBytes: 0,
		Now: func() time.Time { return time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC) },
	}
}

func openLocalTestStore(t *testing.T) (*Store, Config) {
	t.Helper()
	config := localTestConfig(t)
	if err := ProvisionSentinels(config); err != nil {
		t.Fatalf("ProvisionSentinels() error = %v", err)
	}
	store, err := Open(config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store, config
}

func testObject(content []byte) artifactstorage.Object {
	return testObjectWithKey(content, "opaque-key")
}

func testObjectWithKey(content []byte, key string) artifactstorage.Object {
	contentDigest := sha256.Sum256(content)
	keyDigest := sha256.Sum256([]byte(key))
	bindingDigest := sha256.Sum256([]byte("runtime-binding"))
	return artifactstorage.Object{
		Key: hex.EncodeToString(keyDigest[:]), RuntimeBindingDigest: hex.EncodeToString(bindingDigest[:]),
		Size: int64(len(content)), SHA256: hex.EncodeToString(contentDigest[:]),
	}
}

func assertFileContent(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retained file %q: %v", path, err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("retained file %q = %q, want %q", path, actual, expected)
	}
}

type blockingReader struct {
	*bytes.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (reader *blockingReader) Read(value []byte) (int, error) {
	reader.once.Do(func() {
		close(reader.started)
		<-reader.release
	})
	return reader.Reader.Read(value)
}
