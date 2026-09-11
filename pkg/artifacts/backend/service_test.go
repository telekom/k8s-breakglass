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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
)

type memoryRepository struct {
	record  Record
	updates int
}

func (repository *memoryRepository) Get(_ context.Context, namespace, session, artifact string) (Record, error) {
	if repository.record.Namespace != namespace || repository.record.SessionName != session || repository.record.ArtifactID != artifact {
		return Record{}, storage.ErrNotFound
	}
	return repository.record, nil
}

func (repository *memoryRepository) Update(_ context.Context, record Record, expected int64) error {
	if repository.record.Generation != expected {
		return ErrConflict
	}
	repository.record = record
	repository.updates++
	return nil
}

func (repository *memoryRepository) ListBySession(context.Context, string, string, string) ([]Record, error) {
	return []Record{repository.record}, nil
}

type fakeStore struct {
	backendID         string
	versions          []storage.Version
	inventoryCalls    int
	inventorySequence [][]storage.Version
	opened            bool
}

func (store *fakeStore) Backend() string           { return storage.BackendLocal }
func (store *fakeStore) BackendInstanceID() string { return store.backendID }
func (store *fakeStore) PutIfAbsent(context.Context, storage.Object, io.Reader) (storage.Metadata, error) {
	return storage.Metadata{}, errors.New("unexpected put")
}
func (store *fakeStore) OpenVersion(context.Context, storage.Object, storage.Metadata) (io.ReadCloser, storage.Metadata, error) {
	store.opened = true
	return io.NopCloser(nilReader{}), storage.Metadata{}, nil
}
func (store *fakeStore) StatVersion(_ context.Context, _ storage.Object, expected storage.Metadata) (storage.Metadata, error) {
	if expected.VersionID != "" {
		return expected, nil
	}
	return storage.Metadata{}, storage.ErrNotFound
}
func (store *fakeStore) Inventory(context.Context, storage.Object) ([]storage.Version, error) {
	store.inventoryCalls++
	if len(store.inventorySequence) > 0 {
		index := store.inventoryCalls - 1
		if index >= len(store.inventorySequence) {
			index = len(store.inventorySequence) - 1
		}
		return append([]storage.Version(nil), store.inventorySequence[index]...), nil
	}
	return append([]storage.Version(nil), store.versions...), nil
}
func (store *fakeStore) InventoryKey(context.Context, string) ([]storage.Version, error) {
	store.inventoryCalls++
	if len(store.inventorySequence) > 0 {
		index := store.inventoryCalls - 1
		if index >= len(store.inventorySequence) {
			index = len(store.inventorySequence) - 1
		}
		return append([]storage.Version(nil), store.inventorySequence[index]...), nil
	}
	return append([]storage.Version(nil), store.versions...), nil
}
func (store *fakeStore) DeleteVersion(context.Context, storage.Object, storage.Version) error {
	return nil
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

type allowAuthorizer struct{ err error }

func (authorizer allowAuthorizer) AuthorizeArtifact(context.Context, SessionBinding) error {
	return authorizer.err
}

func newServiceForTest(t *testing.T, repository Repository, store storage.Store, authorizer SessionAuthorizer) *Service {
	t.Helper()
	keyring, err := token.NewKeyring("breakglass", "artifact", "k1", []token.Key{{ID: "k1", Secret: []byte("01234567890123456789012345678901")}}, token.Limits{MaxTTL: time.Minute})
	require.NoError(t, err)
	service, err := New(Config{Repository: repository, Store: store, Authorizer: authorizer, Tokens: keyring, StagingDir: t.TempDir(), Now: func() time.Time { return time.Unix(100, 0).UTC() }})
	require.NoError(t, err)
	return service
}

func TestDownloadRejectsBindingMismatchBeforeProviderRead(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-1", SessionUID: "uid", TargetIdentityDigest: "target", OperationEpoch: 2, State: StateAvailable, ExpiresAt: time.Unix(200, 0), Size: 1, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RuntimeBindingDigest: "binding"}}
	store := &fakeStore{backendID: "backend"}
	service := newServiceForTest(t, repository, store, allowAuthorizer{})
	_, _, err := service.Download(context.Background(), "ns", "session", repository.record.ArtifactID, SessionBinding{Namespace: "ns", Name: "session", UID: "other", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.ErrorIs(t, err, ErrForbidden)
	require.False(t, store.opened)
}

func TestArtifactStorageKeyRequiresUIDAndIsOpaque(t *testing.T) {
	if _, err := artifactStorageKey(Record{ArtifactID: "public-id"}); err == nil {
		t.Fatal("artifactStorageKey accepted a record without immutable UID")
	}
	key, err := artifactStorageKey(Record{ArtifactID: "public-id", ArtifactUID: "uid-a"})
	require.NoError(t, err)
	require.NotEqual(t, "public-id", key)
	require.Len(t, key, 64)
}

func TestCleanupPendingArtifactNeedsNoProviderObject(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-1", State: StatePending, Generation: 1}}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	require.NoError(t, service.Cleanup(context.Background(), repository.record, StateExpired))
	require.Equal(t, StateExpired, repository.record.State)
}

func TestCleanupRetainsAmbiguousProviderIdentity(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-1", RuntimeBindingDigest: "binding", State: StateAvailable, Generation: 1, Size: 4, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	store := &fakeStore{backendID: "backend", versions: []storage.Version{{VersionID: "one", RuntimeBindingDigest: "other", Size: 4, SHA256: repository.record.SHA256}}}
	service := newServiceForTest(t, repository, store, allowAuthorizer{})
	require.ErrorIs(t, service.Cleanup(context.Background(), repository.record, StateRevoked), ErrConflict)
	require.Equal(t, StateUnknown, repository.record.State)
	require.True(t, repository.record.CleanupAmbiguous)
}

func TestPublicRecordOmitsProviderMetadata(t *testing.T) {
	record := Record{ArtifactID: "dsa-0123456789abcdef01234567", Recipe: "system-summary.v1", RecipeVersion: 1, State: StateAvailable, Size: 4, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Unix(200, 0), Metadata: storage.Metadata{Key: "private/provider/key", VersionID: "provider-version"}}
	service := newServiceForTest(t, &memoryRepository{}, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	public := service.Public(record)
	require.Equal(t, record.ArtifactID, public.ArtifactID)
	encoded, err := json.Marshal(public)
	require.NoError(t, err)
	require.NotContains(t, strings.ToLower(string(encoded)), "provider")
}

func TestListRequiresLiveBindingAndReturnsOnlyBoundMetadata(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", SessionUID: "uid", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-1", TargetIdentityDigest: "target", OperationEpoch: 2, State: StateAvailable, ExpiresAt: time.Unix(200, 0), Size: 4, SHA256: strings.Repeat("a", 64)}}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	public, err := service.List(context.Background(), "ns", "session", SessionBinding{Namespace: "ns", Name: "session", UID: "uid", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.NoError(t, err)
	require.Len(t, public, 1)
	require.Equal(t, repository.record.ArtifactID, public[0].ArtifactID)
	public, err = service.List(context.Background(), "ns", "session", SessionBinding{Namespace: "ns", Name: "session", UID: "other", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.NoError(t, err)
	require.Empty(t, public)
}

func TestUploadClaimsBindPlanRuntimeAndRecipe(t *testing.T) {
	record := Record{PlanDigest: "plan", RuntimeBindingDigest: "runtime", Recipe: "system-summary.v1", RecipeVersion: 1}
	claims := token.Claims{ArtifactPlanDigest: "plan", RuntimeBindingDigest: "runtime", Recipe: "system-summary.v1", RecipeVersion: 1}
	require.NoError(t, validateUploadClaims(record, claims))
	claims.ArtifactPlanDigest = "other"
	require.ErrorIs(t, validateUploadClaims(record, claims), ErrForbidden)
}

func TestValidTransitionRejectsLifecycleResurrection(t *testing.T) {
	for _, test := range []struct {
		current State
		next    State
		valid   bool
	}{
		{StatePending, StateUploading, true},
		{StateUploading, StateAvailable, true},
		{StateAvailable, StateDeleting, true},
		{StateDeleting, StateDeleted, true},
		{StateUnknown, StateAvailable, false},
		{StateDeleted, StateAvailable, false},
		{StateExpired, StateDeleting, false},
	} {
		t.Run(string(test.current)+"-"+string(test.next), func(t *testing.T) {
			require.Equal(t, test.valid, ValidTransition(test.current, test.next))
		})
	}
}

func TestDownloadRechecksLiveArtifactStateBeforeEachRead(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-1", SessionUID: "uid", TargetIdentityDigest: "target", OperationEpoch: 2, State: StateAvailable, ExpiresAt: time.Unix(200, 0), Size: 1, SHA256: strings.Repeat("a", 64), RuntimeBindingDigest: "binding", Metadata: storage.Metadata{BackendInstanceID: "backend", Key: "dsa-0123456789abcdef01234567", VersionID: "version", RuntimeBindingDigest: "binding", Size: 1, SHA256: strings.Repeat("a", 64)}}}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	reader, _, err := service.Download(context.Background(), "ns", "session", repository.record.ArtifactID, SessionBinding{Namespace: "ns", Name: "session", UID: "uid", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.NoError(t, err)
	repository.record.State = StateRevoked
	_, err = reader.Read(make([]byte, 1))
	require.ErrorIs(t, err, ErrExpired)
	_ = reader.Close()
}

func TestCleanupRequiresTwoEmptyInventoriesAfterExactDelete(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-1", RuntimeBindingDigest: "binding", State: StateAvailable, Generation: 1, Size: 4, SHA256: strings.Repeat("a", 64)}}
	version := storage.Version{VersionID: "one", RuntimeBindingDigest: "binding", Size: 4, SHA256: repository.record.SHA256}
	store := &fakeStore{backendID: "backend", inventorySequence: [][]storage.Version{{version}, {}, {}}}
	service := newServiceForTest(t, repository, store, allowAuthorizer{})
	require.NoError(t, service.Cleanup(context.Background(), repository.record, StateDeleted))
	require.Equal(t, StateDeleted, repository.record.State)
	require.Equal(t, 3, store.inventoryCalls)
}

type callbackReadCloser struct{ read func([]byte) (int, error) }

func (reader callbackReadCloser) Read(buffer []byte) (int, error) { return reader.read(buffer) }
func (callbackReadCloser) Close() error                           { return nil }

func TestDownloadDiscardsBytesWhenIdentityChangesDuringProviderRead(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprint(replacement), func(t *testing.T) {
			repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "artifact", ArtifactUID: "original", SessionUID: "session-uid", TargetIdentityDigest: "target", OperationEpoch: 2, State: StateAvailable, ExpiresAt: time.Unix(200, 0)}}
			service := newServiceForTest(t, repository, &fakeStore{}, allowAuthorizer{})
			reader := &authorizedReadCloser{ctx: context.Background(), service: service, namespace: "ns", sessionName: "session", artifactID: "artifact", artifactUID: "original", binding: SessionBinding{Namespace: "ns", Name: "session", UID: "session-uid", TargetIdentityDigest: "target", OperationEpoch: 2}}
			reader.reader = callbackReadCloser{read: func(buffer []byte) (int, error) {
				n := copy(buffer, "secret")
				if replacement {
					repository.record.ArtifactUID = "replacement"
				} else {
					repository.record.State = StateRevoked
				}
				return n, nil
			}}
			buffer := make([]byte, 6)
			n, err := reader.Read(buffer)
			require.Error(t, err)
			require.Zero(t, n)
			require.Equal(t, make([]byte, 6), buffer)
		})
	}
}

func TestCleanupRetainsUnobservedPublicationIntent(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "uid", RuntimeBindingDigest: "binding", State: StateUploading, Generation: 1, Size: 4, SHA256: strings.Repeat("a", 64)}}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	require.ErrorIs(t, service.Cleanup(context.Background(), repository.record, StateDeleted), storage.ErrAmbiguous)
	require.Equal(t, StateUnknown, repository.record.State)
	require.True(t, repository.record.CleanupAmbiguous)
	require.Equal(t, int64(4), repository.record.Size)
}

type callbackAuthorizer func(context.Context, SessionBinding) error

func (authorize callbackAuthorizer) AuthorizeArtifact(ctx context.Context, binding SessionBinding) error {
	return authorize(ctx, binding)
}
func TestDirectMetadataListRechecksAuthorizationAfterRepositoryIO(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", SessionUID: "uid", TargetClusterUID: "cluster", TargetIdentityDigest: "target", OperationEpoch: 1}}
	calls := 0
	service := newServiceForTest(t, repository, &fakeStore{}, callbackAuthorizer(func(context.Context, SessionBinding) error {
		calls++
		if calls == 2 {
			return ErrForbidden
		}
		return nil
	}))
	records, err := service.List(context.Background(), "ns", "session", SessionBinding{Namespace: "ns", Name: "session", UID: "uid", TargetClusterUID: "cluster", TargetIdentityDigest: "target", OperationEpoch: 1})
	require.ErrorIs(t, err, ErrForbidden)
	require.Nil(t, records)
	require.Equal(t, 2, calls)
}

func TestStagePreservesBinaryPayloadAndDigest(t *testing.T) {
	service := newServiceForTest(t, &memoryRepository{}, &fakeStore{}, allowAuthorizer{})
	payload := []byte("<script>alert(1)</script>\x00\x1b[31m")
	file, size, digest, err := service.stage(context.Background(), bytes.NewReader(payload), int64(len(payload)))
	require.NoError(t, err)
	defer file.Close()
	staged, err := io.ReadAll(file)
	require.NoError(t, err)
	require.Equal(t, payload, staged)
	require.Equal(t, int64(len(payload)), size)
	expected := sha256.Sum256(payload)
	require.Equal(t, hex.EncodeToString(expected[:]), digest)
}

type bindingAuthorizerFunc func(context.Context, SessionBinding) error

func (f bindingAuthorizerFunc) AuthorizeArtifact(ctx context.Context, binding SessionBinding) error {
	return f(ctx, binding)
}

func TestListAuthorizedChecksCompleteArtifactBinding(t *testing.T) {
	record := Record{Namespace: "ns", SessionName: "session", SessionUID: "uid", ArtifactID: "dsa-0123456789abcdef01234567", TargetClusterUID: "cluster", TargetPodNamespace: "target", TargetPodName: "pod", TargetPodUID: "pod-uid", TargetNodeUID: "node-uid", ConnectionLeaseUID: "lease-uid", TargetIdentityDigest: "digest", OperationEpoch: 3}
	expected := SessionBinding{Namespace: "ns", Name: "session", UID: "uid", TargetClusterUID: "cluster", TargetPodNamespace: "target", TargetPodName: "pod", TargetPodUID: "pod-uid", TargetNodeUID: "node-uid", ConnectionLeaseUID: "lease-uid", TargetIdentityDigest: "digest", OperationEpoch: 3}
	for _, reject := range []bool{false, true} {
		service := newServiceForTest(t, &memoryRepository{record: record}, &fakeStore{}, bindingAuthorizerFunc(func(_ context.Context, binding SessionBinding) error {
			require.Equal(t, expected, binding)
			if reject {
				return ErrForbidden
			}
			return nil
		}))
		records, err := service.ListAuthorized(context.Background(), "ns", "session", "uid", func() error { return nil })
		require.NoError(t, err)
		if reject {
			require.Empty(t, records)
		} else {
			require.Len(t, records, 1)
			require.Equal(t, record.ArtifactID, records[0].ArtifactID)
		}
	}
}
