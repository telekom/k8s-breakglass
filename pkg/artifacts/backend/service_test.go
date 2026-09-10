// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"encoding/json"
	"errors"
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
	backendID string
	versions  []storage.Version
	opened    bool
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
func (store *fakeStore) StatVersion(context.Context, storage.Object, storage.Metadata) (storage.Metadata, error) {
	return storage.Metadata{}, storage.ErrNotFound
}
func (store *fakeStore) Inventory(context.Context, storage.Object) ([]storage.Version, error) {
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
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", SessionUID: "uid", TargetIdentityDigest: "target", OperationEpoch: 2, State: StateAvailable, ExpiresAt: time.Unix(200, 0), Size: 1, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RuntimeBindingDigest: "binding"}}
	store := &fakeStore{backendID: "backend"}
	service := newServiceForTest(t, repository, store, allowAuthorizer{})
	_, _, err := service.Download(context.Background(), "ns", "session", repository.record.ArtifactID, SessionBinding{UID: "other", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.ErrorIs(t, err, ErrForbidden)
	require.False(t, store.opened)
}

func TestCleanupPendingArtifactNeedsNoProviderObject(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", State: StatePending, Generation: 1}}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	require.NoError(t, service.Cleanup(context.Background(), repository.record, StateExpired))
	require.Equal(t, StateExpired, repository.record.State)
}

func TestCleanupRetainsAmbiguousProviderIdentity(t *testing.T) {
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", ArtifactID: "dsa-0123456789abcdef01234567", RuntimeBindingDigest: "binding", State: StateAvailable, Generation: 1, Size: 4, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
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
	repository := &memoryRepository{record: Record{Namespace: "ns", SessionName: "session", SessionUID: "uid", ArtifactID: "dsa-0123456789abcdef01234567", TargetIdentityDigest: "target", OperationEpoch: 2, State: StateAvailable, ExpiresAt: time.Unix(200, 0), Size: 4, SHA256: strings.Repeat("a", 64)}}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	public, err := service.List(context.Background(), "ns", "session", SessionBinding{Namespace: "ns", Name: "session", UID: "uid", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.NoError(t, err)
	require.Len(t, public, 1)
	require.Equal(t, repository.record.ArtifactID, public[0].ArtifactID)
	public, err = service.List(context.Background(), "ns", "session", SessionBinding{Namespace: "ns", Name: "session", UID: "other", TargetIdentityDigest: "target", OperationEpoch: 2})
	require.NoError(t, err)
	require.Empty(t, public)
}
