// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
)

// TCAAS-1627 acceptance: cross-session denial and upload-token replay/expiry.
// Every negative asserts the provider is never touched and the record is
// unchanged, so removing the enforcement makes these tests fail.

func uploadFixture(session string) (Record, token.Claims) {
	record := Record{Namespace: "ns", SessionName: session, SessionUID: "uid-" + session, ArtifactID: "dsa-0123456789abcdef01234567", ArtifactUID: "artifact-uid-" + session, TargetIdentityDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), PlanDigest: strings.Repeat("c", 64), Recipe: "system-summary.v1", RecipeVersion: 1, ExpiresAt: time.Unix(200, 0), MaxBytes: 1 << 20, OperationEpoch: 1, UploadJTI: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), State: StatePending, Generation: 1}
	claims := token.Claims{JTI: record.UploadJTI, IssuedAt: time.Unix(100, 0), NotBefore: time.Unix(100, 0), ExpiresAt: time.Unix(150, 0), Method: http.MethodPut, SessionNamespace: record.Namespace, SessionName: record.SessionName, SessionUID: record.SessionUID, ArtifactID: record.ArtifactID, ArtifactPlanDigest: record.PlanDigest, RuntimeBindingDigest: record.RuntimeBindingDigest, OperationEpoch: 1, TargetIdentityDigest: record.TargetIdentityDigest, Recipe: record.Recipe, RecipeVersion: 1}
	claims.Route = token.CanonicalUploadRoute(claims)
	return record, claims
}

func TestUploadTokenOfSessionACannotWriteSessionB(t *testing.T) {
	recordA, claimsA := uploadFixture("session-a")
	recordB, claimsB := uploadFixture("session-b")
	repository := &memoryRepository{record: recordB}
	store := &fakeStore{backendID: "backend"}
	service := newServiceForTest(t, repository, store, allowAuthorizer{})
	signedA, err := service.tokens.Sign(claimsA)
	require.NoError(t, err)
	require.NotEqual(t, recordA.SessionName, recordB.SessionName)
	// A's token against B's route.
	_, err = service.Upload(context.Background(), signedA, claimsB.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrForbidden)
	// A's token against A's route resolves to no record in B's repository.
	_, err = service.Upload(context.Background(), signedA, claimsA.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrForbidden)
	require.Equal(t, StatePending, repository.record.State)
	require.Zero(t, repository.updates, "a cross-session token must not move the victim record")
}

func TestUploadTokenWithForeignSessionUIDIsForbidden(t *testing.T) {
	record, claims := uploadFixture("session-a")
	repository := &memoryRepository{record: record}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	// Same names/route, but the token was minted for another incarnation of the session.
	claims.SessionUID = "uid-other-incarnation"
	signed, err := service.tokens.Sign(claims)
	require.NoError(t, err)
	_, err = service.Upload(context.Background(), signed, claims.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrForbidden)
	require.Zero(t, repository.updates)
}

func TestSessionACannotListOrDownloadSessionBArtifacts(t *testing.T) {
	record, _ := uploadFixture("session-b")
	record.State = StateAvailable
	repository := &memoryRepository{record: record}
	store := &fakeStore{backendID: "backend"}
	service := newServiceForTest(t, repository, store, allowAuthorizer{})
	binding := SessionBinding{Namespace: "ns", Name: "session-a", UID: "uid-session-a", TargetIdentityDigest: record.TargetIdentityDigest, OperationEpoch: 1}
	public, err := service.List(context.Background(), "ns", "session-b", binding)
	require.ErrorIs(t, err, ErrForbidden)
	require.Empty(t, public, "session A must not see session B metadata")
	// Same names but a different session incarnation (UID) sees nothing either.
	binding.Name, binding.UID = "session-b", "uid-other"
	public, err = service.List(context.Background(), "ns", "session-b", binding)
	require.NoError(t, err)
	require.Empty(t, public)
	binding.Name, binding.UID = "session-a", "uid-session-a"
	_, _, err = service.Download(context.Background(), "ns", "session-b", record.ArtifactID, binding)
	require.ErrorIs(t, err, ErrForbidden)
	require.False(t, store.opened, "provider must not be read for a foreign session")
}

func TestUploadTokenExpiredIsRejectedWithoutSideEffects(t *testing.T) {
	record, claims := uploadFixture("session-a")
	claims.IssuedAt, claims.NotBefore, claims.ExpiresAt = time.Unix(10, 0), time.Unix(10, 0), time.Unix(50, 0) // service clock is 100
	claims.Route = token.CanonicalUploadRoute(claims)
	repository := &memoryRepository{record: record}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	signed, err := service.tokens.Sign(claims)
	require.NoError(t, err)
	_, err = service.Upload(context.Background(), signed, claims.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrForbidden)
	require.Equal(t, StatePending, repository.record.State)
	require.Zero(t, repository.updates)
}

func TestUploadRejectsStaleJTIAndConsumedTokens(t *testing.T) {
	record, claims := uploadFixture("session-a")
	repository := &memoryRepository{record: record}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	stale := claims
	stale.JTI = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	signed, err := service.tokens.Sign(stale)
	require.NoError(t, err)
	_, err = service.Upload(context.Background(), signed, stale.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrForbidden, "a validly signed token whose JTI is not the reserved one is a replay of an older lease")
	require.Zero(t, repository.updates)

	valid, err := service.tokens.Sign(claims)
	require.NoError(t, err)
	repository.record.State = StateAvailable
	_, err = service.Upload(context.Background(), valid, claims.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrReplay)
	repository.record.State = StateUploading
	_, err = service.Upload(context.Background(), valid, claims.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrConflict, "concurrent reuse while an upload is in flight is rejected")
	require.Zero(t, repository.updates)
}

func TestUploadAfterReservationExpiryIsRejected(t *testing.T) {
	record, claims := uploadFixture("session-a")
	record.ExpiresAt = time.Unix(100, 0) // equals the service clock: no remaining lifetime
	repository := &memoryRepository{record: record}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	signed, err := service.tokens.Sign(claims)
	require.NoError(t, err)
	_, err = service.Upload(context.Background(), signed, claims.Route, bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrExpired)
	require.Zero(t, repository.updates)
}

func TestUploadTokenCannotBeReplayedOnAnotherArtifactRoute(t *testing.T) {
	record, claims := uploadFixture("session-a")
	repository := &memoryRepository{record: record}
	service := newServiceForTest(t, repository, &fakeStore{backendID: "backend"}, allowAuthorizer{})
	signed, err := service.tokens.Sign(claims)
	require.NoError(t, err)
	other := claims
	other.SessionName = "session-b"
	_, err = service.Upload(context.Background(), signed, token.CanonicalUploadRoute(other), bytes.NewReader([]byte("x")))
	require.ErrorIs(t, err, ErrForbidden)
	require.Zero(t, repository.updates, "the token's route claim must bind the request path")
}
