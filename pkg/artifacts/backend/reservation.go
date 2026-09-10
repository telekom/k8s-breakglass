// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
)

const maximumSessionReservations = 128
const MaximumRecordingBytes int64 = 512 << 20

type reservationCreator interface {
	Create(context.Context, Record) (Record, error)
}

// UploadReservationBinding is domain-separated from token signing and binds a
// reproducible nonce to the immutable reservation, never a requester credential.
func UploadReservationBinding(record Record) string {
	return record.ConnectionLeaseUID + "\x00" + record.ReservationNonce + "\x00" + record.Namespace + "\x00" + record.SessionName + "\x00" + record.SessionUID + "\x00" + record.ArtifactID + "\x00" + record.PlanDigest + "\x00" + strconv.FormatUint(record.OperationEpoch, 10)
}

// Reserve admits a server-resolved collector request. Only the host's trusted
// admission path may build Record; request credentials and locations are absent.
func (service *Service) Reserve(ctx context.Context, record Record) (Record, error) {
	if record.ConnectionLeaseUID == "" {
		return Record{}, ErrForbidden
	}
	if record.Recipe != archive.SystemSummaryRecipe && record.Recipe != archive.CrashdumpCollectionRecipe {
		return Record{}, ErrForbidden
	}
	return service.reserve(ctx, record, func(ctx context.Context) error {
		return service.authorizer.AuthorizeArtifact(ctx, SessionBinding{Namespace: record.Namespace, Name: record.SessionName, UID: record.SessionUID, TargetClusterUID: record.TargetClusterUID, TargetPodNamespace: record.TargetPodNamespace, TargetPodName: record.TargetPodName, TargetPodUID: record.TargetPodUID, TargetNodeUID: record.TargetNodeUID, ConnectionLeaseUID: record.ConnectionLeaseUID, TargetIdentityDigest: record.TargetIdentityDigest, OperationEpoch: record.OperationEpoch})
	})
}

func (service *Service) reserve(ctx context.Context, record Record, authorize func(context.Context) error) (Record, error) {
	creator, ok := service.repository.(reservationCreator)
	if !ok || ctx == nil || authorize == nil || record.Namespace == "" || record.SessionName == "" || record.SessionUID == "" || record.TargetClusterUID == "" || record.OperationEpoch == 0 || !digestValid(record.PlanDigest) || !digestValid(record.RuntimeBindingDigest) || !digestValid(record.TargetIdentityDigest) || record.MaxBytes < 1 || record.MaxBytes > MaximumRecordingBytes || record.ExpiresAt.IsZero() || !service.now().Before(record.ExpiresAt) {
		return Record{}, ErrForbidden
	}
	if err := authorize(ctx); err != nil {
		return Record{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Record{}, fmt.Errorf("create reservation incarnation: %w", err)
	}
	record.ReservationNonce = hex.EncodeToString(nonce[:])
	record.ExpiresAt = record.ExpiresAt.UTC().Truncate(time.Second)
	record.State = StatePending
	record.Generation = 0
	record.ArtifactUID = ""
	record.ResourceVersion = ""
	record.Size = 0
	record.SHA256 = ""
	record.Metadata = storage.Metadata{}
	// Finite deterministic names make the session bound hold across replicas.
	// A slot is reusable only after the controller deletes its cleaned CRD.
	limit := maximumSessionReservations
	domain := "recording"
	if record.Recipe != TerminalRecordingRecipe {
		limit = 2
		domain = "collector"
	}
	for slot := 0; slot < limit; slot++ {
		sum := sha256.Sum256([]byte("artifact-slot-v1\x00" + domain + "\x00" + record.SessionUID + "\x00" + strconv.Itoa(slot)))
		record.ArtifactID = "dsa-" + hex.EncodeToString(sum[:12])
		record.Expected.ArtifactID = record.ArtifactID
		jti, keyID, err := service.tokens.DeriveUploadJTI("", UploadReservationBinding(record))
		if err != nil {
			return Record{}, err
		}
		record.UploadKeyID = keyID
		record.UploadJTIHash = jtiHash(jti)
		record.UploadJTI = ""
		created, err := creator.Create(ctx, record)
		if errors.Is(err, storage.ErrAlreadyExists) {
			continue
		}
		if err != nil {
			return Record{}, err
		}
		if err := authorize(ctx); err != nil {
			return Record{}, err
		}
		if !service.now().Before(created.ExpiresAt) {
			return Record{}, ErrExpired
		}
		return created, nil
	}
	return Record{}, fmt.Errorf("session artifact reservation limit reached: %w", ErrConflict)
}
func digestValid(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && len(value) == 64
}

// ReservationToken issues only the nonce whose hash was committed at creation.
func ReservationToken(keyring *token.Keyring, record Record, route string, now time.Time, ttl time.Duration) (string, error) {
	if record.UploadKeyID == "" || record.ArtifactUID == "" || record.ReservationNonce == "" {
		return "", ErrForbidden
	}
	jti, _, err := keyring.DeriveUploadJTI(record.UploadKeyID, UploadReservationBinding(record))
	if err != nil {
		return "", err
	}
	if jtiHash(jti) != record.UploadJTIHash {
		return "", ErrForbidden
	}
	now = now.UTC().Truncate(time.Second)
	expires := record.ExpiresAt.UTC().Truncate(time.Second)
	if expires.After(now.Add(ttl)) {
		expires = now.Add(ttl)
	}
	if !now.Before(expires) {
		return "", ErrExpired
	}
	claims := token.Claims{JTI: jti, IssuedAt: now, NotBefore: now, ExpiresAt: expires, Method: http.MethodPut, Route: route, SessionNamespace: record.Namespace, SessionName: record.SessionName, SessionUID: record.SessionUID, ArtifactID: record.ArtifactID, ArtifactPlanDigest: record.PlanDigest, RuntimeBindingDigest: record.RuntimeBindingDigest, OperationEpoch: record.OperationEpoch, TargetIdentityDigest: record.TargetIdentityDigest, Recipe: record.Recipe, RecipeVersion: record.RecipeVersion}
	if record.Expected.Node != nil {
		claims.Node = *record.Expected.Node
		claims.NodePresent = true
	}
	if route != token.CanonicalUploadRoute(claims) {
		return "", ErrForbidden
	}
	return keyring.Sign(claims)
}

// AuthorizeCollection rechecks the original collector capability before a spoke mutation.
func (service *Service) AuthorizeCollection(ctx context.Context, record Record) error {
	if record.ConnectionLeaseUID == "" || record.Recipe == TerminalRecordingRecipe {
		return ErrForbidden
	}
	return service.authorize(ctx, record, record.SessionUID, record.TargetIdentityDigest, record.OperationEpoch)
}
