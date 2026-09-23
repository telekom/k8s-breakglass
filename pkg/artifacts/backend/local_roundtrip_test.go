//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
)

func validLocalArchive(t *testing.T, expected archive.Expected) []byte {
	t.Helper()
	payload := []byte(`{"hostname":"worker"}`)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, entry := range []struct {
		name string
		data []byte
		kind byte
	}{{"files", nil, tar.TypeDir}, {"files/system-summary.json", payload, tar.TypeReg}, {"stdout.log", nil, tar.TypeReg}, {"stderr.log", nil, tar.TypeReg}} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(entry.data)), Typeflag: entry.kind}))
		_, err := tw.Write(entry.data)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Flush())
	digest := sha256.New()
	_, err := digest.Write(raw.Bytes())
	require.NoError(t, err)
	_, err = digest.Write(make([]byte, 1024))
	require.NoError(t, err)
	manifest := archive.Manifest{SchemaVersion: archive.SchemaV1, Recipe: expected.Recipe, RecipeVersion: 1, ArtifactID: expected.ArtifactID, ArchiveFormat: archive.ArchiveFormatTarGzip, Inputs: expected.Inputs, DeclaredOutputs: []string{"files/system-summary.json", "manifest.json", "stderr.log", "stdout.log"}, PayloadSHA256: hex.EncodeToString(digest.Sum(nil)), FileCount: 1, Bytes: int64(len(payload)), ExitSemantics: archive.ExitSemanticsCompleteOnly}
	manifest.Session.Namespace = expected.SessionNamespace
	manifest.Session.Name = expected.SessionName
	manifest.Session.UID = expected.SessionUID
	manifest.Redaction.Profile = expected.RedactionProfile
	manifest.Redaction.Version = expected.RedactionVersion
	encoded, err := json.Marshal(manifest)
	require.NoError(t, err)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(encoded))}))
	_, err = tw.Write(encoded)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err = gz.Write(raw.Bytes())
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return compressed.Bytes()
}

func TestServiceRealLocalStoreRoundtripUIDIsolationAndExistingRecovery(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	config := local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: true, ArtifactRoot: filepath.Join(root, "objects"), StagingRoot: filepath.Join(root, "staging"), InstanceID: "backend-roundtrip-instance", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), ServingReplicas: 1, AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate, EncryptionAcknowledged: true, SnapshotPolicy: local.SnapshotsProhibited}
	require.NoError(t, os.Mkdir(config.ArtifactRoot, 0700))
	require.NoError(t, os.Mkdir(config.StagingRoot, 0700))
	require.NoError(t, local.ProvisionSentinels(config))
	store, err := local.Open(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	var services []*Service
	var repositories []*memoryRepository
	var bodies [][]byte
	for index, uid := range []string{"artifact-uid-one", "artifact-uid-two"} {
		detail := "basic"
		expected := archive.Expected{Recipe: archive.SystemSummaryRecipe, RecipeVersion: 1, ArtifactID: "dsa-0123456789abcdef01234567", SessionNamespace: "ns", SessionName: "session", SessionUID: "session-" + uid, RedactionProfile: "credential-text.v1", RedactionVersion: 1, Inputs: archive.Inputs{MaxArchiveBytes: archive.MaxSystemSummaryArchiveBytes, DetailLevel: &detail}}
		body := validLocalArchive(t, expected)
		record := Record{Namespace: "ns", SessionName: "session", SessionUID: expected.SessionUID, ArtifactID: expected.ArtifactID, ArtifactUID: uid, TargetIdentityDigest: strings.Repeat("a", 64), RuntimeBindingDigest: strings.Repeat("b", 64), PlanDigest: strings.Repeat("c", 64), Recipe: expected.Recipe, RecipeVersion: 1, Expected: expected, ExpiresAt: time.Unix(200, 0), MaxBytes: archive.MaxSystemSummaryArchiveBytes, OperationEpoch: 1, UploadJTI: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32)), State: StatePending, Generation: 1}
		repo := &memoryRepository{record: record}
		service := newServiceForTest(t, repo, store, allowAuthorizer{})
		claims := token.Claims{JTI: record.UploadJTI, IssuedAt: time.Unix(100, 0), NotBefore: time.Unix(100, 0), ExpiresAt: time.Unix(150, 0), Method: http.MethodPut, SessionNamespace: record.Namespace, SessionName: record.SessionName, SessionUID: record.SessionUID, ArtifactID: record.ArtifactID, ArtifactPlanDigest: record.PlanDigest, RuntimeBindingDigest: record.RuntimeBindingDigest, OperationEpoch: 1, TargetIdentityDigest: record.TargetIdentityDigest, Recipe: record.Recipe, RecipeVersion: 1}
		claims.Route = token.CanonicalUploadRoute(claims)
		signed, err := service.tokens.Sign(claims)
		require.NoError(t, err)
		if index == 1 { // Simulate a successful provider write whose response was lost.
			key, err := artifactStorageKey(record)
			require.NoError(t, err)
			sum := sha256.Sum256(body)
			_, err = store.PutIfAbsent(ctx, storage.Object{Key: key, RuntimeBindingDigest: record.RuntimeBindingDigest, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}, bytes.NewReader(body))
			require.NoError(t, err)
		}
		result, err := service.Upload(ctx, signed, claims.Route, bytes.NewReader(body))
		require.NoError(t, err)
		require.Equal(t, StateAvailable, result.State)
		_, err = service.Upload(ctx, signed, claims.Route, bytes.NewReader(body))
		require.ErrorIs(t, err, ErrReplay)
		services = append(services, service)
		repositories = append(repositories, repo)
		bodies = append(bodies, body)
	}
	require.NotEqual(t, repositories[0].record.Metadata.Key, repositories[1].record.Metadata.Key)
	read := func(index int) {
		r := repositories[index].record
		reader, _, err := services[index].Download(ctx, r.Namespace, r.SessionName, r.ArtifactID, SessionBinding{Namespace: r.Namespace, Name: r.SessionName, UID: r.SessionUID, TargetIdentityDigest: r.TargetIdentityDigest, OperationEpoch: r.OperationEpoch})
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.NoError(t, reader.Close())
		require.Equal(t, bodies[index], got)
	}
	read(0)
	read(1)
	require.NoError(t, services[0].Cleanup(ctx, repositories[0].record, StateDeleted))
	require.Equal(t, StateDeleted, repositories[0].record.State)
	key, err := artifactStorageKey(repositories[0].record)
	require.NoError(t, err)
	versions, err := store.InventoryKey(ctx, key)
	require.NoError(t, err)
	require.Empty(t, versions)
	read(1)
	require.NoError(t, services[1].Cleanup(ctx, repositories[1].record, StateDeleted))
}
