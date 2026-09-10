// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

func TestConfigValidateRequiresExplicitVersionedHTTPSConfiguration(t *testing.T) {
	base := Config{Region: "eu-central-1", Bucket: "breakglass-artifacts", InstanceID: "instance-0123456789", RequireVersioned: true}
	validated, err := base.validate()
	require.NoError(t, err)
	require.Equal(t, defaultMaximumObjectBytes, validated.MaximumObjectBytes)

	for name, mutate := range map[string]func(*Config){
		"http endpoint":             func(config *Config) { config.Endpoint = "http://storage.example" },
		"path endpoint":             func(config *Config) { config.Endpoint = "https://storage.example/path" },
		"missing bucket versioning": func(config *Config) { config.RequireVersioned = false },
		"invalid bucket":            func(config *Config) { config.Bucket = "../bucket" },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			_, err := config.validate()
			require.Error(t, err)
		})
	}
}

func TestBoundedDigestReaderRejectsSizeAndDigestMismatch(t *testing.T) {
	content := []byte("artifact")
	digest := sha256.Sum256(content)
	reader := &boundedDigestReader{reader: io.LimitReader(strings.NewReader(string(content)), int64(len(content)+1)), expected: int64(len(content)), expectedSHA256: hex.EncodeToString(digest[:])}
	_, err := io.Copy(io.Discard, reader)
	require.NoError(t, err)
	require.NoError(t, reader.Err())

	wrong := &boundedDigestReader{reader: strings.NewReader("artifact"), expected: int64(len(content)), expectedSHA256: strings.Repeat("0", sha256.Size*2)}
	_, err = io.Copy(io.Discard, wrong)
	require.NoError(t, err)
	require.Error(t, wrong.Err())
}

func TestVerifiedReadCloserRejectsIncompleteReads(t *testing.T) {
	content := []byte("artifact")
	digest := sha256.Sum256(content)
	reader := &verifiedReadCloser{body: io.NopCloser(strings.NewReader(string(content))), expected: artifactstorage.Object{Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}, onClose: func() error { return nil }}
	part := make([]byte, 1)
	_, err := reader.Read(part)
	require.NoError(t, err)
	require.ErrorIs(t, reader.Close(), artifactstorage.ErrConflict)

	reader = &verifiedReadCloser{body: io.NopCloser(strings.NewReader(string(content))), expected: artifactstorage.Object{Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}, onClose: func() error { return nil }}
	_, err = io.Copy(io.Discard, reader)
	require.NoError(t, err)
	require.NoError(t, reader.Close())
}

func TestStoreRejectsInvalidObjectBeforeProviderCall(t *testing.T) {
	store := &Store{maximumBytes: 32}
	require.Error(t, store.ready(artifactstorage.Object{Key: "x", Size: 1}))
	require.Error(t, store.ready(artifactstorage.Object{Key: "x", RuntimeBindingDigest: "binding", SHA256: "digest", Size: 1}))
}
