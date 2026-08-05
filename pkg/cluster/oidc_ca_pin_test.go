/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func caPinTestProvider(t *testing.T, objs ...*corev1.Secret) *OIDCTokenProvider {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, o := range objs {
		builder = builder.WithObjects(o)
	}
	return NewOIDCTokenProvider(builder.Build(), zap.NewNop().Sugar())
}

func caPinSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-ca", Namespace: "default"},
		Data:       data,
	}
}

// TestTOFUCARoundTripsUnderDefaultKey is the regression test for findings
// #249/#222: persistTOFUCA wrote the captured CA under "ca.crt" while
// configureTLS read it back under "value", so with caSecretRef.key omitted the
// persisted trust anchor was never re-read and TOFU re-bootstrapped on every
// restart. Before the fix the read below finds nothing and CAData stays empty.
func TestTOFUCARoundTripsUnderDefaultKey(t *testing.T) {
	_, _, caPEM := generateTestCACert(t)

	// Empty secret exists so persistTOFUCA has somewhere to write.
	provider := caPinTestProvider(t, caPinSecret(nil))

	secretRef := &breakglassv1alpha1.SecretKeyReference{
		Name: "cluster-ca", Namespace: "default",
		// Key deliberately omitted — this is the broken shape.
	}

	// Write leg: TOFU persists the captured CA.
	require.NoError(t, provider.persistTOFUCA(context.Background(), secretRef, caPEM))

	// Read leg: a fresh provider (simulating a controller restart with an empty
	// in-memory TOFU cache) must find the same CA again.
	restarted := NewOIDCTokenProvider(provider.k8s, zap.NewNop().Sugar())
	cfg := &rest.Config{}
	oidc := &breakglassv1alpha1.OIDCAuthConfig{
		Server:      "https://api.example.com:6443",
		AllowTOFU:   true,
		CASecretRef: secretRef,
	}
	require.NoError(t, restarted.configureTLS(context.Background(), cfg, oidc))
	assert.Equal(t, caPEM, cfg.TLSClientConfig.CAData,
		"persisted TOFU CA must be re-read after restart when caSecretRef.key is omitted")

	// The pin must also seed the in-memory cache so a reconnect compares
	// against it rather than re-running TOFU.
	restarted.tofuMu.RLock()
	cached := restarted.tofuCAs["https://api.example.com:6443"]
	restarted.tofuMu.RUnlock()
	assert.Equal(t, caPEM, cached, "persisted pin must seed the in-memory TOFU cache")
}

// TestTOFUCAExplicitKeyStillHonoured pins the backwards-compatibility promise:
// an explicitly configured caSecretRef.key keeps working exactly as before and
// is never silently replaced by a default key.
func TestTOFUCAExplicitKeyStillHonoured(t *testing.T) {
	_, _, caPEM := generateTestCACert(t)
	provider := caPinTestProvider(t, caPinSecret(nil))

	secretRef := &breakglassv1alpha1.SecretKeyReference{
		Name: "cluster-ca", Namespace: "default", Key: "my-own-ca",
	}
	require.NoError(t, provider.persistTOFUCA(context.Background(), secretRef, caPEM))

	var secret corev1.Secret
	require.NoError(t, provider.k8s.Get(context.Background(),
		types.NamespacedName{Name: "cluster-ca", Namespace: "default"}, &secret))
	assert.Equal(t, caPEM, secret.Data["my-own-ca"])
	assert.Empty(t, secret.Data[breakglassv1alpha1.DefaultCASecretKey],
		"an explicit key must not also write the canonical key")

	cfg := &rest.Config{}
	require.NoError(t, provider.configureTLS(context.Background(), cfg, &breakglassv1alpha1.OIDCAuthConfig{
		Server:      "https://api.example.com:6443",
		CASecretRef: secretRef,
	}))
	assert.Equal(t, caPEM, cfg.TLSClientConfig.CAData)
}

// TestTOFUCALegacyKeyFallbackRead covers the deployed-cluster case: a Secret
// already holds a correctly pinned CA under the legacy read key "value"
// (written by hand or by an operator following the old read behaviour).
// Changing the read key must not orphan it.
func TestTOFUCALegacyKeyFallbackRead(t *testing.T) {
	_, _, caPEM := generateTestCACert(t)
	provider := caPinTestProvider(t, caPinSecret(map[string][]byte{
		breakglassv1alpha1.LegacyCASecretKey: caPEM,
	}))

	cfg := &rest.Config{}
	require.NoError(t, provider.configureTLS(context.Background(), cfg, &breakglassv1alpha1.OIDCAuthConfig{
		Server:    "https://api.example.com:6443",
		AllowTOFU: true,
		CASecretRef: &breakglassv1alpha1.SecretKeyReference{
			Name: "cluster-ca", Namespace: "default",
		},
	}))
	assert.Equal(t, caPEM, cfg.TLSClientConfig.CAData,
		"a CA pinned under the legacy key must still be honoured")
}

// TestTOFUCACanonicalKeyWinsOverLegacy asserts read precedence: when both keys
// are populated the canonical key is authoritative.
func TestTOFUCACanonicalKeyWinsOverLegacy(t *testing.T) {
	_, _, canonical := generateTestCACert(t)
	_, _, legacy := generateTestCACert(t)
	provider := caPinTestProvider(t, caPinSecret(map[string][]byte{
		breakglassv1alpha1.DefaultCASecretKey: canonical,
		breakglassv1alpha1.LegacyCASecretKey:  legacy,
	}))

	cfg := &rest.Config{}
	require.NoError(t, provider.configureTLS(context.Background(), cfg, &breakglassv1alpha1.OIDCAuthConfig{
		Server: "https://api.example.com:6443",
		CASecretRef: &breakglassv1alpha1.SecretKeyReference{
			Name: "cluster-ca", Namespace: "default",
		},
	}))
	assert.Equal(t, canonical, cfg.TLSClientConfig.CAData)
}

// TestTOFUCAPinMismatchIsAnError is the core TOFU guarantee: a CA that differs
// from the persisted pin must fail loudly, never silently re-pin. Before the
// fix persistTOFUCA blindly overwrote whatever was there.
func TestTOFUCAPinMismatchIsAnError(t *testing.T) {
	_, _, pinned := generateTestCACert(t)
	_, _, imposter := generateTestCACert(t)
	require.NotEqual(t, pinned, imposter)

	for name, existing := range map[string]map[string][]byte{
		"canonical key": {breakglassv1alpha1.DefaultCASecretKey: pinned},
		"legacy key":    {breakglassv1alpha1.LegacyCASecretKey: pinned},
	} {
		t.Run(name, func(t *testing.T) {
			provider := caPinTestProvider(t, caPinSecret(existing))
			err := provider.persistTOFUCA(context.Background(),
				&breakglassv1alpha1.SecretKeyReference{Name: "cluster-ca", Namespace: "default"},
				imposter)
			require.Error(t, err, "a CA differing from the pin must not be re-pinned")
			assert.ErrorIs(t, err, ErrTOFUPinMismatch)

			// The pin must be intact afterwards.
			var secret corev1.Secret
			require.NoError(t, provider.k8s.Get(context.Background(),
				types.NamespacedName{Name: "cluster-ca", Namespace: "default"}, &secret))
			for k, v := range existing {
				assert.Equal(t, v, secret.Data[k], "pinned CA under %q must be untouched", k)
			}
		})
	}
}

// TestTOFUCARepinSameCAIsIdempotent guards against the mismatch check firing on
// a benign re-write of the identical CA.
func TestTOFUCARepinSameCAIsIdempotent(t *testing.T) {
	_, _, caPEM := generateTestCACert(t)
	provider := caPinTestProvider(t, caPinSecret(map[string][]byte{
		breakglassv1alpha1.DefaultCASecretKey: caPEM,
	}))
	require.NoError(t, provider.persistTOFUCA(context.Background(),
		&breakglassv1alpha1.SecretKeyReference{Name: "cluster-ca", Namespace: "default"}, caPEM))
}

// TestTOFUCALegacyPinMigratesOnWrite documents the migration story: once the
// same CA is re-persisted it also lands under the canonical key, so the legacy
// fallback is only needed until the next TOFU write.
func TestTOFUCALegacyPinMigratesOnWrite(t *testing.T) {
	_, _, caPEM := generateTestCACert(t)
	provider := caPinTestProvider(t, caPinSecret(map[string][]byte{
		breakglassv1alpha1.LegacyCASecretKey: caPEM,
	}))
	require.NoError(t, provider.persistTOFUCA(context.Background(),
		&breakglassv1alpha1.SecretKeyReference{Name: "cluster-ca", Namespace: "default"}, caPEM))

	var secret corev1.Secret
	require.NoError(t, provider.k8s.Get(context.Background(),
		types.NamespacedName{Name: "cluster-ca", Namespace: "default"}, &secret))
	assert.Equal(t, caPEM, secret.Data[breakglassv1alpha1.DefaultCASecretKey],
		"the CA must be migrated to the canonical key on write")
}

func TestReadPinnedCA(t *testing.T) {
	ca := []byte("pem")
	tests := map[string]struct {
		data       map[string][]byte
		key        string
		wantCA     []byte
		wantKey    string
		wantLegacy bool
	}{
		"explicit key present": {
			data: map[string][]byte{"k": ca}, key: "k",
			wantCA: ca, wantKey: "k",
		},
		"explicit key absent does not fall back": {
			data: map[string][]byte{breakglassv1alpha1.DefaultCASecretKey: ca}, key: "k",
			wantCA: nil, wantKey: "k",
		},
		"canonical default": {
			data:   map[string][]byte{breakglassv1alpha1.DefaultCASecretKey: ca},
			wantCA: ca, wantKey: breakglassv1alpha1.DefaultCASecretKey,
		},
		"legacy default": {
			data:   map[string][]byte{breakglassv1alpha1.LegacyCASecretKey: ca},
			wantCA: ca, wantKey: breakglassv1alpha1.LegacyCASecretKey, wantLegacy: true,
		},
		"empty value is not a pin": {
			data:   map[string][]byte{breakglassv1alpha1.DefaultCASecretKey: {}},
			wantCA: nil, wantKey: breakglassv1alpha1.DefaultCASecretKey,
		},
		"nothing present": {
			data:   nil,
			wantCA: nil, wantKey: breakglassv1alpha1.DefaultCASecretKey,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotCA, gotKey, gotLegacy := ReadPinnedCA(caPinSecret(tc.data),
				&breakglassv1alpha1.SecretKeyReference{Name: "cluster-ca", Namespace: "default", Key: tc.key})
			assert.Equal(t, tc.wantCA, gotCA)
			assert.Equal(t, tc.wantKey, gotKey)
			assert.Equal(t, tc.wantLegacy, gotLegacy)
		})
	}

	t.Run("nil inputs", func(t *testing.T) {
		ca, key, legacy := ReadPinnedCA(nil, nil)
		assert.Nil(t, ca)
		assert.Empty(t, key)
		assert.False(t, legacy)
	})
}

// TestRotatedRefreshTokenDoesNotClobberSeed is the runtime half of finding
// #190. The seed token lives under the runtime default key ("token") because
// refreshTokenSecretRef.key is omitted. Admission now rejects
// `rotatedRefreshTokenKey: token`, but the runtime must also demonstrably keep
// the seed intact for a legitimately distinct rotated key, and must prefer the
// rotated token on read.
func TestRotatedRefreshTokenDoesNotClobberSeed(t *testing.T) {
	ctx := context.Background()
	seed := "seed-refresh-token"
	rotated := "rotated-refresh-token"

	provider := caPinTestProvider(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-rt", Namespace: "default"},
		Data:       map[string][]byte{breakglassv1alpha1.DefaultRefreshTokenSecretKey: []byte(seed)},
	})

	oidc := &breakglassv1alpha1.OIDCAuthConfig{
		RefreshTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{
			Name: "my-rt", Namespace: "default",
			// Key omitted — runtime resolves it to DefaultRefreshTokenSecretKey.
		},
		RotatedRefreshTokenKey: "refresh-token-rotated",
	}

	// Seed is readable before rotation.
	got, err := provider.readBestRefreshToken(ctx, oidc, "default")
	require.NoError(t, err)
	assert.Equal(t, seed, got)

	provider.persistRotatedRefreshToken(ctx, oidc, "default", rotated, "")

	var secret corev1.Secret
	require.NoError(t, provider.k8s.Get(ctx,
		types.NamespacedName{Name: "my-rt", Namespace: "default"}, &secret))
	assert.Equal(t, seed, string(secret.Data[breakglassv1alpha1.DefaultRefreshTokenSecretKey]),
		"the seed token must survive rotation")
	assert.Equal(t, rotated, string(secret.Data["refresh-token-rotated"]))

	// After rotation the freshest token wins on read.
	got, err = provider.readBestRefreshToken(ctx, oidc, "default")
	require.NoError(t, err)
	assert.Equal(t, rotated, got)
}
