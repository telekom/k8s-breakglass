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

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// TestRotatedRefreshTokenKeyCannotAliasRuntimeDefault is the regression test for
// finding #190. Admission resolved an omitted refreshTokenSecretRef.key to
// "value" while the runtime resolves it to "token", so
// `rotatedRefreshTokenKey: token` with an omitted key was accepted as a
// *distinct* key while the runtime read and wrote the same key — the rotated
// token overwrote the seed token, risking permanent loss of spoke access once
// the rotated token expires. Before the fix both asserts below fail (no error
// is returned for "token").
func TestRotatedRefreshTokenKeyCannotAliasRuntimeDefault(t *testing.T) {
	ref := &SecretKeyReference{Name: "my-rt", Namespace: "breakglass-system"} // key omitted

	t.Run("OIDCAuthConfig", func(t *testing.T) {
		errs := validateOIDCAuthConfig(&OIDCAuthConfig{
			IssuerURL:              "https://idp.example.com",
			ClientID:               "breakglass",
			Server:                 "https://api.cluster.example.com:6443",
			RefreshTokenSecretRef:  ref,
			RotatedRefreshTokenKey: DefaultRefreshTokenSecretKey,
		}, field.NewPath("spec", "oidcAuth"))
		require.NotEmpty(t, errs,
			"rotatedRefreshTokenKey %q must be rejected: the runtime resolves an omitted key to it",
			DefaultRefreshTokenSecretKey)
		assert.Contains(t, errs.ToAggregate().Error(), "must differ")
	})

	t.Run("OIDCFromIdentityProviderConfig", func(t *testing.T) {
		errs := validateOIDCFromIdentityProviderConfig(&OIDCFromIdentityProviderConfig{
			Name:                   "my-idp",
			Server:                 "https://api.cluster.example.com:6443",
			RefreshTokenSecretRef:  ref,
			RotatedRefreshTokenKey: DefaultRefreshTokenSecretKey,
		}, field.NewPath("spec", "oidcFromIdentityProvider"))
		require.NotEmpty(t, errs,
			"rotatedRefreshTokenKey %q must be rejected: the runtime resolves an omitted key to it",
			DefaultRefreshTokenSecretKey)
		assert.Contains(t, errs.ToAggregate().Error(), "must differ")
	})
}

func TestResolveSecretKey(t *testing.T) {
	assert.Equal(t, "explicit", ResolveSecretKey(&SecretKeyReference{Key: "explicit"}, "fb"))
	assert.Equal(t, "fb", ResolveSecretKey(&SecretKeyReference{}, "fb"))
	assert.Equal(t, "fb", ResolveSecretKey(nil, "fb"))
}

func TestReservedRefreshTokenKeys(t *testing.T) {
	// An explicit key is authoritative: only it is reserved, so an operator can
	// still use "token" or "value" as the rotated key alongside an explicit seed
	// key — exactly today's behaviour.
	assert.Equal(t, []string{"seed"}, ReservedRefreshTokenKeys(&SecretKeyReference{Key: "seed"}))

	// With the key omitted both defaults are reserved: "token" because the
	// runtime uses it, "value" because admission already rejected it and this
	// check must never become looser.
	assert.Equal(t, []string{DefaultRefreshTokenSecretKey, DefaultSecretKey},
		ReservedRefreshTokenKeys(&SecretKeyReference{}))
	assert.Equal(t, []string{DefaultRefreshTokenSecretKey, DefaultSecretKey},
		ReservedRefreshTokenKeys(nil))
}

func TestValidateRotatedRefreshTokenKey(t *testing.T) {
	path := field.NewPath("spec", "oidcAuth")

	assert.Nil(t, validateRotatedRefreshTokenKey("rotated", &SecretKeyReference{}, path))
	assert.Nil(t, validateRotatedRefreshTokenKey("token", &SecretKeyReference{Key: "seed"}, path),
		"an explicit seed key must not reserve the runtime default")

	for _, bad := range []string{DefaultRefreshTokenSecretKey, DefaultSecretKey} {
		err := validateRotatedRefreshTokenKey(bad, &SecretKeyReference{}, path)
		if assert.NotNil(t, err, "key %q must be rejected", bad) {
			assert.Contains(t, err.Error(), "must differ")
			assert.Contains(t, err.Field, "rotatedRefreshTokenKey")
		}
	}
	assert.NotNil(t, validateRotatedRefreshTokenKey("seed", &SecretKeyReference{Key: "seed"}, path))
}

// TestCASecretKeyConstantsAreConsistent documents the invariant that broke:
// the key TOFU writes and the canonical key a read resolves to must be
// identical, and the legacy read key must be the generic default.
func TestCASecretKeyConstantsAreConsistent(t *testing.T) {
	assert.Equal(t, "ca.crt", DefaultCASecretKey)
	assert.Equal(t, "value", DefaultSecretKey)
	assert.Equal(t, DefaultSecretKey, LegacyCASecretKey)
	assert.NotEqual(t, DefaultCASecretKey, LegacyCASecretKey)
	assert.Equal(t, "token", DefaultRefreshTokenSecretKey)
}
