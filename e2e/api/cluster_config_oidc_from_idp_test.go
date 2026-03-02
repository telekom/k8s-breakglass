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

package api

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestClusterConfigOIDCFromIDPModes tests the extended OIDC auth modes:
// - [CC-OIDC-FROM-IDP-001] Refresh token only mode (no client secret)
// - [CC-OIDC-FROM-IDP-002] Refresh token with fallback policy
// - [CC-OIDC-FROM-IDP-003] Token exchange mode
// - [CC-OIDC-FROM-IDP-004] Audience and scopes propagation
// - [CC-OIDC-FROM-IDP-005] Webhook rejects invalid combinations
// - [CC-OIDC-FROM-IDP-006] Direct OIDC auth with refresh token
// - [CC-OIDC-FROM-IDP-007] Fallback policy defaults and field parity
func TestClusterConfigOIDCFromIDPModes(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithShortTimeout())

	idpName := "breakglass-e2e-idp"

	// Use env vars for issuer/server URLs to avoid hard-coded unreachable endpoints
	// that cause controller reconciliation noise in the shared E2E environment.
	issuerURL := os.Getenv("KEYCLOAK_ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "https://keycloak.breakglass-system.svc.cluster.local/realms/breakglass"
	}
	serverURL := os.Getenv("E2E_CLUSTER_SERVER_URL")
	if serverURL == "" {
		serverURL = "https://kubernetes.default.svc:443"
	}

	t.Run("CC-OIDC-FROM-IDP-001_RefreshTokenOnly", func(t *testing.T) {
		// Create a refresh token secret
		rtSecretName := helpers.GenerateUniqueName("rt-secret")
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rtSecretName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			StringData: map[string]string{
				"refresh-token": "offline-refresh-token-value",
			},
		}
		s.MustCreateResource(rtSecret)

		// Create ClusterConfig with refresh token only (no client secret)
		name := helpers.GenerateUniqueName("cc-oidc-rt")
		cc := helpers.NewClusterConfigBuilder(name, s.Namespace).
			WithOIDCFromIdentityProvider(idpName, "https://kubernetes.default.svc:443").
			WithOIDCFromIDPRefreshToken(rtSecretName, s.Namespace, "refresh-token").
			Build()
		s.MustCreateResource(cc)

		// Verify the ClusterConfig was created with correct fields
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)

		assert.Equal(t, breakglassv1alpha1.ClusterAuthTypeOIDC, fetched.Spec.AuthType)
		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider)
		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider.RefreshTokenSecretRef)
		assert.Equal(t, rtSecretName, fetched.Spec.OIDCFromIdentityProvider.RefreshTokenSecretRef.Name)
		assert.Nil(t, fetched.Spec.OIDCFromIdentityProvider.ClientSecretRef, "ClientSecretRef should be nil in refresh-token-only mode")

		t.Logf("CC-OIDC-FROM-IDP-001: Created ClusterConfig with refresh token only: %s", name)
	})

	t.Run("CC-OIDC-FROM-IDP-002_RefreshTokenWithFallback", func(t *testing.T) {
		// Create secrets
		rtSecretName := helpers.GenerateUniqueName("rt-fb-secret")
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: rtSecretName, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			StringData: map[string]string{"refresh-token": "offline-token"},
		}
		s.MustCreateResource(rtSecret)

		csSecretName := helpers.GenerateUniqueName("cs-fb-secret")
		csSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: csSecretName, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			StringData: map[string]string{"client-secret": "fallback-client-secret"},
		}
		s.MustCreateResource(csSecret)

		// Create with Auto fallback — refresh token + client secret for fallback
		// Note: On OIDCFromIdentityProvider, refreshTokenSecretRef and clientSecretRef
		// are mutually exclusive. The fallback uses the IDP's Keycloak SA or explicit client secret
		// configured on the IDP itself. Here we test OIDCAuth (direct) which allows both.
		name := helpers.GenerateUniqueName("cc-oidc-fb")
		cc := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: issuerURL,
					ClientID:  "test-client",
					Server:    serverURL,
					RefreshTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name: rtSecretName, Namespace: s.Namespace, Key: "refresh-token",
					},
					ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name: csSecretName, Namespace: s.Namespace, Key: "client-secret",
					},
					FallbackPolicy: breakglassv1alpha1.FallbackPolicyAuto,
				},
			},
		}
		s.MustCreateResource(cc)

		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)

		require.NotNil(t, fetched.Spec.OIDCAuth)
		assert.Equal(t, breakglassv1alpha1.FallbackPolicyAuto, fetched.Spec.OIDCAuth.FallbackPolicy)
		require.NotNil(t, fetched.Spec.OIDCAuth.RefreshTokenSecretRef)
		require.NotNil(t, fetched.Spec.OIDCAuth.ClientSecretRef)

		t.Logf("CC-OIDC-FROM-IDP-002: Created ClusterConfig with refresh token + Auto fallback: %s", name)
	})

	t.Run("CC-OIDC-FROM-IDP-003_TokenExchange", func(t *testing.T) {
		// Create subject token secret
		stSecretName := helpers.GenerateUniqueName("st-secret")
		stSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: stSecretName, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			StringData: map[string]string{"token": "subject-token-value"},
		}
		s.MustCreateResource(stSecret)

		// Create ClusterConfig with token exchange
		name := helpers.GenerateUniqueName("cc-oidc-te")
		cc := helpers.NewClusterConfigBuilder(name, s.Namespace).
			WithOIDCFromIdentityProvider(idpName, "https://kubernetes.default.svc:443").
			WithOIDCFromIDPTokenExchange(stSecretName, s.Namespace, "token").
			Build()
		s.MustCreateResource(cc)

		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)

		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider)
		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider.TokenExchange)
		assert.True(t, fetched.Spec.OIDCFromIdentityProvider.TokenExchange.Enabled)
		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider.TokenExchange.SubjectTokenSecretRef)
		assert.Equal(t, stSecretName, fetched.Spec.OIDCFromIdentityProvider.TokenExchange.SubjectTokenSecretRef.Name)

		t.Logf("CC-OIDC-FROM-IDP-003: Created ClusterConfig with token exchange: %s", name)
	})

	t.Run("CC-OIDC-FROM-IDP-004_AudienceAndScopes", func(t *testing.T) {
		csSecretName := helpers.GenerateUniqueName("cs-as-secret")
		csSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: csSecretName, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			StringData: map[string]string{"client-secret": "test-secret"},
		}
		s.MustCreateResource(csSecret)

		// Create ClusterConfig with audience and scopes
		name := helpers.GenerateUniqueName("cc-oidc-as")
		cc := helpers.NewClusterConfigBuilder(name, s.Namespace).
			WithOIDCFromIdentityProvider(idpName, "https://kubernetes.default.svc:443").
			WithOIDCFromIDPClientSecret(csSecretName, s.Namespace, "client-secret").
			WithOIDCFromIDPAudience("kubernetes").
			WithOIDCFromIDPScopes("openid", "groups", "email").
			Build()
		s.MustCreateResource(cc)

		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)

		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider)
		assert.Equal(t, "kubernetes", fetched.Spec.OIDCFromIdentityProvider.Audience)
		assert.Equal(t, []string{"openid", "groups", "email"}, fetched.Spec.OIDCFromIdentityProvider.Scopes)

		t.Logf("CC-OIDC-FROM-IDP-004: Created ClusterConfig with audience=%s scopes=%v: %s",
			fetched.Spec.OIDCFromIdentityProvider.Audience,
			fetched.Spec.OIDCFromIdentityProvider.Scopes,
			name)
	})

	t.Run("CC-OIDC-FROM-IDP-005_WebhookRejectsInvalid", func(t *testing.T) {
		// FallbackPolicy without RefreshTokenSecretRef should be rejected
		name := helpers.GenerateUniqueName("cc-oidc-invalid")
		cc := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: issuerURL,
					ClientID:  "test-client",
					Server:    serverURL,
					ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name: "some-secret", Namespace: s.Namespace, Key: "client-secret",
					},
					// FallbackPolicy without RefreshTokenSecretRef should be rejected by webhook
					FallbackPolicy: breakglassv1alpha1.FallbackPolicyAuto,
				},
			},
		}

		err := s.Client.Create(s.Ctx, cc)
		require.Error(t, err, "webhook should reject fallbackPolicy without refreshTokenSecretRef")
		assert.Contains(t, err.Error(), "fallbackPolicy",
			"rejection error should mention fallbackPolicy")
		t.Logf("CC-OIDC-FROM-IDP-005: Webhook correctly rejected: %v", err)
	})

	t.Run("CC-OIDC-FROM-IDP-006_DirectOIDCRefreshToken", func(t *testing.T) {
		// Test direct oidcAuth with refreshTokenSecretRef (no clientSecretRef)
		rtSecretName := helpers.GenerateUniqueName("direct-rt")
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: rtSecretName, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			StringData: map[string]string{"refresh-token": "direct-offline-token"},
		}
		s.MustCreateResource(rtSecret)

		name := helpers.GenerateUniqueName("cc-direct-rt")
		cc := helpers.NewClusterConfigBuilder(name, s.Namespace).
			WithOIDCAuth(issuerURL, "test-client", serverURL).
			WithOIDCRefreshToken(rtSecretName, s.Namespace, "refresh-token").
			Build()
		s.MustCreateResource(cc)

		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)

		require.NotNil(t, fetched.Spec.OIDCAuth)
		require.NotNil(t, fetched.Spec.OIDCAuth.RefreshTokenSecretRef)
		assert.Nil(t, fetched.Spec.OIDCAuth.ClientSecretRef)

		t.Logf("CC-OIDC-FROM-IDP-006: Created direct OIDC ClusterConfig with refresh token: %s", name)
	})

	t.Run("CC-OIDC-FROM-IDP-007_FallbackPolicyDefaults", func(t *testing.T) {
		// When no FallbackPolicy is set, it should default to empty (None behavior)
		rtSecretName := helpers.GenerateUniqueName("def-rt")
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: rtSecretName, Namespace: s.Namespace, Labels: helpers.E2ETestLabels(),
			},
			StringData: map[string]string{"refresh-token": "test-token"},
		}
		s.MustCreateResource(rtSecret)

		name := helpers.GenerateUniqueName("cc-fb-def")
		cc := helpers.NewClusterConfigBuilder(name, s.Namespace).
			WithOIDCFromIdentityProvider(idpName, "https://kubernetes.default.svc:443").
			WithOIDCFromIDPRefreshToken(rtSecretName, s.Namespace, "refresh-token").
			Build()
		s.MustCreateResource(cc)

		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err)

		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider)
		// FallbackPolicy should be empty or explicitly None
		assert.True(t,
			fetched.Spec.OIDCFromIdentityProvider.FallbackPolicy == "" ||
				fetched.Spec.OIDCFromIdentityProvider.FallbackPolicy == breakglassv1alpha1.FallbackPolicyNone,
			"Default FallbackPolicy should be empty or None, got: %s",
			fetched.Spec.OIDCFromIdentityProvider.FallbackPolicy)

		t.Logf("CC-OIDC-FROM-IDP-007: FallbackPolicy defaults correctly: %s", name)
	})
}
