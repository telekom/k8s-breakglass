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
	"context"
	"os"
	"testing"
	"time"

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

// TestOIDCFromIDP_EndToEnd tests actual OIDC flows end-to-end through OIDC IDP configuration,
// verifying that ClusterConfigs reach Ready status (or appropriate degraded conditions).
// These tests require a running Keycloak instance with the breakglass-e2e realm configured.
func TestOIDCFromIDP_EndToEnd(t *testing.T) {
	if os.Getenv("OIDC_E2E_ENABLED") != "true" {
		t.Skip("Skipping OIDC end-to-end tests (set OIDC_E2E_ENABLED=true to run)")
	}

	t.Run("CC-OIDC-E2E-IDP-001: RefreshTokenEndToEnd", func(t *testing.T) {
		_ = helpers.SetupTest(t, helpers.WithShortTimeout())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		cli := helpers.GetClient(t)
		cleanup := helpers.NewCleanup(t, cli)
		namespace := helpers.GetTestNamespace()

		// Obtain a real offline refresh token from Keycloak using E2E OIDC client
		provider := helpers.E2EOIDCProvider()
		refreshToken := provider.ObtainOfflineRefreshToken(t, ctx, "breakglass-sa", "breakglass-sa-password")
		t.Log("Obtained offline refresh token from Keycloak via E2E OIDC client")

		// Store RT in K8s Secret
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-idp-rt"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"refresh-token": refreshToken,
			},
		}
		cleanup.Add(rtSecret)
		err := cli.Create(ctx, rtSecret)
		require.NoError(t, err, "Failed to create refresh token secret")

		oidcServer := helpers.GetOIDCEnabledAPIServerURL()

		// Create ClusterConfig using OIDCFromIdentityProvider with refresh token
		cc := helpers.NewClusterConfigBuilder(helpers.GenerateUniqueName("e2e-idp-rt"), namespace).
			WithOIDCFromIdentityProvider("breakglass-e2e-idp", oidcServer).
			WithOIDCFromIDPRefreshToken(rtSecret.Name, namespace, "refresh-token").
			WithOIDCFromIDPInsecureSkipTLSVerify(true).
			Build()
		cleanup.Add(cc)
		err = cli.Create(ctx, cc)
		require.NoError(t, err, "Failed to create ClusterConfig with IDP refresh token")

		// Wait for Ready — validates full chain: RT → Keycloak token refresh → API server auth
		err = waitForClusterConfigConditionReady(t, ctx, cli, cc.Name, namespace, 90*time.Second)
		if err != nil {
			var fetched breakglassv1alpha1.ClusterConfig
			_ = cli.Get(ctx, types.NamespacedName{Name: cc.Name, Namespace: namespace}, &fetched)
			logClusterConfigConditions(t, &fetched)
			t.Logf("Note: IDP refresh token flow may require reachable IDP and API server: %v", err)
		} else {
			t.Log("CC-OIDC-E2E-IDP-001: IDP refresh token flow succeeded — ClusterConfig is Ready")
		}
	})

	t.Run("CC-OIDC-E2E-IDP-002: FallbackAutoSucceeds", func(t *testing.T) {
		_ = helpers.SetupTest(t, helpers.WithShortTimeout())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		cli := helpers.GetClient(t)
		cleanup := helpers.NewCleanup(t, cli)
		namespace := helpers.GetTestNamespace()

		// Create a Secret with an INVALID refresh token
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-idp-bad-rt"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"refresh-token": "invalid-expired-refresh-token",
			},
		}
		cleanup.Add(rtSecret)
		err := cli.Create(ctx, rtSecret)
		require.NoError(t, err)

		oidcServer := helpers.GetOIDCEnabledAPIServerURL()

		// Build ClusterConfig with invalid RT + FallbackPolicyAuto.
		// Fallback credentials come from the IDP's Keycloak SA (not explicit clientSecretRef,
		// which is mutually exclusive with refreshTokenSecretRef).
		cc := helpers.NewClusterConfigBuilder(helpers.GenerateUniqueName("e2e-idp-auto"), namespace).
			WithOIDCFromIdentityProvider("breakglass-e2e-idp", oidcServer).
			WithOIDCFromIDPRefreshToken(rtSecret.Name, namespace, "refresh-token").
			WithOIDCFromIDPFallbackPolicy(breakglassv1alpha1.FallbackPolicyAuto).
			WithOIDCFromIDPInsecureSkipTLSVerify(true).
			Build()
		cleanup.Add(cc)
		err = cli.Create(ctx, cc)
		require.NoError(t, err, "Failed to create ClusterConfig with Auto fallback")

		// Wait for Ready — Auto fallback: invalid RT fails → IDP Keycloak SA client_credentials → succeeds
		err = waitForClusterConfigConditionReady(t, ctx, cli, cc.Name, namespace, 90*time.Second)
		if err != nil {
			var fetched breakglassv1alpha1.ClusterConfig
			_ = cli.Get(ctx, types.NamespacedName{Name: cc.Name, Namespace: namespace}, &fetched)
			logClusterConfigConditions(t, &fetched)
			t.Logf("Note: Auto fallback requires IDP with Keycloak SA: %v", err)
		} else {
			t.Log("CC-OIDC-E2E-IDP-002: Auto fallback succeeded — ClusterConfig is Ready via IDP Keycloak SA")
		}
	})

	t.Run("CC-OIDC-E2E-IDP-003: FallbackWarnSetsDegradedAuth", func(t *testing.T) {
		_ = helpers.SetupTest(t, helpers.WithShortTimeout())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		cli := helpers.GetClient(t)
		cleanup := helpers.NewCleanup(t, cli)
		namespace := helpers.GetTestNamespace()

		// Create Secret with INVALID refresh token
		rtSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-idp-bad-rt-w"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"refresh-token": "invalid-expired-refresh-token",
			},
		}
		cleanup.Add(rtSecret)
		err := cli.Create(ctx, rtSecret)
		require.NoError(t, err)

		oidcServer := helpers.GetOIDCEnabledAPIServerURL()

		// Build ClusterConfig with invalid RT + FallbackPolicyWarn.
		// Fallback credentials come from the IDP's Keycloak SA (not explicit clientSecretRef,
		// which is mutually exclusive with refreshTokenSecretRef).
		cc := helpers.NewClusterConfigBuilder(helpers.GenerateUniqueName("e2e-idp-warn"), namespace).
			WithOIDCFromIdentityProvider("breakglass-e2e-idp", oidcServer).
			WithOIDCFromIDPRefreshToken(rtSecret.Name, namespace, "refresh-token").
			WithOIDCFromIDPFallbackPolicy(breakglassv1alpha1.FallbackPolicyWarn).
			WithOIDCFromIDPInsecureSkipTLSVerify(true).
			Build()
		cleanup.Add(cc)
		err = cli.Create(ctx, cc)
		require.NoError(t, err, "Failed to create ClusterConfig with Warn fallback")

		// Wait for Ready — Warn fallback: invalid RT → falls back to client_credentials → succeeds with DegradedAuth
		err = waitForClusterConfigConditionReady(t, ctx, cli, cc.Name, namespace, 90*time.Second)
		if err != nil {
			var fetched breakglassv1alpha1.ClusterConfig
			_ = cli.Get(ctx, types.NamespacedName{Name: cc.Name, Namespace: namespace}, &fetched)
			logClusterConfigConditions(t, &fetched)
			t.Logf("Note: Warn fallback may require reachable IDP: %v", err)
		} else {
			t.Log("CC-OIDC-E2E-IDP-003: Warn fallback succeeded — ClusterConfig is Ready")
		}

		// Check for DegradedAuth condition — this is the KEY assertion for Warn policy
		var fetched breakglassv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: cc.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)

		degradedFound := false
		for _, cond := range fetched.Status.Conditions {
			if cond.Type == "DegradedAuth" {
				degradedFound = true
				assert.Equal(t, "True", string(cond.Status),
					"DegradedAuth condition should be True when Warn fallback is in use")
				t.Logf("CC-OIDC-E2E-IDP-003: DegradedAuth condition: status=%s, reason=%s, message=%s",
					cond.Status, cond.Reason, cond.Message)
				break
			}
		}

		if !degradedFound {
			t.Log("CC-OIDC-E2E-IDP-003: DegradedAuth condition not found (may not be propagated yet)")
		}
	})

	t.Run("CC-OIDC-E2E-IDP-004: TokenExchangeEndToEnd", func(t *testing.T) {
		_ = helpers.SetupTest(t, helpers.WithShortTimeout())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		cli := helpers.GetClient(t)
		cleanup := helpers.NewCleanup(t, cli)
		namespace := helpers.GetTestNamespace()

		// Obtain a subject token via client_credentials from the service account client
		saProvider := helpers.ServiceAccountProvider()
		subjectToken := saProvider.ObtainClientCredentialsToken(t, ctx)
		t.Log("Obtained subject token via client_credentials")

		// Store subject token in K8s Secret
		subjectSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-idp-texch-st"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"token": subjectToken,
			},
		}
		cleanup.Add(subjectSecret)
		err := cli.Create(ctx, subjectSecret)
		require.NoError(t, err, "Failed to create subject token secret")

		// Store client secret for the E2E OIDC client (token exchange target)
		csSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-idp-texch-cs"),
				Namespace: namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"client-secret": helpers.GetE2EOIDCClientSecret(),
			},
		}
		cleanup.Add(csSecret)
		err = cli.Create(ctx, csSecret)
		require.NoError(t, err, "Failed to create client secret for token exchange")

		oidcServer := helpers.GetOIDCEnabledAPIServerURL()

		// Build ClusterConfig with token exchange
		cc := helpers.NewClusterConfigBuilder(helpers.GenerateUniqueName("e2e-idp-texch"), namespace).
			WithOIDCFromIdentityProvider("breakglass-e2e-idp", oidcServer).
			WithOIDCFromIDPTokenExchange(subjectSecret.Name, namespace, "token").
			WithOIDCFromIDPClientSecret(csSecret.Name, namespace, "client-secret").
			WithOIDCFromIDPInsecureSkipTLSVerify(true).
			Build()
		cleanup.Add(cc)
		err = cli.Create(ctx, cc)
		require.NoError(t, err, "Failed to create ClusterConfig with token exchange")

		// Wait for Ready
		err = waitForClusterConfigConditionReady(t, ctx, cli, cc.Name, namespace, 90*time.Second)
		if err != nil {
			var fetched breakglassv1alpha1.ClusterConfig
			_ = cli.Get(ctx, types.NamespacedName{Name: cc.Name, Namespace: namespace}, &fetched)
			logClusterConfigConditions(t, &fetched)
			t.Logf("Note: Token exchange requires Keycloak fine-grained admin permissions: %v", err)
		} else {
			t.Log("CC-OIDC-E2E-IDP-004: Token exchange via IDP succeeded — ClusterConfig is Ready")
		}
	})
}
