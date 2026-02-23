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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestClusterConfigOIDCAuthentication tests ClusterConfig resources configured
// to use OIDC-based authentication instead of kubeconfig secrets.
//
// These tests verify:
// - [CC-OIDC-001] ClusterConfig with basic OIDC auth configuration
// - [CC-OIDC-002] ClusterConfig with OIDC client secret reference
// - [CC-OIDC-003] ClusterConfig with OIDC token exchange configuration
// - [CC-OIDC-004] ClusterConfig with OIDC from IdentityProvider reference
// - [CC-OIDC-005] ClusterConfig OIDC validation errors
// - [CC-OIDC-006] ClusterConfig OIDC with CA certificate
func TestClusterConfigOIDCAuthentication(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithShortTimeout())

	// Get Keycloak issuer URL from environment or use default
	keycloakIssuer := os.Getenv("KEYCLOAK_ISSUER_URL")
	if keycloakIssuer == "" {
		keycloakIssuer = "https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443/realms/breakglass-e2e"
	}

	t.Run("CC-OIDC-001_BasicOIDCConfig", func(t *testing.T) {
		// Create ClusterConfig with basic OIDC authentication
		name := helpers.GenerateUniqueName("cc-oidc-basic")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-test-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: keycloakIssuer,
					ClientID:  "breakglass-controller",
					Server:    "https://kubernetes.default.svc:443",
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Verify the ClusterConfig was created
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get OIDC ClusterConfig")

		// Verify OIDC configuration
		assert.Equal(t, breakglassv1alpha1.ClusterAuthTypeOIDC, fetched.Spec.AuthType)
		require.NotNil(t, fetched.Spec.OIDCAuth, "OIDCAuth should not be nil")
		assert.Equal(t, keycloakIssuer, fetched.Spec.OIDCAuth.IssuerURL)
		assert.Equal(t, "breakglass-controller", fetched.Spec.OIDCAuth.ClientID)
		assert.Equal(t, "https://kubernetes.default.svc:443", fetched.Spec.OIDCAuth.Server)

		t.Logf("CC-OIDC-001: Created ClusterConfig with basic OIDC auth: %s", name)
	})

	t.Run("CC-OIDC-002_OIDCWithClientSecret", func(t *testing.T) {
		// First create the client secret
		secretName := helpers.GenerateUniqueName("oidc-client-secret")
		clientSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			StringData: map[string]string{
				"client-secret": "test-secret-value",
			},
		}
		s.MustCreateResource(clientSecret)

		// Create ClusterConfig with OIDC and client secret reference
		name := helpers.GenerateUniqueName("cc-oidc-secret")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-secret-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: keycloakIssuer,
					ClientID:  "breakglass-controller",
					Server:    "https://kubernetes.default.svc:443",
					ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name:      secretName,
						Namespace: s.Namespace,
						Key:       "client-secret",
					},
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Verify the ClusterConfig was created with secret reference
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get OIDC ClusterConfig with secret")

		require.NotNil(t, fetched.Spec.OIDCAuth.ClientSecretRef)
		assert.Equal(t, secretName, fetched.Spec.OIDCAuth.ClientSecretRef.Name)
		assert.Equal(t, s.Namespace, fetched.Spec.OIDCAuth.ClientSecretRef.Namespace)
		assert.Equal(t, "client-secret", fetched.Spec.OIDCAuth.ClientSecretRef.Key)

		t.Logf("CC-OIDC-002: Created ClusterConfig with OIDC client secret reference: %s", name)
	})

	t.Run("CC-OIDC-003_OIDCWithTokenExchange", func(t *testing.T) {
		// Create client secret for OIDC authentication (required for token exchange)
		clientSecretName := helpers.GenerateUniqueName("client-secret")
		clientSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clientSecretName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			StringData: map[string]string{
				"client-secret": "test-client-secret",
			},
		}
		s.MustCreateResource(clientSecret)

		// Create subject token secret for token exchange
		subjectTokenSecretName := helpers.GenerateUniqueName("subject-token")
		subjectTokenSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      subjectTokenSecretName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			StringData: map[string]string{
				"token": "test-subject-token",
			},
		}
		s.MustCreateResource(subjectTokenSecret)

		// Create ClusterConfig with OIDC token exchange configuration
		name := helpers.GenerateUniqueName("cc-oidc-exchange")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-exchange-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: keycloakIssuer,
					ClientID:  "breakglass-controller",
					Server:    "https://kubernetes.default.svc:443",
					ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name:      clientSecretName,
						Namespace: s.Namespace,
						Key:       "client-secret",
					},
					TokenExchange: &breakglassv1alpha1.TokenExchangeConfig{
						Enabled: true,
						SubjectTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{
							Name:      subjectTokenSecretName,
							Namespace: s.Namespace,
							Key:       "token",
						},
						SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
						RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
						Resource:           "https://kubernetes.default.svc",
					},
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Verify the ClusterConfig was created with token exchange
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get OIDC ClusterConfig with token exchange")

		require.NotNil(t, fetched.Spec.OIDCAuth.TokenExchange)
		assert.True(t, fetched.Spec.OIDCAuth.TokenExchange.Enabled)
		require.NotNil(t, fetched.Spec.OIDCAuth.TokenExchange.SubjectTokenSecretRef)
		assert.Equal(t, subjectTokenSecretName, fetched.Spec.OIDCAuth.TokenExchange.SubjectTokenSecretRef.Name)
		assert.Equal(t, "https://kubernetes.default.svc", fetched.Spec.OIDCAuth.TokenExchange.Resource)

		t.Logf("CC-OIDC-003: Created ClusterConfig with OIDC token exchange: %s", name)
	})

	t.Run("CC-OIDC-004_OIDCFromIdentityProvider", func(t *testing.T) {
		// First create an IdentityProvider to reference
		idpName := helpers.GenerateUniqueName("test-idp")
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      idpName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				DisplayName: "Test OIDC Provider",
				Primary:     true,
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: keycloakIssuer,
					ClientID:  "breakglass-ui",
				},
			},
		}
		s.MustCreateResource(idp)

		// Create ClusterConfig that references the IdentityProvider
		name := helpers.GenerateUniqueName("cc-oidc-from-idp")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-from-idp-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
					Name:   idpName,
					Server: "https://kubernetes.default.svc:443",
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Verify the ClusterConfig was created with IDP reference
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get OIDC ClusterConfig from IDP")

		require.NotNil(t, fetched.Spec.OIDCFromIdentityProvider)
		assert.Equal(t, idpName, fetched.Spec.OIDCFromIdentityProvider.Name)
		assert.Equal(t, "https://kubernetes.default.svc:443", fetched.Spec.OIDCFromIdentityProvider.Server)

		t.Logf("CC-OIDC-004: Created ClusterConfig with OIDCFromIdentityProvider: %s (IDP: %s)", name, idpName)
	})

	t.Run("CC-OIDC-005_ValidationErrors", func(t *testing.T) {
		t.Run("MissingIssuerURL", func(t *testing.T) {
			name := helpers.GenerateUniqueName("cc-oidc-invalid")
			clusterConfig := &breakglassv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: s.Namespace,
					Labels:    helpers.E2ETestLabels(),
				},
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					ClusterID: "invalid-oidc-cluster",
					AuthType:  breakglassv1alpha1.ClusterAuthTypeOIDC,
					OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
						// Missing IssuerURL
						ClientID: "breakglass-controller",
						Server:   "https://kubernetes.default.svc:443",
					},
				},
			}

			err := s.Client.Create(s.Ctx, clusterConfig)
			require.Error(t, err, "Expected validation error for missing IssuerURL")
			assert.True(t, apierrors.IsInvalid(err) || apierrors.IsBadRequest(err),
				"Expected Invalid or BadRequest error, got: %v", err)
			t.Logf("CC-OIDC-005a: Correctly rejected ClusterConfig with missing IssuerURL")
		})

		t.Run("MissingServer", func(t *testing.T) {
			name := helpers.GenerateUniqueName("cc-oidc-invalid2")
			clusterConfig := &breakglassv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: s.Namespace,
					Labels:    helpers.E2ETestLabels(),
				},
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					ClusterID: "invalid-oidc-cluster2",
					AuthType:  breakglassv1alpha1.ClusterAuthTypeOIDC,
					OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
						IssuerURL: keycloakIssuer,
						ClientID:  "breakglass-controller",
						// Missing Server
					},
				},
			}

			err := s.Client.Create(s.Ctx, clusterConfig)
			require.Error(t, err, "Expected validation error for missing Server")
			assert.True(t, apierrors.IsInvalid(err) || apierrors.IsBadRequest(err),
				"Expected Invalid or BadRequest error, got: %v", err)
			t.Logf("CC-OIDC-005b: Correctly rejected ClusterConfig with missing Server")
		})

		t.Run("InvalidIssuerURLScheme", func(t *testing.T) {
			name := helpers.GenerateUniqueName("cc-oidc-invalid3")
			clusterConfig := &breakglassv1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: s.Namespace,
					Labels:    helpers.E2ETestLabels(),
				},
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					ClusterID: "invalid-oidc-cluster3",
					AuthType:  breakglassv1alpha1.ClusterAuthTypeOIDC,
					OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
						IssuerURL: "http://insecure-issuer.example.com", // Should require https
						ClientID:  "breakglass-controller",
						Server:    "https://kubernetes.default.svc:443",
					},
				},
			}

			err := s.Client.Create(s.Ctx, clusterConfig)
			require.Error(t, err, "Expected validation error for non-HTTPS IssuerURL")
			t.Logf("CC-OIDC-005c: Correctly rejected ClusterConfig with non-HTTPS IssuerURL")
		})
	})

	t.Run("CC-OIDC-006_OIDCWithCACertificate", func(t *testing.T) {
		// Create CA secret for target cluster
		caSecretName := helpers.GenerateUniqueName("target-ca")
		caSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      caSecretName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			StringData: map[string]string{
				"ca.crt": "-----BEGIN CERTIFICATE-----\nMIIC9jCCAd6gAwIBAgI...\n-----END CERTIFICATE-----",
			},
		}
		s.MustCreateResource(caSecret)

		// Create ClusterConfig with OIDC and CA certificate reference
		name := helpers.GenerateUniqueName("cc-oidc-with-ca")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-with-ca-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: keycloakIssuer,
					ClientID:  "breakglass-controller",
					Server:    "https://external-cluster.example.com:6443",
					CASecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name:      caSecretName,
						Namespace: s.Namespace,
						Key:       "ca.crt",
					},
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Verify the ClusterConfig was created with CA reference
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get OIDC ClusterConfig with CA")

		require.NotNil(t, fetched.Spec.OIDCAuth.CASecretRef)
		assert.Equal(t, caSecretName, fetched.Spec.OIDCAuth.CASecretRef.Name)
		assert.Equal(t, "ca.crt", fetched.Spec.OIDCAuth.CASecretRef.Key)

		t.Logf("CC-OIDC-006: Created ClusterConfig with OIDC CA certificate reference: %s", name)
	})

	t.Run("CC-OIDC-007_OIDCWithScopes", func(t *testing.T) {
		name := helpers.GenerateUniqueName("cc-oidc-scopes")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-scopes-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: keycloakIssuer,
					ClientID:  "breakglass-controller",
					Server:    "https://kubernetes.default.svc:443",
					Scopes:    []string{"groups", "profile", "offline_access"},
					Audience:  "kubernetes",
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Verify the ClusterConfig was created with custom scopes
		var fetched breakglassv1alpha1.ClusterConfig
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get OIDC ClusterConfig with scopes")

		assert.Equal(t, []string{"groups", "profile", "offline_access"}, fetched.Spec.OIDCAuth.Scopes)
		assert.Equal(t, "kubernetes", fetched.Spec.OIDCAuth.Audience)

		t.Logf("CC-OIDC-007: Created ClusterConfig with custom OIDC scopes: %s", name)
	})
}

// TestClusterConfigOIDCStatusConditions tests that the controller properly sets
// status conditions for OIDC-based ClusterConfig resources.
func TestClusterConfigOIDCStatusConditions(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithMediumTimeout())

	t.Run("CC-OIDC-STATUS-001_ValidOIDCBecomesReady", func(t *testing.T) {
		// This test requires a reachable Keycloak instance with OIDC properly configured.
		// Skip conditions:
		// 1. KEYCLOAK_ISSUER_URL not set (can't reach Keycloak)
		// 2. SKIP_OIDC_STATUS_TESTS=true explicitly set
		// 3. Running outside cluster without proper network access to Keycloak
		//
		// IMPORTANT: The issuer URL must be reachable FROM THE CONTROLLER POD,
		// not from the test runner. In KIND multi-cluster setup:
		// - Keycloak runs as Docker container on the host
		// - Controller runs inside KIND cluster
		// - Use Keycloak container's Docker network IP (KEYCLOAK_INTERNAL_URL)
		// - Or use breakglass-keycloak.breakglass-system.svc if Keycloak is in-cluster
		if os.Getenv("SKIP_OIDC_STATUS_TESTS") == "true" {
			t.Skip("Skipping OIDC status test - SKIP_OIDC_STATUS_TESTS=true")
		}

		// Check for internal URL (reachable from controller pod)
		issuerURL := os.Getenv("KEYCLOAK_INTERNAL_URL")
		if issuerURL != "" {
			issuerURL = issuerURL + "/realms/breakglass-e2e"
			t.Logf("Using KEYCLOAK_INTERNAL_URL: %s", issuerURL)
		} else {
			// Fall back to KEYCLOAK_ISSUER_URL
			issuerURL = os.Getenv("KEYCLOAK_ISSUER_URL")
		}

		if issuerURL == "" {
			// Neither internal nor external URL set
			// Try to construct from KEYCLOAK_HOST but this may not work from controller
			keycloakHost := os.Getenv("KEYCLOAK_HOST")
			if keycloakHost == "" {
				t.Skip("Skipping OIDC status test - no Keycloak URL configured (set KEYCLOAK_INTERNAL_URL for multi-cluster)")
			}
			// KEYCLOAK_HOST may be localhost which won't work from inside cluster
			if strings.Contains(keycloakHost, "localhost") || strings.Contains(keycloakHost, "127.0.0.1") {
				t.Skip("Skipping OIDC status test - KEYCLOAK_HOST uses localhost which is unreachable from controller pod. Set KEYCLOAK_INTERNAL_URL to the Docker network IP.")
			}
			issuerURL = keycloakHost + "/realms/breakglass-e2e"
			t.Logf("Using constructed issuer URL from KEYCLOAK_HOST: %s", issuerURL)
		}

		// Create client secret (matching Keycloak e2e setup)
		secretName := helpers.GenerateUniqueName("oidc-status-secret")
		clientSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			StringData: map[string]string{
				"client-secret": os.Getenv("KEYCLOAK_CLIENT_SECRET"),
			},
		}
		if clientSecret.StringData["client-secret"] == "" {
			clientSecret.StringData["client-secret"] = "breakglass-group-sync-secret"
		}
		s.MustCreateResource(clientSecret)

		name := helpers.GenerateUniqueName("cc-oidc-status")
		// Use GetOIDCEnabledAPIServerURL which returns a spoke cluster in multi-cluster mode
		// (spokes have OIDC configured, hub doesn't)
		apiServerURL := helpers.GetOIDCEnabledAPIServerURL()

		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-status-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: issuerURL, // Use the validated/constructed issuer URL
					ClientID:  "breakglass-group-sync",
					Server:    apiServerURL, // Use OIDC-enabled API server (spoke in multi-cluster)
					ClientSecretRef: &breakglassv1alpha1.SecretKeyReference{
						Name:      secretName,
						Namespace: s.Namespace,
						Key:       "client-secret",
					},
					InsecureSkipTLSVerify: true, // For e2e testing with self-signed certs
				},
			},
		}
		t.Logf("Creating ClusterConfig %s with OIDC issuer: %s, server: %s", name, issuerURL, apiServerURL)
		s.MustCreateResource(clusterConfig)

		// Wait for the Ready condition to be set with successful OIDC validation
		var fetched breakglassv1alpha1.ClusterConfig
		var finalReason, finalMessage string
		var finalStatus metav1.ConditionStatus

		// First wait for any status condition to be set
		require.Eventually(t, func() bool {
			err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
			if err != nil {
				return false
			}
			return len(fetched.Status.Conditions) > 0
		}, 30*time.Second, time.Second, "ClusterConfig status conditions not set")

		// Log the conditions for debugging
		for _, cond := range fetched.Status.Conditions {
			t.Logf("Condition: Type=%s, Status=%s, Reason=%s, Message=%s",
				cond.Type, cond.Status, cond.Reason, cond.Message)
			if cond.Type == string(breakglassv1alpha1.ClusterConfigConditionReady) {
				finalStatus = cond.Status
				finalReason = cond.Reason
				finalMessage = cond.Message
			}
		}

		// STRICT ASSERTION: This test claims "ValidOIDCBecomesReady" so we MUST verify
		// that OIDC actually worked, not just that some status was set.
		//
		// SUCCESS criteria:
		// - Status must be True (Ready)
		// - Reason must indicate successful OIDC validation (OIDCValidated)
		//
		// FAILURE reasons that should NOT pass this test:
		// - OIDCDiscoveryFailed: Cannot reach OIDC issuer (DNS, network, etc.)
		// - OIDCTokenFetchFailed: Token acquisition failed
		// - OIDCCASecretMissing: CA certificate not configured
		// - ClusterUnreachable: OIDC token acquired but cluster unreachable
		// - SecretMissing: Client secret not found
		if finalStatus != metav1.ConditionTrue {
			t.Fatalf("CC-OIDC-STATUS-001: OIDC validation FAILED - ClusterConfig %s is not Ready.\n"+
				"Status: %s, Reason: %s\nMessage: %s\n\n"+
				"This test requires successful OIDC authentication. Common failures:\n"+
				"- OIDCDiscoveryFailed: Keycloak not reachable (check DNS, network, service)\n"+
				"- OIDCTokenFetchFailed: Invalid client credentials\n"+
				"- ClusterUnreachable: Token acquired but target cluster unreachable\n"+
				"- OIDCCASecretMissing: CA certificate required but not provided",
				name, finalStatus, finalReason, finalMessage)
		}

		// Verify the reason indicates OIDC success, not just any Ready state
		if finalReason != string(breakglassv1alpha1.ClusterConfigReasonOIDCValidated) {
			t.Fatalf("CC-OIDC-STATUS-001: ClusterConfig %s is Ready but reason is %s, expected OIDCValidated.\n"+
				"Message: %s\n"+
				"This could indicate the cluster is using kubeconfig auth instead of OIDC.",
				name, finalReason, finalMessage)
		}

		t.Logf("CC-OIDC-STATUS-001: ClusterConfig %s successfully validated with OIDC (reason: %s)", name, finalReason)
	})

	t.Run("CC-OIDC-STATUS-002_InvalidIssuerSetsFailedCondition", func(t *testing.T) {
		name := helpers.GenerateUniqueName("cc-oidc-invalid-issuer")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-invalid-issuer",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL:             "https://nonexistent-issuer.invalid:8443/realms/test",
					ClientID:              "breakglass-controller",
					Server:                "https://kubernetes.default.svc:443",
					InsecureSkipTLSVerify: true,
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Wait for failure condition to be set
		var fetched breakglassv1alpha1.ClusterConfig
		require.Eventually(t, func() bool {
			err := s.Client.Get(s.Ctx, types.NamespacedName{Name: name, Namespace: s.Namespace}, &fetched)
			if err != nil {
				return false
			}
			// Check for Ready=False condition
			for _, cond := range fetched.Status.Conditions {
				if cond.Type == string(breakglassv1alpha1.ClusterConfigConditionReady) &&
					cond.Status == metav1.ConditionFalse {
					return true
				}
			}
			return false
		}, 60*time.Second, 2*time.Second, "Expected Ready=False condition for invalid OIDC issuer")

		// Verify the reason indicates OIDC discovery failure
		for _, cond := range fetched.Status.Conditions {
			if cond.Type == string(breakglassv1alpha1.ClusterConfigConditionReady) {
				t.Logf("Ready condition: Status=%s, Reason=%s, Message=%s",
					cond.Status, cond.Reason, cond.Message)
				// The reason should indicate OIDC-related failure
				assert.Contains(t, []string{
					string(breakglassv1alpha1.ClusterConfigReasonOIDCDiscoveryFailed),
					string(breakglassv1alpha1.ClusterConfigReasonClusterUnreachable),
					string(breakglassv1alpha1.ClusterConfigReasonValidationFailed),
					string(breakglassv1alpha1.ClusterConfigReasonOIDCConfigMissing),
				}, cond.Reason, "Expected OIDC-related failure reason")
			}
		}

		t.Logf("CC-OIDC-STATUS-002: ClusterConfig %s correctly shows failed status for invalid issuer", name)
	})
}

// TestClusterConfigOIDCWithEscalation tests end-to-end flow with OIDC-based ClusterConfig
// and BreakglassEscalation that references it.
func TestClusterConfigOIDCWithEscalation(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithMediumTimeout())

	// Get Keycloak issuer URL from environment or use default
	keycloakIssuer := os.Getenv("KEYCLOAK_ISSUER_URL")
	if keycloakIssuer == "" {
		keycloakIssuer = "https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443/realms/breakglass-e2e"
	}

	t.Run("CC-OIDC-ESC-001_EscalationWithOIDCClusterConfigRef", func(t *testing.T) {
		// Create OIDC-based ClusterConfig
		ccName := helpers.GenerateUniqueName("cc-oidc-for-esc")
		clusterConfig := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ccName,
				Namespace: s.Namespace,
				Labels:    helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				ClusterID:   "oidc-esc-cluster",
				Tenant:      "e2e-tenant",
				Environment: "test",
				AuthType:    breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL:             keycloakIssuer,
					ClientID:              "breakglass-controller",
					Server:                "https://kubernetes.default.svc:443",
					InsecureSkipTLSVerify: true,
				},
			},
		}
		s.MustCreateResource(clusterConfig)

		// Create Escalation that references the OIDC ClusterConfig
		escName := helpers.GenerateUniqueName("esc-with-oidc-cc")
		escalation := helpers.NewEscalationBuilder(escName, s.Namespace).
			WithEscalatedGroup(helpers.TestGroupPodsAdmin).
			WithClusterConfigRefs(ccName).
			WithApproverUsers(helpers.TestUsers.Approver.Email).
			Build()
		s.MustCreateResource(escalation)

		// Verify the escalation was created with ClusterConfigRefs
		var fetched breakglassv1alpha1.BreakglassEscalation
		err := s.Client.Get(s.Ctx, types.NamespacedName{Name: escName, Namespace: s.Namespace}, &fetched)
		require.NoError(t, err, "Failed to get Escalation")

		assert.Contains(t, fetched.Spec.ClusterConfigRefs, ccName)
		assert.Empty(t, fetched.Spec.Allowed.Clusters,
			"Escalation should use ClusterConfigRefs instead of allowed.clusters")

		t.Logf("CC-OIDC-ESC-001: Created Escalation %s referencing OIDC ClusterConfig %s", escName, ccName)
	})
}
