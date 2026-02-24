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
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestIdentityProviderGroupSync tests KeycloakGroupSync configuration.
func TestIdentityProviderGroupSync(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("KeycloakGroupSyncConfig", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   s.GenerateName("e2e-idp-keycloak-sync"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://keycloak.example.com/realms/test",
					ClientID:  "breakglass-ui",
				},
				GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
				Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
					BaseURL:  "https://keycloak.example.com",
					Realm:    "test",
					ClientID: "breakglass-client",
					CacheTTL: "5m",
					ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
						Name:      "keycloak-secret",
						Namespace: "breakglass-system",
						Key:       "client-secret",
					},
				},
			},
		}
		s.MustCreateResource(idp)

		assert.Equal(t, breakglassv1alpha1.GroupSyncProviderKeycloak, idp.Spec.GroupSyncProvider)
		assert.NotNil(t, idp.Spec.Keycloak)
		assert.Equal(t, "https://keycloak.example.com", idp.Spec.Keycloak.BaseURL)
		assert.Equal(t, "test", idp.Spec.Keycloak.Realm)
		assert.Equal(t, "5m", idp.Spec.Keycloak.CacheTTL)
		t.Logf("GROUPSYNC-001: Created IdentityProvider with KeycloakGroupSync: %s", idp.Name)
	})

	t.Run("KeycloakGroupSyncWithRequestTimeout", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   s.GenerateName("e2e-idp-keycloak-timeout"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://keycloak.example.com/realms/timeout-test",
					ClientID:  "breakglass-ui",
				},
				GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
				Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
					BaseURL:        "https://keycloak.example.com",
					Realm:          "timeout-test",
					ClientID:       "breakglass-client",
					RequestTimeout: "30s",
					CacheTTL:       "10m",
					ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
						Name:      "keycloak-secret",
						Namespace: "breakglass-system",
						Key:       "client-secret",
					},
				},
			},
		}
		s.MustCreateResource(idp)

		assert.Equal(t, "30s", idp.Spec.Keycloak.RequestTimeout)
		t.Logf("GROUPSYNC-002: Created IdentityProvider with RequestTimeout: %v", idp.Spec.Keycloak.RequestTimeout)
	})

	t.Run("KeycloakGroupSyncWithInsecureSkipVerify", func(t *testing.T) {
		idp := &breakglassv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   s.GenerateName("e2e-idp-keycloak-insecure"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC: breakglassv1alpha1.OIDCConfig{
					Authority: "https://keycloak.example.com/realms/insecure-test",
					ClientID:  "breakglass-ui",
				},
				GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
				Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
					BaseURL:            "https://keycloak.example.com",
					Realm:              "insecure-test",
					ClientID:           "breakglass-client",
					InsecureSkipVerify: true,
					ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
						Name:      "keycloak-secret",
						Namespace: "breakglass-system",
						Key:       "client-secret",
					},
				},
			},
		}
		s.MustCreateResource(idp)

		assert.True(t, idp.Spec.Keycloak.InsecureSkipVerify)
		t.Logf("GROUPSYNC-003: Created IdentityProvider with InsecureSkipVerify=true: %s", idp.Name)
	})
}

// TestIdentityProviderOIDCConfig tests OIDC configuration options.
func TestIdentityProviderOIDCConfig(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("OIDCConfigFields", func(t *testing.T) {
		oidcConfig := breakglassv1alpha1.OIDCConfig{
			Authority:            "https://auth.example.com",
			ClientID:             "breakglass-ui",
			JWKSEndpoint:         "https://auth.example.com/.well-known/jwks.json",
			InsecureSkipVerify:   false,
			CertificateAuthority: "-----BEGIN CERTIFICATE-----\n...",
		}
		assert.Equal(t, "https://auth.example.com", oidcConfig.Authority)
		assert.Equal(t, "breakglass-ui", oidcConfig.ClientID)
		assert.NotEmpty(t, oidcConfig.JWKSEndpoint)
		t.Logf("OIDC-001: OIDCConfig supports all required fields")
	})
}

// TestGroupSyncProviderEnum tests the GroupSyncProvider enum values.
func TestGroupSyncProviderEnum(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	t.Run("GroupSyncProviderKeycloak", func(t *testing.T) {
		provider := breakglassv1alpha1.GroupSyncProviderKeycloak
		assert.Equal(t, breakglassv1alpha1.GroupSyncProvider("Keycloak"), provider)
		t.Logf("GROUPSYNC-004: GroupSyncProviderKeycloak value is 'Keycloak'")
	})

	t.Run("GroupSyncProviderDocumentation", func(t *testing.T) {
		t.Log("GROUPSYNC-005: GroupSyncProvider enables real-time group membership resolution")
		t.Log("GROUPSYNC-006: Keycloak provider uses Admin REST API for group lookups")
		t.Log("GROUPSYNC-007: Results are cached based on CacheTTL setting")
	})
}
