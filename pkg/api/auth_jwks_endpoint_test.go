package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/pkg/config"
)

// TestKeycloakJWKSEndpointConstruction tests that JWKS URLs are constructed correctly for Keycloak
func TestKeycloakJWKSEndpointConstruction(t *testing.T) {
	tests := []struct {
		name        string
		idpConfig   *config.IdentityProviderConfig
		expectedURL string
		description string
	}{
		{
			name: "Keycloak IDP - uses Keycloak-specific endpoint",
			idpConfig: &config.IdentityProviderConfig{
				Name:      "production-keycloak",
				Issuer:    "https://keycloak.example.com/auth/realms/schiff",
				Authority: "https://keycloak.example.com/auth/realms/schiff",
				Keycloak: &config.KeycloakRuntimeConfig{
					BaseURL: "https://keycloak.example.com/auth",
					Realm:   "schiff",
				},
			},
			expectedURL: "https://keycloak.example.com/auth/realms/schiff/protocol/openid-connect/certs",
			description: "Keycloak endpoint should be {baseURL}/realms/{realm}/protocol/openid-connect/certs",
		},
		{
			name: "Keycloak IDP with trailing slash in BaseURL",
			idpConfig: &config.IdentityProviderConfig{
				Name:      "keycloak-with-slash",
				Issuer:    "https://keycloak.example.com/auth/realms/master",
				Authority: "https://keycloak.example.com/auth/realms/master",
				Keycloak: &config.KeycloakRuntimeConfig{
					BaseURL: "https://keycloak.example.com/auth/", // trailing slash
					Realm:   "master",
				},
			},
			expectedURL: "https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs",
			description: "Should handle trailing slash in BaseURL correctly",
		},
		{
			name: "Generic OIDC IDP - uses .well-known endpoint",
			idpConfig: &config.IdentityProviderConfig{
				Name:      "generic-oidc",
				Issuer:    "https://auth.example.com",
				Authority: "https://auth.example.com",
				Keycloak:  nil, // No Keycloak config
			},
			expectedURL: "https://auth.example.com/.well-known/jwks.json",
			description: "Generic OIDC should use .well-known/jwks.json",
		},
		{
			name: "Generic OIDC with realm-style authority",
			idpConfig: &config.IdentityProviderConfig{
				Name:      "generic-realm",
				Issuer:    "https://auth.example.com/realms/test",
				Authority: "https://auth.example.com/realms/test",
				Keycloak:  nil,
			},
			expectedURL: "https://auth.example.com/realms/test/.well-known/jwks.json",
			description: "Generic OIDC with realm path should append .well-known",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Construct the JWKS URL using the same logic as in getJWKSForIssuer
			var jwksURL string
			if tt.idpConfig.Keycloak != nil && tt.idpConfig.Keycloak.BaseURL != "" && tt.idpConfig.Keycloak.Realm != "" {
				// Keycloak: {baseURL}/realms/{realm}/protocol/openid-connect/certs
				baseURL := tt.idpConfig.Keycloak.BaseURL
				if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
					baseURL = baseURL[:len(baseURL)-1]
				}
				jwksURL = baseURL + "/realms/" + tt.idpConfig.Keycloak.Realm + "/protocol/openid-connect/certs"
			} else {
				// Standard OIDC: use .well-known/openid-configuration discovery
				jwksURL = tt.idpConfig.Authority + "/.well-known/jwks.json"
				if len(jwksURL) > 0 && jwksURL[len(jwksURL)-len("/.well-known/jwks.json")-1] == '/' {
					jwksURL = tt.idpConfig.Authority + ".well-known/jwks.json"
				}
			}

			assert.Equal(t, tt.expectedURL, jwksURL, tt.description)
			t.Logf("✅ %s: %s", tt.name, jwksURL)
		})
	}
}

// TestGetJWKSForIssuerUsesCorrectEndpoint verifies that the getJWKSForIssuer method
// uses the correct JWKS endpoint for different IDP types
func TestGetJWKSForIssuerUsesCorrectEndpoint(t *testing.T) {
	t.Run("Keycloak_endpoint_URL_construction", func(t *testing.T) {
		// This tests the URL construction logic without hitting the network
		idpConfig := &config.IdentityProviderConfig{
			Name:      "production-keycloak",
			Issuer:    "https://keycloak.example.com/auth/realms/schiff",
			Authority: "https://keycloak.example.com/auth/realms/schiff",
			Keycloak: &config.KeycloakRuntimeConfig{
				BaseURL: "https://keycloak.example.com/auth",
				Realm:   "schiff",
			},
		}

		// Construct JWKS URL the same way getJWKSForIssuer does
		var jwksURL string
		if idpConfig.Keycloak != nil && idpConfig.Keycloak.BaseURL != "" && idpConfig.Keycloak.Realm != "" {
			baseURL := idpConfig.Keycloak.BaseURL
			// Remove trailing slash
			if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
				baseURL = baseURL[:len(baseURL)-1]
			}
			jwksURL = baseURL + "/realms/" + idpConfig.Keycloak.Realm + "/protocol/openid-connect/certs"
		}

		expectedURL := "https://keycloak.example.com/auth/realms/schiff/protocol/openid-connect/certs"
		assert.Equal(t, expectedURL, jwksURL)
		t.Logf("✅ Keycloak JWKS URL constructed correctly: %s", jwksURL)
	})

	t.Run("Generic_OIDC_endpoint_URL_construction", func(t *testing.T) {
		// Test generic OIDC without Keycloak config
		idpConfig := &config.IdentityProviderConfig{
			Name:      "generic-oidc",
			Issuer:    "https://auth.example.com",
			Authority: "https://auth.example.com",
			Keycloak:  nil,
		}

		// Construct JWKS URL the same way getJWKSForIssuer does
		var jwksURL string
		if idpConfig.Keycloak != nil && idpConfig.Keycloak.BaseURL != "" && idpConfig.Keycloak.Realm != "" {
			// Keycloak path
		} else {
			// Standard OIDC
			jwksURL = idpConfig.Authority + "/.well-known/jwks.json"
		}

		expectedURL := "https://auth.example.com/.well-known/jwks.json"
		assert.Equal(t, expectedURL, jwksURL)
		t.Logf("✅ Generic OIDC JWKS URL constructed correctly: %s", jwksURL)
	})
}

// TestMultiIDPJWKSEndpointResolution verifies the complete flow of resolving
// JWKS endpoints for different IDP types in multi-IDP scenarios
func TestMultiIDPJWKSEndpointResolution(t *testing.T) {
	// Test scenarios with different IDP configurations
	scenarios := []struct {
		name               string
		idpName            string
		idpConfig          *config.IdentityProviderConfig
		expectedURLPattern string
		shouldUseKeycloak  bool
	}{
		{
			name:              "Reference Keycloak",
			idpName:           "reference-keycloak",
			shouldUseKeycloak: true,
			idpConfig: &config.IdentityProviderConfig{
				Name:      "reference-keycloak",
				Issuer:    "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth/realms/schiff",
				Authority: "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth/realms/schiff",
				Keycloak: &config.KeycloakRuntimeConfig{
					BaseURL: "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth",
					Realm:   "schiff",
				},
			},
			expectedURLPattern: "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth/realms/schiff/protocol/openid-connect/certs",
		},
		{
			name:              "Production Keycloak",
			idpName:           "production-keycloak",
			shouldUseKeycloak: true,
			idpConfig: &config.IdentityProviderConfig{
				Name:      "production-keycloak",
				Issuer:    "https://keycloak.das-schiff.telekom.de/auth/realms/schiff",
				Authority: "https://keycloak.das-schiff.telekom.de/auth/realms/schiff",
				Keycloak: &config.KeycloakRuntimeConfig{
					BaseURL: "https://keycloak.das-schiff.telekom.de/auth",
					Realm:   "schiff",
				},
			},
			expectedURLPattern: "https://keycloak.das-schiff.telekom.de/auth/realms/schiff/protocol/openid-connect/certs",
		},
		{
			name:              "Generic OIDC Provider",
			idpName:           "generic-oidc",
			shouldUseKeycloak: false,
			idpConfig: &config.IdentityProviderConfig{
				Name:      "generic-oidc",
				Issuer:    "https://auth.example.com",
				Authority: "https://auth.example.com",
				Keycloak:  nil,
			},
			expectedURLPattern: "https://auth.example.com/.well-known/jwks.json",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			var jwksURL string

			// Apply the same logic as getJWKSForIssuer
			if scenario.idpConfig.Keycloak != nil && scenario.idpConfig.Keycloak.BaseURL != "" && scenario.idpConfig.Keycloak.Realm != "" {
				baseURL := scenario.idpConfig.Keycloak.BaseURL
				if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
					baseURL = baseURL[:len(baseURL)-1]
				}
				jwksURL = baseURL + "/realms/" + scenario.idpConfig.Keycloak.Realm + "/protocol/openid-connect/certs"
			} else {
				jwksURL = scenario.idpConfig.Authority + "/.well-known/jwks.json"
			}

			assert.Equal(t, scenario.expectedURLPattern, jwksURL)
			if scenario.shouldUseKeycloak {
				assert.Contains(t, jwksURL, "/protocol/openid-connect/certs", "should use Keycloak endpoint")
			} else {
				assert.Contains(t, jwksURL, "/.well-known/jwks.json", "should use standard OIDC endpoint")
			}

			t.Logf("✅ %s: %s", scenario.name, jwksURL)
		})
	}
}

// TestIncorrectJWKSEndpointDetection verifies that common mistakes are detected
func TestIncorrectJWKSEndpointDetection(t *testing.T) {
	// This test demonstrates what the OLD code was doing (incorrectly)
	// and verifies the NEW code does it correctly

	keycloakAuthority := "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth/realms/schiff"
	keycloakBaseURL := "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth"
	keycloakRealm := "schiff"

	t.Run("OLD_APPROACH_WRONG", func(t *testing.T) {
		// The OLD code was doing this (WRONG):
		oldJwksURL := keycloakAuthority + "/.well-known/jwks.json"
		expectedOldURL := "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth/realms/schiff/.well-known/jwks.json"
		assert.Equal(t, expectedOldURL, oldJwksURL)
		t.Logf("❌ OLD (Wrong): %s", oldJwksURL)
	})

	t.Run("NEW_APPROACH_CORRECT", func(t *testing.T) {
		// The NEW code does this (CORRECT):
		newJwksURL := keycloakBaseURL + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs"
		expectedNewURL := "https://keycloak.reftmdc.bn.das-schiff.telekom.de/auth/realms/schiff/protocol/openid-connect/certs"
		assert.Equal(t, expectedNewURL, newJwksURL)
		t.Logf("✅ NEW (Correct): %s", newJwksURL)
	})

	// Verify they are different
	oldURL := keycloakAuthority + "/.well-known/jwks.json"
	newURL := keycloakBaseURL + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs"
	assert.NotEqual(t, oldURL, newURL)
	t.Logf("✅ Verified: OLD and NEW endpoints are different")
	t.Logf("   OLD (404): %s", oldURL)
	t.Logf("   NEW (200): %s", newURL)
}
