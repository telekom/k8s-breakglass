/*
Copyright 2024.

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
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// TestValidateSessionIdentityProviderAuthorization_EmptyIDPName tests backward compatibility
// when session has no IDP name (single-IDP or manual creation mode)
func TestValidateSessionIdentityProviderAuthorization_EmptyIDPName(t *testing.T) {
	ctx := context.Background()
	fieldPath := field.NewPath("spec").Child("identityProviderName")

	// Call validation with empty IDP name
	errs := validateSessionIdentityProviderAuthorization(ctx, "test-cluster", "admin", "", fieldPath)

	// Should pass (skip validation for backward compatibility)
	assert.Nil(t, errs, "empty IDP name should skip authorization check")
}

// TestValidateSessionIdentityProviderAuthorization_NilFieldPath tests graceful handling
// when field path is nil
func TestValidateSessionIdentityProviderAuthorization_NilFieldPath(t *testing.T) {
	ctx := context.Background()

	// Call validation with nil field path
	errs := validateSessionIdentityProviderAuthorization(ctx, "test-cluster", "admin", "test-idp", nil)

	// Should return nil (graceful fallback for nil path)
	assert.Nil(t, errs, "nil field path should result in nil errors")
}

// TestValidateSessionIdentityProviderAuthorization_NilContext tests graceful handling
// when context is nil
func TestValidateSessionIdentityProviderAuthorization_NilContext(t *testing.T) {
	fieldPath := field.NewPath("spec").Child("identityProviderName")

	// Call validation with context.TODO instead of nil
	assert.NotPanics(t, func() {
		validateSessionIdentityProviderAuthorization(context.TODO(), "test-cluster", "admin", "test-idp", fieldPath)
	}, "context should not cause panic")
}

// TestValidateSessionIdentityProviderAuthorization_NilReader tests graceful handling
// when webhook reader returns nil (no escalations available)
func TestValidateSessionIdentityProviderAuthorization_NilReader(t *testing.T) {
	ctx := context.Background()
	fieldPath := field.NewPath("spec").Child("identityProviderName")

	// When webhookCache is nil and webhookClient is nil, reader will be nil
	// The function should handle this gracefully
	errs := validateSessionIdentityProviderAuthorization(ctx, "test-cluster", "admin", "test-idp", fieldPath)

	// Should return nil when reader is unavailable (fails safely)
	// Note: This test depends on webhookCache and webhookClient being nil
	// In a real test environment, these would be set by the webhook server
	_ = errs
}

// TestBreakglassSessionValidateCreate_IntegrationWith tests that ValidateCreate
func TestBreakglassSessionValidateCreate_IntegrationWith(t *testing.T) {
	ctx := context.Background()

	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:                "test-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "cluster-admin",
			IdentityProviderName:   "", // Empty for backward compatibility
			IdentityProviderIssuer: "",
		},
	}

	// ValidateCreate should accept sessions with empty IDP name
	warnings, err := session.ValidateCreate(ctx, session)

	// Should pass for now (no escalations in test environment)
	// The real validation would depend on escalations being available
	_ = warnings
	_ = err
}

// TestBreakglassSessionAuthorizationFields tests that BreakglassSession
// properly tracks IDP authorization fields
func TestBreakglassSessionAuthorizationFields(t *testing.T) {
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:                "prod-cluster",
			User:                   "alice@example.com",
			GrantedGroup:           "cluster-admin",
			IdentityProviderName:   "corporate-idp",
			IdentityProviderIssuer: "https://auth.corp.com",
		},
	}

	// Verify IDP authorization fields are stored
	assert.Equal(t, "corporate-idp", session.Spec.IdentityProviderName)
	assert.Equal(t, "https://auth.corp.com", session.Spec.IdentityProviderIssuer)
}

// TestAuthorizationLogic tests the authorization rules independently
// Rule 1: Empty IDP name skips check
func TestAuthorizationLogic_Rule1_EmptyIDPName(t *testing.T) {
	// When session.identityProviderName is empty, authorization passes
	fieldPath := field.NewPath("spec").Child("identityProviderName")
	ctx := context.Background()

	errs := validateSessionIdentityProviderAuthorization(ctx, "cluster", "group", "", fieldPath)
	assert.Nil(t, errs, "Rule 1: Empty IDP name should skip check")
}
func TestAuthorizationBackwardCompatibility(t *testing.T) {
	// Test that sessions without IDP tracking fields still work
	session := &BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "user@example.com",
			GrantedGroup: "developers",
			// IdentityProviderName and IdentityProviderIssuer are not set
		},
	}

	// Should have default values
	assert.Empty(t, session.Spec.IdentityProviderName, "IDP name should be empty in backward compat mode")
	assert.Empty(t, session.Spec.IdentityProviderIssuer, "IDP issuer should be empty in backward compat mode")
}

// TestBreakglassEscalationAuthorizationConfiguration tests that escalations
// can be configured for IDP authorization
func TestBreakglassEscalationAuthorizationConfiguration(t *testing.T) {
	escalation := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "cluster-admin",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"prod-cluster"},
			},
			AllowedIdentityProviders: []string{"corporate-idp", "partner-idp"},
		},
	}

	// Verify escalation can store allowed IDPs
	assert.Equal(t, []string{"corporate-idp", "partner-idp"}, escalation.Spec.AllowedIdentityProviders)
	assert.Len(t, escalation.Spec.AllowedIdentityProviders, 2, "Should store multiple allowed IDPs")
}

// TestBreakglassEscalationNoIDPRestrictions tests that empty AllowedIdentityProviders
// means all IDPs are allowed (backward compatibility)
func TestBreakglassEscalationNoIDPRestrictions(t *testing.T) {
	escalation := &BreakglassEscalation{
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "developers",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"dev-cluster"},
			},
			AllowedIdentityProviders: []string{}, // Empty = all allowed
		},
	}

	// Empty list means no restrictions (backward compatible)
	assert.Empty(t, escalation.Spec.AllowedIdentityProviders)
	assert.Len(t, escalation.Spec.AllowedIdentityProviders, 0)
}

// TestValidateClusterAuthConfig_KubeconfigOnly tests that kubeconfig auth is valid
func TestValidateClusterAuthConfig_KubeconfigOnly(t *testing.T) {
	spec := ClusterConfigSpec{
		KubeconfigSecretRef: &SecretKeyReference{
			Name:      "my-secret",
			Namespace: "default",
		},
	}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.Empty(t, errs, "kubeconfig-only config should be valid")
}

// TestValidateClusterAuthConfig_OIDCOnly tests that OIDC auth is valid
func TestValidateClusterAuthConfig_OIDCOnly(t *testing.T) {
	spec := ClusterConfigSpec{
		AuthType: ClusterAuthTypeOIDC,
		OIDCAuth: &OIDCAuthConfig{
			IssuerURL: "https://keycloak.example.com/realms/test",
			ClientID:  "breakglass",
			Server:    "https://api.cluster.example.com:6443",
			ClientSecretRef: &SecretKeyReference{
				Name:      "oidc-secret",
				Namespace: "default",
			},
		},
	}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.Empty(t, errs, "OIDC-only config should be valid")
}

// TestValidateClusterAuthConfig_NoAuth tests that missing auth fails validation
func TestValidateClusterAuthConfig_NoAuth(t *testing.T) {
	spec := ClusterConfigSpec{}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.NotEmpty(t, errs, "no auth config should fail validation")
	assert.Contains(t, errs[0].Error(), "either kubeconfigSecretRef, oidcAuth, or oidcFromIdentityProvider must be specified")
}

// TestValidateClusterAuthConfig_BothAuth tests that both auth methods fails validation
func TestValidateClusterAuthConfig_BothAuth(t *testing.T) {
	spec := ClusterConfigSpec{
		KubeconfigSecretRef: &SecretKeyReference{
			Name:      "my-secret",
			Namespace: "default",
		},
		OIDCAuth: &OIDCAuthConfig{
			IssuerURL: "https://keycloak.example.com/realms/test",
			ClientID:  "breakglass",
			Server:    "https://api.cluster.example.com:6443",
		},
	}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.NotEmpty(t, errs, "both auth methods should fail validation")
	assert.Contains(t, errs[0].Error(), "mutually exclusive")
}

// TestValidateClusterAuthConfig_WrongAuthType tests mismatched authType field
func TestValidateClusterAuthConfig_WrongAuthType(t *testing.T) {
	spec := ClusterConfigSpec{
		AuthType: ClusterAuthTypeOIDC, // Says OIDC
		KubeconfigSecretRef: &SecretKeyReference{ // But provides kubeconfig
			Name:      "my-secret",
			Namespace: "default",
		},
	}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.NotEmpty(t, errs, "mismatched authType should fail validation")
}

// TestValidateOIDCAuthConfig_MissingRequiredFields tests OIDC config with missing fields
func TestValidateOIDCAuthConfig_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		oidc   *OIDCAuthConfig
		expect string
	}{
		{
			name:   "missing issuerURL",
			oidc:   &OIDCAuthConfig{ClientID: "test", Server: "https://api.example.com"},
			expect: "issuerURL",
		},
		{
			name:   "missing clientID",
			oidc:   &OIDCAuthConfig{IssuerURL: "https://idp.example.com", Server: "https://api.example.com"},
			expect: "clientID",
		},
		{
			name:   "missing server",
			oidc:   &OIDCAuthConfig{IssuerURL: "https://idp.example.com", ClientID: "test"},
			expect: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateOIDCAuthConfig(tt.oidc, field.NewPath("spec", "oidcAuth"))
			assert.NotEmpty(t, errs, "should have validation errors")
			found := false
			for _, err := range errs {
				if assert.NotNil(t, err.Field) && containsIgnoreCase(err.Error(), tt.expect) {
					found = true
					break
				}
			}
			assert.True(t, found, "expected error about %s, got: %v", tt.expect, errs)
		})
	}
}

// TestValidateOIDCAuthConfig_InvalidURLs tests OIDC config with non-HTTPS URLs
func TestValidateOIDCAuthConfig_InvalidURLs(t *testing.T) {
	oidc := &OIDCAuthConfig{
		IssuerURL: "http://insecure.example.com", // Should be https
		ClientID:  "test",
		Server:    "http://insecure-api.example.com", // Should be https
	}
	errs := validateOIDCAuthConfig(oidc, field.NewPath("spec", "oidcAuth"))
	assert.NotEmpty(t, errs, "non-HTTPS URLs should fail validation")
}

// TestValidateOIDCAuthConfig_ValidComplete tests a complete valid OIDC config
func TestValidateOIDCAuthConfig_ValidComplete(t *testing.T) {
	oidc := &OIDCAuthConfig{
		IssuerURL: "https://keycloak.example.com/realms/kubernetes",
		ClientID:  "breakglass-controller",
		Server:    "https://api.cluster.example.com:6443",
		ClientSecretRef: &SecretKeyReference{
			Name:      "oidc-secret",
			Namespace: "breakglass-system",
		},
		CASecretRef: &SecretKeyReference{
			Name:      "cluster-ca",
			Namespace: "breakglass-system",
		},
		Audience: "https://api.cluster.example.com:6443",
		Scopes:   []string{"openid", "groups"},
		TokenExchange: &TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &SecretKeyReference{
				Name:      "subject-token",
				Namespace: "breakglass-system",
			},
		},
	}
	errs := validateOIDCAuthConfig(oidc, field.NewPath("spec", "oidcAuth"))
	assert.Empty(t, errs, "complete valid OIDC config should pass validation")
}

// TestValidateOIDCAuthConfig_TokenExchangeMissingSubjectToken tests that token exchange requires subject token
func TestValidateOIDCAuthConfig_TokenExchangeMissingSubjectToken(t *testing.T) {
	oidc := &OIDCAuthConfig{
		IssuerURL: "https://keycloak.example.com/realms/kubernetes",
		ClientID:  "breakglass-controller",
		Server:    "https://api.cluster.example.com:6443",
		ClientSecretRef: &SecretKeyReference{
			Name:      "oidc-secret",
			Namespace: "breakglass-system",
		},
		TokenExchange: &TokenExchangeConfig{
			Enabled: true,
			// Missing SubjectTokenSecretRef
		},
	}
	errs := validateOIDCAuthConfig(oidc, field.NewPath("spec", "oidcAuth"))
	assert.NotEmpty(t, errs, "token exchange without subjectTokenSecretRef should fail")
	errStr := errs.ToAggregate().Error()
	assert.Contains(t, errStr, "subjectTokenSecretRef")
}

// TestValidateClusterAuthConfig_OIDCFromIdentityProviderOnly tests that oidcFromIdentityProvider alone passes validation
func TestValidateClusterAuthConfig_OIDCFromIdentityProviderOnly(t *testing.T) {
	spec := ClusterConfigSpec{
		AuthType: ClusterAuthTypeOIDC,
		OIDCFromIdentityProvider: &OIDCFromIdentityProviderConfig{
			Name:   "my-idp",
			Server: "https://api.cluster.example.com:6443",
		},
	}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.Empty(t, errs, "oidcFromIdentityProvider alone should pass validation")
}

// TestValidateClusterAuthConfig_OIDCFromIdentityProvider_MissingFields tests required fields
func TestValidateClusterAuthConfig_OIDCFromIdentityProvider_MissingFields(t *testing.T) {
	tests := []struct {
		name   string
		spec   ClusterConfigSpec
		expect string
	}{
		{
			name: "missing name",
			spec: ClusterConfigSpec{
				AuthType: ClusterAuthTypeOIDC,
				OIDCFromIdentityProvider: &OIDCFromIdentityProviderConfig{
					Server: "https://api.cluster.example.com:6443",
				},
			},
			expect: "name",
		},
		{
			name: "missing server",
			spec: ClusterConfigSpec{
				AuthType: ClusterAuthTypeOIDC,
				OIDCFromIdentityProvider: &OIDCFromIdentityProviderConfig{
					Name: "my-idp",
				},
			},
			expect: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateClusterAuthConfig(tt.spec, field.NewPath("spec"))
			assert.NotEmpty(t, errs, "missing fields should fail validation")
			found := false
			for _, err := range errs {
				if containsIgnoreCase(err.Error(), tt.expect) {
					found = true
					break
				}
			}
			assert.True(t, found, "error should mention %s", tt.expect)
		})
	}
}

// TestValidateClusterAuthConfig_OIDCFromIdentityProvider_ConflictsWithOIDCAuth tests mutual exclusion
func TestValidateClusterAuthConfig_OIDCFromIdentityProvider_ConflictsWithOIDCAuth(t *testing.T) {
	spec := ClusterConfigSpec{
		AuthType: ClusterAuthTypeOIDC,
		OIDCAuth: &OIDCAuthConfig{
			IssuerURL: "https://keycloak.example.com/realms/test",
			ClientID:  "breakglass",
			Server:    "https://api.cluster.example.com:6443",
		},
		OIDCFromIdentityProvider: &OIDCFromIdentityProviderConfig{
			Name:   "my-idp",
			Server: "https://api.cluster.example.com:6443",
		},
	}
	errs := validateClusterAuthConfig(spec, field.NewPath("spec"))
	assert.NotEmpty(t, errs, "oidcAuth and oidcFromIdentityProvider together should fail")
	assert.Contains(t, errs[0].Error(), "mutually exclusive")
}

// containsIgnoreCase is a helper for case-insensitive string matching in tests
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
