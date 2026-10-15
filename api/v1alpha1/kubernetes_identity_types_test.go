// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

func TestKubernetesIdentityConfigToJWTAuthenticator(t *testing.T) {
	prefix := "tdi_security_oidc:"
	config := &KubernetesIdentityConfig{
		ClaimMappings: apiserverv1.ClaimMappings{
			Username: apiserverv1.PrefixedClaimOrExpression{Claim: "preferred_username", Prefix: &prefix},
			Groups:   apiserverv1.PrefixedClaimOrExpression{Claim: "groups", Prefix: &prefix},
		},
		ClaimValidationRules: []apiserverv1.ClaimValidationRule{{Claim: "tenant", RequiredValue: "security"}},
		UserValidationRules:  []apiserverv1.UserValidationRule{{Expression: "user.username.startsWith('tdi_security_oidc:')"}},
	}

	got, err := config.ToJWTAuthenticator("https://issuer.example", []string{"cluster", "breakglass"})
	if err != nil {
		t.Fatalf("ToJWTAuthenticator() error = %v", err)
	}
	if got.Issuer.URL != "https://issuer.example" || len(got.Issuer.Audiences) != 2 {
		t.Fatalf("issuer conversion = %#v", got.Issuer)
	}
	if got.Issuer.AudienceMatchPolicy != apiserver.AudienceMatchPolicyMatchAny {
		t.Fatalf("audience match policy = %q", got.Issuer.AudienceMatchPolicy)
	}
	if got.ClaimMappings.Username.Claim != "preferred_username" || got.ClaimMappings.Username.Prefix == nil || *got.ClaimMappings.Username.Prefix != prefix {
		t.Fatalf("username mapping conversion = %#v", got.ClaimMappings.Username)
	}
}

func TestNilKubernetesIdentityConfigCannotConvert(t *testing.T) {
	var config *KubernetesIdentityConfig
	if _, err := config.ToJWTAuthenticator("https://issuer.example", []string{"audience"}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("ToJWTAuthenticator() error = %v, want nil configuration error", err)
	}
}

func TestKubernetesIdentityConfigUsesUpstreamValidation(t *testing.T) {
	config := &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
		Username: apiserverv1.PrefixedClaimOrExpression{Expression: "claims.missing +"},
	}}
	if errs := config.Validate("https://issuer.example", []string{"audience"}); len(errs) == 0 {
		t.Fatal("Validate() accepted malformed CEL")
	}
}

func TestKubernetesIdentityConfigValidationMatrix(t *testing.T) {
	tests := []struct {
		name      string
		config    KubernetesIdentityConfig
		wantValid bool
		wantError string
	}{
		{
			name: "arbitrary claim name",
			config: KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
				Username: apiserverv1.PrefixedClaimOrExpression{Claim: "urn:example:principal", Prefix: stringPtr("")},
			}},
			wantValid: true,
		},
		{
			name: "claim requires prefix field",
			config: KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
				Username: apiserverv1.PrefixedClaimOrExpression{Claim: "preferred_username"},
			}},
			wantValid: false,
			wantError: "prefix",
		},
		{
			name: "explicit empty prefix",
			config: KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
				Username: apiserverv1.PrefixedClaimOrExpression{Claim: "preferred_username", Prefix: stringPtr("")},
			}},
			wantValid: true,
		},
		{
			name: "literal hyphen prefix",
			config: KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
				Username: apiserverv1.PrefixedClaimOrExpression{Claim: "preferred_username", Prefix: stringPtr("-")},
			}},
			wantValid: true,
		},
		{
			name: "expression cannot set prefix",
			config: KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
				Username: apiserverv1.PrefixedClaimOrExpression{Expression: "claims.preferred_username", Prefix: stringPtr("")},
			}},
			wantValid: false,
			wantError: "prefix",
		},
		{
			name: "claim and expression are exclusive",
			config: KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
				Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Expression: "claims.sub", Prefix: stringPtr("")},
			}},
			wantValid: false,
			wantError: "claim",
		},
		{
			name: "duplicate claim validation rules",
			config: KubernetesIdentityConfig{
				ClaimMappings:        apiserverv1.ClaimMappings{Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
				ClaimValidationRules: []apiserverv1.ClaimValidationRule{{Claim: "tenant"}, {Claim: "tenant"}},
			},
			wantValid: false,
			wantError: "duplicate",
		},
		{
			name: "empty user validation expression",
			config: KubernetesIdentityConfig{
				ClaimMappings:       apiserverv1.ClaimMappings{Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
				UserValidationRules: []apiserverv1.UserValidationRule{{}},
			},
			wantValid: false,
			wantError: "expression",
		},
		{
			name: "invalid extra key",
			config: KubernetesIdentityConfig{
				ClaimMappings: apiserverv1.ClaimMappings{
					Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")},
					Extra:    []apiserverv1.ExtraMapping{{Key: "not-namespaced", ValueExpression: "claims.team"}},
				},
			},
			wantValid: false,
			wantError: "key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.config.Validate("https://issuer.example", []string{"audience"})
			if got := len(errs) == 0; got != tt.wantValid {
				t.Fatalf("Validate() valid=%v, want %v; errors=%v", got, tt.wantValid, errs)
			}
			if tt.wantError != "" {
				var text string
				for _, err := range errs {
					text += err.Error() + "\n"
				}
				if !strings.Contains(strings.ToLower(text), strings.ToLower(tt.wantError)) {
					t.Fatalf("Validate() errors %q do not contain %q", text, tt.wantError)
				}
			}
		})
	}
}

func TestIdentityProviderOIDCOptionsValidation(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*IdentityProvider)
		wantValid bool
		wantError string
	}{
		{
			name: "additional audiences and signing algorithms",
			mutate: func(idp *IdentityProvider) {
				idp.Spec.OIDC.Audiences = []string{"secondary-audience"}
				idp.Spec.OIDC.SupportedSigningAlgs = []string{"RS256", "ES256"}
			},
			wantValid: true,
		},
		{
			name: "empty additional audience",
			mutate: func(idp *IdentityProvider) {
				idp.Spec.OIDC.Audiences = []string{""}
			},
			wantError: "spec.oidc.audiences[0]",
		},
		{
			name: "duplicate expected audience",
			mutate: func(idp *IdentityProvider) {
				idp.Spec.OIDC.Audiences = []string{idp.Spec.OIDC.ExpectedAudience}
			},
			wantError: "spec.oidc.audiences[0]",
		},
		{
			name: "empty signing algorithm",
			mutate: func(idp *IdentityProvider) {
				idp.Spec.OIDC.SupportedSigningAlgs = []string{""}
			},
			wantError: "spec.oidc.supportedSigningAlgs[0]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testKubernetesIdentityIDP()
			tt.mutate(idp)
			result := ValidateIdentityProvider(idp)
			if got := result.IsValid(); got != tt.wantValid {
				t.Fatalf("ValidateIdentityProvider() valid=%v, want %v: %s", got, tt.wantValid, result.ErrorMessage())
			}
			if tt.wantError != "" && !strings.Contains(result.ErrorMessage(), tt.wantError) {
				t.Fatalf("ValidateIdentityProvider() error %q does not contain %q", result.ErrorMessage(), tt.wantError)
			}
		})
	}
}

func TestStructuredKubernetesIdentityCannotMixShorthand(t *testing.T) {
	idp := testKubernetesIdentityIDP()
	idp.Spec.UserIdentifierClaim = UserIdentifierClaimType("employee_id")
	idp.Spec.KubernetesIdentity = &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
		Username: apiserverv1.PrefixedClaimOrExpression{Claim: "employee_id", Prefix: stringPtr("")},
	}}
	if result := ValidateIdentityProvider(idp); result.IsValid() || !strings.Contains(result.ErrorMessage(), "userIdentifierClaim") {
		t.Fatalf("ValidateIdentityProvider() conflict result = %s", result.ErrorMessage())
	}

	cc := testKubernetesIdentityClusterConfig()
	cc.Spec.UserIdentifierPrefix = stringPtr("prefix:")
	cc.Spec.KubernetesIdentity = &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
		Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")},
	}}
	if result := ValidateClusterConfig(cc); result.IsValid() || !strings.Contains(result.ErrorMessage(), "userIdentifierPrefix") {
		t.Fatalf("ValidateClusterConfig() conflict result = %s", result.ErrorMessage())
	}
}

func TestKubernetesIdentityConfigDeepCopyDoesNotAlias(t *testing.T) {
	prefix := "tdi:"
	original := &KubernetesIdentityConfig{
		ClaimMappings: apiserverv1.ClaimMappings{
			Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: &prefix},
		},
		ClaimValidationRules: []apiserverv1.ClaimValidationRule{{Claim: "tenant", RequiredValue: "security"}},
	}
	cloned := original.DeepCopy()
	*cloned.ClaimMappings.Username.Prefix = "copy:"
	cloned.ClaimValidationRules[0].Claim = "other"
	if *original.ClaimMappings.Username.Prefix != "tdi:" || original.ClaimValidationRules[0].Claim != "tenant" {
		t.Fatalf("DeepCopy() aliases mutable nested fields: original=%#v copy=%#v", original, cloned)
	}
}

func TestLegacyIdentityMappingRemainsValid(t *testing.T) {
	idp := testKubernetesIdentityIDP()
	idp.Spec.UserIdentifierClaim = UserIdentifierClaimType("preferred username")
	idp.Spec.UserIdentifierPrefix = "-"
	if result := ValidateIdentityProvider(idp); !result.IsValid() {
		t.Fatalf("ValidateIdentityProvider() rejected legacy mapping: %s", result.ErrorMessage())
	}

	cluster := testKubernetesIdentityClusterConfig()
	cluster.Spec.UserIdentifierClaim = UserIdentifierClaimType("upn")
	if result := ValidateClusterConfig(cluster); !result.IsValid() {
		t.Fatalf("ValidateClusterConfig() rejected legacy mapping: %s", result.ErrorMessage())
	}
}

func TestIdentityProviderStructuredDiscoveryUsesKubernetesValidation(t *testing.T) {
	tests := []struct {
		name         string
		discoveryURL string
		structured   bool
		wantRejected bool
	}{
		{name: "structured query", discoveryURL: "https://issuer.example/.well-known/openid-configuration?x=1", structured: true, wantRejected: true},
		{name: "structured fragment", discoveryURL: "https://issuer.example/.well-known/openid-configuration#fragment", structured: true, wantRejected: true},
		{name: "structured same as issuer", discoveryURL: "https://issuer.example", structured: true, wantRejected: true},
		{name: "structured valid", discoveryURL: "https://discovery.example/.well-known/openid-configuration", structured: true, wantRejected: false},
		{name: "shorthand query", discoveryURL: "https://issuer.example/.well-known/openid-configuration?x=1", wantRejected: true},
		{name: "shorthand fragment", discoveryURL: "https://issuer.example/.well-known/openid-configuration#fragment", wantRejected: true},
		{name: "shorthand same as issuer", discoveryURL: "https://issuer.example", wantRejected: true},
		{name: "shorthand valid", discoveryURL: "https://discovery.example/.well-known/openid-configuration", wantRejected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testKubernetesIdentityIDP()
			idp.Spec.Issuer = "https://issuer.example"
			idp.Spec.OIDC.DiscoveryURL = tt.discoveryURL
			if tt.structured {
				idp.Spec.KubernetesIdentity = &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
					Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")},
				}}
			}
			gotRejected := !ValidateIdentityProvider(idp).IsValid()
			if gotRejected != tt.wantRejected {
				t.Fatalf("ValidateIdentityProvider() rejected=%v, want %v", gotRejected, tt.wantRejected)
			}
		})
	}
}

func TestIdentityProviderAcceptsURLAudience(t *testing.T) {
	idp := testKubernetesIdentityIDP()
	idp.Spec.OIDC.ExpectedAudience = "https://audience.example/cluster?resource=api"
	if result := ValidateIdentityProvider(idp); !result.IsValid() {
		t.Fatalf("ValidateIdentityProvider() rejected URL audience: %s", result.ErrorMessage())
	}
}

func stringPtr(value string) *string { return &value }

func testKubernetesIdentityIDP() *IdentityProvider {
	return &IdentityProvider{Spec: IdentityProviderSpec{OIDC: OIDCConfig{
		Authority:        "https://auth.example.com",
		ClientID:         "breakglass-client",
		ExpectedAudience: "breakglass-client",
	}}}
}

func testKubernetesIdentityClusterConfig() *ClusterConfig {
	return &ClusterConfig{Spec: ClusterConfigSpec{KubeconfigSecretRef: &SecretKeyReference{
		Name: "test-secret", Namespace: "test-ns",
	}}}
}
