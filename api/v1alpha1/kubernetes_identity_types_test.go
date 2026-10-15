// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
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

func TestKubernetesIdentityConfigUsesUpstreamValidation(t *testing.T) {
	config := &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
		Username: apiserverv1.PrefixedClaimOrExpression{Expression: "claims.missing +"},
	}}
	if errs := config.Validate("https://issuer.example", []string{"audience"}); len(errs) == 0 {
		t.Fatal("Validate() accepted malformed CEL")
	}
}

func TestStructuredKubernetesIdentityCannotMixShorthand(t *testing.T) {
	idp := testKubernetesIdentityIDP()
	idp.Spec.UserIdentifierClaim = UserIdentifierClaimType("employee_id")
	idp.Spec.KubernetesIdentity = &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
		Username: apiserverv1.PrefixedClaimOrExpression{Claim: "employee_id"},
	}}
	if result := ValidateIdentityProvider(idp); result.IsValid() {
		t.Fatal("ValidateIdentityProvider() accepted structured and shorthand identity policy")
	}

	cc := testKubernetesIdentityClusterConfig()
	cc.Spec.UserIdentifierPrefix = stringPtr("prefix:")
	cc.Spec.KubernetesIdentity = &KubernetesIdentityConfig{ClaimMappings: apiserverv1.ClaimMappings{
		Username: apiserverv1.PrefixedClaimOrExpression{Claim: "sub"},
	}}
	if result := ValidateClusterConfig(cc); result.IsValid() {
		t.Fatal("ValidateClusterConfig() accepted structured and shorthand identity policy")
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
