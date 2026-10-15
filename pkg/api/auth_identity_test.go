// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/utils/ptr"
)

func TestTargetJWTPolicyPrecedence(t *testing.T) {
	cfg := &config.IdentityProviderConfig{Issuer: "https://issuer.example", ExpectedAudience: "breakglass", UserIdentifierClaim: "preferred_username", UserIdentifierPrefix: "provider:"}
	tests := []struct {
		name          string
		cluster       *breakglassv1alpha1.ClusterConfig
		claim, prefix string
	}{
		{name: "provider defaults", claim: "preferred_username", prefix: "provider:"},
		{name: "cluster claim retains prefix", cluster: &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierClaim: "employee_id"}}, claim: "employee_id", prefix: "provider:"},
		{name: "cluster prefix", cluster: &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierPrefix: ptr.To("tdi_security_oidc:")}}, claim: "preferred_username", prefix: "tdi_security_oidc:"},
		{name: "explicit empty prefix", cluster: &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierPrefix: ptr.To("")}}, claim: "preferred_username", prefix: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := targetJWTPolicy(cfg, tt.cluster, breakglassv1alpha1.UserIdentifierClaimType("email"))
			require.NoError(t, err)
			require.Equal(t, tt.claim, policy.ClaimMappings.Username.Claim)
			require.Equal(t, ptr.To(tt.prefix), policy.ClaimMappings.Username.Prefix)
			require.Equal(t, []string{"breakglass"}, policy.Issuer.Audiences)
		})
	}
}

func TestTargetJWTPolicyDefaultsAndNativeInheritance(t *testing.T) {
	native := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{Claim: "employee_id", Prefix: ptr.To("native:")},
			Groups:   apiserver.PrefixedClaimOrExpression{Claim: "roles", Prefix: ptr.To("role:")},
		},
		ClaimValidationRules: []apiserver.ClaimValidationRule{{Claim: "tenant", RequiredValue: "operations"}},
	}
	for _, tc := range []struct {
		name          string
		cfg           config.IdentityProviderConfig
		cluster       *breakglassv1alpha1.ClusterConfig
		fallback      breakglassv1alpha1.UserIdentifierClaimType
		claim, prefix string
	}{
		{name: "legacy email default", claim: "email"},
		{name: "global custom claim", fallback: "employee_id", claim: "employee_id"},
		{name: "provider claim overrides global", cfg: config.IdentityProviderConfig{UserIdentifierClaim: "preferred_username"}, fallback: "sub", claim: "preferred_username"},
		{name: "native inherited without cluster", cfg: config.IdentityProviderConfig{KubernetesIdentity: &native}, claim: "employee_id", prefix: "native:"},
		{name: "native inherited with empty cluster", cfg: config.IdentityProviderConfig{KubernetesIdentity: &native}, cluster: &breakglassv1alpha1.ClusterConfig{}, claim: "employee_id", prefix: "native:"},
		{name: "prefix overrides native claim", cfg: config.IdentityProviderConfig{KubernetesIdentity: &native}, cluster: &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierPrefix: ptr.To("cluster:")}}, claim: "employee_id", prefix: "cluster:"},
		{name: "empty prefix disables native prefix", cfg: config.IdentityProviderConfig{KubernetesIdentity: &native}, cluster: &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierPrefix: ptr.To("")}}, claim: "employee_id"},
		{name: "literal hyphen is preserved", cfg: config.IdentityProviderConfig{UserIdentifierClaim: "sub", UserIdentifierPrefix: "-"}, claim: "sub", prefix: "-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := targetJWTPolicy(&tc.cfg, tc.cluster, tc.fallback)
			require.NoError(t, err)
			require.Equal(t, tc.claim, policy.ClaimMappings.Username.Claim)
			require.Equal(t, ptr.To(tc.prefix), policy.ClaimMappings.Username.Prefix)
			if tc.cfg.KubernetesIdentity != nil {
				require.Equal(t, native.ClaimMappings.Groups, policy.ClaimMappings.Groups)
				require.Equal(t, native.ClaimValidationRules, policy.ClaimValidationRules)
			}
		})
	}
}

func TestTargetJWTPolicyReplacesMappingsButPreservesProviderConnection(t *testing.T) {
	provider := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://discovery.example/config", Audiences: []string{"breakglass", "spoke"}, AudienceMatchPolicy: apiserver.AudienceMatchPolicyMatchAny},
		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{Expression: "claims.sub"},
			Groups:   apiserver.PrefixedClaimOrExpression{Claim: "roles", Prefix: ptr.To("role:")},
		},
		ClaimValidationRules: []apiserver.ClaimValidationRule{{Claim: "tenant", RequiredValue: "operations"}},
	}
	cluster := &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{
		KubernetesIdentity: &breakglassv1alpha1.KubernetesIdentityConfig{
			ClaimMappings:       apiserverv1.ClaimMappings{Username: apiserverv1.PrefixedClaimOrExpression{Expression: "'cluster:' + claims.employee_id"}},
			UserValidationRules: []apiserverv1.UserValidationRule{{Expression: "!user.username.startsWith('system:')"}},
		},
	}}
	policy, err := targetJWTPolicy(&config.IdentityProviderConfig{KubernetesIdentity: &provider}, cluster, "email")
	require.NoError(t, err)
	require.Equal(t, provider.Issuer, policy.Issuer)
	require.Equal(t, "'cluster:' + claims.employee_id", policy.ClaimMappings.Username.Expression)
	require.Empty(t, policy.ClaimMappings.Groups)
	require.Empty(t, policy.ClaimValidationRules)
	require.Equal(t, "!user.username.startsWith('system:')", policy.UserValidationRules[0].Expression)
	policy.Issuer.Audiences[0] = "changed"
	require.Equal(t, "breakglass", provider.Issuer.Audiences[0])
	require.Equal(t, "claims.sub", provider.ClaimMappings.Username.Expression)
}

func TestProviderJWTPolicyLegacyConnectionDefaults(t *testing.T) {
	cfg := &config.IdentityProviderConfig{Authority: "https://authority.example", ExpectedAudience: "breakglass", DiscoveryURL: "https://discovery.example/config"}
	policy := providerJWTPolicy(cfg)
	require.Equal(t, cfg.Authority, policy.Issuer.URL)
	require.Equal(t, cfg.DiscoveryURL, policy.Issuer.DiscoveryURL)
	require.Equal(t, []string{"breakglass"}, policy.Issuer.Audiences)
	cfg.Issuer = "https://explicit.example"
	cfg.Audiences = []string{"primary", "secondary"}
	policy = providerJWTPolicy(cfg)
	require.Equal(t, cfg.Issuer, policy.Issuer.URL)
	require.Equal(t, cfg.Audiences, policy.Issuer.Audiences)
	policy.Issuer.Audiences[0] = "changed"
	require.Equal(t, "primary", cfg.Audiences[0])
}

func TestTargetJWTPolicyStructuredOverrideIsIndependent(t *testing.T) {
	original := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Expression: "claims.sub"}, Groups: apiserver.PrefixedClaimOrExpression{Claim: "roles", Prefix: ptr.To("role:")}}, ClaimValidationRules: []apiserver.ClaimValidationRule{{Claim: "tenant", RequiredValue: "operations"}}}
	cfg := &config.IdentityProviderConfig{KubernetesIdentity: &original}
	cluster := &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierPrefix: ptr.To("cluster:")}}
	_, err := targetJWTPolicy(cfg, cluster, "")
	require.ErrorContains(t, err, "inherited username expression")
	cluster.Spec.UserIdentifierClaim = "employee_id"
	policy, err := targetJWTPolicy(cfg, cluster, "")
	require.NoError(t, err)
	require.Equal(t, "employee_id", policy.ClaimMappings.Username.Claim)
	require.Empty(t, policy.ClaimMappings.Username.Expression)
	require.Equal(t, original.ClaimMappings.Groups, policy.ClaimMappings.Groups)
	require.Equal(t, original.ClaimValidationRules, policy.ClaimValidationRules)
	*policy.ClaimMappings.Groups.Prefix = "changed:"
	policy.ClaimValidationRules[0].RequiredValue = "changed"
	require.Equal(t, "role:", *original.ClaimMappings.Groups.Prefix)
	require.Equal(t, "operations", original.ClaimValidationRules[0].RequiredValue)
	require.Equal(t, "claims.sub", original.ClaimMappings.Username.Expression)
}
