// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"k8s.io/apiserver/pkg/apis/apiserver"
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
