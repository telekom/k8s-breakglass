// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func providerJWTPolicy(cfg *config.IdentityProviderConfig) apiserver.JWTAuthenticator {
	if cfg.KubernetesIdentity != nil {
		return *cfg.KubernetesIdentity.DeepCopy()
	}
	audiences := append([]string(nil), cfg.Audiences...)
	if len(audiences) == 0 {
		audiences = []string{cfg.ExpectedAudience}
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = cfg.Authority
	}
	return apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: issuer, DiscoveryURL: cfg.DiscoveryURL, Audiences: audiences, AudienceMatchPolicy: apiserver.AudienceMatchPolicyMatchAny}}
}

// verifyProviderToken delegates cryptographic verification and identity policy to
// Kubernetes, retaining the existing required-expiry and future-iat checks.
func (a *AuthHandler) verifyProviderToken(ctx context.Context, bearer string, claims jwt.MapClaims) (*config.IdentityProviderConfig, *authenticator.Response, error) {
	issuer, err := claims.GetIssuer()
	if err != nil || !isValidIssuerURL(issuer) {
		return nil, nil, errUnknownIdentityProvider
	}
	cfg, err := a.idpLoader.LoadIdentityProviderByIssuer(ctx, issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("load token identity provider: %w", err)
	}
	if err := a.validateJWKSIdentityProviderConfig(cfg); err != nil {
		return nil, nil, err
	}
	policy := providerJWTPolicy(cfg)
	if cfg.KubernetesIdentity == nil {
		claim := cfg.UserIdentifierClaim
		if claim == "" {
			for _, candidate := range []string{"sub", "preferred_username", "email"} {
				if value, ok := claims[candidate].(string); ok && value != "" {
					claim = candidate
					break
				}
			}
		}
		if claim == "" {
			return nil, nil, fmt.Errorf("token has no configured API identity")
		}
		prefix := cfg.UserIdentifierPrefix
		policy.ClaimMappings.Username = apiserver.PrefixedClaimOrExpression{Claim: claim, Prefix: &prefix}
	}
	response, err := a.authenticateWithProviderPolicy(ctx, bearer, policy, cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := jwt.NewValidator(jwt.WithIssuedAt(), jwt.WithExpirationRequired()).Validate(claims); err != nil {
		return nil, nil, fmt.Errorf("validate token timestamps: %w", err)
	}
	return cfg, response, nil
}

func targetJWTPolicy(cfg *config.IdentityProviderConfig, cluster *breakglassv1alpha1.ClusterConfig, fallback breakglassv1alpha1.UserIdentifierClaimType) (apiserver.JWTAuthenticator, error) {
	policy := providerJWTPolicy(cfg)
	if cluster != nil && cluster.Spec.KubernetesIdentity != nil {
		mapped, err := cluster.Spec.KubernetesIdentity.ToJWTAuthenticator(policy.Issuer.URL, policy.Issuer.Audiences)
		if err != nil {
			return apiserver.JWTAuthenticator{}, fmt.Errorf("convert cluster identity policy: %w", err)
		}
		mapped.Issuer = policy.Issuer
		return mapped, nil
	}
	override := cluster != nil && (cluster.Spec.UserIdentifierClaim != "" || cluster.Spec.UserIdentifierPrefix != nil)
	if cfg.KubernetesIdentity != nil && !override {
		return policy, nil
	}
	claim := string(fallback)
	if cfg.UserIdentifierClaim != "" {
		claim = cfg.UserIdentifierClaim
	}
	prefix := cfg.UserIdentifierPrefix
	if cfg.KubernetesIdentity != nil {
		username := policy.ClaimMappings.Username
		if username.Expression != "" && cluster.Spec.UserIdentifierClaim == "" {
			return apiserver.JWTAuthenticator{}, fmt.Errorf("a cluster prefix cannot override an inherited username expression; configure a claim or structured mapping")
		}
		claim = username.Claim
		if username.Prefix != nil {
			prefix = *username.Prefix
		}
	}
	if cluster != nil {
		if cluster.Spec.UserIdentifierClaim != "" {
			claim = string(cluster.Spec.UserIdentifierClaim)
		}
		if cluster.Spec.UserIdentifierPrefix != nil {
			prefix = *cluster.Spec.UserIdentifierPrefix
		}
	}
	if claim == "" {
		claim = "email"
	}
	policy.ClaimMappings.Username = apiserver.PrefixedClaimOrExpression{Claim: claim, Prefix: &prefix}
	return policy, nil
}
