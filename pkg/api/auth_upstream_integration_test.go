// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	upstreamoidc "github.com/telekom/k8s-breakglass/pkg/oidc"
	"go.uber.org/zap"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
)

type signedOIDCServer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	caPEM  string
}

func newSignedOIDCServer(t *testing.T, discoveryPaths ...string) *signedOIDCServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := "integration-kid"
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}})
	require.NoError(t, err)

	discoveryPath := "/.well-known/openid-configuration"
	if len(discoveryPaths) > 0 {
		discoveryPath = discoveryPaths[0]
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case discoveryPath:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			_, _ = w.Write(jwks)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return &signedOIDCServer{
		server: server,
		key:    key,
		kid:    kid,
		caPEM:  string(pemEncodeCertificate(server.Certificate().Raw)),
	}
}

func pemEncodeCertificate(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func (s *signedOIDCServer) token(t *testing.T, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func newUpstreamTestAuth(s *signedOIDCServer, cfg *config.IdentityProviderConfig) *AuthHandler {
	auth := NewAuth(zap.NewNop().Sugar(), config.Config{})
	auth.WithIdentityProviderLoader(staticIdentityProviderByIssuerLoader{cfg: cfg})
	return auth
}

func TestAuthMiddlewareUpstreamOIDCMappingOverSignedTLS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		UserIdentifierClaim: "employee_id", UserIdentifierPrefix: "idp:",
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)

	token := s.token(t, s.key, jwt.MapClaims{
		"iss": s.server.URL, "aud": "breakglass", "employee_id": "k834798",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) {
		if got := c.GetString("username"); got != "idp:k834798" {
			t.Errorf("username = %q, want idp:k834798", got)
		}
		if got := c.GetString("user_id"); got != "" {
			t.Errorf("user_id = %q, want empty for a token without sub", got)
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
}

func TestAuthMiddlewareUpstreamOIDCStandardClaimsAndRealmGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		UserIdentifierClaim: "preferred_username", UserIdentifierPrefix: "tdi_security_oidc:",
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	token := s.token(t, s.key, jwt.MapClaims{
		"iss": s.server.URL, "aud": "breakglass", "sub": "subject-123",
		"email": "user@example.com", "email_verified": true,
		"preferred_username": "k834798",
		"realm_access":       map[string]any{"roles": []any{"ops", "sre", "ops"}},
		"exp":                time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) {
		require.Equal(t, "k834798", c.GetString("username"), "raw preferred_username remains available to legacy API consumers")
		require.Equal(t, "tdi_security_oidc:k834798", c.GetString("authenticated_username"), "provider mapping is the authenticated API principal")
		require.Equal(t, "subject-123", c.GetString("user_id"))
		require.Equal(t, "user@example.com", c.GetString("email"))
		groups, exists := c.Get("groups")
		require.True(t, exists)
		require.Equal(t, []string{"ops", "sre"}, groups)
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
}

func TestAuthMiddlewareUpstreamOIDCAdditionalAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", Audiences: []string{"breakglass", "spoke-api"},
		CertificateAuthority: s.caPEM, UserIdentifierClaim: "employee_id",
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := func(audience string) int {
		t.Helper()
		token := s.token(t, s.key, jwt.MapClaims{
			"iss": s.server.URL, "aud": audience, "employee_id": "employee",
			"exp": time.Now().Add(time.Minute).Unix(),
		})
		req := httptest.NewRequest(http.MethodGet, "/identity", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	require.Equal(t, http.StatusNoContent, request("spoke-api"))
	require.Equal(t, http.StatusNoContent, request("breakglass"))
	require.Equal(t, http.StatusUnauthorized, request("unlisted"))
}

func TestAuthMiddlewareUpstreamOIDCExplicitDiscoveryJWKSAndAlgorithms(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, directJWKS := range []bool{false, true} {
		name := "discovery override"
		if directJWKS {
			name = "direct JWKS without discovery"
		}
		t.Run(name, func(t *testing.T) {
			// The default discovery endpoint returns 404, so ignoring either override fails.
			s := newSignedOIDCServer(t, "/custom-discovery")
			cfg := &config.IdentityProviderConfig{
				Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
				ExpectedAudience: "breakglass", SupportedSigningAlgs: []string{"RS256"},
				CertificateAuthority: s.caPEM, UserIdentifierClaim: "employee_id",
			}
			if directJWKS {
				cfg.JWKSURL = s.server.URL + "/keys"
			} else {
				cfg.DiscoveryURL = s.server.URL + "/custom-discovery"
			}
			auth := newUpstreamTestAuth(s, cfg)
			t.Cleanup(auth.Close)
			token := s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL, "aud": "breakglass", "employee_id": "employee", "exp": time.Now().Add(time.Minute).Unix()})
			router := gin.New()
			router.Use(auth.Middleware())
			router.GET("/identity", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			request := func() int {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "/identity", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				return rec.Code
			}
			require.Equal(t, http.StatusNoContent, request())
			cfg.SupportedSigningAlgs = []string{"ES256"}
			require.Equal(t, http.StatusUnauthorized, request(), "configured signing algorithms must be enforced")
		})
	}
}

func TestAuthMiddlewareUpstreamOIDCStructuredValidationAcceptsAndRejects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	prefix := "tdi:"
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		KubernetesIdentity: &apiserver.JWTAuthenticator{
			Issuer:               apiserver.Issuer{URL: s.server.URL, Audiences: []string{"breakglass"}},
			ClaimMappings:        apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "employee_id", Prefix: &prefix}},
			ClaimValidationRules: []apiserver.ClaimValidationRule{{Expression: "claims.tenant == 'operations'", Message: "operations tenant required"}},
			UserValidationRules:  []apiserver.UserValidationRule{{Expression: "!user.username.startsWith('tdi:system:')", Message: "reserved username"}},
		},
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := func(claims jwt.MapClaims) int {
		t.Helper()
		token := s.token(t, s.key, claims)
		req := httptest.NewRequest(http.MethodGet, "/identity", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	base := jwt.MapClaims{"iss": s.server.URL, "aud": "breakglass", "employee_id": "employee", "tenant": "operations", "exp": time.Now().Add(time.Minute).Unix()}
	require.Equal(t, http.StatusNoContent, request(base))
	badTenant := maps.Clone(base)
	badTenant["tenant"] = "other"
	require.Equal(t, http.StatusUnauthorized, request(badTenant))
	badUser := maps.Clone(base)
	badUser["employee_id"] = "system:admin"
	require.Equal(t, http.StatusUnauthorized, request(badUser))
}

func TestOptionalAuthUpstreamOIDCRecordsVerifiedMappedIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		UserIdentifierClaim: "employee_id", UserIdentifierPrefix: "idp:",
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)

	newContext := func(token string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		c.Request.Header.Set("Authorization", "Bearer "+token)
		return c
	}
	valid := s.token(t, s.key, jwt.MapClaims{
		"iss": s.server.URL, "aud": "breakglass", "employee_id": "k834798",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	validContext := newContext(valid)
	require.Empty(t, auth.tryExtractUserIdentity(validContext), "mapped username must not be used as an email rate-limit identity")
	require.Equal(t, "idp:k834798", validContext.GetString("authenticated_username"))
	require.Equal(t, s.server.URL, validContext.GetString("issuer"))
	require.Equal(t, "corp", validContext.GetString("identity_provider_name"))

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	invalid := s.token(t, otherKey, jwt.MapClaims{
		"iss": s.server.URL, "aud": "breakglass", "employee_id": "forged",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	invalidContext := newContext(invalid)
	require.Empty(t, auth.tryExtractUserIdentity(invalidContext))
	_, hasUsername := invalidContext.Get("authenticated_username")
	_, hasIssuer := invalidContext.Get("issuer")
	_, hasProvider := invalidContext.Get("identity_provider_name")
	require.False(t, hasUsername)
	require.False(t, hasIssuer)
	require.False(t, hasProvider)
}

func TestAuthMiddlewareUpstreamOIDCStructuredGroupsAreAuthoritative(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	prefix := "structured:"
	groupPrefix := "role:"
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		KubernetesIdentity: &apiserver.JWTAuthenticator{
			Issuer: apiserver.Issuer{URL: s.server.URL, Audiences: []string{"breakglass"}},
			ClaimMappings: apiserver.ClaimMappings{
				Username: apiserver.PrefixedClaimOrExpression{Claim: "employee_id", Prefix: &prefix},
				Groups:   apiserver.PrefixedClaimOrExpression{Claim: "roles", Prefix: &groupPrefix},
			},
		},
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	token := s.token(t, s.key, jwt.MapClaims{
		"iss": s.server.URL, "aud": "breakglass", "employee_id": "k834798", "roles": []string{},
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) {
		require.Equal(t, "structured:k834798", c.GetString("username"))
		groups, exists := c.Get("groups")
		require.True(t, exists)
		require.Equal(t, []string{}, groups)
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
}

func TestAuthMiddlewareUpstreamOIDCRejectsBadSignatureAndExpiry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		UserIdentifierClaim: "employee_id",
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	unsupported := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": s.server.URL, "aud": "breakglass", "employee_id": "u", "exp": time.Now().Add(time.Minute).Unix(),
	})
	unsupportedToken, err := unsupported.SignedString([]byte("unsupported-algorithm-key"))
	require.NoError(t, err)
	for name, token := range map[string]string{
		"bad signature":          s.token(t, otherKey, jwt.MapClaims{"iss": s.server.URL, "aud": "breakglass", "employee_id": "u", "exp": time.Now().Add(time.Minute).Unix()}),
		"expired":                s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL, "aud": "breakglass", "employee_id": "u", "exp": time.Now().Add(-time.Minute).Unix()}),
		"wrong issuer":           s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL + "/other", "aud": "breakglass", "employee_id": "u", "exp": time.Now().Add(time.Minute).Unix()}),
		"wrong audience":         s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL, "aud": "other", "employee_id": "u", "exp": time.Now().Add(time.Minute).Unix()}),
		"missing username claim": s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL, "aud": "breakglass", "exp": time.Now().Add(time.Minute).Unix()}),
		"unsupported algorithm":  unsupportedToken,
	} {
		t.Run(name, func(t *testing.T) {
			reached := false
			router := gin.New()
			router.Use(auth.Middleware())
			router.GET("/identity", func(c *gin.Context) { reached = true; c.Status(http.StatusOK) })
			req := httptest.NewRequest(http.MethodGet, "/identity", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)
			require.Equal(t, http.StatusUnauthorized, resp.Code)
			require.False(t, reached, "failed authentication must not invoke the handler")
		})
	}
}

func TestAuthMiddlewareUpstreamOIDCRejectsTimestampAndUnverifiedEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corp", Issuer: s.server.URL, Authority: s.server.URL,
		ExpectedAudience: "breakglass", CertificateAuthority: s.caPEM,
		UserIdentifierClaim: "email",
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	for name, claims := range map[string]jwt.MapClaims{
		"missing expiration": {"iss": s.server.URL, "aud": "breakglass", "email": "user@example.com", "email_verified": true},
		"future issued at":   {"iss": s.server.URL, "aud": "breakglass", "email": "user@example.com", "email_verified": true, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Add(time.Minute).Unix()},
		"future not before":  {"iss": s.server.URL, "aud": "breakglass", "email": "user@example.com", "email_verified": true, "exp": time.Now().Add(2 * time.Minute).Unix(), "iat": time.Now().Unix(), "nbf": time.Now().Add(time.Minute).Unix()},
		"unverified email":   {"iss": s.server.URL, "aud": "breakglass", "email": "user@example.com", "email_verified": false, "exp": time.Now().Add(time.Minute).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			token := s.token(t, s.key, claims)
			req := httptest.NewRequest(http.MethodGet, "/identity", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			router := gin.New()
			router.Use(auth.Middleware())
			router.GET("/identity", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
	valid := s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL, "aud": "breakglass", "email": "user@example.com", "email_verified": true, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()})
	req := httptest.NewRequest(http.MethodGet, "/identity", nil)
	req.Header.Set("Authorization", "Bearer "+valid)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestTargetIdentityResolverRejectsUnsafeClusterOverride(t *testing.T) {
	s := newSignedOIDCServer(t)
	auth := NewAuth(zap.NewNop().Sugar(), config.Config{})
	t.Cleanup(auth.Close)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	auth.installTargetIdentityResolver(c, "unused", &config.IdentityProviderConfig{
		Issuer:               s.server.URL,
		Authority:            s.server.URL,
		ExpectedAudience:     "breakglass",
		CertificateAuthority: s.caPEM,
		KubernetesIdentity: &apiserver.JWTAuthenticator{
			Issuer: apiserver.Issuer{URL: s.server.URL, Audiences: []string{"breakglass"}},
			ClaimMappings: apiserver.ClaimMappings{
				Username: apiserver.PrefixedClaimOrExpression{Expression: "claims.sub"},
			},
		},
	})
	resolverValue, exists := c.Get(upstreamoidc.TargetIdentityResolverKey)
	require.True(t, exists)
	resolver, ok := resolverValue.(upstreamoidc.TargetIdentityResolver)
	require.True(t, ok)
	clusterPrefix := "cluster:"
	_, err := resolver(context.Background(), &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierPrefix: &clusterPrefix}}, "")
	require.ErrorContains(t, err, "cannot override an inherited username expression")
}

func TestAuthMiddlewareUpstreamOIDCLiveAudienceAndLegacyCA(t *testing.T) {
	s := newSignedOIDCServer(t)
	cfg := &config.IdentityProviderConfig{
		Name: "corporate", Issuer: s.server.URL, Authority: s.server.URL, ExpectedAudience: "first",
		UserIdentifierClaim: "employee_id", Keycloak: &config.KeycloakRuntimeConfig{CertificateAuthority: s.caPEM},
	}
	auth := newUpstreamTestAuth(s, cfg)
	t.Cleanup(auth.Close)
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/identity", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	request := func(audience string) int {
		t.Helper()
		token := s.token(t, s.key, jwt.MapClaims{"iss": s.server.URL, "aud": audience, "employee_id": "employee", "exp": time.Now().Add(time.Minute).Unix()})
		req := httptest.NewRequest(http.MethodGet, "/identity", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}
	require.Equal(t, http.StatusNoContent, request("first"))
	cfg.ExpectedAudience = "second"
	require.Equal(t, http.StatusUnauthorized, request("first"), "cached verifier must not retain the previous audience")
	require.Equal(t, http.StatusNoContent, request("second"))
	cfg.Keycloak.CertificateAuthority = ""
	require.Equal(t, http.StatusUnauthorized, request("second"), "removed CA must not reuse a trusted cached connection")
	cfg.Keycloak.CertificateAuthority = s.caPEM
	require.Equal(t, http.StatusNoContent, request("second"))
}
