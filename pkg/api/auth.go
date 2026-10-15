package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/oidc"
	"go.uber.org/zap"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const (
	AuthHeaderKey = "Authorization"
	// maxJWKSCacheSize bounds the handler-owned upstream authenticator cache.
	maxJWKSCacheSize = 100

	// defaultOIDCTimeout is the HTTP client timeout for OIDC discovery
	// and JWKS requests.
	defaultOIDCTimeout = 10 * time.Second

	// maxIssuerLength is the maximum allowed length for a JWT issuer claim.
	// Prevents log pollution and memory abuse from maliciously long issuer strings. (SEC-003)
	maxIssuerLength = 512
)

var allowedJWTAlgs = []string{
	jwt.SigningMethodRS256.Alg(),
	jwt.SigningMethodRS384.Alg(),
	jwt.SigningMethodRS512.Alg(),
	jwt.SigningMethodPS256.Alg(),
	jwt.SigningMethodPS384.Alg(),
	jwt.SigningMethodPS512.Alg(),
	jwt.SigningMethodES256.Alg(),
	jwt.SigningMethodES384.Alg(),
	jwt.SigningMethodES512.Alg(),
}

var errUnknownIdentityProvider = errors.New("invalid or unknown identity provider")

type AuthHandler struct {
	providerEngineMu  sync.Mutex
	closed            bool
	providerEngines   map[string]*oidc.Engine
	log               *zap.SugaredLogger
	idpLoader         identityProviderByIssuerLoader
	defaultHTTPClient *http.Client
}

type identityProviderByIssuerLoader interface {
	LoadIdentityProviderByIssuer(context.Context, string) (*config.IdentityProviderConfig, error)
}

func (a *AuthHandler) validateJWKSIdentityProviderConfig(cfg *config.IdentityProviderConfig) error {
	if cfg == nil || cfg.InsecureSkipVerify || (cfg.Keycloak != nil && cfg.Keycloak.InsecureSkipVerify) || cfg.ExpectedAudience == "" {
		return errUnknownIdentityProvider
	}
	return nil
}

func defaultOIDCTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok || base == nil {
		base = &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true}
	}
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else if t.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.TLSClientConfig = t.TLSClientConfig.Clone()
		t.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	return t
}

func NewAuth(log *zap.SugaredLogger, _ config.Config) *AuthHandler {
	client := &http.Client{Transport: defaultOIDCTransport(), Timeout: defaultOIDCTimeout}
	return &AuthHandler{log: log, defaultHTTPClient: client, providerEngines: make(map[string]*oidc.Engine)}
}

func (a *AuthHandler) authenticateWithProviderPolicy(ctx context.Context, rawToken string, policy apiserver.JWTAuthenticator, cfg *config.IdentityProviderConfig) (*authenticator.Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("OIDC provider configuration is required")
	}
	algorithms := append([]string(nil), cfg.SupportedSigningAlgs...)
	if len(algorithms) == 0 {
		algorithms = append([]string(nil), allowedJWTAlgs...)
	}
	engine, err := a.providerEngine(policy, cfg, algorithms)
	if err != nil {
		return nil, err
	}
	return engine.Authenticate(ctx, rawToken, policy)
}

func (a *AuthHandler) providerEngine(policy apiserver.JWTAuthenticator, cfg *config.IdentityProviderConfig, algorithms []string) (*oidc.Engine, error) {
	ca := cfg.CertificateAuthority
	if ca == "" && cfg.Keycloak != nil {
		ca = cfg.Keycloak.CertificateAuthority
	}
	keyBytes, _ := json.Marshal(struct {
		Issuer, Discovery, CA, JWKS string
		Algs                        []string
	}{policy.Issuer.URL, policy.Issuer.DiscoveryURL, ca, cfg.JWKSURL, algorithms})
	sum := sha256.Sum256(keyBytes)
	key := hex.EncodeToString(sum[:])
	a.providerEngineMu.Lock()
	defer a.providerEngineMu.Unlock()
	if a.closed {
		return nil, fmt.Errorf("OIDC authentication handler is closed")
	}
	if a.providerEngines == nil {
		a.providerEngines = make(map[string]*oidc.Engine)
	}
	if engine := a.providerEngines[key]; engine != nil {
		return engine, nil
	}
	if len(a.providerEngines) >= maxJWKSCacheSize {
		for oldKey, oldEngine := range a.providerEngines {
			oldEngine.Close()
			delete(a.providerEngines, oldKey)
			break
		}
	}
	client := a.defaultHTTPClient
	if ca != "" {
		pool, err := buildCertPoolFromPEM(ca)
		if err != nil {
			return nil, fmt.Errorf("parse OIDC certificate authority: %w", err)
		}
		transport := defaultOIDCTransport()
		transport.TLSClientConfig.RootCAs = pool
		client = &http.Client{Transport: transport, Timeout: defaultOIDCTimeout}
	}
	engine := oidc.New(context.Background(), oidc.Options{Client: client, JWKSURL: cfg.JWKSURL, MaxAuthenticators: maxJWKSCacheSize, SupportedSigningAlgs: algorithms})
	a.providerEngines[key] = engine
	return engine, nil
}

// Close releases cached OIDC authenticators and prevents their recreation.
func (a *AuthHandler) Close() {
	if a == nil {
		return
	}
	a.providerEngineMu.Lock()
	defer a.providerEngineMu.Unlock()
	a.closed = true
	for key, engine := range a.providerEngines {
		engine.Close()
		delete(a.providerEngines, key)
	}
}

func (a *AuthHandler) installTargetIdentityResolver(c *gin.Context, bearer string, cfg *config.IdentityProviderConfig) {
	if cfg == nil {
		return
	}
	c.Set("user_identifier_claim", cfg.UserIdentifierClaim)
	c.Set(oidc.TargetIdentityResolverKey, oidc.TargetIdentityResolver(func(ctx context.Context, cluster *breakglassv1alpha1.ClusterConfig, fallback breakglassv1alpha1.UserIdentifierClaimType) (oidc.TargetIdentity, error) {
		policy, err := targetJWTPolicy(cfg, cluster, fallback)
		if err != nil {
			return oidc.TargetIdentity{}, err
		}
		response, err := a.authenticateWithProviderPolicy(ctx, bearer, policy, cfg)
		if err != nil {
			return oidc.TargetIdentity{}, err
		}
		return oidc.TargetIdentity{User: response.User}, nil
	}))
}

func (a *AuthHandler) WithIdentityProviderLoader(loader identityProviderByIssuerLoader) *AuthHandler {
	a.idpLoader = loader
	return a
}

func (a *AuthHandler) authenticate(c *gin.Context) bool {
	if c.Request.Method == http.MethodOptions {
		return true
	}

	// Determine IDP mode for metrics (recorded after IDP resolution below)
	mode := "single-idp"
	if a.idpLoader != nil {
		mode = "multi-idp"
	}

	authHeader := c.GetHeader(AuthHeaderKey)
	// delete the header to avoid logging it by accident
	c.Request.Header.Del(AuthHeaderKey)
	if !strings.HasPrefix(authHeader, "Bearer ") {
		RespondUnauthorizedWithMessage(c, "No Bearer token provided in Authorization header")
		c.Abort()
		return false
	}
	bearer := authHeader[7:]

	// Parse JWT without verification first to extract issuer and basic claims
	unverifiedClaims := jwt.MapClaims{}
	parser := jwt.NewParser()
	_, _, err := parser.ParseUnverified(bearer, unverifiedClaims)
	if err != nil {
		RespondUnauthorizedWithMessage(c, "Invalid JWT format")
		c.Abort()
		return false
	}

	// Extract issuer from claims for multi-IDP mode
	var issuer string
	if iss, ok := unverifiedClaims["iss"]; ok {
		issuer, _ = iss.(string)
	}

	// SEC-003: Validate issuer format before using it for JWKS routing.
	// The issuer is extracted from the unverified token, so we must ensure it
	// is a well-formed HTTPS URL to prevent SSRF and log injection attacks.
	if issuer != "" && !isValidIssuerURL(issuer) {
		metrics.JWTValidationRequests.WithLabelValues("unknown", mode).Inc()
		metrics.JWTValidationFailure.WithLabelValues("unknown", "invalid_issuer_format").Inc()
		RespondUnauthorizedWithMessage(c, "Invalid token issuer format")
		c.Abort()
		return false
	}

	// Canonicalize issuer by trimming all trailing slashes so that
	// "https://auth.example.com", "https://auth.example.com/" and
	// "https://auth.example.com//" all map to the same cache/limiter key,
	// consistent with LoadIdentityProviderByIssuer.
	issuer = strings.TrimRight(issuer, "/")

	startTime := time.Now()

	var selectedIDP string
	var selectedIDPConfig *config.IdentityProviderConfig
	var mappedIdentity *authenticator.Response
	claims := unverifiedClaims
	var token *jwt.Token
	if a.idpLoader != nil {
		selectedIDPConfig, mappedIdentity, err = a.verifyProviderToken(c.Request.Context(), bearer, claims)
		if selectedIDPConfig != nil {
			selectedIDP = selectedIDPConfig.Name
		}
		if err == nil {
			token = &jwt.Token{Claims: claims, Valid: true}
		}
	} else {
		err = errors.New("JWT verifier is not configured")
	}
	idpLabel := selectedIDP
	if idpLabel == "" {
		idpLabel = mode
	}
	metrics.JWTValidationRequests.WithLabelValues(idpLabel, mode).Inc()
	if err != nil {
		// Record failure with reason using typed errors from jwt/v5.
		failureReason := "verification_failed"
		if errors.Is(err, jwt.ErrTokenUnverifiable) {
			failureReason = "key_id_not_found"
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			failureReason = "invalid_signature"
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			failureReason = "token_expired"
		} else if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			failureReason = "audience_mismatch"
		} else if errors.Is(err, jwt.ErrTokenMalformed) {
			failureReason = "malformed_token"
		} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
			failureReason = "token_not_yet_valid"
		}
		metrics.JWTValidationFailure.WithLabelValues(idpLabel, failureReason).Inc()

		errorMsg := "Token verification failed. Please re-authenticate."
		RespondUnauthorizedWithMessage(c, errorMsg)
		c.Abort()
		return false
	}

	// Record successful validation with duration — use normalized IDP label (bounded cardinality)
	metrics.JWTValidationSuccess.WithLabelValues(idpLabel).Inc()
	metrics.JWTValidationDuration.WithLabelValues(idpLabel).Observe(time.Since(startTime).Seconds())

	// Extract core identity claims
	userID := claims["sub"]
	email := claims["email"]
	username := claims["preferred_username"]

	// Multi-IDP: Store issuer and IDP name for downstream use
	if issuer != "" {
		c.Set("issuer", issuer)
	}
	if selectedIDPConfig != nil {
		c.Set("identity_provider_name", selectedIDP)
		c.Set("user_identifier_prefix", selectedIDPConfig.UserIdentifierPrefix)
		c.Set("user_identifier_claim", selectedIDPConfig.UserIdentifierClaim)
	}

	// This trusted middleware signal is independent of whether a JWT happens
	// to carry an issuer. Unknown/multi-provider configuration fails closed.
	legacyIdentityAllowed := a.idpLoader == nil
	if loader, ok := a.idpLoader.(*config.IdentityProviderLoader); ok {
		legacyIdentityAllowed = loader.AllowsLegacyIdentity(c.Request.Context(), selectedIDP, issuer)
	}
	c.Set("legacy_identity_allowed", legacyIdentityAllowed)

	// Attach raw claims for downstream debugging if needed
	// Note: this is only used for debug logs and should not be exposed to end users.
	c.Set("raw_claims", claims)
	if mappedIdentity != nil {
		c.Set("authenticated_username", mappedIdentity.User.GetName())
		if value, ok := username.(string); !ok || value == "" {
			username = mappedIdentity.User.GetName()
		}
		a.installTargetIdentityResolver(c, bearer, selectedIDPConfig)
	}

	// Attempt to extract groups from common Keycloak / OIDC claims.
	// groupsClaimPresent tracks whether the token itself carried group
	// information (the "groups" claim or Keycloak's "realm_access" claim),
	// as distinct from `groups` being empty because the user genuinely
	// belongs to zero groups. Downstream consumers rely on this distinction
	// to avoid mistaking "token asserts no groups" for "token carries no
	// group information at all" (which would otherwise trigger an
	// unintended fallback to cluster-based group resolution).
	var groups []string
	groupsClaimPresent := false
	if rawGroups, ok := claims["groups"]; ok {
		groupsClaimPresent = true
		switch g := rawGroups.(type) {
		case []interface{}:
			for _, v := range g {
				if s, ok := v.(string); ok && s != "" {
					groups = append(groups, s)
				}
			}
		case []string:
			groups = append(groups, g...)
		}
	} else if rawRealm, ok := claims["realm_access"]; ok { // Keycloak specific structure
		if m, ok := rawRealm.(map[string]interface{}); ok {
			if rolesRaw, ok := m["roles"]; ok {
				groupsClaimPresent = true
				switch roles := rolesRaw.(type) {
				case []interface{}:
					for _, v := range roles {
						if s, ok := v.(string); ok && s != "" {
							groups = append(groups, s)
						}
					}
				case []string:
					groups = append(groups, roles...)
				}
			}
		}
	}

	// Normalize group claims without changing their identity. Escalation group
	// matching is exact, so hierarchical OIDC group paths must stay distinct
	// from same-named leaf groups in other hierarchies.
	if len(groups) > 0 {
		seen := make(map[string]struct{}, len(groups))
		normalized := make([]string, 0, len(groups))
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" { // skip empty
				continue
			}
			if _, exists := seen[g]; exists {
				continue
			}
			seen[g] = struct{}{}
			normalized = append(normalized, g)
		}
		groups = normalized
	}

	// If groups are empty, log claims at debug so we can diagnose missing group mappers
	// or confirm that the user legitimately belongs to no groups.
	if len(groups) == 0 {
		// avoid logging tokens at info level; use debug for development troubleshooting
		if a.log != nil {
			msg := "JWT parsed but no groups claim found"
			if groupsClaimPresent {
				msg = "JWT groups claim present but resolved to zero groups"
			}
			a.log.Debugw(msg, "sub", userID, "username", username, "claims_keys", func() []string {
				keys := make([]string, 0, len(claims))
				for k := range claims {
					keys = append(keys, k)
				}
				return keys
			}())
		}
	}

	if selectedIDPConfig != nil && selectedIDPConfig.KubernetesIdentity != nil {
		groups = mappedIdentity.User.GetGroups()
		groupsClaimPresent = true
	}

	c.Set("token", token)
	c.Set("user_id", userID)
	c.Set("email", email)
	c.Set("username", username)
	// Extract display name from "name" claim (standard OIDC claim for full name)
	if displayName, ok := claims["name"]; ok {
		c.Set("displayName", displayName)
	}
	// Set the "groups" context key whenever the token carried group
	// information, even if it resolved to zero groups. This lets downstream
	// consumers distinguish "token asserts the user belongs to no groups"
	// (key present, empty slice) from "token carries no group information at
	// all" (key absent), so a legitimately group-less token is not silently
	// treated the same as a token without a groups/realm_access claim.
	// groupsClaimPresent is the only way `groups` is ever populated above, so
	// this is the single, exhaustive condition for setting the context key.
	if groupsClaimPresent {
		if groups == nil {
			groups = []string{}
		}
		c.Set("groups", groups)
		var identifiers []string
		for _, claim := range []interface{}{userID, email, username, c.GetString("authenticated_username")} {
			if identifier, ok := claim.(string); ok && identifier != "" {
				identifiers = append(identifiers, identifier)
			}
		}
		c.Request = c.Request.WithContext(audit.WithAuthenticatedActor(c.Request.Context(), identifiers, groups))
	}

	return true
}

func (a *AuthHandler) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.authenticate(c) {
			return
		}
		c.Next()
	}
}

// MiddlewareWithRateLimiting returns a Gin middleware chain that combines:
// 1. JWT authentication (same as Middleware())
// 2. Authenticated rate limiting (higher limits for authenticated users, lower for unauthenticated)
// This should be used for API endpoints that handle authenticated requests.
// The rate limiter uses the "email" context key to identify users after authentication.
func (a *AuthHandler) MiddlewareWithRateLimiting(rl RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First run authentication
		if !a.authenticate(c) {
			return
		}

		// Then apply rate limiting (uses email set by auth middleware)
		allowed, isAuthenticated := rl.Allow(c)
		if !allowed {
			msg := "Rate limit exceeded, please try again later"
			if !isAuthenticated {
				msg = "Rate limit exceeded. Please authenticate for higher limits."
			}
			RespondTooManyRequestsWithAuthState(c, msg, isAuthenticated)
			c.Abort()
			return
		}

		c.Next()
	}
}

// OptionalAuthRateLimitMiddleware returns a middleware that applies rate limiting
// with higher limits for users who provide a valid JWT token, even on public endpoints.
// Unlike MiddlewareWithRateLimiting, this does NOT require authentication - it just
// gives better rate limits to authenticated users.
// This should be used for public endpoints that the frontend calls frequently.
func (a *AuthHandler) OptionalAuthRateLimitMiddleware(rl RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to extract user identity from JWT if present
		userIdentity := a.tryExtractUserIdentity(c)
		if userIdentity != "" {
			// Set the identity so the rate limiter can use it
			c.Set("email", userIdentity)
		}

		// Apply rate limiting (uses email if set, otherwise falls back to IP)
		allowed, isAuthenticated := rl.Allow(c)
		if !allowed {
			msg := "Rate limit exceeded, please try again later"
			if !isAuthenticated {
				msg = "Rate limit exceeded. Please authenticate for higher limits."
			}
			RespondTooManyRequestsWithAuthState(c, msg, isAuthenticated)
			c.Abort()
			return
		}

		c.Next()
	}
}

// tryExtractUserIdentity attempts to extract user identity from a JWT token
// without enforcing authentication. Returns empty string if no valid token.
func (a *AuthHandler) tryExtractUserIdentity(c *gin.Context) string {
	authHeader := c.GetHeader(AuthHeaderKey)
	if authHeader != "" {
		// Remove to avoid accidental logging of bearer tokens downstream
		c.Request.Header.Del(AuthHeaderKey)
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	bearer := authHeader[7:]

	// Parse JWT without verification first to extract issuer
	unverifiedClaims := jwt.MapClaims{}
	parser := jwt.NewParser()
	_, _, err := parser.ParseUnverified(bearer, unverifiedClaims)
	if err != nil {
		return ""
	}

	// Extract issuer from claims
	var issuer string
	if iss, ok := unverifiedClaims["iss"]; ok {
		issuer, _ = iss.(string)
	}

	// SEC-003: reject malformed issuers in optional auth path too
	if issuer != "" && !isValidIssuerURL(issuer) {
		return ""
	}

	// Short-circuit empty issuer in multi-IDP mode to avoid unnecessary
	// loader calls and warning log noise on public endpoints.
	if a.idpLoader != nil && issuer == "" {
		return ""
	}

	if a.idpLoader != nil {
		cfg, response, verifyErr := a.verifyProviderToken(c.Request.Context(), bearer, unverifiedClaims)
		if verifyErr != nil {
			return ""
		}
		c.Set("authenticated_username", response.User.GetName())
		c.Set("issuer", issuer)
		c.Set("identity_provider_name", cfg.Name)
		if email, ok := unverifiedClaims["email"].(string); ok && email != "" {
			return email
		}
		return ""
	}

	return ""
}

// RateLimiter interface for rate limiters that support authentication differentiation
type RateLimiter interface {
	Allow(c *gin.Context) (allowed bool, isAuthenticated bool)
}

// isValidIssuerURL validates that a URL is a well-formed HTTPS issuer URL with
// reasonable length limits. Rejects query strings, fragments, and userinfo per
// the OIDC Discovery spec (issuer identifiers must not contain these).
func isValidIssuerURL(issuer string) bool {
	if len(issuer) == 0 || len(issuer) > maxIssuerLength {
		return false
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.Host == "" {
		return false
	}
	// OIDC issuer identifiers must not contain query, fragment, or userinfo
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return true
}

func buildCertPoolFromPEM(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(pemData)); !ok {
		return nil, fmt.Errorf("failed to append certificates from PEM data")
	}
	return pool, nil
}
