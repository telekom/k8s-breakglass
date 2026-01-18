package api

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
)

const (
	AuthHeaderKey = "Authorization"
	// maxJWKSCacheSize limits the number of cached JWKS to prevent memory exhaustion
	// from malicious tokens claiming many different issuers
	maxJWKSCacheSize = 100
)

// jwksCacheEntry holds the JWKS and its position in the LRU list
type jwksCacheEntry struct {
	issuer string
	jwks   *keyfunc.JWKS
}

type AuthHandler struct {
	// Multi-IDP support: LRU cache for JWKS by issuer URL
	jwksCache   map[string]*list.Element // issuer -> list element
	jwksLRUList *list.List               // list of *jwksCacheEntry (front = most recent)
	jwksMutex   sync.RWMutex

	// Single-IDP fallback (for backward compatibility)
	jwks *keyfunc.JWKS

	log *zap.SugaredLogger

	// IDPLoader for multi-IDP mode
	idpLoader *config.IdentityProviderLoader
}

func NewAuth(log *zap.SugaredLogger, cfg config.Config) *AuthHandler {
	// JWKS loading happens dynamically via WithIdentityProviderLoader()
	// using IdentityProvider CRDs configured in the cluster
	return &AuthHandler{
		jwksCache:   make(map[string]*list.Element),
		jwksLRUList: list.New(),
		log:         log,
	}
}

// WithIdentityProviderLoader sets the IDP loader for multi-IDP support
func (a *AuthHandler) WithIdentityProviderLoader(loader *config.IdentityProviderLoader) *AuthHandler {
	a.idpLoader = loader
	return a
}

// getJWKSForIssuer returns the JWKS for a given issuer URL, loading it if necessary
// For single-IDP mode (no idpLoader), returns the default JWKS
// Uses LRU eviction to prevent memory exhaustion when cache is full.
func (a *AuthHandler) getJWKSForIssuer(ctx context.Context, issuer string) (*keyfunc.JWKS, error) {
	// Single-IDP mode: use default JWKS
	if a.idpLoader == nil {
		return a.jwks, nil
	}

	// Multi-IDP mode: check LRU cache for specific issuer
	a.jwksMutex.Lock()
	if elem, exists := a.jwksCache[issuer]; exists {
		// Move to front of LRU list (mark as recently used)
		a.jwksLRUList.MoveToFront(elem)
		entry := elem.Value.(*jwksCacheEntry)
		a.jwksMutex.Unlock()
		return entry.jwks, nil
	}
	a.jwksMutex.Unlock()

	// Load IDP config by issuer
	idpCfg, err := a.idpLoader.LoadIdentityProviderByIssuer(ctx, issuer)
	if err != nil {
		a.log.Warnw("failed to load IDP config for issuer", "issuer", issuer, "error", err)
		// Don't expose the issuer in error message to prevent reconnaissance attacks
		return nil, fmt.Errorf("invalid or unknown identity provider")
	}

	// Create JWKS options
	options := keyfunc.Options{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second * 10,
		RefreshErrorHandler: func(err error) {
			a.log.Warnf("failed to refresh JWKS for issuer %s: %v", issuer, err)
		},
	}

	// Configure TLS if needed (from IDP config)
	if idpCfg.CertificateAuthority != "" {
		pool, err := buildCertPoolFromPEM(idpCfg.CertificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("could not parse CA certificate for IDP %s: %w", idpCfg.Name, err)
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
		options.Client = &http.Client{Transport: transport}
	} else if idpCfg.Keycloak != nil && idpCfg.Keycloak.CertificateAuthority != "" {
		pool, err := buildCertPoolFromPEM(idpCfg.Keycloak.CertificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("could not parse CA certificate for IDP %s: %w", idpCfg.Name, err)
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
		options.Client = &http.Client{Transport: transport}
	} else if idpCfg.InsecureSkipVerify || (idpCfg.Keycloak != nil && idpCfg.Keycloak.InsecureSkipVerify) {
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		options.Client = &http.Client{Transport: transport}
		a.log.Warnf("TLS verification disabled for IDP %s (dev/e2e only)", idpCfg.Name)
	}

	// Build JWKS endpoint URL from IDP's configuration
	if idpCfg.Authority == "" {
		return nil, fmt.Errorf("IDP %s has no authority configured", idpCfg.Name)
	}

	// For Keycloak IDPs, use the Keycloak-specific JWKS endpoint
	// This avoids relying on .well-known discovery which may not be available at the realm URL
	var jwksURL string
	if idpCfg.Keycloak != nil && idpCfg.Keycloak.BaseURL != "" && idpCfg.Keycloak.Realm != "" {
		// Keycloak: {baseURL}/realms/{realm}/protocol/openid-connect/certs
		baseURL := strings.TrimRight(idpCfg.Keycloak.BaseURL, "/")
		jwksURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", baseURL, idpCfg.Keycloak.Realm)
	} else {
		// Standard OIDC: use .well-known/openid-configuration discovery
		discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", strings.TrimRight(idpCfg.Authority, "/"))

		// Use the configured client (or default) to fetch discovery
		client := options.Client
		if client == nil {
			// Create client with explicit timeout to prevent goroutine hangs
			// when OIDC provider is slow or unresponsive
			client = &http.Client{Timeout: 10 * time.Second}
		}

		// Try discovery
		var discoverySuccess bool
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode == http.StatusOK {
					var discovery struct {
						JWKSURI string `json:"jwks_uri"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&discovery); err == nil && discovery.JWKSURI != "" {
						jwksURL = discovery.JWKSURI
						discoverySuccess = true
					}
				}
			}
		}

		if !discoverySuccess {
			// Fallback: Try appending /.well-known/jwks.json directly to authority
			jwksURL = fmt.Sprintf("%s/.well-known/jwks.json", strings.TrimRight(idpCfg.Authority, "/"))
			a.log.Debugw("OIDC discovery failed or returned no jwks_uri, falling back to default path", "url", jwksURL)
		}
	}

	// Fetch JWKS
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to load JWKS for IDP %s (%s): %w", idpCfg.Name, issuer, err)
	}

	// Cache with LRU eviction to prevent memory exhaustion
	a.jwksMutex.Lock()
	defer a.jwksMutex.Unlock()

	// Check again in case another goroutine loaded it while we were fetching
	if elem, exists := a.jwksCache[issuer]; exists {
		// Another goroutine beat us to it - use theirs, discard ours
		jwks.EndBackground()
		a.jwksLRUList.MoveToFront(elem)
		return elem.Value.(*jwksCacheEntry).jwks, nil
	}

	// LRU eviction: remove least recently used entries if cache is full
	for len(a.jwksCache) >= maxJWKSCacheSize {
		// Evict the back element (least recently used)
		oldest := a.jwksLRUList.Back()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*jwksCacheEntry)
		a.log.Debugw("JWKS cache LRU eviction",
			"evictedIssuer", entry.issuer,
			"currentSize", len(a.jwksCache),
			"maxSize", maxJWKSCacheSize)
		// Stop the background refresh goroutine
		if entry.jwks != nil {
			entry.jwks.EndBackground()
		}
		delete(a.jwksCache, entry.issuer)
		a.jwksLRUList.Remove(oldest)
	}

	// Add new entry at front (most recently used)
	entry := &jwksCacheEntry{issuer: issuer, jwks: jwks}
	elem := a.jwksLRUList.PushFront(entry)
	a.jwksCache[issuer] = elem

	a.log.Debugw("loaded JWKS for issuer", "issuer", issuer, "idp_name", idpCfg.Name)
	return jwks, nil
}

func (a *AuthHandler) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Record JWT validation request
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
			return
		}
		bearer := authHeader[7:]

		// Parse JWT without verification first to extract issuer and basic claims
		unverifiedClaims := jwt.MapClaims{}
		parser := jwt.NewParser()
		_, _, err := parser.ParseUnverified(bearer, unverifiedClaims)
		if err != nil {
			RespondUnauthorizedWithMessage(c, "Invalid JWT format")
			c.Abort()
			return
		}

		// Extract issuer from claims for multi-IDP mode
		var issuer string
		if iss, ok := unverifiedClaims["iss"]; ok {
			issuer, _ = iss.(string)
		}

		// Record validation attempt
		metrics.JWTValidationRequests.WithLabelValues(issuer, mode).Inc()
		startTime := time.Now()

		// Get appropriate JWKS (based on issuer or default)
		var jwks *keyfunc.JWKS
		var selectedIDP string

		if a.idpLoader != nil && issuer != "" {
			// Multi-IDP mode: load JWKS for specific issuer
			// Record cache check (using RLock for read-only check)
			a.jwksMutex.RLock()
			elem, cacheHit := a.jwksCache[issuer]
			_ = elem // silence unused variable warning
			a.jwksMutex.RUnlock()

			if cacheHit {
				metrics.JWKSCacheHits.WithLabelValues(issuer).Inc()
			} else {
				metrics.JWKSCacheMisses.WithLabelValues(issuer).Inc()
			}

			loadedJwks, err := a.getJWKSForIssuer(c.Request.Context(), issuer)
			if err != nil {
				a.log.Debugw("failed to get JWKS for issuer", "issuer", issuer, "error", err)
				metrics.JWTValidationFailure.WithLabelValues(issuer, "jwks_load_failed").Inc()

				// Try to provide helpful error message with IDP suggestions.
				// Do not echo the raw issuer back to the client to avoid reconnaissance leaks.
				idpName, idpLookupErr := a.idpLoader.GetIDPNameByIssuer(c.Request.Context(), issuer)
				errorMsg := "unable to verify token"
				if idpLookupErr == nil && idpName != "" {
					errorMsg = fmt.Sprintf("token issuer is not configured. Please use the '%s' identity provider to log in.", idpName)
				}
				RespondUnauthorizedWithMessage(c, errorMsg)
				c.Abort()
				return
			}
			jwks = loadedJwks
			idpName, err := a.idpLoader.GetIDPNameByIssuer(c.Request.Context(), issuer)
			if err != nil {
				a.log.Debugw("failed to get IDP name by issuer", "issuer", issuer, "error", err)
			} else {
				selectedIDP = idpName
			}
		} else if a.idpLoader != nil && issuer == "" {
			// Multi-IDP mode but no issuer in token: require issuer claim
			metrics.JWTValidationFailure.WithLabelValues("", "missing_issuer").Inc()
			RespondUnauthorizedWithMessage(c, "No issuer (iss) claim found in token. Please ensure you are logged in with a valid identity provider.")
			c.Abort()
			return
		} else {
			// Single-IDP mode: use default JWKS (issuer claim optional for backward compatibility)
			jwks = a.jwks
		}

		// Verify and parse JWT with selected JWKS
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(bearer, &claims, jwks.Keyfunc)
		if err != nil {
			// Attempt single forced JWKS refresh if kid missing
			if strings.Contains(err.Error(), "key ID") {
				c.Set("jwks_refresh_attempt", true)
				if rErr := jwks.Refresh(context.Background(), keyfunc.RefreshOptions{}); rErr == nil {
					token, err = jwt.ParseWithClaims(bearer, &claims, jwks.Keyfunc)
				}
			}
		}
		if err != nil {
			// Record failure with reason
			failureReason := "verification_failed"
			if strings.Contains(err.Error(), "key ID") {
				failureReason = "key_id_not_found"
			} else if strings.Contains(err.Error(), "signature") {
				failureReason = "invalid_signature"
			} else if strings.Contains(err.Error(), "expired") {
				failureReason = "token_expired"
			}
			metrics.JWTValidationFailure.WithLabelValues(issuer, failureReason).Inc()

			errorMsg := "Token verification failed. Please re-authenticate."
			RespondUnauthorizedWithMessage(c, errorMsg)
			c.Abort()
			return
		}

		// Record successful validation with duration
		metrics.JWTValidationSuccess.WithLabelValues(issuer).Inc()
		metrics.JWTValidationDuration.WithLabelValues(issuer).Observe(time.Since(startTime).Seconds())

		// Extract core identity claims
		user_id := claims["sub"]
		email := claims["email"]
		username := claims["preferred_username"]

		// Multi-IDP: Store issuer and IDP name for downstream use
		if issuer != "" {
			c.Set("issuer", issuer)
		}
		if selectedIDP != "" {
			c.Set("identity_provider_name", selectedIDP)
		}

		// Attach raw claims for downstream debugging if needed
		// Note: this is only used for debug logs and should not be exposed to end users.
		c.Set("raw_claims", claims)

		// Attempt to extract groups from common Keycloak / OIDC claims
		var groups []string
		if rawGroups, ok := claims["groups"]; ok {
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

		// Normalize group names: strip leading slashes and reduce nested paths to final segment.
		if len(groups) > 0 {
			seen := make(map[string]struct{}, len(groups))
			normalized := make([]string, 0, len(groups))
			for _, g := range groups {
				g = strings.TrimSpace(g)
				if g == "" { // skip empty
					continue
				}
				// Remove leading slash (Keycloak group path style: /team/role)
				for strings.HasPrefix(g, "/") {
					g = strings.TrimPrefix(g, "/")
				}
				if idx := strings.LastIndex(g, "/"); idx != -1 && idx < len(g)-1 { // keep only final path element
					g = g[idx+1:]
				}
				if g == "" { // after normalization
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
		if len(groups) == 0 {
			// avoid logging tokens at info level; use debug for development troubleshooting
			if a.log != nil {
				a.log.Debugw("JWT parsed but no groups claim found", "sub", user_id, "username", username, "claims_keys", func() []string {
					keys := make([]string, 0, len(claims))
					for k := range claims {
						keys = append(keys, k)
					}
					return keys
				}())
			}
		}

		c.Set("token", token)
		c.Set("user_id", user_id)
		c.Set("email", email)
		c.Set("username", username)
		if len(groups) > 0 {
			c.Set("groups", groups)
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
	authMiddleware := a.Middleware()
	return func(c *gin.Context) {
		// First run authentication
		authMiddleware(c)
		if c.IsAborted() {
			return
		}

		// Then apply rate limiting (uses email set by auth middleware)
		allowed, isAuthenticated := rl.Allow(c)
		if !allowed {
			msg := "Rate limit exceeded, please try again later"
			if !isAuthenticated {
				msg = "Rate limit exceeded. Please authenticate for higher limits."
			}
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":         msg,
				"authenticated": isAuthenticated,
			})
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
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":         msg,
				"authenticated": isAuthenticated,
			})
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

	// Get JWKS for verification
	jwks, err := a.getJWKSForIssuer(c.Request.Context(), issuer)
	if err != nil || jwks == nil {
		return ""
	}

	// Verify the token
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(bearer, claims, jwks.Keyfunc)
	if err != nil {
		return ""
	}

	// Extract email as user identity
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}

	// Fallback to subject if email not available
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}

	return ""
}

// RateLimiter interface for rate limiters that support authentication differentiation
type RateLimiter interface {
	Allow(c *gin.Context) (allowed bool, isAuthenticated bool)
}

func buildCertPoolFromPEM(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(pemData)); !ok {
		return nil, fmt.Errorf("failed to append certificates from PEM data")
	}
	return pool, nil
}
