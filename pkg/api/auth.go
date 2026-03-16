package api

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	AuthHeaderKey = "Authorization"
	// maxJWKSCacheSize limits the number of cached JWKS to prevent memory exhaustion
	// from malicious tokens claiming many different issuers
	maxJWKSCacheSize = 100

	// defaultOIDCTimeout is the HTTP client timeout for OIDC discovery
	// and JWKS requests.
	defaultOIDCTimeout = 10 * time.Second

	// jwksFetchMinInterval is the minimum interval between JWKS fetch attempts
	// for the same issuer. Prevents DoS against the OIDC provider when an attacker
	// floods requests with unknown kid values that trigger JWKS re-fetches. (SEC-004)
	jwksFetchMinInterval = 10 * time.Second

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

var (
	errUnknownIdentityProvider = errors.New("invalid or unknown identity provider")
	errJWKSFetchRateLimited    = errors.New("jwks fetch rate limited")
)

// jwksCacheEntry holds the JWKS and its position in the LRU list
type jwksCacheEntry struct {
	issuer              string
	idpName             string // resolved IDP name, cached to avoid redundant K8s API calls
	expectedAudience    string // from IDP config; when non-empty, JWT aud claim is validated
	audienceRefreshedAt time.Time
	audienceAttemptedAt time.Time
	jwks                keyfunc.Keyfunc
	cancel              context.CancelFunc // stops the background refresh goroutine
}

// audienceRefreshInterval controls how often expectedAudience is re-read from
// the live IDP config on cache hits. This avoids a K8s API call on every request
// while still picking up config changes within a reasonable window.
const audienceRefreshInterval = 30 * time.Second

// audienceRefreshFailureBackoff prevents repeated refresh attempts on every
// request when the refresh operation is currently failing.
const audienceRefreshFailureBackoff = 5 * time.Second

type AuthHandler struct {
	// Multi-IDP support: LRU cache for JWKS by issuer URL
	jwksCache   map[string]*list.Element // issuer -> list element
	jwksLRUList *list.List               // list of *jwksCacheEntry (front = most recent)
	jwksMutex   sync.RWMutex

	// Per-issuer JWKS fetch rate limiting (SEC-004)
	// Maps issuer URL -> last fetch time to prevent flooding the OIDC provider
	jwksFetchLimiter sync.Map // map[string]time.Time

	// Singleflight deduplicates concurrent JWKS fetches for the same issuer (SEC-004)
	jwksFlight singleflight.Group

	// Single-IDP fallback (for backward compatibility)
	jwks keyfunc.Keyfunc

	log *zap.SugaredLogger

	// IDPLoader for multi-IDP mode
	idpLoader *config.IdentityProviderLoader

	// defaultHTTPClient is a shared HTTP client for OIDC discovery when no
	// custom CA is configured. Reusing it avoids per-request allocations and
	// enables connection pooling.
	defaultHTTPClient *http.Client
}

// defaultOIDCTransport clones http.DefaultTransport to inherit its sensible
// defaults (proxy support, dial/idle timeouts, keep-alives) and layers TLS 1.2
// minimum on top. If http.DefaultTransport is not a *http.Transport, it falls
// back to a known-good Transport configuration.
func defaultOIDCTransport() *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)

	var t *http.Transport
	if ok && base != nil {
		t = base.Clone()
	} else {
		t = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else if t.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		cfg := t.TLSClientConfig.Clone()
		cfg.MinVersion = tls.VersionTLS12
		t.TLSClientConfig = cfg
	}
	return t
}

func NewAuth(log *zap.SugaredLogger, cfg config.Config) *AuthHandler {
	// JWKS loading happens dynamically via WithIdentityProviderLoader()
	// using IdentityProvider CRDs configured in the cluster
	return &AuthHandler{
		jwksCache:   make(map[string]*list.Element),
		jwksLRUList: list.New(),
		log:         log,
		defaultHTTPClient: &http.Client{
			Transport: defaultOIDCTransport(),
			Timeout:   defaultOIDCTimeout,
		},
	}
}

// WithIdentityProviderLoader sets the IDP loader for multi-IDP support
func (a *AuthHandler) WithIdentityProviderLoader(loader *config.IdentityProviderLoader) *AuthHandler {
	a.idpLoader = loader
	return a
}

// jwksFetchResult holds the result of a JWKS fetch operation for singleflight deduplication.
type jwksFetchResult struct {
	jwks     keyfunc.Keyfunc
	audience string
	idpName  string // resolved IDP name, avoids a second K8s lookup in the request path
}

// getJWKSForIssuer returns the JWKS and expected audience for a given issuer URL,
// loading and caching them if necessary.
// For single-IDP mode (no idpLoader), returns the default JWKS with empty audience.
// Uses LRU eviction to prevent memory exhaustion when cache is full.
// Concurrent fetches for the same issuer are deduplicated via singleflight (SEC-004).
func (a *AuthHandler) getJWKSForIssuer(ctx context.Context, issuer string) (jwks keyfunc.Keyfunc, audience string, idpName string, cacheHit bool, err error) {
	// Single-IDP mode: use default JWKS
	if a.idpLoader == nil {
		return a.jwks, "", "", true, nil
	}

	// Multi-IDP mode: check LRU cache for specific issuer (fast path)
	a.jwksMutex.Lock()
	if elem, exists := a.jwksCache[issuer]; exists {
		// Move to front of LRU list (mark as recently used)
		a.jwksLRUList.MoveToFront(elem)
		entry := elem.Value.(*jwksCacheEntry)
		cachedElem := elem
		// Snapshot mutable fields under the lock to avoid a data race:
		// another goroutine could write these fields concurrently.
		cachedJWKS := entry.jwks
		cachedAudience := entry.expectedAudience
		cachedIDPName := entry.idpName
		lastRefresh := entry.audienceRefreshedAt
		lastAttempt := entry.audienceAttemptedAt
		a.jwksMutex.Unlock()

		// Refresh expectedAudience from the live IDP config periodically so
		// changes take effect without waiting for JWKS cache eviction or a restart.
		// Use singleflight to avoid thundering herd when many requests arrive
		// just after the refresh interval elapses for the same issuer.
		if time.Since(lastRefresh) > audienceRefreshInterval &&
			(lastAttempt.IsZero() || time.Since(lastAttempt) > audienceRefreshFailureBackoff) {
			_, refreshErr, _ := a.jwksFlight.Do("audience:"+issuer, func() (interface{}, error) {
				idpCfg, err := a.idpLoader.LoadIdentityProviderByIssuer(ctx, issuer)
				now := time.Now()

				a.jwksMutex.Lock()
				defer a.jwksMutex.Unlock()

				// Re-check the cache entry under the lock so we don't update a
				// stale/evicted pointer captured before unlocking.
				currentElem, stillCached := a.jwksCache[issuer]
				if !stillCached || currentElem != cachedElem {
					return nil, nil
				}
				currentEntry := currentElem.Value.(*jwksCacheEntry)
				currentEntry.audienceAttemptedAt = now

				if err != nil {
					return nil, err
				}

				currentEntry.expectedAudience = idpCfg.ExpectedAudience
				currentEntry.idpName = idpCfg.Name
				currentEntry.audienceRefreshedAt = now
				return nil, nil
			})
			if refreshErr == nil {
				a.jwksMutex.Lock()
				currentElem, stillCached := a.jwksCache[issuer]
				if !stillCached || currentElem != cachedElem {
					a.jwksMutex.Unlock()
					return cachedJWKS, cachedAudience, cachedIDPName, true, nil
				}
				currentEntry := currentElem.Value.(*jwksCacheEntry)
				refreshedAudience := currentEntry.expectedAudience
				refreshedIDPName := currentEntry.idpName
				a.jwksMutex.Unlock()
				return cachedJWKS, refreshedAudience, refreshedIDPName, true, nil
			}
		}

		return cachedJWKS, cachedAudience, cachedIDPName, true, nil
	}
	a.jwksMutex.Unlock()

	// SEC-004: Use singleflight to deduplicate concurrent JWKS fetches for the same issuer.
	// This prevents fetch storms when many requests arrive simultaneously with a new issuer.
	v, err, _ := a.jwksFlight.Do(issuer, func() (interface{}, error) {
		return a.loadJWKSForIssuer(ctx, issuer)
	})
	if err != nil {
		return nil, "", "", false, err
	}
	res := v.(*jwksFetchResult)
	return res.jwks, res.audience, res.idpName, false, nil
}

// loadJWKSForIssuer performs the actual JWKS fetch, IDP resolution, and cache population.
// It is called via singleflight to ensure only one concurrent fetch per issuer.
func (a *AuthHandler) loadJWKSForIssuer(ctx context.Context, issuer string) (*jwksFetchResult, error) {
	// Double-check cache inside singleflight (another goroutine may have populated it)
	a.jwksMutex.Lock()
	if elem, exists := a.jwksCache[issuer]; exists {
		a.jwksLRUList.MoveToFront(elem)
		entry := elem.Value.(*jwksCacheEntry)
		result := &jwksFetchResult{jwks: entry.jwks, audience: entry.expectedAudience, idpName: entry.idpName}
		a.jwksMutex.Unlock()
		return result, nil
	}
	a.jwksMutex.Unlock()

	// SEC-004: per-issuer rate limiting on initial JWKS client creation.
	// Prevents an attacker from flooding requests with crafted issuer claims
	// to trigger excessive JWKS fetches against upstream OIDC providers.
	// Note: once a JWKS client is created and cached, subsequent refreshes
	// (including those triggered by unknown kid values) are managed internally
	// by keyfunc/v3's RefreshInterval and per-URL deduplication — not by this
	// limiter. Network-level and IdP-side rate limits should be configured as
	// additional defense-in-depth for the JWKS endpoint.
	if lastFetch, ok := a.jwksFetchLimiter.Load(issuer); ok {
		if t, ok := lastFetch.(time.Time); ok {
			elapsed := time.Since(t)
			if elapsed < jwksFetchMinInterval {
				retryAfter := jwksFetchMinInterval - elapsed
				return nil, fmt.Errorf("%w: retry after %s", errJWKSFetchRateLimited, retryAfter.Truncate(time.Millisecond))
			}
		}
	}

	// Load IDP config by issuer
	idpCfg, err := a.idpLoader.LoadIdentityProviderByIssuer(ctx, issuer)
	if err != nil {
		a.log.Warnw("failed to load IDP config for issuer", "issuer", issuer, "error", err)
		// Don't expose the issuer in error message to prevent reconnaissance attacks
		return nil, errUnknownIdentityProvider
	}

	// Create JWKS override options for keyfunc/v3
	override := keyfunc.Override{
		RefreshInterval: time.Hour,
		HTTPTimeout:     defaultOIDCTimeout,
		RefreshErrorHandlerFunc: func(u string) func(ctx context.Context, err error) {
			return func(_ context.Context, err error) {
				a.log.Warnw("failed to refresh JWKS", "issuer", issuer, "url", u, "error", err)
			}
		},
	}

	// Configure TLS if needed (from IDP config)
	if idpCfg.CertificateAuthority != "" {
		pool, err := buildCertPoolFromPEM(idpCfg.CertificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("could not parse CA certificate for IDP %s: %w", idpCfg.Name, err)
		}
		transport := defaultOIDCTransport()
		transport.TLSClientConfig.RootCAs = pool
		override.Client = &http.Client{Transport: transport, Timeout: defaultOIDCTimeout}
	} else if idpCfg.Keycloak != nil && idpCfg.Keycloak.CertificateAuthority != "" {
		pool, err := buildCertPoolFromPEM(idpCfg.Keycloak.CertificateAuthority)
		if err != nil {
			return nil, fmt.Errorf("could not parse CA certificate for IDP %s: %w", idpCfg.Name, err)
		}
		transport := defaultOIDCTransport()
		transport.TLSClientConfig.RootCAs = pool
		override.Client = &http.Client{Transport: transport, Timeout: defaultOIDCTimeout}
	} else if idpCfg.InsecureSkipVerify || (idpCfg.Keycloak != nil && idpCfg.Keycloak.InsecureSkipVerify) {
		transport := defaultOIDCTransport()
		transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // Operator-opted via InsecureSkipVerify flag; TLS 1.2 enforced by defaultOIDCTransport
		override.Client = &http.Client{Transport: transport, Timeout: defaultOIDCTimeout}
		a.log.Warnw("TLS verification disabled for IDP (dev/e2e only)", "idp", idpCfg.Name)
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
		client := override.Client
		if client == nil {
			client = a.defaultHTTPClient
		}
		if client == nil {
			// Fallback for struct-literal construction: ensure TLS 1.2 minimum
			client = &http.Client{
				Transport: defaultOIDCTransport(),
				Timeout:   defaultOIDCTimeout,
			}
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
					if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err == nil && discovery.JWKSURI != "" {
						// Validate the discovered JWKS URI to prevent SSRF if an IDP
						// is compromised and returns a malicious jwks_uri.
						if !isValidJWKSURL(discovery.JWKSURI) {
							a.log.Warnw("OIDC discovery returned invalid jwks_uri, ignoring", "jwks_uri", discovery.JWKSURI)
						} else if !jwksHostMatchesAuthority(discovery.JWKSURI, idpCfg.Authority) {
							a.log.Warnw("OIDC discovery returned jwks_uri with mismatched host, ignoring",
								"jwks_uri", discovery.JWKSURI, "authority", idpCfg.Authority)
						} else {
							jwksURL = discovery.JWKSURI
							discoverySuccess = true
						}
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

	// Create a per-entry context to control the background refresh goroutine.
	// Cancelling this context stops the refresh goroutine (replaces EndBackground in keyfunc v1).
	entryCtx, entryCancel := context.WithCancel(context.Background())
	k, err := keyfunc.NewDefaultOverrideCtx(entryCtx, []string{jwksURL}, override)
	if err != nil {
		entryCancel()
		return nil, fmt.Errorf("failed to load JWKS for IDP %s (%s): %w", idpCfg.Name, issuer, err)
	}

	// SEC-004: store rate-limit timestamp only after successful JWKS fetch.
	// This prevents rate-limiting subsequent requests when the upstream JWKS
	// endpoint is temporarily unavailable (transient failure amplification).
	a.jwksFetchLimiter.Store(issuer, time.Now())

	// Cache with LRU eviction to prevent memory exhaustion
	a.jwksMutex.Lock()
	defer a.jwksMutex.Unlock()

	// Check again in case another goroutine loaded it while we were fetching
	if elem, exists := a.jwksCache[issuer]; exists {
		// Another goroutine beat us to it - use theirs, discard ours
		entryCancel()
		a.jwksLRUList.MoveToFront(elem)
		entry := elem.Value.(*jwksCacheEntry)
		return &jwksFetchResult{jwks: entry.jwks, audience: entry.expectedAudience, idpName: entry.idpName}, nil
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
		// Stop the background refresh goroutine via context cancellation
		if entry.cancel != nil {
			entry.cancel()
		}
		// Clean up rate limiter entry to prevent unbounded sync.Map growth
		a.jwksFetchLimiter.Delete(entry.issuer)
		delete(a.jwksCache, entry.issuer)
		a.jwksLRUList.Remove(oldest)
	}

	// Add new entry at front (most recently used)
	now := time.Now()
	entry := &jwksCacheEntry{issuer: issuer, idpName: idpCfg.Name, expectedAudience: idpCfg.ExpectedAudience, audienceRefreshedAt: now, audienceAttemptedAt: now, jwks: k, cancel: entryCancel}
	elem := a.jwksLRUList.PushFront(entry)
	a.jwksCache[issuer] = elem

	a.log.Debugw("loaded JWKS for issuer", "issuer", issuer, "idp_name", idpCfg.Name)
	return &jwksFetchResult{jwks: k, audience: idpCfg.ExpectedAudience, idpName: idpCfg.Name}, nil
}

func authErrorMessageForJWKSLoad(err error) string {
	switch {
	case errors.Is(err, errUnknownIdentityProvider):
		return "token issuer is not configured for this service"
	case errors.Is(err, errJWKSFetchRateLimited):
		return "temporarily unable to verify token; please retry shortly"
	default:
		return "unable to verify token"
	}
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

	// Get appropriate JWKS (based on issuer or default)
	var jwks keyfunc.Keyfunc
	var selectedIDP string

	var expectedAudience string

	if a.idpLoader != nil && issuer != "" {
		// Multi-IDP mode: load JWKS for specific issuer
		loadedJwks, loadedAudience, loadedIDPName, wasCacheHit, err := a.getJWKSForIssuer(c.Request.Context(), issuer)
		if err != nil {
			a.log.Debugw("failed to get JWKS for issuer", "issuer", issuer, "error", err)
			metrics.JWTValidationRequests.WithLabelValues("unknown", mode).Inc()
			metrics.JWTValidationFailure.WithLabelValues("unknown", "jwks_load_failed").Inc()

			RespondUnauthorizedWithMessage(c, authErrorMessageForJWKSLoad(err))
			c.Abort()
			return false
		}
		jwks = loadedJwks
		expectedAudience = loadedAudience
		selectedIDP = loadedIDPName

		// Record JWKS cache hit/miss with bounded IDP name label
		cacheLabel := selectedIDP
		if cacheLabel == "" {
			cacheLabel = "unknown"
		}
		if wasCacheHit {
			metrics.JWKSCacheHits.WithLabelValues(cacheLabel).Inc()
		} else {
			metrics.JWKSCacheMisses.WithLabelValues(cacheLabel).Inc()
		}
	} else if a.idpLoader != nil && issuer == "" {
		// Multi-IDP mode but no issuer in token: require issuer claim
		metrics.JWTValidationRequests.WithLabelValues("unknown", mode).Inc()
		metrics.JWTValidationFailure.WithLabelValues("unknown", "missing_issuer").Inc()
		RespondUnauthorizedWithMessage(c, "No issuer (iss) claim found in token. Please ensure you are logged in with a valid identity provider.")
		c.Abort()
		return false
	} else {
		// Single-IDP mode: use default JWKS (issuer claim optional for backward compatibility)
		jwks = a.jwks
	}

	// Record validation attempt after IDP resolution so the label carries
	// the resolved provider name instead of an empty string.
	idpLabel := selectedIDP
	if idpLabel == "" {
		idpLabel = "unknown"
	}
	metrics.JWTValidationRequests.WithLabelValues(idpLabel, mode).Inc()

	// Verify and parse JWT with selected JWKS
	// Note: keyfunc/v3 automatically refreshes on unknown kid, so no manual refresh needed
	claims := jwt.MapClaims{}
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedJWTAlgs),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(), // SEC-005: reject tokens without exp claim
	}

	// SEC-005: Audience validation when expectedAudience is configured.
	// Prevents cross-service token confusion from other OIDC clients at the
	// same IDP. Only applied when the admin explicitly sets expectedAudience
	// and configures a matching audience protocol mapper in their IDP.
	if expectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(expectedAudience))
	}

	verifiedParser := jwt.NewParser(parserOpts...)
	token, err := verifiedParser.ParseWithClaims(bearer, &claims, jwks.Keyfunc)
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
			a.log.Debugw("JWT parsed but no groups claim found", "sub", userID, "username", username, "claims_keys", func() []string {
				keys := make([]string, 0, len(claims))
				for k := range claims {
					keys = append(keys, k)
				}
				return keys
			}())
		}
	}

	c.Set("token", token)
	c.Set("user_id", userID)
	c.Set("email", email)
	c.Set("username", username)
	// Extract display name from "name" claim (standard OIDC claim for full name)
	if displayName, ok := claims["name"]; ok {
		c.Set("displayName", displayName)
	}
	if len(groups) > 0 {
		c.Set("groups", groups)
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

	// Canonicalize issuer consistently with authenticate() to avoid
	// duplicate cache entries from trailing slash variations.
	issuer = strings.TrimRight(issuer, "/")

	// Get JWKS for verification
	jwks, expectedAudience, _, _, err := a.getJWKSForIssuer(c.Request.Context(), issuer)
	if err != nil || jwks == nil {
		return ""
	}

	// Verify the token
	claims := jwt.MapClaims{}
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedJWTAlgs),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(), // SEC-005: consistent with authenticate()
	}
	// SEC-005: apply audience validation in optional auth path too
	if expectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(expectedAudience))
	}
	verifiedParser := jwt.NewParser(parserOpts...)
	_, err = verifiedParser.ParseWithClaims(bearer, &claims, jwks.Keyfunc)
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

// isValidJWKSURL validates that a JWKS URI is a well-formed HTTPS URL.
// Unlike isValidIssuerURL, this allows query parameters since legitimate
// JWKS endpoints may include them (e.g., versioned endpoints).
func isValidJWKSURL(jwksURI string) bool {
	if len(jwksURI) == 0 || len(jwksURI) > maxIssuerLength {
		return false
	}
	u, err := url.Parse(jwksURI)
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.Host == "" {
		return false
	}
	// Reject fragment and userinfo but allow query parameters
	if u.Fragment != "" || u.User != nil {
		return false
	}
	return true
}

// jwksHostMatchesAuthority returns true when the discovered jwks_uri origin
// matches the configured authority origin (hostname + effective port).
// This prevents SSRF if a compromised IDP discovery endpoint returns a
// jwks_uri pointing to an internal, unrelated, or different-port host.
func jwksHostMatchesAuthority(jwksURI, authority string) bool {
	jwksURL, err := url.Parse(jwksURI)
	if err != nil {
		return false
	}
	authURL, err := url.Parse(authority)
	if err != nil || !authURL.IsAbs() {
		return false
	}
	if !strings.EqualFold(jwksURL.Hostname(), authURL.Hostname()) {
		return false
	}
	// Compare effective ports (default 443 for HTTPS when unspecified)
	return effectivePort(jwksURL) == effectivePort(authURL)
}

// effectivePort returns the port from the URL, defaulting to "443" for https.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return ""
}

func buildCertPoolFromPEM(pemData string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM([]byte(pemData)); !ok {
		return nil, fmt.Errorf("failed to append certificates from PEM data")
	}
	return pool, nil
}
