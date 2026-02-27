package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/ratelimit"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/version"
	"github.com/telekom/k8s-breakglass/pkg/webhook"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"
)

type APIController interface {
	BasePath() string
	Register(rg *gin.RouterGroup) error
	Handlers() []gin.HandlerFunc
}

type Server struct {
	gin    *gin.Engine
	config config.Config
	auth   *AuthHandler
	log    *zap.Logger
	// httpServer is the underlying http.Server for graceful shutdown support
	httpServer *http.Server
	// idpReconciler maintains a cache of enabled IdentityProviders
	// Used by getMultiIDPConfig to avoid querying the Kubernetes APIServer
	idpReconciler *config.IdentityProviderReconciler
	// escalationReconciler maintains a cache of escalation→IDP mappings
	// Used by getMultiIDPConfig to avoid querying the Kubernetes APIServer
	escalationReconciler *config.EscalationReconciler
	// idpConfig caches the loaded IdentityProvider configuration for API responses
	// This is protected by idpMutex to support safe reloading
	idpConfig *config.IdentityProviderConfig
	// idpMutex protects concurrent access to idpConfig during reloads
	idpMutex sync.RWMutex
	// parsed OIDC authority (original configured value) used by the OIDC proxy
	oidcAuthority *url.URL
	// rateLimiters holds references to rate limiters for cleanup
	publicRateLimiter     *ratelimit.IPRateLimiter
	publicAuthRateLimiter *ratelimit.AuthenticatedRateLimiter
}
type ServerConfig struct {
	Auth  *AuthHandler
	Log   *zap.Logger
	Cfg   config.Config
	Debug bool
}

var defaultAllowedOrigins = []string{
	"https://localhost:8443",
	"http://localhost:28081",
	"http://localhost:28080",
	"http://localhost:5173",
}

var allowedOIDCProxyResponseHeaders = map[string]struct{}{
	"Cache-Control":               {},
	"Content-Encoding":            {},
	"Content-Language":            {},
	"Content-Length":              {},
	"Content-Type":                {},
	"Date":                        {},
	"ETag":                        {},
	"Expires":                     {},
	"Last-Modified":               {},
	"Pragma":                      {},
	"WWW-Authenticate":            {},
	"X-Content-Type-Options":      {},
	"Vary":                        {},
	"Access-Control-Allow-Origin": {},
	"Strict-Transport-Security":   {},
}

var oidcProxyTLSModeState struct {
	sync.Mutex
	current string
}

func NewServer(log *zap.Logger, cfg config.Config,
	debug bool, auth *AuthHandler,
) *Server {
	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()

	// Request body size limit middleware (1MB default)
	// Prevents DoS attacks via excessively large request bodies
	const maxBodySize = 1 << 20 // 1 MiB
	engine.Use(func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodySize)
		}
		c.Next()
	})

	// Security headers middleware
	// Adds essential security headers to all responses
	// Create Server early so the CSP middleware can access s.buildCSP()
	s := &Server{
		log:    log,
		config: cfg,
		auth:   auth,
		gin:    engine,
	}

	engine.Use(func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking attacks (SAMEORIGIN matches CSP frame-ancestors 'self')
		c.Writer.Header().Set("X-Frame-Options", "SAMEORIGIN")
		// Enable XSS filter in older browsers
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		// Control referrer information
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Restrict browser features
		c.Writer.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// HTTP Strict Transport Security (HSTS)
		// Set when:
		// 1. Direct TLS connection (c.Request.TLS != nil), or
		// 2. Behind TLS-terminating proxy with X-Forwarded-Proto: https
		// This ensures HSTS works correctly behind ingress controllers
		isHTTPS := c.Request.TLS != nil ||
			c.GetHeader("X-Forwarded-Proto") == "https" ||
			c.GetHeader("X-Forwarded-Ssl") == "on"
		if isHTTPS {
			// max-age=31536000 (1 year), includeSubDomains for comprehensive protection
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Content Security Policy - allow same-origin and configured OIDC endpoints
		// Note: 'unsafe-inline' for styles is required for many UI frameworks
		// Dynamically include OIDC authority if configured
		csp := s.buildCSP()
		c.Writer.Header().Set("Content-Security-Policy", csp)
		c.Next()
	})

	// Basic per-IP rate limiter for public/unauthenticated endpoints
	// This applies to all requests before authentication (e.g., /api/config, /api/identity-provider)
	// Uses a moderate limit: 20 req/s per IP, burst of 50
	// Authenticated endpoints have separate, more generous per-user limits applied in their handlers
	// Static assets are excluded from rate limiting as they are immutable cached resources
	publicRateLimiter := ratelimit.New(ratelimit.DefaultAPIConfig())
	engine.Use(publicRateLimiter.MiddlewareWithExclusions([]string{
		"/assets/", // Static assets (JS, CSS, fonts)
		"/favicon", // Favicon files
	}))

	// Configure trusted proxies for X-Forwarded-For headers
	// Only trust proxies that are explicitly configured (typically the ingress/load balancer)
	// Empty/nil slice means don't trust any proxies - safe default if no reverse proxy is used
	// For production with reverse proxy, configure in config.yaml:
	//   server:
	//     trustedProxies: ["10.0.0.0/8", "127.0.0.1"]
	trustedProxies := cfg.Server.TrustedProxies
	if trustedProxies == nil {
		trustedProxies = []string{}
	}
	if err := engine.SetTrustedProxies(trustedProxies); err != nil {
		log.Warn("Failed to set trusted proxies", zap.String("error", err.Error()))
	}

	// Correlation ID middleware
	engine.Use(func(c *gin.Context) {
		cid := c.Request.Header.Get("X-Request-ID")
		if cid == "" {
			cid = uuid.NewString()
		}
		c.Set("cid", cid)
		c.Writer.Header().Set("X-Request-ID", cid)
		c.Next()
	})

	// OpenTelemetry tracing middleware — creates a span per HTTP request.
	// When tracing is disabled, OTel installs a no-op provider so this
	// middleware becomes a near-zero-cost pass-through.
	engine.Use(otelgin.Middleware("k8s-breakglass"))

	engine.Use(
		ginzap.Ginzap(log, time.RFC3339, true),
		ginzap.RecoveryWithZap(log, false),
		// Request-scoped logger middleware: attach a sugared logger with request fields
		func(c *gin.Context) {
			cid, _ := c.Get("cid")
			reqLogger := log.Sugar().With("cid", cid, "method", c.Request.Method, "path", c.FullPath(), "remote", c.ClientIP())
			// store under canonical key so system.GetReqLogger can find it
			c.Set("reqLogger", reqLogger)
			c.Set("reqLoggerKey", "reqLogger")
			c.Set(system.ReqLoggerKey, reqLogger)
			c.Next()
		},
		func(c *gin.Context) { // request start/end structured log
			start := time.Now()
			c.Next()
			cid, _ := c.Get("cid")
			// ensure a concise http_request log always includes cid
			log.Info("http_request", zap.String("cid", fmt.Sprintf("%v", cid)), zap.String("method", c.Request.Method), zap.String("path", c.FullPath()), zap.Int("status", c.Writer.Status()), zap.Duration("latency", time.Since(start)))
		},
		func(c *gin.Context) { // unified error propagation: if handler set context error, respond JSON
			if len(c.Errors) > 0 {
				cid, _ := c.Get("cid")
				first := c.Errors[0]
				metaStr, _ := first.Meta.(string)
				// Prefer using the request-scoped logger if present so cid is already included
				if v, ok := c.Get(system.ReqLoggerKey); ok {
					if rl, ok2 := v.(*zap.SugaredLogger); ok2 {
						rl.Errorw("handler_error", "error", first.Error(), "meta", metaStr)
					} else {
						// Use zap.String to avoid stacktrace in error logs
						log.Error("handler_error", zap.String("cid", fmt.Sprintf("%v", cid)), zap.String("error", first.Error()), zap.String("meta", metaStr))
					}
				} else {
					// Use zap.String to avoid stacktrace in error logs
					log.Error("handler_error", zap.String("cid", fmt.Sprintf("%v", cid)), zap.String("error", first.Error()), zap.String("meta", metaStr))
				}
				if !c.IsAborted() {
					c.JSON(c.Writer.Status(), gin.H{"error": first.Error(), "cid": cid, "meta": metaStr})
				}
			}
		},
	)

	allowedOrigins, usedDefaults := buildAllowedOrigins(cfg)

	if usedDefaults {
		log.Warn("CORS: using default localhost origins because BREAKGLASS_ALLOW_DEFAULT_ORIGINS is enabled — not suitable for production; set server.allowedOrigins in config",
			zap.Strings("origins", allowedOrigins),
			zap.String("BREAKGLASS_ALLOW_DEFAULT_ORIGINS", os.Getenv("BREAKGLASS_ALLOW_DEFAULT_ORIGINS")))
	} else if len(allowedOrigins) == 0 {
		log.Warn("CORS: no allowed origins configured and defaults not enabled — browser requests with Origin header will be blocked; set server.allowedOrigins in config")
	} else {
		log.Info("CORS: allowed origins configured", zap.Strings("origins", allowedOrigins))
	}

	allowedOriginSet := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowedOriginSet[origin] = struct{}{}
	}

	engine.Use(func(c *gin.Context) {
		if len(allowedOriginSet) == 0 {
			c.Next()
			return
		}

		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		originHeader := c.Request.Header.Get("Origin")
		if originHeader == "" {
			c.Next()
			return
		}

		normalized := normalizeOrigin(originHeader)
		if _, ok := allowedOriginSet[normalized]; ok {
			c.Next()
			return
		}

		cid, _ := c.Get("cid")
		log.Warn("blocked_request_origin", zap.String("origin", originHeader), zap.String("normalized_origin", normalized), zap.String("cid", fmt.Sprintf("%v", cid)))
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "origin not allowed",
			"cid":   cid,
		})
	})

	// Always expose CORS for browser-based OIDC flows (token exchange happens against keycloak but frontend hits API)
	engine.Use(
		cors.New(cors.Config{
			AllowOrigins:     allowedOrigins,
			AllowMethods:     []string{"GET", "PUT", "PATCH", "POST", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
			ExposeHeaders:    []string{"Authorization"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		}),
	)

	// Serve static assets (must be before NoRoute handler)
	engine.Use(static.Serve("/assets/", static.LocalFile("/frontend/dist/assets", false)))

	// Serve root-level files like favicon - use route handler to normalize trailing slashes
	engine.GET("/favicon-oss.svg", func(c *gin.Context) {
		c.File("/frontend/dist/favicon-oss.svg")
	})
	engine.GET("/favicon-oss.svg/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/favicon-oss.svg")
	})

	// Custom NoRoute: JSON 404 for /api/*, SPA fallback for others
	engine.NoRoute(func(c *gin.Context) {
		if len(c.Request.URL.Path) >= 5 && c.Request.URL.Path[:5] == "/api/" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found", "path": c.Request.URL.Path})
		} else {
			ServeSPA("/", "/frontend/dist/")(c)
		}
	})

	if auth == nil {
		auth = NewAuth(log.Sugar(), cfg)
		s.auth = auth
	}

	// Create authenticated rate limiter for public endpoints
	// Even public endpoints get better rate limits if the user provides a valid JWT
	// Unauthenticated: 10 req/s per IP, Authenticated: 50 req/s per user
	publicAuthRateLimiter := ratelimit.NewAuthenticated(ratelimit.DefaultAuthenticatedAPIConfig())

	// Update the server with rate limiters
	s.publicRateLimiter = publicRateLimiter
	s.publicAuthRateLimiter = publicAuthRateLimiter

	// Note: oidcAuthority is set dynamically when IdentityProvider is loaded via SetIdentityProvider()

	// OIDC proxy endpoint: proxies discovery and JWKS calls to the configured OIDC authority
	// This allows the browser to fetch .well-known/openid-configuration and jwks via the
	// server origin (avoiding the need to trust the Keycloak cert in the browser).
	engine.GET("/api/oidc/authority/*proxyPath", s.handleOIDCProxy)
	// Also handle POST for token endpoint
	engine.POST("/api/oidc/authority/*proxyPath", s.handleOIDCProxy)

	// Metrics endpoint info - actual metrics are served by controller-runtime on port 8081
	engine.GET("/api/metrics", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Metrics are served by controller-runtime on port 8081 at /metrics",
			"endpoint": "http://localhost:8081/metrics",
			"note":     "Use the controller-runtime metrics endpoint for all breakglass and controller metrics",
		})
	})

	// Public configuration endpoints with optional auth rate limiting
	// These endpoints don't require auth, but authenticated users get higher rate limits
	optionalAuthRateLimit := auth.OptionalAuthRateLimitMiddleware(publicAuthRateLimiter)
	engine.GET("/api/config", optionalAuthRateLimit, s.getConfig)
	engine.GET("/api/identity-provider", optionalAuthRateLimit, s.getIdentityProvider)
	engine.GET("/api/config/idps", optionalAuthRateLimit, s.getMultiIDPConfig)

	// Debug endpoint: build information
	engine.GET("/api/debug/buildinfo", func(c *gin.Context) {
		c.JSON(http.StatusOK, version.GetBuildInfo())
	})

	return s
}

// buildCSP generates a Content-Security-Policy header value.
// It includes 'self' for all directives and dynamically adds all configured OIDC authorities
// to connect-src (for API calls) and frame-src (for silent token refresh via iframe).
// Supports multiple identity providers when using the IDP reconciler.
func (s *Server) buildCSP() string {
	// Base CSP with 'self' for all directives
	connectSrc := "'self'"
	frameSrc := "'none'" // Default to none, will be updated if OIDC is configured

	// Collect unique authority URLs from all sources
	authorities := make(map[string]struct{})

	// First, check single IDP config (legacy mode or fallback)
	s.idpMutex.RLock()
	if s.oidcAuthority != nil {
		authority := s.oidcAuthority.Scheme + "://" + s.oidcAuthority.Host
		authorities[authority] = struct{}{}
	}
	s.idpMutex.RUnlock()

	// Second, check multi-IDP reconciler for all enabled identity providers
	if s.idpReconciler != nil {
		for _, idp := range s.idpReconciler.GetCachedIdentityProviders() {
			if idp.Spec.Disabled {
				continue
			}
			// Determine the authority URL for this IDP
			var authorityURL string
			if idp.Spec.Keycloak != nil && idp.Spec.Keycloak.BaseURL != "" {
				// For Keycloak, use the base URL (realm path is included in auth requests)
				authorityURL = idp.Spec.Keycloak.BaseURL
			} else if idp.Spec.OIDC.Authority != "" {
				// OIDC config is embedded (not a pointer), so just check the Authority field
				authorityURL = idp.Spec.OIDC.Authority
			}
			if authorityURL != "" {
				if u, err := url.Parse(authorityURL); err == nil {
					authority := u.Scheme + "://" + u.Host
					authorities[authority] = struct{}{}
				}
			}
		}
	}

	// Build the CSP directives from collected authorities
	if len(authorities) > 0 {
		var authorityList []string
		for authority := range authorities {
			authorityList = append(authorityList, authority)
		}
		// Sort for consistent ordering
		sort.Strings(authorityList)
		authoritiesStr := strings.Join(authorityList, " ")
		connectSrc += " " + authoritiesStr
		// Include 'self' in frame-src for the silent renew callback (/auth/silent-renew)
		// which is loaded in an iframe on the same origin
		frameSrc = "'self' " + authoritiesStr
	}

	// Script hashes for Vite's @vitejs/plugin-legacy inline scripts
	// These are required for legacy browser detection and Safari 10.1 module support
	// The hashes are stable across builds as they're from the plugin's fixed inline code
	// 1. Modern browser detection: import.meta.url;import("_")...
	// 2. Legacy loader: !function(){if(window.__vite_is_modern_browser)...
	// 3. Safari 10.1 nomodule fix: !function(){var e=document...
	// 4. Legacy entry System.import: System.import(document.getElementById...)
	legacyScriptHashes := "'sha256-ZxAi3a7m9Mzbc+Z1LGuCCK5Xee6reDkEPRas66H9KSo=' 'sha256-+5XkZFazzJo8n0iOP4ti/cLCMUudTf//Mzkb7xNPXIc=' 'sha256-MS6/3FCg4WjP9gwgaBGwLpRCY6fZBgwmhVCdrPrNf3E=' 'sha256-tQjf8gvb2ROOMapIxFvFAYBeUJ0v1HCbOcSmDNXGtDo='"

	return fmt.Sprintf(
		"default-src 'self'; script-src 'self' %s; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src %s; frame-src %s; frame-ancestors 'self'",
		legacyScriptHashes,
		connectSrc,
		frameSrc,
	)
}

// SetIdentityProvider sets the loaded IdentityProvider configuration on the server.
// This is called after loading the IDP to ensure it's available for API responses.
// Thread-safe: uses mutex to protect concurrent access during reloads.
func (s *Server) SetIdentityProvider(idpConfig *config.IdentityProviderConfig) {
	s.idpMutex.Lock()
	defer s.idpMutex.Unlock()

	if idpConfig != nil {
		s.idpConfig = idpConfig

		// Determine the OIDC authority URL
		authority := idpConfig.Authority
		if idpConfig.Keycloak != nil && idpConfig.Keycloak.BaseURL != "" && idpConfig.Keycloak.Realm != "" {
			// For Keycloak, construct the authority with realm path
			// Keycloak's OIDC discovery endpoint is at: {BaseURL}/realms/{Realm}/.well-known/openid-configuration
			baseURL := strings.TrimRight(idpConfig.Keycloak.BaseURL, "/")
			authority = fmt.Sprintf("%s/realms/%s", baseURL, idpConfig.Keycloak.Realm)
		}

		// Parse the authority URL for OIDC proxy requests
		if authority != "" {
			if u, err := url.Parse(authority); err == nil {
				s.oidcAuthority = u
			} else {
				s.log.Sugar().Warnw("failed to parse OIDC authority URL", "authority", authority, "error", err)
			}
		}

		s.log.Sugar().Infow("identity provider loaded", "type", idpConfig.Type, "authority", authority, "name", idpConfig.Name)
		// Record metric for provider type
		metrics.IdentityProviderLoaded.WithLabelValues(idpConfig.Type).Inc()
	}
}

// ReloadIdentityProvider reloads the IdentityProvider configuration from the provided loader.
// This is called when the IdentityProvider CR is updated to pick up changes like:
// - Certificate rotations
// - Timeout adjustments
// - Authority URL changes
// - Secret updates (e.g., ClientSecret, ServiceAccountToken)
// Thread-safe: acquires write lock during reload.
// Returns error if reload fails; existing config remains unchanged on error.
func (s *Server) ReloadIdentityProvider(loader *config.IdentityProviderLoader) error {
	if loader == nil {
		return fmt.Errorf("identity provider loader is nil")
	}

	ctx := context.Background()
	newConfig, err := loader.LoadIdentityProvider(ctx)
	if err != nil {
		s.log.Sugar().Errorw("failed_to_reload_identity_provider", "error", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("reload_error").Inc()
		return fmt.Errorf("failed to reload identity provider: %w", err)
	}

	// Update config atomically
	s.SetIdentityProvider(newConfig)
	s.log.Sugar().Infow("identity provider reloaded successfully", "type", newConfig.Type, "name", newConfig.Name)
	return nil
}

func buildAllowedOrigins(cfg config.Config) (origins []string, usedDefaults bool) {
	seen := make(map[string]struct{})

	add := func(candidate string) {
		normalized := normalizeOrigin(candidate)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		origins = append(origins, normalized)
	}

	for _, raw := range cfg.Server.AllowedOrigins {
		add(raw)
	}

	if len(origins) == 0 && allowDefaultOrigins() {
		for _, raw := range defaultAllowedOrigins {
			add(raw)
		}
		usedDefaults = true
	}

	if (usedDefaults || len(origins) == 0) && cfg.Frontend.BaseURL != "" {
		add(cfg.Frontend.BaseURL)
	}

	return origins, usedDefaults
}

func normalizeOrigin(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.TrimRight(trimmed, "/")

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return trimmed
	}

	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	defaultPort := (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
	switch {
	case port != "" && !defaultPort:
		host = net.JoinHostPort(host, port)
	case port != "" && defaultPort:
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = fmt.Sprintf("[%s]", host)
		}
	case port == "" && strings.Contains(host, ":") && !strings.HasPrefix(host, "["):
		host = fmt.Sprintf("[%s]", host)
	}

	return fmt.Sprintf("%s://%s", scheme, host)
}

func allowDefaultOrigins() bool {
	val := strings.TrimSpace(strings.ToLower(os.Getenv("BREAKGLASS_ALLOW_DEFAULT_ORIGINS")))
	return val == "true" || val == "1" || val == "yes"
}

// SetIdentityProviderReconciler sets the reconciler for accessing cached IDPs
// This is called after the reconciler is initialized so the API can use
// its cache to avoid DDoSing the Kubernetes APIServer
func (s *Server) SetIdentityProviderReconciler(reconciler *config.IdentityProviderReconciler) {
	s.idpReconciler = reconciler
}

// SetEscalationReconciler sets the reconciler for accessing cached escalation→IDP mappings
// This is called after the reconciler is initialized so the API can use
// its cache to avoid DDoSing the Kubernetes APIServer
func (s *Server) SetEscalationReconciler(reconciler *config.EscalationReconciler) {
	s.escalationReconciler = reconciler
}

func (s *Server) RegisterAll(controllers []APIController) error {
	apiGroup := s.gin.Group("/api")
	for _, c := range controllers {
		// Register under /api/<base>
		if err := c.Register(apiGroup.Group(c.BasePath(), c.Handlers()...)); err != nil {
			return err
		}
		// For backwards compatibility, register the webhook authorizer under the legacy root path as well.
		// Only do this for the webhook controller to avoid exposing all handlers at the root.
		if c.BasePath() == "breakglass/webhook" {
			rootGroup := s.gin.Group("")
			if err := c.Register(rootGroup.Group(c.BasePath(), c.Handlers()...)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) Listen() {
	// Create http.Server with timeouts from configuration (defaults applied if unset)
	timeouts := s.config.Server.GetServerTimeouts()
	s.httpServer = &http.Server{
		Addr:              s.config.Server.ListenAddress,
		Handler:           s.gin,
		ReadTimeout:       timeouts.GetReadTimeout(),
		ReadHeaderTimeout: timeouts.GetReadHeaderTimeout(),
		WriteTimeout:      timeouts.GetWriteTimeout(),
		IdleTimeout:       timeouts.GetIdleTimeout(),
		MaxHeaderBytes:    timeouts.GetMaxHeaderBytes(),
	}

	var err error
	if s.config.Server.TLSCertFile != "" && s.config.Server.TLSKeyFile != "" {
		s.log.Sugar().Infow("Starting HTTPS server", "address", s.config.Server.ListenAddress)
		err = s.httpServer.ListenAndServeTLS(s.config.Server.TLSCertFile, s.config.Server.TLSKeyFile)
	} else {
		s.log.Sugar().Infow("Starting HTTP server", "address", s.config.Server.ListenAddress)
		err = s.httpServer.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Sugar().Errorw("Server listen error", "error", err)
	}
}

// Shutdown gracefully shuts down the HTTP server, allowing in-flight requests to complete.
// The provided context can set a deadline for the shutdown. If the deadline is exceeded,
// remaining connections are forcibly closed.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	s.log.Sugar().Infow("Initiating graceful HTTP server shutdown")
	err := s.httpServer.Shutdown(ctx)
	if err != nil {
		s.log.Sugar().Warnw("HTTP server shutdown error", "error", err)
	} else {
		s.log.Sugar().Infow("HTTP server shutdown complete")
	}
	return err
}

// Handler exposes the underlying HTTP handler (Gin engine). This is primarily intended
// for tests that need to exercise the full API stack without starting a real TCP server.
func (s *Server) Handler() http.Handler {
	return s.gin
}

// Close cleans up server resources including stopping rate limiter cleanup goroutines.
// This should be called when the server is no longer needed (e.g., in tests or graceful shutdown).
func (s *Server) Close() {
	if s.publicAuthRateLimiter != nil {
		s.publicAuthRateLimiter.Stop()
	}
	if s.publicRateLimiter != nil {
		s.publicRateLimiter.Stop()
	}
}

type FrontendConfig struct {
	OIDCAuthority string `json:"oidcAuthority"`
	OIDCClientID  string `json:"oidcClientID"`
	BrandingName  string `json:"brandingName,omitempty"`
	UIFlavour     string `json:"uiFlavour,omitempty"`
}

type PublicConfig struct {
	Frontend FrontendConfig `json:"frontend"`
}

// IdentityProviderResponse exposes the configured IdentityProvider details to the frontend.
// IMPORTANT: This never includes secrets (ClientSecret, ServiceAccountToken, etc.)
type IdentityProviderResponse struct {
	// Type is the provider type (e.g., "OIDC", "Keycloak", "LDAP", "AzureAD")
	Type string `json:"type"`
	// Authority is the OIDC or OAuth authority URL (exposed to frontend for browser flows)
	Authority string `json:"authority"`
	// ClientID is the OIDC or OAuth client ID
	ClientID string `json:"clientId"`
	// KeycloakMetadata contains Keycloak-specific non-secret configuration if applicable
	KeycloakMetadata *KeycloakResponseMetadata `json:"keycloakMetadata,omitempty"`
}

// KeycloakResponseMetadata contains Keycloak-specific metadata exposed to the frontend.
// This intentionally excludes all secrets and sensitive information.
type KeycloakResponseMetadata struct {
	// BaseURL is the Keycloak server base URL (visible to frontend)
	BaseURL string `json:"baseUrl"`
	// Realm is the Keycloak realm name (visible to frontend)
	Realm string `json:"realm"`
}

// MultiIDPConfigResponse provides IDP configuration and escalation IDP mappings for frontend UI.
// This enables the frontend to show available IDPs and which IDPs are allowed for each escalation.
type MultiIDPConfigResponse struct {
	// IdentityProviders lists all enabled identity providers
	IdentityProviders []IDPInfo `json:"identityProviders"`
	// EscalationIDPMapping maps escalation names to their allowed IDPs
	// Empty list means all enabled IDPs are allowed for that escalation
	EscalationIDPMapping map[string][]string `json:"escalationIDPMapping"`
}

// IDPInfo represents a single Identity Provider in the multi-IDP configuration.
type IDPInfo struct {
	// Name is the unique identifier for the IDP
	Name string `json:"name"`
	// DisplayName is the human-readable name to show in UI
	DisplayName string `json:"displayName"`
	// Issuer is the OIDC issuer URL for this IDP
	Issuer string `json:"issuer"`
	// Enabled indicates if this IDP is active
	Enabled bool `json:"enabled"`
	// OIDCAuthority is the OIDC authority endpoint for this IDP (used for login redirect)
	// Will be proxied through /api/oidc/authority if configured
	OIDCAuthority string `json:"oidcAuthority,omitempty"`
	// OIDCClientID is the OIDC client ID for this IDP (used for login redirect)
	OIDCClientID string `json:"oidcClientID,omitempty"`
}

func (s *Server) getConfig(c *gin.Context) {
	// Expose a frontend-facing OIDC authority that points at the server-side proxy
	// so the browser performs discovery/JWKS calls against the API server origin
	// (avoids requiring the Keycloak cert to be trusted by the host/browser).
	frontendAuthority := ""
	clientID := ""

	// Load OIDC config from IdentityProvider if available (thread-safe read)
	s.idpMutex.RLock()
	if s.idpConfig != nil {
		frontendAuthority = s.idpConfig.Authority
		clientID = s.idpConfig.ClientID
	}
	s.idpMutex.RUnlock()

	// If the configured authority is an absolute URL (OIDC), expose the proxy
	// path instead for the browser. Keep s.config.AuthorizationServer.URL intact so
	// the server-side proxy can still target the real OIDC authority.
	if s.oidcAuthority != nil {
		// Build a proxy URL relative to the API server. Use the controller listen
		// address as origin when available; prefer relative proxy root so client
		// uses same origin: /api/oidc/authority
		frontendAuthority = "/api/oidc/authority"
	}

	c.JSON(http.StatusOK, PublicConfig{
		Frontend: FrontendConfig{
			OIDCAuthority: frontendAuthority,
			OIDCClientID:  clientID,
			BrandingName:  s.config.Frontend.BrandingName,
			UIFlavour:     s.config.Frontend.UIFlavour,
		},
	})
}

// getIdentityProvider returns the configured IdentityProvider metadata (non-secrets).
// This endpoint is called by the frontend to determine which authentication method to use.
// IMPORTANT: No secrets (ClientSecret, ServiceAccountToken, etc.) are ever exposed.
func (s *Server) getIdentityProvider(c *gin.Context) {
	start := time.Now()
	metrics.APIEndpointRequests.WithLabelValues("getIdentityProvider").Inc()

	// Thread-safe read of idpConfig with RLock
	s.idpMutex.RLock()
	idpCfg := s.idpConfig
	s.idpMutex.RUnlock()

	// If no IdentityProvider is loaded, return 404
	if idpCfg == nil {
		s.log.Sugar().Warnw("identity_provider_not_loaded")
		metrics.APIEndpointErrors.WithLabelValues("getIdentityProvider", "not_configured").Inc()
		metrics.APIEndpointDuration.WithLabelValues("getIdentityProvider").Observe(time.Since(start).Seconds())
		RespondNotFoundSimple(c, "Identity provider not configured")
		return
	}

	// Build response with only non-secret fields
	resp := IdentityProviderResponse{
		Type:      idpCfg.Type,
		Authority: idpCfg.Authority,
		ClientID:  idpCfg.ClientID,
	}

	// If Keycloak is configured, expose only non-secret metadata
	if idpCfg.Keycloak != nil {
		resp.KeycloakMetadata = &KeycloakResponseMetadata{
			BaseURL: idpCfg.Keycloak.BaseURL,
			Realm:   idpCfg.Keycloak.Realm,
		}
	}

	s.log.Sugar().Debugw("identity_provider_exposed", "type", resp.Type)
	metrics.APIEndpointDuration.WithLabelValues("getIdentityProvider").Observe(time.Since(start).Seconds())
	c.JSON(http.StatusOK, resp)
}

// getMultiIDPConfig returns multi-IDP configuration for frontend IDP selection.
// This endpoint provides:
// 1. List of enabled identity providers with their metadata
// 2. Mapping of escalations to their allowed IDPs for authorization enforcement
//
// Frontend uses this to:
// - Show available IDPs in IDP selector dropdown
// - Display which IDPs are allowed for each escalation
// - Pre-populate IDP field based on escalation selection
//
// Uses cached IDPs from the reconciler to avoid querying the Kubernetes APIServer
// Cache is maintained by the IdentityProviderReconciler and updated whenever
// IdentityProvider CRs change, preventing DDoS attacks via repeated API queries
func (s *Server) getMultiIDPConfig(c *gin.Context) {
	start := time.Now()
	metrics.MultiIDPConfigRequests.WithLabelValues().Inc()

	// Use cached IDPs from reconciler to avoid APIServer queries
	// If reconciler not available, return empty config and let frontend fall back
	if s.idpReconciler == nil {
		s.log.Sugar().Warnw("idp reconciler not available, returning empty config")
		metrics.MultiIDPConfigFailure.WithLabelValues("reconciler_unavailable").Inc()
		metrics.APIEndpointErrors.WithLabelValues("getMultiIDPConfig", "reconciler_unavailable").Inc()
		metrics.APIEndpointDuration.WithLabelValues("getMultiIDPConfig").Observe(time.Since(start).Seconds())
		resp := MultiIDPConfigResponse{
			IdentityProviders:    []IDPInfo{},
			EscalationIDPMapping: map[string][]string{},
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	// Get cached IDPs (thread-safe read from reconciler cache)
	cachedIDPs := s.idpReconciler.GetCachedIdentityProviders()

	// Convert cached IdentityProviders to IDPInfo responses
	var idpInfos []IDPInfo
	for _, idp := range cachedIDPs {
		idpInfos = append(idpInfos, IDPInfo{
			Name:          idp.Name,
			DisplayName:   idp.Spec.DisplayName,
			Issuer:        idp.Spec.Issuer,
			Enabled:       true,
			OIDCAuthority: idp.Spec.OIDC.Authority,
			OIDCClientID:  idp.Spec.OIDC.ClientID,
		})
	}

	// Get escalation→IDP mapping from reconciler cache
	escalationIDPMapping := make(map[string][]string)
	if s.escalationReconciler != nil {
		escalationIDPMapping = s.escalationReconciler.GetCachedEscalationIDPMapping()
		s.log.Sugar().Debugw("using cached escalation→IDP mapping", "escalationCount", len(escalationIDPMapping))
	} else {
		s.log.Sugar().Debugw("escalation reconciler not available, returning empty escalation→IDP mapping")
	}

	resp := MultiIDPConfigResponse{
		IdentityProviders:    idpInfos,
		EscalationIDPMapping: escalationIDPMapping,
	}

	s.log.Sugar().Debugw("multi_idp_config_returned", "idp_count", len(idpInfos), "escalation_count", len(resp.EscalationIDPMapping))
	metrics.MultiIDPConfigSuccess.WithLabelValues().Inc()
	metrics.APIEndpointRequests.WithLabelValues("getMultiIDPConfig").Inc()
	metrics.APIEndpointDuration.WithLabelValues("getMultiIDPConfig").Observe(time.Since(start).Seconds())
	c.JSON(http.StatusOK, resp)
}

// isKnownIDPAuthority checks if the given authority URL is from a known IDP configuration
// This prevents SSRF attacks by ensuring we only proxy to configured Keycloak instances
func (s *Server) isKnownIDPAuthority(authority string) bool {
	// Check against cached IDPs
	if s.idpReconciler != nil {
		cachedIDPs := s.idpReconciler.GetCachedIdentityProviders()
		for _, idp := range cachedIDPs {
			if idp.Spec.OIDC.Authority == authority {
				return true
			}
		}
	}

	// Also check against the default configured authority for single-IDP mode
	if s.oidcAuthority != nil && s.oidcAuthority.String() == authority {
		return true
	}

	return false
}

// handleOIDCProxy proxies OIDC discovery and JWKS endpoints from the configured authority.
// It validates the requested path and optional X-OIDC-Authority header rigorously to prevent SSRF.
func (s *Server) handleOIDCProxy(c *gin.Context) {
	start := time.Now()
	metrics.OIDCProxyRequests.WithLabelValues("authority").Inc()
	if s.oidcAuthority == nil {
		s.log.Sugar().Warnw("oidc_proxy_missing_authority")
		recordOIDCProxyFailure("missing_authority", start)
		RespondNotFoundSimple(c, "OIDC authority not configured")
		return
	}

	proxyPath := c.Param("proxyPath")
	normalizedPath, err := validateOIDCProxyPath(proxyPath)
	if err != nil {
		s.handleOIDCProxyPathError(c, proxyPath, normalizedPath, err, start)
		return
	}

	customAuthority := strings.TrimSpace(c.Request.Header.Get("X-OIDC-Authority"))
	targetAuthority, err := s.selectOIDCProxyAuthority(customAuthority)
	if err != nil {
		s.handleOIDCProxyAuthorityError(c, customAuthority, err, start)
		return
	}
	if customAuthority != "" {
		s.log.Sugar().Debugw("oidc_proxy_using_custom_authority", "authority", targetAuthority.Scheme+"://"+targetAuthority.Host, "path", targetAuthority.Path)
	}

	targetURL, err := buildOIDCProxyTargetURL(targetAuthority, normalizedPath, proxyPath)
	if err != nil {
		s.handleOIDCProxyPathError(c, proxyPath, normalizedPath, err, start)
		return
	}

	target := targetURL.String()
	s.log.Sugar().Debugw("oidc_proxy_request", "path", proxyPath, "target_scheme", targetURL.Scheme, "target_host", targetURL.Host, "target_path", targetURL.Path)

	client, err := s.newOIDCProxyHTTPClient(targetURL.Scheme == "https")
	if err != nil {
		s.log.Sugar().Errorw("oidc_proxy_client_error", "error", err)
		recordOIDCProxyFailure("tls_configuration_error", start)
		RespondInternalErrorSimple(c, "oidc proxy TLS configuration error")
		return
	}
	req, err := buildOIDCProxyHTTPRequest(c, target)
	if err != nil {
		s.log.Sugar().Errorw("oidc_proxy_build_error", "error", err, "target", target)
		if errors.Is(err, errOIDCProxyReadBody) {
			recordOIDCProxyFailure("read_body_error", start)
			RespondInternalErrorSimple(c, "failed to read request body")
		} else {
			recordOIDCProxyFailure("request_build_error", start)
			RespondInternalErrorSimple(c, "failed to build proxy request")
		}
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		s.log.Sugar().Errorw("oidc_proxy_upstream_error", "error", err, "target", target, "elapsed", time.Since(start))
		recordOIDCProxyFailure("upstream_error", start)
		RespondBadGateway(c, "failed to fetch from authority")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	s.log.Sugar().Debugw("oidc_proxy_upstream_response", "status", resp.StatusCode, "target", target, "elapsed", time.Since(start))

	for k, vs := range resp.Header {
		if !isAllowedOIDCProxyResponseHeader(k) {
			continue
		}
		canonical := http.CanonicalHeaderKey(k)
		for _, v := range vs {
			c.Writer.Header().Add(canonical, v)
		}
	}
	c.Status(resp.StatusCode)
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		s.log.Sugar().Errorw("oidc_proxy_copy_error", "error", err, "target", target)
		recordOIDCProxyFailure("response_copy_error", start)
		RespondBadGateway(c, "failed to stream response from authority")
		return
	}

	recordOIDCProxySuccess(start)
}

func (s *Server) handleOIDCProxyPathError(c *gin.Context, proxyPath, normalizedPath string, err error, start time.Time) {
	switch {
	case errors.Is(err, errProxyPathNotAllowed):
		s.log.Sugar().Warnw("oidc_proxy_path_not_whitelisted", "path", proxyPath, "normalized", normalizedPath)
		recordOIDCProxyFailure("path_not_allowed", start)
		RespondForbidden(c, errProxyPathNotAllowed.Error())
	case errors.Is(err, errProxyPathSuspicious):
		s.log.Sugar().Warnw("oidc_proxy_suspicious_pattern", "path", proxyPath)
		recordOIDCProxyFailure("suspicious_pattern", start)
		RespondForbidden(c, errProxyPathSuspicious.Error())
	case errors.Is(err, errProxyPathMalformed):
		s.log.Sugar().Warnw("oidc_proxy_malformed_path", "path", proxyPath, "normalized", normalizedPath, "error", err)
		recordOIDCProxyFailure("malformed_path", start)
		RespondBadRequest(c, errProxyPathMalformed.Error())
	case errors.Is(err, errProxyAuthorityMissing):
		s.log.Sugar().Errorw("oidc_proxy_missing_authority_base", "path", proxyPath)
		recordOIDCProxyFailure("missing_authority", start)
		RespondInternalErrorSimple(c, errProxyAuthorityMissing.Error())
	case errors.Is(err, errProxyPathAbsolute):
		s.log.Sugar().Warnw("oidc_proxy_absolute_url_detected", "path", proxyPath)
		recordOIDCProxyFailure("absolute_url_detected", start)
		RespondForbidden(c, errProxyPathAbsolute.Error())
	case errors.Is(err, errURLResolutionAttack):
		s.log.Sugar().Warnw("oidc_proxy_url_resolution_attack", "originalPath", proxyPath)
		recordOIDCProxyFailure("url_resolution_attack", start)
		RespondForbidden(c, errURLResolutionAttack.Error())
	default:
		s.log.Sugar().Errorw("oidc_proxy_unknown_path_error", "path", proxyPath, "error", err)
		recordOIDCProxyFailure("path_error", start)
		RespondBadRequest(c, "invalid proxy path")
	}
}

func (s *Server) handleOIDCProxyAuthorityError(c *gin.Context, headerValue string, err error, start time.Time) {
	switch {
	case errors.Is(err, errInvalidAuthorityHeader):
		s.log.Sugar().Warnw("oidc_proxy_invalid_authority_header", "customAuthority", headerValue, "error", err)
		recordOIDCProxyFailure("invalid_authority_header", start)
		RespondBadRequest(c, errInvalidAuthorityHeader.Error())
	case errors.Is(err, errUnknownOIDCAuthority):
		s.log.Sugar().Warnw("oidc_proxy_unknown_authority", "customAuthority", headerValue)
		recordOIDCProxyFailure("unknown_authority", start)
		RespondForbidden(c, errUnknownOIDCAuthority.Error())
	default:
		s.log.Sugar().Errorw("oidc_proxy_authority_error", "customAuthority", headerValue, "error", err)
		recordOIDCProxyFailure("authority_error", start)
		RespondBadRequest(c, "invalid authority header")
	}
}

const (
	tlsModeHTTP     = "http"
	tlsModeSystemCA = "system_ca"
	tlsModeCustomCA = "custom_ca"
	tlsModeInsecure = "insecure_skip_verify"
)

func (s *Server) newOIDCProxyHTTPClient(requiresTLS bool) (*http.Client, error) {
	transport := &http.Transport{}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	if !requiresTLS {
		recordOIDCProxyTLSMode(tlsModeHTTP)
		return client, nil
	}

	s.idpMutex.RLock()
	idpCfg := s.idpConfig
	s.idpMutex.RUnlock()
	if idpCfg == nil {
		return nil, fmt.Errorf("identity provider not loaded")
	}

	mode := tlsModeSystemCA
	var tlsConfig *tls.Config

	switch {
	case idpCfg.CertificateAuthority != "":
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM([]byte(idpCfg.CertificateAuthority)); !ok {
			return nil, fmt.Errorf("failed to parse certificateAuthority for IDP %s", idpCfg.Name)
		}
		tlsConfig = &tls.Config{RootCAs: roots}
		mode = tlsModeCustomCA
	case idpCfg.InsecureSkipVerify, idpCfg.Keycloak != nil && idpCfg.Keycloak.InsecureSkipVerify:
		// WARNING: InsecureSkipVerify disables TLS certificate verification.
		// This is a security risk and should only be used in development/testing.
		s.log.Sugar().Warnw("SECURITY WARNING: TLS certificate verification is disabled for identity provider",
			"idpName", idpCfg.Name,
			"authority", idpCfg.Authority,
			"warning", "This setting should NOT be used in production environments")
		tlsConfig = &tls.Config{InsecureSkipVerify: true}
		mode = tlsModeInsecure
	default:
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w", err)
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		tlsConfig = &tls.Config{RootCAs: roots}
	}

	transport.TLSClientConfig = tlsConfig

	recordOIDCProxyTLSMode(mode)
	return client, nil
}

func recordOIDCProxyTLSMode(mode string) {
	oidcProxyTLSModeState.Lock()
	prev := oidcProxyTLSModeState.current
	if prev == mode {
		oidcProxyTLSModeState.Unlock()
		return
	}
	oidcProxyTLSModeState.current = mode
	oidcProxyTLSModeState.Unlock()

	if prev != "" {
		metrics.OIDCProxyTLSMode.WithLabelValues(prev).Set(0)
	}
	metrics.OIDCProxyTLSMode.WithLabelValues(mode).Set(1)
}

var errOIDCProxyReadBody = errors.New("oidc_proxy_read_body_error")

func buildOIDCProxyHTTPRequest(c *gin.Context, target string) (*http.Request, error) {
	method := http.MethodGet
	var body io.Reader
	if c.Request.Method == http.MethodPost {
		method = http.MethodPost
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errOIDCProxyReadBody, err)
		}
		body = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), method, target, body)
	if err != nil {
		return nil, err
	}
	if method == http.MethodPost {
		if contentType := c.Request.Header.Get("Content-Type"); contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	}
	if accept := c.Request.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	return req, nil
}

func recordOIDCProxyFailure(metric string, start time.Time) {
	metrics.OIDCProxyFailure.WithLabelValues("authority", metric).Inc()
	metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", metric).Inc()
	metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
}

func recordOIDCProxySuccess(start time.Time) {
	metrics.OIDCProxySuccess.WithLabelValues("authority").Inc()
	metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
}

func isAllowedOIDCProxyResponseHeader(name string) bool {
	if name == "" {
		return false
	}
	_, ok := allowedOIDCProxyResponseHeaders[http.CanonicalHeaderKey(name)]
	return ok
}

func Setup(sessionController *breakglass.BreakglassSessionController, escalationManager *escalation.EscalationManager,
	sessionManager *breakglass.SessionManager, enableFrontend, enableAPI bool, configPath string,
	auth *AuthHandler, ccProvider *cluster.ClientProvider, denyEval *policy.Evaluator,
	cfg *config.Config, log *zap.SugaredLogger, debugSessionCtrl *debug.DebugSessionAPIController,
	auditService *audit.Service) ([]APIController, *webhook.WebhookController) {
	// Register API controllers based on component flags
	apiControllers := []APIController{}

	if enableFrontend {
		log.Infow("Frontend UI enabled via --enable-frontend=true")
	}

	// Create authenticated rate limiter for API endpoints
	// Authenticated users get 50 req/s (per user), unauthenticated get 10 req/s (per IP)
	apiRateLimiter := ratelimit.NewAuthenticated(ratelimit.DefaultAuthenticatedAPIConfig())

	if enableAPI {
		apiControllers = append(apiControllers, sessionController)
		// Use combined auth + rate limiting middleware for escalation controller
		apiControllers = append(apiControllers, escalation.NewBreakglassEscalationController(log, escalationManager, auth.MiddlewareWithRateLimiting(apiRateLimiter), configPath))
		// Register debug session API controller if provided
		if debugSessionCtrl != nil {
			apiControllers = append(apiControllers, debugSessionCtrl)
			log.Infow("Debug session API controller enabled")
		}
		// Note: ClusterBindingAPIController is NOT registered as a public API.
		// Cluster bindings are internal resources aggregated through the unified
		// template/clusters endpoint (GET /templates/:name/clusters).
		log.Infow("API controllers enabled", "components", "BreakglassSession, BreakglassEscalation")
	}

	// Webhook controller is always registered but may not be exposed via webhooks
	webhookCtrl := webhook.NewWebhookController(log, *cfg, sessionManager, escalationManager, ccProvider, denyEval).
		WithAuditService(auditService)

	// Only attach ActivityTracker when session activity tracking is enabled.
	// When disabled (default), the webhook still increments Prometheus counters
	// but skips buffered status updates to avoid unnecessary API server writes.
	if cfg.Server.EnableActivityTracking {
		webhookCtrl.WithActivityTracker(webhook.NewActivityTracker(
			sessionManager.Client,
			webhook.WithReader(sessionManager.Reader()),
		))
		log.Infow("Session activity tracking enabled")
	}
	apiControllers = append(apiControllers, webhookCtrl)
	return apiControllers, webhookCtrl
}
