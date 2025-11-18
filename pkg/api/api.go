package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
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
}
type ServerConfig struct {
	Auth  *AuthHandler
	Log   *zap.Logger
	Cfg   config.Config
	Debug bool
}

func NewServer(log *zap.Logger, cfg config.Config,
	debug bool, auth *AuthHandler,
) *Server {
	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
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
						log.Error("handler_error", zap.String("cid", fmt.Sprintf("%v", cid)), zap.Error(first), zap.String("meta", metaStr))
					}
				} else {
					log.Error("handler_error", zap.String("cid", fmt.Sprintf("%v", cid)), zap.Error(first), zap.String("meta", metaStr))
				}
				if !c.IsAborted() {
					c.JSON(c.Writer.Status(), gin.H{"error": first.Error(), "cid": cid, "meta": metaStr})
				}
			}
		},
	)

	// Always expose CORS for browser-based OIDC flows (token exchange happens against keycloak but frontend hits API)
	engine.Use(
		cors.New(cors.Config{
			// Allow HTTPS origin for Keycloak local forward and controller UI
			AllowOrigins:     []string{"https://localhost:8443", "http://localhost:28081", "http://localhost:28080", "*"},
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
	}

	s := &Server{
		gin:    engine,
		config: cfg,
		auth:   auth,
		log:    log,
	}

	// parse configured authorization server URL for proxying requests when possible
	if cfg.AuthorizationServer.URL != "" {
		if u, err := url.Parse(cfg.AuthorizationServer.URL); err == nil {
			s.oidcAuthority = u
		}
	}

	// OIDC proxy endpoint: proxies discovery and JWKS calls to the configured OIDC authority
	// This allows the browser to fetch .well-known/openid-configuration and jwks via the
	// server origin (avoiding the need to trust the Keycloak cert in the browser).
	engine.GET("api/oidc/authority/*proxyPath", s.handleOIDCProxy)
	// Also handle POST for token endpoint
	engine.POST("api/oidc/authority/*proxyPath", s.handleOIDCProxy)

	// Prometheus metrics endpoint (under /api/metrics)
	engine.GET("/api/metrics", func(c *gin.Context) {
		metricsHandler := func(w http.ResponseWriter, r *http.Request) {
			metrics.MetricsHandler().ServeHTTP(w, r)
		}
		metricsHandler(c.Writer, c.Request)
	})

	// Public configuration endpoint
	engine.GET("api/config", s.getConfig)

	// Identity Provider configuration endpoint (non-secrets)
	engine.GET("api/identity-provider", s.getIdentityProvider)

	// Multi-IDP configuration endpoint for frontend IDP selection
	engine.GET("api/config/idps", s.getMultiIDPConfig)

	return s
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
	apiGroup := s.gin.Group("api")
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
	var err error
	if s.config.Server.TLSCertFile != "" && s.config.Server.TLSKeyFile != "" {
		err = s.gin.RunTLS(s.config.Server.ListenAddress, s.config.Server.TLSCertFile, s.config.Server.TLSKeyFile)
	} else {
		err = s.gin.Run(s.config.Server.ListenAddress)
	}
	if err != nil {
		s.log.Sugar().Errorw("[E2E-DEBUG] Server listen error", "error", err)
	}
}

type FrontendConfig struct {
	OIDCAuthority string `json:"oidcAuthority"`
	OIDCClientID  string `json:"oidcClientID"`
	BrandingName  string `json:"brandingName,omitempty"`
	UIFlavour     string `json:"uiFlavour,omitempty"`
}

type AuthorizationServerConfig struct {
	URL          string `json:"url"`
	JWKSEndpoint string `json:"jwksEndpoint"`
}

type PublicConfig struct {
	Frontend            FrontendConfig            `json:"frontend"`
	AuthorizationServer AuthorizationServerConfig `json:"authorizationServer"`
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
		AuthorizationServer: AuthorizationServerConfig{
			URL:          s.config.AuthorizationServer.URL,
			JWKSEndpoint: s.config.AuthorizationServer.JWKSEndpoint,
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
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity provider not configured"})
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

// handleOIDCProxy proxies OIDC discovery and JWKS endpoints from the configured
// authorization server authority. The route is mounted at /api/oidc/authority/*proxyPath
// and performs a backend GET to the configured authority, returning the body and
// status to the browser. This avoids requiring the browser to trust the Keycloak
// certificate for e2e local runs. Only simple GET proxying is implemented here.
//
// In multi-IDP setups, the frontend can send X-OIDC-Authority header to specify
// which Keycloak instance to proxy to. This header is validated against known IDPs
// to prevent SSRF attacks.
//
// Security: This function uses strict whitelist validation on both the path parameter
// and the authority header to prevent SSRF attacks. Only known OIDC endpoints are allowed.
func (s *Server) handleOIDCProxy(c *gin.Context) {
	if s.oidcAuthority == nil {
		s.log.Sugar().Warnw("oidc_proxy_missing_authority")
		metrics.OIDCProxyRequests.WithLabelValues("authority").Inc()
		metrics.OIDCProxyFailure.WithLabelValues("authority", "missing_authority").Inc()
		c.JSON(http.StatusNotFound, gin.H{"error": "OIDC authority not configured"})
		return
	}
	start := time.Now()
	metrics.OIDCProxyRequests.WithLabelValues("authority").Inc()
	proxyPath := c.Param("proxyPath")

	// Whitelist of allowed OIDC endpoints - only these paths can be proxied
	// This prevents SSRF by ensuring only known OIDC discovery and authorization endpoints are accessible
	allowedPathPrefixes := []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/jwks.json",
		"/auth/realms/", // Keycloak specific
		"/protocol/openid-connect/auth",
		"/protocol/openid-connect/token",
		"/protocol/openid-connect/certs",
		"/protocol/openid-connect/userinfo",
		"/protocol/openid-connect/logout",
		"/certs", // Some OIDC providers use this
		"/token",
		"/authorize",
		"/userinfo",
		"/revocation",
		"/introspection",
	}

	// Normalize the path - remove query string and fragment
	normalizedPath := proxyPath
	if idx := strings.Index(normalizedPath, "?"); idx != -1 {
		normalizedPath = normalizedPath[:idx]
	}
	if idx := strings.Index(normalizedPath, "#"); idx != -1 {
		normalizedPath = normalizedPath[:idx]
	}

	// Check if path matches any allowed prefix
	pathAllowed := false
	for _, prefix := range allowedPathPrefixes {
		if strings.HasPrefix(normalizedPath, prefix) {
			pathAllowed = true
			break
		}
	}

	if !pathAllowed {
		s.log.Sugar().Warnw("oidc_proxy_path_not_whitelisted", "path", proxyPath, "normalized", normalizedPath)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "path_not_allowed").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "path_not_allowed").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusForbidden, gin.H{"error": "requested path is not an allowed OIDC endpoint"})
		return
	}

	// Additional validation: reject suspicious patterns even if they pass the prefix check
	// This catches encoded attacks and other bypasses
	if strings.Contains(proxyPath, "://") || strings.HasPrefix(proxyPath, "//") || strings.Contains(proxyPath, "..") {
		s.log.Sugar().Warnw("oidc_proxy_suspicious_pattern", "path", proxyPath)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "suspicious_pattern").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "suspicious_pattern").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid proxy path: absolute URLs and path traversal not allowed"})
		return
	}

	// Validate that the path is still URL-safe after normalization
	parsedPath, parseErr := url.Parse(normalizedPath)
	if parseErr != nil {
		s.log.Sugar().Warnw("oidc_proxy_malformed_path", "path", proxyPath, "normalized", normalizedPath, "error", parseErr)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "malformed_path").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "malformed_path").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy path: malformed"})
		return
	}

	// Ensure the parsed path doesn't contain URL scheme or host (which would indicate an absolute URL)
	if parsedPath.Scheme != "" || parsedPath.Host != "" {
		s.log.Sugar().Warnw("oidc_proxy_absolute_url_detected", "path", proxyPath, "scheme", parsedPath.Scheme, "host", parsedPath.Host)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "absolute_url_detected").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "absolute_url_detected").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid proxy path: must be relative"})
		return
	}

	// Check for X-OIDC-Authority header to support multi-IDP routing
	// The frontend sends this header when using a specific IDP to tell backend which Keycloak to proxy to
	targetAuthority := s.oidcAuthority
	if customAuthority := c.Request.Header.Get("X-OIDC-Authority"); customAuthority != "" {
		// Validate that the custom authority is a valid URL with allowed scheme
		if parsed, err := url.Parse(customAuthority); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" {
			// Verify this is from a known IDP configuration to prevent SSRF attacks
			if s.isKnownIDPAuthority(customAuthority) {
				targetAuthority = parsed
				s.log.Sugar().Debugw("oidc_proxy_using_custom_authority", "authority", parsed.Scheme+"://"+parsed.Host)
			} else {
				s.log.Sugar().Warnw("oidc_proxy_unknown_authority", "customAuthority", customAuthority)
				metrics.OIDCProxyFailure.WithLabelValues("authority", "unknown_authority").Inc()
				metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "unknown_authority").Inc()
				metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
				c.JSON(http.StatusForbidden, gin.H{"error": "unknown OIDC authority"})
				return
			}
		} else {
			s.log.Sugar().Warnw("oidc_proxy_invalid_authority_header", "customAuthority", customAuthority)
			metrics.OIDCProxyFailure.WithLabelValues("authority", "invalid_authority_header").Inc()
			metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "invalid_authority_header").Inc()
			metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid X-OIDC-Authority header"})
			return
		}
	}

	// Construct target URL safely using URL.ResolveReference
	// This ensures we're building a proper URL with the authority as base
	base := targetAuthority
	if base.Path != "" {
		base.Path = strings.TrimRight(base.Path, "/")
	}

	// Create a URL from the normalized path with the base authority
	relativeURL := &url.URL{Path: normalizedPath}
	if idx := strings.Index(proxyPath, "?"); idx != -1 {
		relativeURL.RawQuery = proxyPath[idx+1:]
	}

	targetURL := base.ResolveReference(relativeURL)

	// Final validation: ensure the resolved URL has the same scheme and host as our target authority
	if targetURL.Scheme != base.Scheme || targetURL.Host != base.Host {
		s.log.Sugar().Warnw("oidc_proxy_url_resolution_attack", "originalPath", proxyPath, "resultScheme", targetURL.Scheme, "resultHost", targetURL.Host, "expectedScheme", base.Scheme, "expectedHost", base.Host)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "url_resolution_attack").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "url_resolution_attack").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid proxy path: resolved to different host"})
		return
	}

	target := targetURL.String()
	s.log.Sugar().Debugw("oidc_proxy_request", "path", proxyPath, "target_scheme", targetURL.Scheme, "target_host", targetURL.Host, "target_path", targetURL.Path)

	// Create HTTP client; trust configured CA if present otherwise skip verify for e2e
	transport := &http.Transport{}
	// If an authorization server CA is embedded in config, use it
	if s.config.AuthorizationServer.CertificateAuthority != "" {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(s.config.AuthorizationServer.CertificateAuthority))
		if ok {
			transport.TLSClientConfig = &tls.Config{RootCAs: roots}
		}
	} else {
		// For convenience in e2e local setups, allow insecure TLS to the authority
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	// Support both GET and POST methods
	var req *http.Request
	var err error

	if c.Request.Method == "POST" {
		// For POST requests (e.g., token endpoint), copy the body
		req, err = http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target, c.Request.Body)
		if err != nil {
			s.log.Sugar().Errorw("oidc_proxy_build_error", "error", err, "target", target)
			metrics.OIDCProxyFailure.WithLabelValues("authority", "request_build_error").Inc()
			metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "request_build_error").Inc()
			metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build proxy request", "detail": err.Error()})
			return
		}
		// Forward Content-Type header for POST
		if contentType := c.Request.Header.Get("Content-Type"); contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	} else {
		// For GET requests (default)
		req, err = http.NewRequestWithContext(c.Request.Context(), "GET", target, nil)
		if err != nil {
			s.log.Sugar().Errorw("oidc_proxy_build_error", "error", err, "target", target)
			metrics.OIDCProxyFailure.WithLabelValues("authority", "request_build_error").Inc()
			metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "request_build_error").Inc()
			metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build proxy request", "detail": err.Error()})
			return
		}
	}

	if err != nil {
		s.log.Sugar().Errorw("oidc_proxy_build_error", "error", err, "target", target)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "request_build_error").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "request_build_error").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build proxy request", "detail": err.Error()})
		return
	}

	// Forward Accept header if present
	if accept := c.Request.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := client.Do(req)
	if err != nil {
		s.log.Sugar().Errorw("oidc_proxy_upstream_error", "error", err, "target", target, "elapsed", time.Since(start))
		metrics.OIDCProxyFailure.WithLabelValues("authority", "upstream_error").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "upstream_error").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch from authority", "detail": err.Error(), "target": target})
		return
	}
	defer resp.Body.Close()
	s.log.Sugar().Debugw("oidc_proxy_upstream_response", "status", resp.StatusCode, "target", target, "elapsed", time.Since(start))

	// Copy status, headers (selectively) and body
	for k, vs := range resp.Header {
		for _, v := range vs {
			c.Writer.Header().Add(k, v)
		}
	}
	c.Status(resp.StatusCode)
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		s.log.Sugar().Errorw("oidc_proxy_copy_error", "error", err, "target", target)
		metrics.OIDCProxyFailure.WithLabelValues("authority", "response_copy_error").Inc()
		metrics.APIEndpointErrors.WithLabelValues("handleOIDCProxy", "response_copy_error").Inc()
		metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to stream response from authority", "detail": err.Error(), "target": target})
		return
	}

	// Record successful proxy completion
	metrics.OIDCProxySuccess.WithLabelValues("authority").Inc()
	metrics.APIEndpointDuration.WithLabelValues("handleOIDCProxy").Observe(time.Since(start).Seconds())
}
