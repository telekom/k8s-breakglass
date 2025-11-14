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

	// Custom NoRoute: JSON 404 for /api/*, SPA fallback for others
	engine.NoRoute(func(c *gin.Context) {
		if len(c.Request.URL.Path) >= 5 && c.Request.URL.Path[:5] == "/api/" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found", "path": c.Request.URL.Path})
		} else {
			ServeSPA("/", "/frontend/dist/")(c)
		}
	})

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
				s.log.Sugar().Warnw("failed_to_parse_oidc_authority", "authority", authority, "error", err)
			}
		}

		s.log.Sugar().Infow("identity_provider_loaded", "type", idpConfig.Type, "authority", authority)
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
	s.log.Sugar().Infow("identity_provider_reloaded", "type", newConfig.Type)
	return nil
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

// RegisterHealthChecks registers liveness and readiness probes with the server.
// webhooksReady should be a channel that is closed when webhooks are initialized and ready to handle traffic.
// If webhooksReady is nil, readiness probe will always report ready (webhooks disabled).
func (s *Server) RegisterHealthChecks(webhooksReady <-chan struct{}) {
	logger := s.log.Sugar()

	// Liveness probe: checks if the process is alive (always true unless manager crashes)
	s.gin.GET("/healthz", func(c *gin.Context) {
		logger.Debugw("Liveness probe check")
		c.JSON(200, gin.H{"status": "alive"})
	})

	// Readiness probe: checks if webhooks are ready (if enabled) and the service can accept traffic
	s.gin.GET("/readyz", func(c *gin.Context) {
		if webhooksReady != nil {
			select {
			case <-webhooksReady:
				logger.Debugw("Readiness probe check - ready")
				c.JSON(200, gin.H{"status": "ready"})
			default:
				logger.Debugw("Readiness probe check - not ready, waiting for webhooks")
				c.JSON(503, gin.H{"status": "not_ready", "reason": "webhooks_not_ready"})
			}
		} else {
			logger.Debugw("Readiness probe check - ready (webhooks disabled)")
			c.JSON(200, gin.H{"status": "ready"})
		}
	})
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
	// Thread-safe read of idpConfig with RLock
	s.idpMutex.RLock()
	idpCfg := s.idpConfig
	s.idpMutex.RUnlock()

	// If no IdentityProvider is loaded, return 404
	if idpCfg == nil {
		s.log.Sugar().Warnw("identity_provider_not_loaded")
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
	c.JSON(http.StatusOK, resp)
}

// handleOIDCProxy proxies OIDC discovery and JWKS endpoints from the configured
// authorization server authority. The route is mounted at /api/oidc/authority/*proxyPath
// and performs a backend GET to the configured authority, returning the body and
// status to the browser. This avoids requiring the browser to trust the Keycloak
// certificate for e2e local runs. Only simple GET proxying is implemented here.
func (s *Server) handleOIDCProxy(c *gin.Context) {
	if s.oidcAuthority == nil {
		s.log.Sugar().Warnw("oidc_proxy_missing_authority")
		c.JSON(http.StatusNotFound, gin.H{"error": "OIDC authority not configured"})
		return
	}
	start := time.Now()
	proxyPath := c.Param("proxyPath")

	// Validate proxyPath to prevent SSRF attacks: must be a relative path
	// Check that it doesn't contain a scheme (://) or absolute URL
	if strings.Contains(proxyPath, "://") || strings.HasPrefix(proxyPath, "//") {
		s.log.Sugar().Warnw("oidc_proxy_invalid_path", "path", proxyPath)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy path: absolute URLs not allowed"})
		return
	}

	// Safe join using parsed authority rather than raw configured string
	base := strings.TrimRight(s.oidcAuthority.String(), "/")
	target := base + proxyPath
	s.log.Sugar().Debugw("oidc_proxy_request", "path", proxyPath, "target", target)

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

	req, err := http.NewRequestWithContext(c.Request.Context(), "GET", target, nil)
	if err != nil {
		s.log.Sugar().Errorw("oidc_proxy_build_error", "error", err, "target", target)
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
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to stream response from authority", "detail": err.Error(), "target": target})
		return
	}
}
