package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
			ServeSPA("/", "./frontend/dist/")(c)
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

	// parse configured frontend OIDC authority for proxying requests when possible
	if cfg.Frontend.OIDCAuthority != "" {
		if u, err := url.Parse(cfg.Frontend.OIDCAuthority); err == nil {
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

	engine.GET("api/config", s.getConfig)

	return s
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

func (s *Server) getConfig(c *gin.Context) {
	// Expose a frontend-facing OIDC authority that points at the server-side proxy
	// so the browser performs discovery/JWKS calls against the API server origin
	// (avoids requiring the Keycloak cert to be trusted by the host/browser).
	frontendAuthority := s.config.Frontend.OIDCAuthority
	// If the configured authority is an absolute URL (Keycloak), expose the proxy
	// path instead for the browser. Keep s.config.Frontend.OIDCAuthority intact so
	// the server-side proxy can still target the real Keycloak authority.
	if s.oidcAuthority != nil {
		// Build a proxy URL relative to the API server. Use the controller listen
		// address as origin when available; prefer relative proxy root so client
		// uses same origin: /api/oidc/authority
		frontendAuthority = "/api/oidc/authority"
	}

	c.JSON(http.StatusOK, PublicConfig{
		Frontend: FrontendConfig{
			OIDCAuthority: frontendAuthority,
			OIDCClientID:  s.config.Frontend.OIDCClientID,
			BrandingName:  s.config.Frontend.BrandingName,
			UIFlavour:     s.config.Frontend.UIFlavour,
		},
		AuthorizationServer: AuthorizationServerConfig{
			URL:          s.config.AuthorizationServer.URL,
			JWKSEndpoint: s.config.AuthorizationServer.JWKSEndpoint,
		},
	})
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
