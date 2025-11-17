package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
)

const (
	AuthHeaderKey = "Authorization"
)

type AuthHandler struct {
	// Multi-IDP support: map issuer URL to JWKS
	jwksCache map[string]*keyfunc.JWKS
	jwksMutex sync.RWMutex

	// Single-IDP fallback (for backward compatibility)
	jwks *keyfunc.JWKS

	log *zap.SugaredLogger

	// IDPLoader for multi-IDP mode
	idpLoader *config.IdentityProviderLoader
}

func NewAuth(log *zap.SugaredLogger, cfg config.Config) *AuthHandler {
	options := keyfunc.Options{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second * 10,
		RefreshErrorHandler: func(err error) {
			log.Errorf("failed to refresh JWKS configuration: %v", err)
		},
	}

	url := fmt.Sprintf("%s/%s", cfg.AuthorizationServer.URL, cfg.AuthorizationServer.JWKSEndpoint)

	// TLS handling for JWKS fetch:
	// 1. If a CA PEM is provided, use it (strict validation).
	// 2. Else if InsecureSkipVerify is explicitly enabled, skip validation (dev/e2e only).
	// 3. Else rely on system roots (default production behavior).
	if cfg.AuthorizationServer.CertificateAuthority != "" {
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM([]byte(cfg.AuthorizationServer.CertificateAuthority))
		if !ok {
			log.Fatalf("Could not parse certificateAuthority PEM from configuration")
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
		options.Client = &http.Client{Transport: transport}
	} else if cfg.AuthorizationServer.InsecureSkipVerify {
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		options.Client = &http.Client{Transport: transport}
		log.Warn("authorizationServer.insecureSkipVerify=true: TLS certificate verification is DISABLED (dev/e2e only)")
	}

	jwks, err := keyfunc.Get(url, options)
	if err != nil {
		log.Fatalf("Could not get JWKS: %v\n", err)
	}

	return &AuthHandler{
		jwks:      jwks,
		jwksCache: make(map[string]*keyfunc.JWKS),
		log:       log,
	}
}

// WithIdentityProviderLoader sets the IDP loader for multi-IDP support
func (a *AuthHandler) WithIdentityProviderLoader(loader *config.IdentityProviderLoader) *AuthHandler {
	a.idpLoader = loader
	return a
}

// getJWKSForIssuer returns the JWKS for a given issuer URL, loading it if necessary
// For single-IDP mode (no idpLoader), returns the default JWKS
func (a *AuthHandler) getJWKSForIssuer(ctx context.Context, issuer string) (*keyfunc.JWKS, error) {
	// Single-IDP mode: use default JWKS
	if a.idpLoader == nil {
		return a.jwks, nil
	}

	// Multi-IDP mode: load JWKS for specific issuer
	a.jwksMutex.RLock()
	cachedJwks, exists := a.jwksCache[issuer]
	a.jwksMutex.RUnlock()
	if exists {
		return cachedJwks, nil
	}

	// Load IDP config by issuer
	idpCfg, err := a.idpLoader.LoadIdentityProviderByIssuer(ctx, issuer)
	if err != nil {
		a.log.Warnw("failed to load IDP config for issuer", "issuer", issuer, "error", err)
		return nil, fmt.Errorf("unknown issuer: %s", issuer)
	}

	// Build JWKS endpoint URL from IDP's authority
	if idpCfg.Authority == "" {
		return nil, fmt.Errorf("IDP %s has no authority configured", idpCfg.Name)
	}

	jwksURL := fmt.Sprintf("%s/.well-known/jwks.json", strings.TrimRight(idpCfg.Authority, "/"))

	// Create JWKS options
	options := keyfunc.Options{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second * 10,
		RefreshErrorHandler: func(err error) {
			a.log.Warnf("failed to refresh JWKS for issuer %s: %v", issuer, err)
		},
	}

	// Configure TLS if needed (from IDP config)
	if idpCfg.Keycloak != nil && idpCfg.Keycloak.CertificateAuthority != "" {
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM([]byte(idpCfg.Keycloak.CertificateAuthority)); !ok {
			return nil, fmt.Errorf("could not parse CA certificate for IDP %s", idpCfg.Name)
		}
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
		options.Client = &http.Client{Transport: transport}
	} else if idpCfg.Keycloak != nil && idpCfg.Keycloak.InsecureSkipVerify {
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		options.Client = &http.Client{Transport: transport}
		a.log.Warnf("TLS verification disabled for IDP %s (dev/e2e only)", idpCfg.Name)
	}

	// Fetch JWKS
	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to load JWKS for IDP %s (%s): %w", idpCfg.Name, issuer, err)
	}

	// Cache it
	a.jwksMutex.Lock()
	a.jwksCache[issuer] = jwks
	a.jwksMutex.Unlock()

	a.log.Debugw("loaded JWKS for issuer", "issuer", issuer, "idp_name", idpCfg.Name)
	return jwks, nil
}

func (a *AuthHandler) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		authHeader := c.GetHeader(AuthHeaderKey)
		// delete the header to avoid logging it by accident
		c.Request.Header.Del(AuthHeaderKey)
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "No Bearer token provided in Authorization header",
			})
			c.Abort()
			return
		}
		bearer := authHeader[7:]

		// Parse JWT without verification first to extract issuer and basic claims
		unverifiedClaims := jwt.MapClaims{}
		parser := jwt.NewParser()
		_, _, err := parser.ParseUnverified(bearer, unverifiedClaims)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid JWT format",
			})
			c.Abort()
			return
		}

		// Extract issuer from claims for multi-IDP mode
		var issuer string
		if iss, ok := unverifiedClaims["iss"]; ok {
			issuer, _ = iss.(string)
		}

		// Get appropriate JWKS (based on issuer or default)
		var jwks *keyfunc.JWKS
		var selectedIDP string

		if issuer != "" && a.idpLoader != nil {
			// Multi-IDP mode: load JWKS for specific issuer
			loadedJwks, err := a.getJWKSForIssuer(c.Request.Context(), issuer)
			if err != nil {
				a.log.Debugw("failed to get JWKS for issuer", "issuer", issuer, "error", err)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": fmt.Sprintf("unable to verify token: %v", err),
				})
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
		} else {
			// Single-IDP mode or issuer not found: use default JWKS
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
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

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
