package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/telekom/das-schiff-breakglass/pkg/config"
	"go.uber.org/zap"
)

const (
	AuthHeaderKey = "Authorization"
)

type AuthHandler struct {
	jwks *keyfunc.JWKS
	log  *zap.SugaredLogger
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

	// If a CA PEM is provided in configuration, use it to validate TLS for JWKS fetching.
	if cfg.AuthorizationServer.CertificateAuthority != "" {
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM([]byte(cfg.AuthorizationServer.CertificateAuthority))
		if !ok {
			log.Fatalf("Could not parse certificateAuthority PEM from configuration")
		}
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		}
		options.Client = &http.Client{Transport: transport}
	}

	jwks, err := keyfunc.Get(url, options)
	if err != nil {
		log.Fatalf("Could not get JWKS: %v\n", err)
	}

	return &AuthHandler{
		jwks: jwks,
		log:  log,
	}
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

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(bearer, &claims, a.jwks.Keyfunc)
		if err != nil {
			// Attempt single forced JWKS refresh if kid missing
			if strings.Contains(err.Error(), "key ID") {
				c.Set("jwks_refresh_attempt", true)
				if rErr := a.jwks.Refresh(context.Background(), keyfunc.RefreshOptions{}); rErr == nil {
					token, err = jwt.ParseWithClaims(bearer, &claims, a.jwks.Keyfunc)
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
