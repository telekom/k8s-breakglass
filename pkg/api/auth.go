package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
)

const (
	AuthHeaderKey = "Authorization"
)

type AuthHandler struct {
	jwks *keyfunc.JWKS
}

func NewAuth(log *zap.SugaredLogger, cfg config.Config) *AuthHandler {
	options := keyfunc.Options{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second * 10,
		RefreshErrorHandler: func(err error) {
			log.Errorf("failed to refresh JWKS configuration: %v", err)
		},
	}

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", cfg.Keycloak.Url, cfg.Keycloak.ManagedRealm)

	jwks, err := keyfunc.Get(url, options)
	if err != nil {
		log.Fatalf("Could not get JWKS: %v\n", err)
	}

	return &AuthHandler{
		jwks: jwks,
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
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		// NOTE: for future a token will contain a list of groups that user has
		user_id := claims["sub"]
		email := claims["email"]
		username := claims["preferred_username"]

		c.Set("token", token)
		c.Set("user_id", user_id)
		c.Set("email", email)
		c.Set("username", username)

		c.Next()
	}
}
