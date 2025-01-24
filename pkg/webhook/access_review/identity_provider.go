package accessreview

import (
	"errors"

	"github.com/gin-gonic/gin"
)

type IdentityProvider interface {
	GetEmail(*gin.Context) (string, error)
	GetIdentity(*gin.Context) string
}

type KeycloakIdentityProvider struct{}

func (kip KeycloakIdentityProvider) GetEmail(c *gin.Context) (email string, err error) {
	email = c.GetString("email")

	if email == "" {
		err = errors.New("keycloak provider failed to retrieve email identity")
	}
	return
}

func (kip KeycloakIdentityProvider) GetIdentity(c *gin.Context) string {
	return c.GetString("user_id")
}
