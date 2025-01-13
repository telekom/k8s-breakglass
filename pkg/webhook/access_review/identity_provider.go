package accessreview

import (
	"errors"

	"github.com/gin-gonic/gin"
)

type IdentityProvider interface {
	GetIdentity(*gin.Context) (string, error)
}

type KeycloakIdentityProvider struct{}

func (kip KeycloakIdentityProvider) GetIdentity(c *gin.Context) (id string, err error) {
	id = c.GetString("user_id")
	if id == "" {
		err = errors.New("provider failed to retrieve user_id from keycloak")
	}
	return id, err
}
