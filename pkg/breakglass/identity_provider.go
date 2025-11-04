// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"errors"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type IdentityProvider interface {
	GetEmail(*gin.Context) (string, error)
	GetUsername(*gin.Context) string
	GetIdentity(*gin.Context) string
}

type KeycloakIdentityProvider struct{}

func (kip KeycloakIdentityProvider) GetEmail(c *gin.Context) (email string, err error) {
	email = c.GetString("email")
	if email == "" {
		zap.S().Warn("Keycloak provider failed to retrieve email identity from context")
		err = errors.New("keycloak provider failed to retrieve email identity")
	} else {
		zap.S().Debugw("Keycloak provider retrieved email", "email", email)
	}
	return
}

func (kip KeycloakIdentityProvider) GetIdentity(c *gin.Context) string {
	id := c.GetString("user_id")
	zap.S().Debugw("Keycloak provider retrieved user_id", "user_id", id)
	return id
}

func (kip KeycloakIdentityProvider) GetUsername(c *gin.Context) string {
	username := c.GetString("username")
	zap.S().Debugw("Keycloak provider retrieved username", "username", username)
	return username
}
