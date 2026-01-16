package breakglass

import (
	"errors"

	"github.com/gin-gonic/gin"
	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
)

type IdentityProvider interface {
	GetEmail(*gin.Context) (string, error)
	GetUsername(*gin.Context) string
	GetIdentity(*gin.Context) string
	// GetUserIdentifier returns the user identifier based on the configured claim type.
	// This is used to match the OIDC claim configuration on spoke clusters.
	GetUserIdentifier(*gin.Context, v1alpha1.UserIdentifierClaimType) (string, error)
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

// GetUserIdentifier returns the user identifier based on the configured claim type.
// It maps the UserIdentifierClaimType to the corresponding JWT claim value stored in context.
func (kip KeycloakIdentityProvider) GetUserIdentifier(c *gin.Context, claimType v1alpha1.UserIdentifierClaimType) (string, error) {
	var identifier string
	switch claimType {
	case v1alpha1.UserIdentifierClaimEmail:
		identifier = c.GetString("email")
		if identifier == "" {
			return "", errors.New("email claim not found in token")
		}
	case v1alpha1.UserIdentifierClaimPreferredUsername:
		identifier = c.GetString("username")
		if identifier == "" {
			return "", errors.New("preferred_username claim not found in token")
		}
	case v1alpha1.UserIdentifierClaimSub:
		identifier = c.GetString("user_id")
		if identifier == "" {
			return "", errors.New("sub claim not found in token")
		}
	default:
		// Default to email for backward compatibility
		identifier = c.GetString("email")
		if identifier == "" {
			return "", errors.New("email claim not found in token (default)")
		}
	}
	zap.S().Debugw("Keycloak provider retrieved user identifier", "claimType", claimType, "identifier", identifier)
	return identifier, nil
}
