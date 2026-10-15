package breakglass

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	upstreamoidc "github.com/telekom/k8s-breakglass/pkg/oidc"
	"go.uber.org/zap"
)

// UserIdentifierPrefix resolves target-cluster policy without changing authenticated claims.
func UserIdentifierPrefix(c *gin.Context, cluster *breakglassv1alpha1.ClusterConfig) string {
	if cluster != nil && cluster.Spec.UserIdentifierPrefix != nil {
		return *cluster.Spec.UserIdentifierPrefix
	}
	return c.GetString("user_identifier_prefix")
}

// ResolveKubernetesUser maps the verified token through the upstream target policy.
func ResolveKubernetesUser(c *gin.Context, cluster *breakglassv1alpha1.ClusterConfig, fallback breakglassv1alpha1.UserIdentifierClaimType, identity IdentityProvider) (string, error) {
	if raw, exists := c.Get(upstreamoidc.TargetIdentityResolverKey); exists {
		resolver, ok := raw.(upstreamoidc.TargetIdentityResolver)
		if !ok || resolver == nil {
			return "", errors.New("invalid target identity resolver")
		}
		result, err := resolver(c.Request.Context(), cluster, fallback)
		if err != nil {
			return "", fmt.Errorf("resolve Kubernetes identity: %w", err)
		}
		if result.User == nil || result.User.GetName() == "" {
			return "", errors.New("empty Kubernetes username")
		}
		return result.User.GetName(), nil
	}
	// Compatibility for legacy authentication and injected identity providers.
	if cluster != nil && cluster.Spec.KubernetesIdentity != nil {
		return "", errors.New("structured identity mapping requires OIDC authentication")
	}
	claim := fallback
	if providerClaim := c.GetString("user_identifier_claim"); providerClaim != "" {
		claim = breakglassv1alpha1.UserIdentifierClaimType(providerClaim)
	}
	if cluster != nil && cluster.Spec.UserIdentifierClaim != "" {
		claim = cluster.Spec.UserIdentifierClaim
	}
	name, err := identity.GetUserIdentifier(c, claim)
	if err != nil {
		return "", err
	}
	return UserIdentifierPrefix(c, cluster) + name, nil
}

type IdentityProvider interface {
	GetEmail(*gin.Context) (string, error)
	GetUsername(*gin.Context) string
	GetIdentity(*gin.Context) string
	// GetUserIdentifier returns the user identifier based on the configured claim type.
	// This is used to match the OIDC claim configuration on spoke clusters.
	GetUserIdentifier(*gin.Context, breakglassv1alpha1.UserIdentifierClaimType) (string, error)
}

type KeycloakIdentityProvider struct {
	log *zap.SugaredLogger
}

// NewKeycloakIdentityProvider creates a KeycloakIdentityProvider with the given logger.
// Exported for use by sub-packages that cannot access the unexported log field.
func NewKeycloakIdentityProvider(log *zap.SugaredLogger) KeycloakIdentityProvider {
	return KeycloakIdentityProvider{log: log}
}

// getLogger returns the injected logger or falls back to the global logger.
func (kip KeycloakIdentityProvider) getLogger() *zap.SugaredLogger {
	if kip.log != nil {
		return kip.log
	}
	return zap.S()
}

func (kip KeycloakIdentityProvider) GetEmail(c *gin.Context) (email string, err error) {
	email = c.GetString("email")
	if email == "" {
		kip.getLogger().Warn("Keycloak provider failed to retrieve email identity from context")
		err = errors.New("keycloak provider failed to retrieve email identity")
	} else {
		kip.getLogger().Debugw("Keycloak provider retrieved email", "email", email)
	}
	return
}

func (kip KeycloakIdentityProvider) GetIdentity(c *gin.Context) string {
	id := c.GetString("user_id")
	kip.getLogger().Debugw("Keycloak provider retrieved user_id", "user_id", id)
	return id
}

func (kip KeycloakIdentityProvider) GetUsername(c *gin.Context) string {
	username := c.GetString("username")
	if username == "" {
		username = c.GetString("authenticated_username")
	}
	kip.getLogger().Debugw("Keycloak provider retrieved username", "username", username)
	return username
}

// GetUserIdentifier returns the user identifier based on the configured claim type.
// It maps the UserIdentifierClaimType to the corresponding JWT claim value stored in context.
func (kip KeycloakIdentityProvider) GetUserIdentifier(c *gin.Context, claimType breakglassv1alpha1.UserIdentifierClaimType) (string, error) {
	var identifier string
	switch claimType {
	case "", breakglassv1alpha1.UserIdentifierClaimEmail:
		identifier = c.GetString("email")
		if identifier == "" {
			return "", errors.New("email claim not found in token")
		}
	case breakglassv1alpha1.UserIdentifierClaimPreferredUsername:
		identifier = c.GetString("username")
		if identifier == "" {
			return "", errors.New("preferred_username claim not found in token")
		}
	case breakglassv1alpha1.UserIdentifierClaimSub:
		identifier = c.GetString("user_id")
		if identifier == "" {
			return "", errors.New("sub claim not found in token")
		}
	default:
		return "", errors.New("custom user claims require OIDC target identity resolution")
	}
	kip.getLogger().Debugw("Keycloak provider retrieved user identifier", "claimType", claimType, "identifier", identifier)
	return identifier, nil
}
