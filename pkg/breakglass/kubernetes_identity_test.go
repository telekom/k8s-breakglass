// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	upstreamoidc "github.com/telekom/k8s-breakglass/pkg/oidc"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestResolveKubernetesUserPreservesAuthenticatedRequesterAndGroups(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Set("email", "christos.ntogkas@telekom.com")
	c.Set("username", "k834798")
	c.Set("user_id", "stable-subject")
	c.Set("groups", []string{"legacy-admin"})
	cluster := &breakglassv1alpha1.ClusterConfig{}
	c.Set(upstreamoidc.TargetIdentityResolverKey, upstreamoidc.TargetIdentityResolver(func(_ context.Context, got *breakglassv1alpha1.ClusterConfig, fallback breakglassv1alpha1.UserIdentifierClaimType) (upstreamoidc.TargetIdentity, error) {
		require.Same(t, cluster, got)
		require.Equal(t, breakglassv1alpha1.UserIdentifierClaimEmail, fallback)
		return upstreamoidc.TargetIdentity{User: &user.DefaultInfo{Name: "tdi_security_oidc:k834798", Groups: []string{}}}, nil
	}))
	name, err := ResolveKubernetesUser(c, cluster, breakglassv1alpha1.UserIdentifierClaimEmail, KeycloakIdentityProvider{})
	require.NoError(t, err)
	require.Equal(t, "tdi_security_oidc:k834798", name)
	require.Equal(t, "k834798", c.GetString("username"))
	require.Equal(t, "stable-subject", c.GetString("user_id"))
	require.Equal(t, "christos.ntogkas@telekom.com", c.GetString("email"))
	groups, present := c.Get("groups")
	require.True(t, present)
	require.Equal(t, []string{"legacy-admin"}, groups, "target mappings must not replace authenticated provider authorization groups")
}

func TestResolveKubernetesUserFailsClosed(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Set("email", "alice@example.com")
	c.Set(upstreamoidc.TargetIdentityResolverKey, upstreamoidc.TargetIdentityResolver(func(context.Context, *breakglassv1alpha1.ClusterConfig, breakglassv1alpha1.UserIdentifierClaimType) (upstreamoidc.TargetIdentity, error) {
		return upstreamoidc.TargetIdentity{}, errors.New("claim validation denied")
	}))
	name, err := ResolveKubernetesUser(c, nil, "", KeycloakIdentityProvider{})
	require.ErrorContains(t, err, "claim validation denied")
	require.Empty(t, name)
	c.Set(upstreamoidc.TargetIdentityResolverKey, "invalid resolver")
	name, err = ResolveKubernetesUser(c, nil, "", KeycloakIdentityProvider{})
	require.Error(t, err)
	require.Empty(t, name)
}

func TestResolveKubernetesUserRejectsInvalidResolverResults(t *testing.T) {
	newContext := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		return c
	}

	t.Run("nil typed resolver", func(t *testing.T) {
		c := newContext()
		c.Set(upstreamoidc.TargetIdentityResolverKey, upstreamoidc.TargetIdentityResolver(nil))

		name, err := ResolveKubernetesUser(c, nil, "", KeycloakIdentityProvider{})
		require.ErrorContains(t, err, "invalid target identity resolver")
		require.Empty(t, name)
	})

	t.Run("resolver returns nil user", func(t *testing.T) {
		c := newContext()
		c.Set(upstreamoidc.TargetIdentityResolverKey, upstreamoidc.TargetIdentityResolver(func(context.Context, *breakglassv1alpha1.ClusterConfig, breakglassv1alpha1.UserIdentifierClaimType) (upstreamoidc.TargetIdentity, error) {
			return upstreamoidc.TargetIdentity{}, nil
		}))

		name, err := ResolveKubernetesUser(c, nil, "", KeycloakIdentityProvider{})
		require.ErrorContains(t, err, "empty Kubernetes username")
		require.Empty(t, name)
	})

	t.Run("resolver returns empty username", func(t *testing.T) {
		c := newContext()
		c.Set(upstreamoidc.TargetIdentityResolverKey, upstreamoidc.TargetIdentityResolver(func(context.Context, *breakglassv1alpha1.ClusterConfig, breakglassv1alpha1.UserIdentifierClaimType) (upstreamoidc.TargetIdentity, error) {
			return upstreamoidc.TargetIdentity{User: &user.DefaultInfo{}}, nil
		}))

		name, err := ResolveKubernetesUser(c, nil, "", KeycloakIdentityProvider{})
		require.ErrorContains(t, err, "empty Kubernetes username")
		require.Empty(t, name)
	})

	t.Run("structured cluster without resolver", func(t *testing.T) {
		c := newContext()
		cluster := &breakglassv1alpha1.ClusterConfig{Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubernetesIdentity: &breakglassv1alpha1.KubernetesIdentityConfig{},
		}}

		name, err := ResolveKubernetesUser(c, cluster, "", KeycloakIdentityProvider{})
		require.ErrorContains(t, err, "structured identity mapping requires OIDC authentication")
		require.Empty(t, name)
	})

	t.Run("fallback claim failure", func(t *testing.T) {
		c := newContext()

		name, err := ResolveKubernetesUser(c, nil, breakglassv1alpha1.UserIdentifierClaimEmail, KeycloakIdentityProvider{})
		require.ErrorContains(t, err, "email claim not found in token")
		require.Empty(t, name)
	})
}
