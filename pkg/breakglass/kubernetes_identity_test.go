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
