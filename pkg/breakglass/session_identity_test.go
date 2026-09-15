// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestSessionIdentityProviderMatches(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("identity_provider_name", "idp-a")
	c.Set("issuer", "https://a.example")
	require.True(t, sessionIdentityProviderMatches(c, "idp-a", "https://a.example/", false))
	require.False(t, sessionIdentityProviderMatches(c, "idp-b", "https://b.example", false))
	require.False(t, sessionIdentityProviderMatches(c, "idp-b", "https://b.example", true), "spoke compatibility must not relax ownership")
	require.False(t, sessionIdentityProviderMatches(c, "", "", false))
	c.Set("legacy_identity_allowed", true)
	require.True(t, sessionIdentityProviderMatches(c, "", "", false), "authenticated single-provider legacy owner")
}

func TestRecordApproverKeepsLegacyProviderAlignment(t *testing.T) {
	status := breakglassv1alpha1.BreakglassSessionStatus{Approvers: []string{"old-a", "alice@example.com"}}
	recordApprover(&status, "alice@example.com", "idp-a")
	recordApprover(&status, "alice@example.com", "idp-b")
	recordApprover(&status, "alice@example.com", "idp-b")
	recordApprover(&status, "bob@example.com", "idp-b")
	require.Equal(t, []string{"old-a", "alice@example.com", "alice@example.com", "alice@example.com", "bob@example.com"}, status.Approvers)
	require.Equal(t, []string{"", "", "idp-a", "idp-b", "idp-b"}, status.ApproverIdentityProviders)
	session := breakglassv1alpha1.BreakglassSession{Status: status}
	require.False(t, userHasApprovedSessionForProvider(session, "old-a", "idp-a", false))
	require.True(t, userHasApprovedSessionForProvider(session, "old-a", "idp-a", true))
	require.True(t, userHasApprovedSessionForProvider(session, "alice@example.com", "idp-a", false))
	require.True(t, userHasApprovedSessionForProvider(session, "alice@example.com", "idp-b", false))
	require.False(t, userHasApprovedSessionForProvider(session, "alice@example.com", "idp-c", false))
}

func TestClusterIdentityProviderPolicyRejectsBeforeGroupLookup(t *testing.T) {
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke"}, Spec: breakglassv1alpha1.ClusterConfigSpec{IdentityProviderRefs: []string{"idp-a"}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
	wc := &BreakglassSessionController{clusterConfigManager: NewClusterConfigManager(cli), log: zap.NewNop().Sugar()}
	for _, provider := range []string{"idp-a", "idp-b", ""} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Set("identity_provider_name", provider)
		allowed := wc.validateClusterIdentityProvider(c, context.Background(), "spoke")
		require.Equal(t, provider == "idp-a", allowed)
		if !allowed {
			require.Equal(t, http.StatusForbidden, rec.Code)
		}
	}
	wc.clusterConfigManager = NewClusterConfigManager(nil)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	require.True(t, wc.validateClusterIdentityProvider(c, context.Background(), "spoke"))
}

func TestSessionRequestUsesCanonicalSubjectForGroupFallback(t *testing.T) {
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke"}, Spec: breakglassv1alpha1.ClusterConfigSpec{IdentityProviderRefs: []string{"idp-a"}, UserIdentifierClaim: breakglassv1alpha1.UserIdentifierClaimSub}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(cc).Build()
	for _, provider := range []string{"idp-a", "idp-b"} {
		t.Run(provider, func(t *testing.T) {
			called := false
			wc := &BreakglassSessionController{log: zap.NewNop().Sugar(), identityProvider: KeycloakIdentityProvider{}, clusterConfigManager: NewClusterConfigManager(cli), getUserGroupsFn: func(_ context.Context, cug ClusterUserGroup) ([]string, error) {
				called = true
				require.Equal(t, "subject-123", cug.Username)
				return nil, errors.New("stop after verifying canonical lookup")
			}}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"cluster":"spoke","group":"admin"}`))
			c.Request.Header.Set("Content-Type", "application/json")
			c.Set("username", "login-name")
			c.Set("email", "email@example.com")
			c.Set("user_id", "subject-123")
			c.Set("identity_provider_name", provider)
			c.Set("issuer", "https://a.example")
			wc.handleRequestBreakglassSession(c)
			require.Equal(t, provider == "idp-a", called, rec.Body.String())
			if provider == "idp-a" {
				require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
			} else {
				require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestApprovalUsesOnlyAuthenticatedProvidersMembership(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{ObjectMeta: metav1.ObjectMeta{Name: "esc"}, Spec: breakglassv1alpha1.BreakglassEscalationSpec{Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{Clusters: []string{"spoke"}}, EscalatedGroup: "admin", Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{Groups: []string{"approvers"}}}, Status: breakglassv1alpha1.BreakglassEscalationStatus{ApproverGroupMembers: map[string][]string{"approvers": {"same@example.com"}}, IDPGroupMemberships: map[string]map[string][]string{"idp-b": {"approvers": {"same@example.com"}}}}}
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithObjects(esc).Build()
	wc := &BreakglassSessionController{log: zap.NewNop().Sugar(), identityProvider: KeycloakIdentityProvider{}, escalationManager: &testEscalationLookup{Client: cli}, getUserGroupsFn: func(context.Context, ClusterUserGroup) ([]string, error) { return nil, nil }}
	session := breakglassv1alpha1.BreakglassSession{Spec: breakglassv1alpha1.BreakglassSessionSpec{Cluster: "spoke", GrantedGroup: "admin", User: "requester"}}
	for _, provider := range []string{"idp-a", "idp-b", ""} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
		c.Set("email", "same@example.com")
		c.Set("identity_provider_name", provider)
		result := wc.checkApprovalAuthorization(c, session)
		require.Equal(t, provider == "idp-b", result.Allowed, "provider %q: %s", provider, result.Message)
	}
}

func TestClusterIdentityLookupFailureIsLogged(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	lookupErr := errors.New("cluster lookup unavailable")
	cli := fake.NewClientBuilder().WithScheme(Scheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return lookupErr
		},
	}).Build()
	wc := &BreakglassSessionController{clusterConfigManager: NewClusterConfigManager(cli), log: zap.New(core).Sugar()}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	require.False(t, wc.validateClusterIdentityProvider(c, context.Background(), "spoke"))
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	entries := observed.All()
	require.Len(t, entries, 1)
	require.Equal(t, "Failed to resolve cluster identity provider policy", entries[0].Message)
	require.Contains(t, entries[0].ContextMap()["error"], lookupErr.Error())
}
