// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionIdentityMatchesProvider(t *testing.T) {
	identity := debugSessionReadIdentity{username: "same@example.com", provider: "idp-a", issuer: "https://a.example"}
	require.True(t, debugSessionIdentityMatchesProvider(identity, "idp-a", "https://a.example", "same@example.com"))
	require.False(t, debugSessionIdentityMatchesProvider(identity, "idp-b", "https://b.example", "same@example.com"))
	require.False(t, debugSessionIdentityMatchesProvider(identity, "", "", "same@example.com"))
	identity.legacyAllowed = true
	require.True(t, debugSessionIdentityMatchesProvider(identity, "", "", "same@example.com"))
}

func TestDebugSessionApprovalIdentityMatches(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{
		IdentityProviderName: "idp-a", IdentityProviderIssuer: "https://a.example/",
	}}
	require.True(t, debugSessionApprovalIdentityMatches(session, debugSessionReadIdentity{
		provider: "idp-a", issuer: "https://a.example",
	}))
	require.False(t, debugSessionApprovalIdentityMatches(session, debugSessionReadIdentity{
		provider: "idp-b", issuer: "https://a.example",
	}))
	require.False(t, debugSessionApprovalIdentityMatches(session, debugSessionReadIdentity{
		provider: "idp-a", issuer: "https://b.example",
	}))

	legacy := &breakglassv1alpha1.DebugSession{}
	require.True(t, debugSessionApprovalIdentityMatches(legacy, debugSessionReadIdentity{
		legacyAllowed: true,
	}))
	require.True(t, debugSessionApprovalIdentityMatches(&breakglassv1alpha1.DebugSession{}, debugSessionReadIdentity{
		provider: "idp-a", issuer: "https://a.example", legacyAllowed: true,
	}))
	issuerOnlyLegacy := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{
		IdentityProviderIssuer: "https://single.example/",
	}}
	require.True(t, debugSessionApprovalIdentityMatches(issuerOnlyLegacy, debugSessionReadIdentity{
		issuer: "https://single.example", legacyAllowed: true,
	}))
}

func TestDebugSessionApprovalMigrationRequired(t *testing.T) {
	complete := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{
		IdentityProviderName: "idp-a", IdentityProviderIssuer: "https://a.example",
	}}
	require.False(t, debugSessionApprovalMigrationRequired(complete, debugSessionReadIdentity{
		provider: "idp-b", issuer: "https://b.example",
	}))
	require.True(t, debugSessionApprovalMigrationRequired(&breakglassv1alpha1.DebugSession{}, debugSessionReadIdentity{}))
	require.False(t, debugSessionApprovalMigrationRequired(
		&breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{
			IdentityProviderIssuer: "https://single.example",
		}},
		debugSessionReadIdentity{issuer: "https://single.example", legacyAllowed: true},
	))
}

func TestDebugSessionHandlersRejectCollidingProvider(t *testing.T) {
	for _, action := range []string{"get", "terminate", "renew", "join", "inject"} {
		t.Run(action, func(t *testing.T) {
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{RequestedBy: "same@example.com", IdentityProviderName: "idp-a", IdentityProviderIssuer: "https://a.example", InvitedParticipants: []string{"same@example.com"}},
				Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry, ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"security@example.com"}}, TerminalSharing: &breakglassv1alpha1.TerminalSharingConfig{Enabled: true}}},
			}

			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(session).Build()
			ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			body := ""
			if action == "renew" {
				body = `{"extendBy":"10m"}`
			}
			if action == "inject" {
				body = `{"namespace":"default","podName":"pod","containerName":"debugger","image":"busybox"}`
			}
			ctx.Request = httptest.NewRequest(http.MethodPost, "/?namespace=default", strings.NewReader(body))
			ctx.Params = gin.Params{{Key: "name", Value: "session"}}
			ctx.Set("username", "same@example.com")
			ctx.Set("email", "same@example.com")
			ctx.Set("identity_provider_name", "idp-b")
			ctx.Set("issuer", "https://b.example")
			ctx.Set("legacy_identity_allowed", false)
			switch action {
			case "get":
				ctrl.handleGetDebugSession(ctx)
			case "terminate":
				ctrl.handleTerminateDebugSession(ctx)
			case "renew":
				ctrl.handleRenewDebugSession(ctx)
			case "join":
				ctrl.handleJoinDebugSession(ctx)
			case "inject":
				ctrl.handleInjectEphemeralContainer(ctx)
			}
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}
}

func TestTerminatePendingRetirementHandlerIdentityFence(t *testing.T) {
	tests := []struct {
		name       string
		state      breakglassv1alpha1.DebugSessionState
		provider   string
		issuer     string
		identity   debugSessionReadIdentity
		wantStatus int
	}{
		{"pending partial provider matches", breakglassv1alpha1.DebugSessionStatePending, "idp-a", "", debugSessionReadIdentity{username: "owner", provider: "idp-a"}, http.StatusOK},
		{"pending approval partial provider matches", breakglassv1alpha1.DebugSessionStatePendingApproval, "idp-a", "", debugSessionReadIdentity{username: "owner", provider: "idp-a"}, http.StatusOK},
		{"partial provider mismatches", breakglassv1alpha1.DebugSessionStatePending, "idp-a", "", debugSessionReadIdentity{username: "owner", provider: "idp-b"}, http.StatusForbidden},
		{"issuer matches", breakglassv1alpha1.DebugSessionStatePending, "", "https://issuer", debugSessionReadIdentity{username: "owner", issuer: "https://issuer"}, http.StatusOK},
		{"issuer mismatches", breakglassv1alpha1.DebugSessionStatePending, "", "https://issuer", debugSessionReadIdentity{username: "owner", issuer: "https://other"}, http.StatusForbidden},
		{"providerless migrated requester", breakglassv1alpha1.DebugSessionStatePending, "", "", debugSessionReadIdentity{username: "owner"}, http.StatusOK},
		{"providerless wrong requester", breakglassv1alpha1.DebugSessionStatePendingApproval, "", "", debugSessionReadIdentity{username: "other"}, http.StatusForbidden},
		{"single jwks issuer-only requester", breakglassv1alpha1.DebugSessionStatePendingApproval, "", "https://single", debugSessionReadIdentity{username: "owner", issuer: "https://single", legacyAllowed: true}, http.StatusOK},
		{"active provider mismatch remains denied", breakglassv1alpha1.DebugSessionStateActive, "idp-a", "https://issuer", debugSessionReadIdentity{username: "owner", provider: "idp-b", issuer: "https://issuer"}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					RequestedBy: "owner", IdentityProviderName: tt.provider, IdentityProviderIssuer: tt.issuer,
				},
				Status: breakglassv1alpha1.DebugSessionStatus{State: tt.state},
			}
			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(session).Build()
			ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/", nil)
			ctx.Params = gin.Params{{Key: "name", Value: "session"}}
			ctx.Set("username", tt.identity.username)
			ctx.Set("identity_provider_name", tt.identity.provider)
			ctx.Set("issuer", tt.identity.issuer)
			ctx.Set("legacy_identity_allowed", tt.identity.legacyAllowed)
			ctrl.handleTerminateDebugSession(ctx)
			require.Equal(t, tt.wantStatus, rec.Code, rec.Body.String())
			var persisted breakglassv1alpha1.DebugSession
			require.NoError(t, cli.Get(context.Background(), client.ObjectKey{Name: "session", Namespace: "default"}, &persisted))
			if tt.wantStatus == http.StatusOK {
				require.Equal(t, breakglassv1alpha1.DebugSessionStateTerminated, persisted.Status.State)
			} else {
				require.Equal(t, tt.state, persisted.Status.State)
			}
		})
	}
}

func TestLegacyDebugOwnerReadRequiresResolvedSingleProvider(t *testing.T) {
	ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), fake.NewClientBuilder().WithScheme(Scheme).Build(), nil, nil)
	session := &breakglassv1alpha1.DebugSession{Spec: breakglassv1alpha1.DebugSessionSpec{RequestedBy: "owner"}, Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"other"}}}}}
	id := debugSessionReadIdentity{username: "owner", provider: "single", issuer: "https://single.example", legacyAllowed: true}
	allowed, err := ctrl.canReadDebugSession(context.Background(), session, id)
	require.NoError(t, err)
	require.True(t, allowed)
	id.legacyAllowed = false
	allowed, err = ctrl.canReadDebugSession(context.Background(), session, id)
	require.NoError(t, err)
	require.False(t, allowed)
}

func TestDebugSessionApprovalHandlersEnforceProviderFence(t *testing.T) {
	tests := []struct {
		name               string
		handler            func(*DebugSessionAPIController, *gin.Context)
		sessionProvider    string
		sessionIssuer      string
		identityProvider   string
		identityIssuer     string
		legacyAllowed      bool
		expectedStatusCode int
	}{
		{
			name:               "approve denies provider mismatch",
			handler:            (*DebugSessionAPIController).handleApproveDebugSession,
			sessionProvider:    "idp-a",
			sessionIssuer:      "https://issuer.example",
			identityProvider:   "idp-b",
			identityIssuer:     "https://issuer.example",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "reject denies provider mismatch",
			handler:            (*DebugSessionAPIController).handleRejectDebugSession,
			sessionProvider:    "idp-a",
			sessionIssuer:      "https://issuer.example",
			identityProvider:   "idp-b",
			identityIssuer:     "https://issuer.example",
			expectedStatusCode: http.StatusForbidden,
		},
		{
			name:               "approve conflicts legacy providerless without legacy allowance",
			handler:            (*DebugSessionAPIController).handleApproveDebugSession,
			sessionProvider:    "",
			sessionIssuer:      "https://issuer.example",
			identityProvider:   "idp-a",
			identityIssuer:     "https://issuer.example",
			legacyAllowed:      false,
			expectedStatusCode: http.StatusConflict,
		},
		{
			name:               "reject conflicts legacy providerless without legacy allowance",
			handler:            (*DebugSessionAPIController).handleRejectDebugSession,
			sessionProvider:    "",
			sessionIssuer:      "https://issuer.example",
			identityProvider:   "idp-a",
			identityIssuer:     "https://issuer.example",
			legacyAllowed:      false,
			expectedStatusCode: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "default"},
				Spec: breakglassv1alpha1.DebugSessionSpec{
					RequestedBy:            "requester@example.com",
					RequestedByEmail:       "requester@example.com",
					IdentityProviderName:   tt.sessionProvider,
					IdentityProviderIssuer: tt.sessionIssuer,
				},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStatePendingApproval,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver@example.com"}},
					},
				},
			}

			cli := fake.NewClientBuilder().WithScheme(Scheme).WithStatusSubresource(session).WithObjects(session).Build()
			ctrl := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/?namespace=default", strings.NewReader(`{"reason":"approved"}`))
			ctx.Params = gin.Params{{Key: "name", Value: "session"}}
			ctx.Set("username", "approver@example.com")
			ctx.Set("identity_provider_name", tt.identityProvider)
			ctx.Set("issuer", tt.identityIssuer)
			ctx.Set("legacy_identity_allowed", tt.legacyAllowed)

			tt.handler(ctrl, ctx)
			require.Equal(t, tt.expectedStatusCode, rec.Code, rec.Body.String())
		})
	}
}
