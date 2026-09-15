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
