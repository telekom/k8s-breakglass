// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
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

func TestDebugSessionCapturesTargetKubernetesIdentity(t *testing.T) {
	for _, tc := range []struct {
		name            string
		global, cluster breakglassv1alpha1.UserIdentifierClaimType
		want, missing   string
	}{
		{name: "default email", want: "alice@example.test"},
		{name: "global subject", global: breakglassv1alpha1.UserIdentifierClaimSub, want: "alice-sub"},
		{name: "cluster username overrides email", cluster: breakglassv1alpha1.UserIdentifierClaimPreferredUsername, want: "alice"},
		{name: "cluster subject overrides username", global: breakglassv1alpha1.UserIdentifierClaimPreferredUsername, cluster: breakglassv1alpha1.UserIdentifierClaimSub, want: "alice-sub"},
		{name: "missing email", missing: "email"},
		{name: "missing subject", cluster: breakglassv1alpha1.UserIdentifierClaimSub, missing: "user_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"production"}}}}
			cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "default"}, Spec: breakglassv1alpha1.ClusterConfigSpec{UserIdentifierClaim: tc.cluster}}
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, cc).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil).WithUserIdentifierClaim(tc.global)
			user := "alice"
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("legacy_identity_allowed", true)
				ctx.Set("username", user)
				if tc.missing != "email" {
					ctx.Set("email", user+"@example.test")
				}
				if tc.missing != "user_id" {
					ctx.Set("user_id", user+"-sub")
				}
				ctx.Next()
			})
			require.NoError(t, controller.Register(router.Group("/debugSessions")))
			request := httptest.NewRequest(http.MethodPost, "/debugSessions", strings.NewReader(`{"templateRef":"template","cluster":"production"}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if tc.missing != "" {
				require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
				var sessions breakglassv1alpha1.DebugSessionList
				require.NoError(t, hub.List(context.Background(), &sessions))
				require.Empty(t, sessions.Items)
				return
			}
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var detail DebugSessionDetailResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &detail))
			session := detail.DebugSession
			require.Equal(t, "alice", session.Spec.RequestedBy, "API ownership identity must remain unchanged")
			require.Equal(t, tc.want, session.Spec.RequestedByKubernetesUser)
			// The existing API owner can still read the canonicalized session.
			read := httptest.NewRecorder()
			router.ServeHTTP(read, httptest.NewRequest(http.MethodGet, "/debugSessions/"+session.Name, nil))
			require.Equal(t, http.StatusOK, read.Code, read.Body.String())
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&session), &session))
			session.Spec.InvitedParticipants = []string{"bob@example.test"}
			require.NoError(t, hub.Update(context.Background(), &session))
			future := metav1.NewTime(time.Now().Add(time.Hour))
			session.Status.State = breakglassv1alpha1.DebugSessionStateActive
			session.Status.ExpiresAt = &future
			session.Status.TerminalSharing = &breakglassv1alpha1.TerminalSharingStatus{Enabled: true}
			require.NoError(t, hub.Status().Update(context.Background(), &session))
			user = "bob"
			join := httptest.NewRecorder()
			router.ServeHTTP(join, httptest.NewRequest(http.MethodPost, "/debugSessions/"+session.Name+"/join", nil))
			require.Equal(t, http.StatusOK, join.Code, join.Body.String())
			require.NoError(t, hub.Get(context.Background(), client.ObjectKeyFromObject(&session), &session))
			require.Len(t, session.Status.Participants, 1)
			require.Equal(t, "bob", session.Status.Participants[0].User)
			require.Equal(t, strings.Replace(tc.want, "alice", "bob", 1), session.Status.Participants[0].KubernetesUser)
		})
	}
}

func TestActivationCopiesCanonicalKubernetesOwner(t *testing.T) {
	controller, session, template, _ := newDeploymentFenceFixture(t)
	controller.connectionLeases = nil
	session.Spec.RequestedByKubernetesUser = "canonical-subject"
	require.NoError(t, controller.client.Update(context.Background(), session))
	_, err := controller.activateSession(context.Background(), session, template, nil)
	require.NoError(t, err)
	require.Len(t, session.Status.Participants, 1)
	require.Equal(t, "tester", session.Status.Participants[0].User)
	require.Equal(t, "canonical-subject", session.Status.Participants[0].KubernetesUser)
}
