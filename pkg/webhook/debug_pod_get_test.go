// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionPodGetAuthorization(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*breakglassv1alpha1.DebugSession, *authorizationv1.SubjectAccessReview)
		allow  bool
	}{
		{name: "get own pod", allow: true},
		{name: "participant gets own pod", allow: true, mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.Participants[0].Role = breakglassv1alpha1.ParticipantRoleParticipant
		}},
		{name: "exec own pod remains allowed", allow: true, mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Verb = "create"
			sar.Spec.ResourceAttributes.Subresource = "exec"
		}},
		{name: "get own pod with operations disabled", allow: true, mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.AllowedPodOperations = &breakglassv1alpha1.AllowedPodOperations{Exec: boolPtr(false), Attach: boolPtr(false), PortForward: boolPtr(false)}
		}},
		{name: "non-session pod", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Name = "other-pod"
		}},
		{name: "list namespace", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Verb = "list"
			sar.Spec.ResourceAttributes.Name = ""
		}},
		{name: "list with name", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Verb = "list"
		}},
		{name: "watch", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Verb = "watch"
		}},
		{name: "get without name", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Name = ""
		}},
		{name: "delete own pod", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Verb = "delete"
		}},
		{name: "non-participant", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.User = "outsider"
		}},
		{name: "viewer", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.Participants[0].Role = breakglassv1alpha1.ParticipantRoleViewer
		}},
		{name: "participant left", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			left := metav1.Now()
			ds.Status.Participants[0].LeftAt = &left
		}},
		{name: "expired", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			expired := metav1.NewTime(time.Now().Add(-time.Minute))
			ds.Status.ExpiresAt = &expired
		}},
		{name: "missing expiry", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.ExpiresAt = nil
		}},
		{name: "terminated", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		}},
		{name: "pending approval", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
		}},
		{name: "other namespace", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Namespace = "other"
		}},
		{name: "other cluster", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Spec.Cluster = "other"
		}},
		{name: "replacement pod UID", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.AllowedPods[0].UID = "old-pod-uid"
		}},
		{name: "other issuer", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.Participants[0].IdentityProviderIssuer = "https://other.example"
		}},
		{name: "other provider", mutate: func(ds *breakglassv1alpha1.DebugSession, _ *authorizationv1.SubjectAccessReview) {
			ds.Status.Participants[0].IdentityProviderName = "other"
		}},
		{name: "other API group", mutate: func(_ *breakglassv1alpha1.DebugSession, sar *authorizationv1.SubjectAccessReview) {
			sar.Spec.ResourceAttributes.Group = "other.example"
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			ds := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "controller", UID: "session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry,
					AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Namespace: "debug", Name: "own-pod", UID: "pod-uid"}},
					Participants: []breakglassv1alpha1.DebugSessionParticipant{{
						User: "requester", Role: breakglassv1alpha1.ParticipantRoleOwner,
						IdentityProviderName: "provider", IdentityProviderIssuer: "https://issuer.example",
					}},
				},
			}
			sar := authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "requester", Groups: []string{"app-owners"},
					Extra:              map[string]authorizationv1.ExtraValue{"identity.t-caas.telekom.com/issuer": {"https://issuer.example"}},
					ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "get", Resource: "pods", Namespace: "debug", Name: "own-pod"},
				},
			}
			if tc.mutate != nil {
				tc.mutate(ds, &sar)
			}
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(ds,
				&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "provider"}, Spec: breakglassv1alpha1.IdentityProviderSpec{Issuer: "https://issuer.example"}},
			).WithStatusSubresource(&breakglassv1alpha1.DebugSession{})
			for key, fn := range debugSessionIndexFnsWebhook {
				builder = builder.WithIndex(&breakglassv1alpha1.DebugSession{}, key, fn)
			}
			for key, fn := range sessionIndexFnsWebhook {
				builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, key, fn)
			}
			cli := builder.Build()
			log := zap.NewNop().Sugar()
			wc := NewWebhookController(log, config.Config{}, breakglass.NewSessionManagerWithClient(cli),
				&escalation.EscalationManager{Client: cli}, nil, policy.NewEvaluator(cli, log))
			wc.canDoFn = func(context.Context, *rest.Config, []string, authorizationv1.SubjectAccessReview, string) (bool, error) {
				return false, nil
			}
			wc.podFetchFn = func(context.Context, string, string, string) (*corev1.Pod, error) {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "pod-uid"}}, nil
			}
			state := &authorizeState{
				ctx: context.Background(), clusterName: "cluster", issuer: "https://issuer.example", idpName: "provider", idpLookupOK: true,
				reqLog: log, phases: NewSARPhaseTracker("cluster", log), sar: sar,
			}
			t.Run("helper", func(t *testing.T) {
				require.Equal(t, tc.allow, wc.checkEarlyDebugSession(nil, state))
				require.Equal(t, tc.allow, state.allowed)
				if tc.allow && sar.Spec.ResourceAttributes.Subresource == "" {
					require.Contains(t, state.reason, "operation: get")
				}
			})
			t.Run("webhook SAR without baseline RBAC", func(t *testing.T) {
				engine := gin.New()
				require.NoError(t, wc.Register(engine.Group("/"+wc.BasePath())))
				body, err := json.Marshal(sar)
				require.NoError(t, err)
				response := httptest.NewRecorder()
				engine.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/cluster", bytes.NewReader(body)))
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				var result SubjectAccessReviewResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
				require.Equal(t, tc.allow, result.Status.Allowed, result.Status.Reason)
				if tc.allow && sar.Spec.ResourceAttributes.Subresource == "" {
					require.Contains(t, result.Status.Reason, "operation: get")
				}
			})
		})
	}
}

func TestDebugSessionPodGetFinalFence(t *testing.T) {
	for _, transition := range []string{"terminated", "expired", "participant left", "list request"} {
		t.Run(transition, func(t *testing.T) {
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			ds := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "controller", UID: "session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiry,
					AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Namespace: "debug", Name: "own-pod", UID: "pod-uid"}},
					Participants: []breakglassv1alpha1.DebugSessionParticipant{{
						User: "requester", Role: breakglassv1alpha1.ParticipantRoleOwner,
						IdentityProviderName: "provider", IdentityProviderIssuer: "https://issuer.example",
					}},
				},
			}
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(ds).WithStatusSubresource(ds)
			for key, fn := range debugSessionIndexFnsWebhook {
				builder = builder.WithIndex(ds, key, fn)
			}
			cli := builder.Build()
			log := zap.NewNop().Sugar()
			wc := &WebhookController{
				log: log, escalManager: &escalation.EscalationManager{Client: cli},
				sesManager: breakglass.NewSessionManagerWithClient(cli),
				podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
					return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "pod-uid"}}, nil
				},
			}
			state := &authorizeState{
				ctx: context.Background(), clusterName: "cluster", issuer: "https://issuer.example", idpName: "provider", idpLookupOK: true,
				reqLog: log, phases: NewSARPhaseTracker("cluster", log),
				sar: authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "requester", ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "get", Resource: "pods", Namespace: "debug", Name: "own-pod"},
				}},
			}
			require.True(t, wc.checkEarlyDebugSession(nil, state))
			var live breakglassv1alpha1.DebugSession
			require.NoError(t, cli.Get(context.Background(), client.ObjectKeyFromObject(ds), &live))
			switch transition {
			case "terminated":
				live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
			case "expired":
				expired := metav1.NewTime(time.Now().Add(-time.Minute))
				live.Status.ExpiresAt = &expired
			case "participant left":
				left := metav1.Now()
				live.Status.Participants[0].LeftAt = &left
			case "list request":
				state.sar.Spec.ResourceAttributes.Verb = "list"
			}
			require.NoError(t, cli.Status().Update(context.Background(), &live))
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			wc.sendAuthorizationResponse(c, state)
			var result SubjectAccessReviewResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
			require.False(t, result.Status.Allowed, "an early candidate must never bypass the final live fence")
		})
	}
}
