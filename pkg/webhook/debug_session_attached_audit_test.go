// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/audit/audittest"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
)

// The final authorization response emits debug_session.attached for an exec,
// attach or port-forward that a DebugSession authorized, and only then: not
// for a debug-session get or log, not for an allow from another source, and
// not when the final live fence denies the request.
func TestSendAuthorizationResponseEmitsDebugSessionAttached(t *testing.T) {
	var mu sync.Mutex
	var attached []*audit.Event
	audit.ObserveEmitted(func(event *audit.Event) {
		audittest.Record(event)
		if event.Type == audit.EventDebugSessionAttached {
			mu.Lock()
			attached = append(attached, event)
			mu.Unlock()
		}
	})
	t.Cleanup(func() { audit.ObserveEmitted(audittest.Record) })

	for _, tc := range []struct {
		name, verb, subresource, allowSource string
		terminated, want                     bool
	}{
		{name: "exec", verb: "create", subresource: "exec", allowSource: "debug-session", want: true},
		{name: "attach", verb: "create", subresource: "attach", allowSource: "debug-session", want: true},
		{name: "port-forward", verb: "create", subresource: "portforward", allowSource: "debug-session", want: true},
		{name: "get own pod", verb: "get", allowSource: "debug-session"},
		{name: "exec allowed by RBAC", verb: "create", subresource: "exec", allowSource: "rbac"},
		{name: "exec after the session ended", verb: "create", subresource: "exec", allowSource: "debug-session", terminated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			attached = nil
			mu.Unlock()
			expiry := metav1.NewTime(time.Now().Add(time.Hour))
			state := breakglassv1alpha1.DebugSessionStateActive
			if tc.terminated {
				state = breakglassv1alpha1.DebugSessionStateTerminated
			}
			ds := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "controller", UID: "session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "cluster"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State: state, ExpiresAt: &expiry,
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
			svc := audit.NewService(cli, nil, zap.NewNop(), "controller")
			require.NoError(t, svc.Reload(context.Background(), &breakglassv1alpha1.AuditConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "attached"},
				Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true, Sinks: []breakglassv1alpha1.AuditSinkConfig{{
					Name: "log", Type: breakglassv1alpha1.AuditSinkTypeLog,
				}}},
			}))
			t.Cleanup(func() { _ = svc.Close() })
			log := zap.NewNop().Sugar()
			wc := &WebhookController{
				log: log, escalManager: &escalation.EscalationManager{Client: cli},
				sesManager: breakglass.NewSessionManagerWithClient(cli), auditService: svc,
				podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
					return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "pod-uid"}}, nil
				},
			}
			s := &authorizeState{
				ctx: context.Background(), clusterName: "cluster", issuer: "https://issuer.example", idpName: "provider", idpLookupOK: true,
				reqLog: log, phases: NewSARPhaseTracker("cluster", log),
				sar: authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "requester", Groups: []string{"ops"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: tc.verb, Resource: "pods", Subresource: tc.subresource, Namespace: "debug", Name: "own-pod"},
				}},
				allowed: true, allowSource: tc.allowSource,
				debugSessionNamespace: ds.Namespace, debugSessionName: ds.Name, debugSessionUID: string(ds.UID),
			}
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			wc.sendAuthorizationResponse(c, s)
			var result SubjectAccessReviewResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))

			mu.Lock()
			defer mu.Unlock()
			if tc.allowSource == "rbac" {
				require.True(t, result.Status.Allowed, "the request is allowed, but not by a debug session")
			}
			if !tc.want {
				require.Empty(t, attached)
				return
			}
			require.True(t, result.Status.Allowed, result.Status.Reason)
			require.Len(t, attached, 1)
			event := attached[0]
			require.Equal(t, tc.subresource, event.Details["operation"])
			require.Equal(t, "own-pod", event.Details["podName"])
			require.Equal(t, "requester", event.Actor.User)
			require.Equal(t, "session-uid", event.RequestContext.DebugSessionUID)
			require.Equal(t, "cluster", event.Target.Cluster)
			require.NoError(t, audittest.Check(event))
		})
	}
}
