// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionCanonicalKubernetesIdentityFences(t *testing.T) {
	for _, cachedDiscovery := range []bool{false, true} {
		mode := "live discovery"
		if cachedDiscovery {
			mode = "cached discovery"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []string{"email", "subject", "username collision", "email collision", "legacy username", "wrong email", "blank username", "wrong issuer", "wrong provider", "unresolved provider", "viewer", "left", "expired", "terminated", "replacement pod", "replacement session"} {
				t.Run(tc, func(t *testing.T) {
					ctx := context.Background()
					expires := metav1.NewTime(time.Now().Add(time.Hour))
					ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "controller", UID: "session-uid", Labels: map[string]string{debugSessionClusterLabelKey: "spoke"}}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expires, AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Name: "pod", Namespace: "workloads", UID: "pod-uid"}}, Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "platform-requester", KubernetesUser: "platform-requester@example.test", Email: "platform-requester@example.test", IdentityProviderName: "provider", IdentityProviderIssuer: "https://issuer.example", Role: breakglassv1alpha1.ParticipantRoleOwner}}}}
					username, issuer, provider, lookupOK := "platform-requester@example.test", "https://issuer.example", "provider", true
					podUID, candidateUID := types.UID("pod-uid"), "session-uid"
					allowed := tc == "email" || tc == "subject" || tc == "legacy username"
					switch tc {
					case "username collision":
						username = "platform-requester"
					case "email collision":
						ds.Status.Participants[0].KubernetesUser = "platform-requester"
					case "subject":
						username = "subject-uuid"
						ds.Status.Participants[0].KubernetesUser = username
					case "legacy username":
						username = "platform-requester"
						ds.Status.Participants[0].KubernetesUser = ""
					case "wrong email":
						username = "another@example.test"
					case "blank username":
						username = ""
					case "wrong issuer":
						issuer = "https://other.example"
					case "wrong provider":
						provider = "other-provider"
					case "unresolved provider":
						provider = ""
						lookupOK = false
					case "viewer":
						ds.Status.Participants[0].Role = breakglassv1alpha1.ParticipantRoleViewer
					case "left":
						now := metav1.Now()
						ds.Status.Participants[0].LeftAt = &now
					case "expired":
						past := metav1.NewTime(time.Now().Add(-time.Minute))
						ds.Status.ExpiresAt = &past
					case "terminated":
						ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
					case "replacement pod":
						podUID = "replacement-pod"
					case "replacement session":
						candidateUID = "old-session-uid"
					}
					builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
					for field, fn := range debugSessionIndexFnsWebhook {
						builder = builder.WithIndex(ds, field, fn)
					}
					if cachedDiscovery {
						builder = builder.WithObjects(ds)
					}
					cached := builder.Build()
					live := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(ds).Build()
					reader := &recordingDebugSessionReader{Reader: live}
					wc := &WebhookController{escalManager: &escalation.EscalationManager{Client: cached}, sesManager: breakglass.NewSessionManagerWithClientAndReader(cached, reader, breakglass.WithQuotaNamespace("controller")), log: zap.NewNop().Sugar(), podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
						return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: podUID}}, nil
					}}
					ra := &authorizationv1.ResourceAttributes{Resource: "pods", Subresource: "exec", Namespace: "workloads", Name: "pod"}
					discovered, _ := wc.findDebugSessionAccessForProviderInNamespace(ctx, username, "spoke", issuer, provider, lookupOK, "controller", ra, wc.log)
					if tc != "replacement session" {
						require.Equal(t, allowed, discovered != nil)
					}
					if cachedDiscovery && tc == "email" {
						require.Zero(t, reader.listCalls, "canonical identity must be discoverable through the participant cache index")
					}
					final, _ := wc.liveDebugSessionAccessForProvider(ctx, username, issuer, provider, lookupOK, "spoke", ra, "controller", "debug", candidateUID)
					require.Equal(t, allowed, final, "final uncached fence must apply canonical identity and all safety checks")
				})
			}
		})
	}
}
