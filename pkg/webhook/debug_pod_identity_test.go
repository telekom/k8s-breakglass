// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
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

func TestDebugSessionAccessRequiresLiveTargetPodIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, recorded, live string
		fail, want           bool
	}{
		{"original", "original", "original", false, true},
		{"replacement", "original", "replacement", false, false},
		{"legacy", "", "original", false, false},
		{"lookup failed", "original", "original", true, false},
		{"missing pod", "original", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke"}, Status: breakglassv1alpha1.DebugSessionStatus{
				State:        breakglassv1alpha1.DebugSessionStateActive,
				ExpiresAt:    &expiresAt,
				AllowedPods:  []breakglassv1alpha1.AllowedPodRef{{Name: "pod", Namespace: "workloads", UID: tc.recorded}},
				Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "user", IdentityProviderIssuer: "https://a.example", Role: breakglassv1alpha1.ParticipantRoleOwner}},
			}}
			if tc.recorded != "" {
				session.Status.AllowedPods = append([]breakglassv1alpha1.AllowedPodRef{
					{Name: "other", Namespace: "workloads", UID: "unrelated"},
					{Name: "pod", Namespace: "other", UID: "unrelated"},
					{Name: "pod", Namespace: "workloads", UID: "stale"},
				}, session.Status.AllowedPods...)
			}
			fetches := 0
			live := tc.live
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(session)
			for key, fn := range debugSessionIndexFnsWebhook {
				builder = builder.WithIndex(session, key, fn)
			}
			wc := &WebhookController{escalManager: &escalation.EscalationManager{Client: builder.Build()}, podFetchFn: func(_ context.Context, cluster, namespace, name string) (*corev1.Pod, error) {
				fetches++
				require.Equal(t, "spoke", cluster)
				require.Equal(t, "workloads", namespace)
				require.Equal(t, "pod", name)
				if tc.fail {
					return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(live)}}, errors.New("unavailable")
				}
				if live == "" {
					return nil, nil
				}
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(live)}}, nil
			}}
			allowed, _, _ := wc.checkDebugSessionAccessForIssuer(context.Background(), "user", "spoke", "https://a.example", &authorizationv1.ResourceAttributes{Resource: "pods", Subresource: "exec", Namespace: "workloads", Name: "pod"}, zap.NewNop().Sugar())
			require.Equal(t, tc.want, allowed)
			wantFetches := 1
			if tc.recorded == "" {
				wantFetches = 0
			}
			require.Equal(t, wantFetches, fetches)
			live = "replacement-on-next-request"
			allowed, _, _ = wc.checkDebugSessionAccessForIssuer(context.Background(), "user", "spoke", "https://a.example", &authorizationv1.ResourceAttributes{Resource: "pods", Subresource: "exec", Namespace: "workloads", Name: "pod"}, zap.NewNop().Sugar())
			require.False(t, allowed)
			require.Equal(t, 2*wantFetches, fetches)
		})
	}
}
