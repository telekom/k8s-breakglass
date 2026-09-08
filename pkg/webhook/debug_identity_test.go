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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestDebugSessionSARIssuerAndRole(t *testing.T) {
	for _, tc := range []struct {
		name, stored, request string
		role                  breakglassv1alpha1.ParticipantRole
		legacyIDP, allowed    bool
	}{
		{"matching", "https://a.example", "https://a.example", breakglassv1alpha1.ParticipantRoleParticipant, false, true},
		{"wrong", "https://a.example", "https://b.example", breakglassv1alpha1.ParticipantRoleOwner, false, false},
		{"missing request", "https://a.example", "", breakglassv1alpha1.ParticipantRoleOwner, false, false},
		{"unbound ambiguous", "", "https://a.example", breakglassv1alpha1.ParticipantRoleOwner, false, false},
		{"unbound single provider", "", "https://a.example", breakglassv1alpha1.ParticipantRoleOwner, true, true},
		{"viewer", "https://a.example", "https://a.example", breakglassv1alpha1.ParticipantRoleViewer, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
			ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiresAt, AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Name: "pod", Namespace: "default", UID: "pod-uid"}}, Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "same", IdentityProviderIssuer: tc.stored, Role: tc.role}}}}
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(ds)
			for field, fn := range debugSessionIndexFnsWebhook {
				builder = builder.WithIndex(ds, field, fn)
			}
			if tc.legacyIDP {
				builder = builder.WithObjects(&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "only"}, Spec: breakglassv1alpha1.IdentityProviderSpec{Issuer: "https://a.example"}})
			}
			wc := &WebhookController{podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
				return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "pod-uid"}}, nil
			}, log: zap.NewNop().Sugar(), escalManager: &escalation.EscalationManager{Client: builder.Build()}}
			allowed, _, _ := wc.checkDebugSessionAccessForIssuer(context.Background(), "same", "spoke", tc.request, &authorizationv1.ResourceAttributes{Resource: "pods", Subresource: "exec", Namespace: "default", Name: "pod"}, wc.log)
			require.Equal(t, tc.allowed, allowed)
		})
	}
}
