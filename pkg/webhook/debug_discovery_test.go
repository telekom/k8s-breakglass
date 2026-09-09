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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordingDebugSessionReader struct {
	client.Reader
	listOptions client.ListOptions
}

func (r *recordingDebugSessionReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	r.listOptions = client.ListOptions{}
	for _, opt := range opts {
		opt.ApplyToList(&r.listOptions)
	}
	return r.Reader.List(ctx, list, opts...)
}

func TestDebugSessionAccessFallsBackToLiveDiscoveryAndKeepsPodUIDFence(t *testing.T) {
	expiresAt := metav1.NewTime(time.Now().Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "debug", Namespace: "breakglass-system", UID: types.UID("session-uid"),
			Labels: map[string]string{debugSessionClusterLabelKey: "spoke"},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:       breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt:   &expiresAt,
			AllowedPods: []breakglassv1alpha1.AllowedPodRef{{Name: "pod", Namespace: "workloads", UID: "pod-uid"}},
			Participants: []breakglassv1alpha1.DebugSessionParticipant{{
				User: "user", IdentityProviderIssuer: "https://issuer.example", Role: breakglassv1alpha1.ParticipantRoleOwner,
			}},
		},
	}

	// Simulate the informer cache missing the freshly activated session while
	// the API reader already observes it.
	cachedBuilder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for field, fn := range debugSessionIndexFnsWebhook {
		cachedBuilder = cachedBuilder.WithIndex(&breakglassv1alpha1.DebugSession{}, field, fn)
	}
	cached := cachedBuilder.Build()
	live := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(session).Build()
	liveReader := &recordingDebugSessionReader{Reader: live}

	var livePodUID types.UID = "pod-uid"
	wc := &WebhookController{
		escalManager: &escalation.EscalationManager{Client: cached},
		sesManager:   breakglass.NewSessionManagerWithClientAndReader(cached, liveReader, breakglass.WithQuotaNamespace("breakglass-system")),
		podFetchFn: func(context.Context, string, string, string) (*corev1.Pod, error) {
			return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: livePodUID}}, nil
		},
		log: zap.NewNop().Sugar(),
	}
	ra := &authorizationv1.ResourceAttributes{Resource: "pods", Subresource: "exec", Namespace: "workloads", Name: "pod"}

	allowed, _, _ := wc.checkDebugSessionAccessForIssuer(context.Background(), "user", "spoke", "https://issuer.example", ra, wc.log)
	require.True(t, allowed, "live active session must be found when cache discovery is empty")
	require.Equal(t, "breakglass-system", liveReader.listOptions.Namespace)
	require.Equal(t, maxLiveDebugSessionDiscoveryCandidates, liveReader.listOptions.Limit)
	require.Equal(t, debugSessionClusterLabelKey+"=spoke", liveReader.listOptions.LabelSelector.String())

	livePodUID = "replacement-uid"
	allowed, _, _ = wc.checkDebugSessionAccessForIssuer(context.Background(), "user", "spoke", "https://issuer.example", ra, wc.log)
	require.False(t, allowed, "live replacement must remain denied by the Pod UID fence")
}
