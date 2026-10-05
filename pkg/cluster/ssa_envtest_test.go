// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestRotatedRefreshTokenApplyCountsAndOwnership(t *testing.T) {
	apiClient := ssatest.Start(t)
	c := &ssatest.CountingClient{Client: apiClient}
	provider := NewOIDCTokenProvider(c, zap.NewNop().Sugar())
	config := &breakglassv1alpha1.OIDCAuthConfig{
		RefreshTokenSecretRef:  &breakglassv1alpha1.SecretKeyReference{Name: "rotation", Namespace: "default"},
		RotatedRefreshTokenKey: "rotated",
	}
	provider.persistRotatedRefreshToken(t.Context(), config, "ignored", "first", "")
	require.EqualValues(t, 1, c.Applies.Load())
	provider.persistRotatedRefreshToken(t.Context(), config, "ignored", "first", "")
	require.EqualValues(t, 1, c.Applies.Load())
	provider.persistRotatedRefreshToken(t.Context(), config, "ignored", "", "")
	require.EqualValues(t, 1, c.Applies.Load())
	require.NoError(t, apiClient.Apply(t.Context(), corev1ac.Secret("rotation", "default").
		WithData(map[string][]byte{"rotated": []byte("foreign"), "original": []byte("preserve")}),
		client.FieldOwner("competitor"), client.ForceOwnership))
	provider.persistRotatedRefreshToken(t.Context(), config, "ignored", "second", "")
	require.EqualValues(t, 2, c.Applies.Load())
	live := &corev1.Secret{}
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKey{Name: "rotation", Namespace: "default"}, live))
	require.Equal(t, []byte("second"), live.Data["rotated"])
	require.Equal(t, []byte("preserve"), live.Data["original"])
	require.Equal(t, "breakglass", live.Labels["app.kubernetes.io/managed-by"])
}
