// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPrivilegedCredentialIdentity(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	secret := func(name string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "hub", Name: name, UID: types.UID(name + "-uid")}}
	}
	ref := func(name string) *breakglassv1alpha1.SecretKeyReference {
		return &breakglassv1alpha1.SecretKeyReference{Namespace: "hub", Name: name}
	}
	for name, tc := range map[string]struct {
		spec    breakglassv1alpha1.ClusterConfigSpec
		wantUID types.UID
		wantErr string
	}{
		"kubeconfig":           {spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: ref("kubeconfig")}, wantUID: "kubeconfig-uid"},
		"oidc client":          {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{ClientSecretRef: ref("oidc")}}, wantUID: "oidc-uid"},
		"oidc from idp":        {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{RefreshTokenSecretRef: ref("refresh")}}, wantUID: "refresh-uid"},
		"idp keycloak":         {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: "idp"}}, wantUID: "keycloak-uid"},
		"idp without keycloak": {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: "plain"}}, wantErr: "has no credential secret"},
		"missing secret":       {spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: ref("absent")}, wantErr: "read cluster credential secret"},
		"secretless config":    {wantErr: "has no credential secret"},
	} {
		t.Run(name, func(t *testing.T) {
			cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret("kubeconfig"), secret("oidc"), secret("refresh"), secret("keycloak"),
				&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{Keycloak: &breakglassv1alpha1.KeycloakGroupSync{ClientSecretRef: *ref("keycloak")}}},
				&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "plain"}}).Build()
			provider := NewClientProvider(cli, zaptest.NewLogger(t).Sugar())
			uid, version, err := provider.PrivilegedCredentialIdentity(context.Background(), &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke"}, Spec: tc.spec})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantUID, uid)
			require.NotEmpty(t, version)
		})
	}
}
