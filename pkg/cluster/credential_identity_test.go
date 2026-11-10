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
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func identityScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	return scheme
}

func identitySecret(name string) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "hub", Name: name, UID: types.UID(name + "-uid")}}
}

func identityRef(name string) *breakglassv1alpha1.SecretKeyReference {
	return &breakglassv1alpha1.SecretKeyReference{Namespace: "hub", Name: name}
}

func TestPrivilegedCredentialIdentityPrimarySecret(t *testing.T) {
	for name, tc := range map[string]struct {
		spec    breakglassv1alpha1.ClusterConfigSpec
		wantUID types.UID
		wantErr string
	}{
		"kubeconfig":           {spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: identityRef("kubeconfig")}, wantUID: "kubeconfig-uid"},
		"oidc client":          {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{ClientSecretRef: identityRef("oidc")}}, wantUID: "oidc-uid"},
		"oidc from idp":        {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: "idp", RefreshTokenSecretRef: identityRef("refresh")}}, wantUID: "refresh-uid"},
		"idp keycloak":         {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: "idp"}}, wantUID: "keycloak-uid"},
		"idp without keycloak": {spec: breakglassv1alpha1.ClusterConfigSpec{OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: "plain"}}, wantErr: "has no credential secret"},
		"missing secret":       {spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: identityRef("absent")}, wantErr: "read cluster credential inputs"},
		"secretless config":    {wantErr: "has no credential secret"},
	} {
		t.Run(name, func(t *testing.T) {
			cli := fake.NewClientBuilder().WithScheme(identityScheme(t)).WithObjects(identitySecret("kubeconfig"), identitySecret("oidc"), identitySecret("refresh"), identitySecret("keycloak"),
				&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{Keycloak: &breakglassv1alpha1.KeycloakGroupSync{ClientSecretRef: *identityRef("keycloak")}}},
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

// Every hub input of the privileged client is part of the identity: rotating
// any of them (not only the first Secret) must change it.
func TestPrivilegedCredentialIdentityCoversEveryInput(t *testing.T) {
	inputs := []string{"oidc-client", "oidc-refresh", "oidc-ca", "oidc-subject", "oidc-actor", "idp-client", "idp-refresh", "idp-ca", "idp-subject", "idp-actor", "keycloak"}
	objects := []ctrlclient.Object{&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{Keycloak: &breakglassv1alpha1.KeycloakGroupSync{ClientSecretRef: *identityRef("keycloak")}}}}
	for _, name := range append(inputs, "kubeconfig") {
		objects = append(objects, identitySecret(name))
	}
	cli := fake.NewClientBuilder().WithScheme(identityScheme(t)).WithObjects(objects...).Build()
	provider := NewClientProvider(cli, zaptest.NewLogger(t).Sugar())
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke"}, Spec: breakglassv1alpha1.ClusterConfigSpec{
		OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
			ClientSecretRef: identityRef("oidc-client"), RefreshTokenSecretRef: identityRef("oidc-refresh"), CASecretRef: identityRef("oidc-ca"),
			TokenExchange: &breakglassv1alpha1.TokenExchangeConfig{SubjectTokenSecretRef: identityRef("oidc-subject"), ActorTokenSecretRef: identityRef("oidc-actor")},
		},
		OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
			Name: "idp", ClientSecretRef: identityRef("idp-client"), RefreshTokenSecretRef: identityRef("idp-refresh"), CASecretRef: identityRef("idp-ca"),
			TokenExchange: &breakglassv1alpha1.TokenExchangeConfig{SubjectTokenSecretRef: identityRef("idp-subject"), ActorTokenSecretRef: identityRef("idp-actor")},
		},
	}}
	ctx := context.Background()
	_, previous, err := provider.PrivilegedCredentialIdentity(ctx, cc)
	require.NoError(t, err)
	touch := func(obj ctrlclient.Object) {
		require.NoError(t, cli.Get(ctx, ctrlclient.ObjectKeyFromObject(obj), obj))
		obj.SetAnnotations(map[string]string{"rotated": obj.GetResourceVersion()})
		require.NoError(t, cli.Update(ctx, obj))
	}
	changes := map[string]func(){"identityprovider": func() { touch(&breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp"}}) }}
	for _, name := range inputs {
		changes[name] = func() { touch(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "hub", Name: name}}) }
	}
	for name, change := range changes {
		change()
		_, current, err := provider.PrivilegedCredentialIdentity(ctx, cc)
		require.NoError(t, err)
		require.NotEqual(t, previous, current, "changing %s must change the identity", name)
		previous = current
	}
	_, unchanged, err := provider.PrivilegedCredentialIdentity(ctx, cc)
	require.NoError(t, err)
	require.Equal(t, previous, unchanged, "the identity is stable without changes")
}
