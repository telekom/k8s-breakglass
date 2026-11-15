// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestClientSecretRotationUsedForNextClusterClient proves that an in-place
// update of a ClusterConfig OIDC client secret reaches the next cluster
// client without a restart: the Secret update handler invalidates the cached
// client and token, and the rebuilt client requests its token with the new
// secret. See docs/identity-provider.md#rotating-client-secrets.
func TestClientSecretRotationUsedForNextClusterClient(t *testing.T) {
	for _, mode := range []string{"oidcAuth", "oidcFromIdentityProvider"} {
		t.Run(mode, func(t *testing.T) {
			var issuer string
			grants := make(chan string, 10)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "openid-configuration") {
					_, _ = fmt.Fprintf(w, `{"token_endpoint":%q}`, issuer+"/token")
					return
				}
				if err := r.ParseForm(); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				grants <- r.Form.Get("client_secret")
				_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600,"token_type":"Bearer"}`))
			}))
			defer server.Close()
			issuer = server.URL

			scheme := runtime.NewScheme()
			require.NoError(t, clientgoscheme.AddToScheme(scheme))
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			secretRef := &breakglassv1alpha1.SecretKeyReference{Name: "oidc-client", Namespace: "workloads", Key: "value"}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretRef.Name, Namespace: secretRef.Namespace}, Data: map[string][]byte{"value": []byte("old-secret")}}
			idp := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC: breakglassv1alpha1.OIDCConfig{Authority: issuer, ClientID: "client"},
			}}
			cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "workloads"}, Spec: breakglassv1alpha1.ClusterConfigSpec{AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC}}
			if mode == "oidcAuth" {
				cc.Spec.OIDCAuth = &breakglassv1alpha1.OIDCAuthConfig{IssuerURL: issuer, ClientID: "client", Server: issuer, InsecureSkipTLSVerify: true, ClientSecretRef: secretRef}
			} else {
				cc.Spec.OIDCFromIdentityProvider = &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: idp.Name, Server: issuer, InsecureSkipTLSVerify: true, ClientSecretRef: secretRef}
			}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp, secret, cc).Build()
			provider := NewClientProvider(kube, zaptest.NewLogger(t).Sugar())
			ctx := context.Background()

			_, err := provider.GetRESTConfig(ctx, "workloads/cluster")
			require.NoError(t, err)
			require.Equal(t, "old-secret", nextGrant(t, grants))
			require.True(t, provider.IsOIDCSecretTracked(secretRef.Namespace, secretRef.Name))

			secret.Data["value"] = []byte("new-secret")
			require.NoError(t, kube.Update(ctx, secret))
			// The Secret informer handler (RegisterInvalidationHandlers) runs this on update.
			provider.InvalidateOIDCSecrets(secretRef.Namespace, secretRef.Name)

			_, err = provider.GetRESTConfig(ctx, "workloads/cluster")
			require.NoError(t, err)
			require.Equal(t, "new-secret", nextGrant(t, grants))
		})
	}
}

// nextGrant returns the client secret of the token request GetRESTConfig made
// synchronously during its preflight, or fails when it made none.
func nextGrant(t *testing.T, grants <-chan string) string {
	t.Helper()
	select {
	case secret := <-grants:
		return secret
	default:
		t.Fatal("no token request was made")
		return ""
	}
}
