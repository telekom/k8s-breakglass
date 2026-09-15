// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func approverResolverProvider(name string) (*breakglassv1alpha1.IdentityProvider, *corev1.Secret) {
	return &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: breakglassv1alpha1.IdentityProviderSpec{
		Issuer:            "https://issuer.example.com/" + name,
		OIDC:              breakglassv1alpha1.OIDCConfig{Authority: "https://issuer.example.com", ClientID: "client", ExpectedAudience: "client"},
		GroupSyncProvider: breakglassv1alpha1.GroupSyncProviderKeycloak,
		Keycloak:          &breakglassv1alpha1.KeycloakGroupSync{BaseURL: "https://groups.example.com", Realm: "realm", ClientID: "sync", CacheTTL: "10m", ClientSecretRef: breakglassv1alpha1.SecretKeyReference{Name: name, Namespace: "ns", Key: "secret"}},
	}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"}, Data: map[string][]byte{"secret": []byte("initial")}}
}

func TestApproverResolverReusesProductionMembershipCache(t *testing.T) {
	var tokens, searches, members, details atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			tokens.Add(1)
			fmt.Fprint(w, `{"access_token":"token","expires_in":300,"token_type":"Bearer"}`)
		case strings.HasSuffix(r.URL.Path, "/groups/group-id/members"):
			members.Add(1)
			fmt.Fprint(w, `[{"id":"user","username":"security","email":"security@example.com"}]`)
		case strings.HasSuffix(r.URL.Path, "/groups/group-id"):
			details.Add(1)
			fmt.Fprint(w, `{"id":"group-id","name":"security-team","subGroups":[]}`)
		case strings.HasSuffix(r.URL.Path, "/groups"):
			searches.Add(1)
			fmt.Fprint(w, `[{"id":"group-id","name":"security-team"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	idp, secret := approverResolverProvider("provider")
	idp.Spec.Keycloak.BaseURL = server.URL
	idp.Spec.Keycloak.CertificateAuthority = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	kube := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(idp, secret).Build()
	core, observed := observer.New(zap.DebugLevel)
	controller := &WebhookController{log: zap.New(core).Sugar(), escalManager: &escalation.EscalationManager{Client: kube}}
	first, err := controller.resolveApproverProvider(context.Background(), idp.Name)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		resolver, err := controller.resolveApproverProvider(context.Background(), idp.Name)
		require.NoError(t, err)
		require.Same(t, first, resolver)
		got, err := resolver.Members(context.Background(), "security-team")
		require.NoError(t, err)
		require.Equal(t, []string{"security@example.com"}, got)
	}
	require.EqualValues(t, 1, tokens.Load())
	require.EqualValues(t, 1, searches.Load())
	require.EqualValues(t, 1, members.Load())
	require.EqualValues(t, 1, details.Load())
	require.NotEmpty(t, observed.FilterMessage("Loading specific IdentityProvider resource").All())
	require.Len(t, observed.FilterMessage("Keycloak group sync enabled").All(), 1)
	require.NotEmpty(t, observed.FilterMessage("Keycloak cache hit for group").All())
}

func TestApproverResolverReloadsIdentityAndCredentials(t *testing.T) {
	idp, secret := approverResolverProvider("provider")
	caServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer caServer.Close()
	other, otherSecret := approverResolverProvider("other")
	kube := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(idp, secret, other, otherSecret).Build()
	controller := &WebhookController{escalManager: &escalation.EscalationManager{Client: kube}}
	ctx := context.Background()
	previous, err := controller.resolveApproverProvider(ctx, idp.Name)
	require.NoError(t, err)
	second, err := controller.resolveApproverProvider(ctx, other.Name)
	require.NoError(t, err)
	require.NotSame(t, previous, second)
	for _, change := range []func(){
		func() { secret.Data["secret"] = []byte("rotated"); require.NoError(t, kube.Update(ctx, secret)) },
		func() { idp.Spec.Keycloak.Realm = "new-realm"; require.NoError(t, kube.Update(ctx, idp)) },
		func() { idp.Spec.Issuer = "https://new-issuer.example.com"; require.NoError(t, kube.Update(ctx, idp)) },
		func() {
			idp.Spec.Keycloak.CertificateAuthority = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caServer.Certificate().Raw}))
			require.NoError(t, kube.Update(ctx, idp))
		},
		func() { idp.Spec.Keycloak.CacheTTL = "1m"; require.NoError(t, kube.Update(ctx, idp)) },
	} {
		change()
		next, err := controller.resolveApproverProvider(ctx, idp.Name)
		require.NoError(t, err)
		require.NotSame(t, previous, next)
		previous = next
	}
	require.NoError(t, kube.Delete(ctx, secret))
	missing, err := controller.resolveApproverProvider(ctx, idp.Name)
	require.Error(t, err)
	require.Nil(t, missing)
	require.NotContains(t, controller.approverResolvers, idp.Name)
	secret.ResourceVersion = ""
	require.NoError(t, kube.Create(ctx, secret))
	restored, err := controller.resolveApproverProvider(ctx, idp.Name)
	require.NoError(t, err)
	require.NotSame(t, previous, restored)
	require.NoError(t, kube.Delete(ctx, idp))
	missing, err = controller.resolveApproverProvider(ctx, idp.Name)
	require.Error(t, err)
	require.Nil(t, missing)
}

func TestApproverResolverConcurrentRotationPublishesLatest(t *testing.T) {
	idp, secret := approverResolverProvider("provider")
	firstRead := make(chan struct{})
	release := make(chan struct{})
	var reads atomic.Int32
	kube := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(idp, secret).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			err := c.Get(ctx, key, obj, opts...)
			if _, ok := obj.(*corev1.Secret); ok && reads.Add(1) == 1 {
				close(firstRead)
				<-release
			}
			return err
		},
	}).Build()
	controller := &WebhookController{escalManager: &escalation.EscalationManager{Client: kube}}
	type result struct {
		resolver breakglass.GroupMemberResolver
		err      error
	}
	first := make(chan result, 1)
	go func() {
		v, e := controller.resolveApproverProvider(context.Background(), idp.Name)
		first <- result{v, e}
	}()
	<-firstRead
	secret.Data["secret"] = []byte("rotated")
	require.NoError(t, kube.Update(context.Background(), secret))
	const callers = 8
	following := make(chan result, callers)
	for i := 0; i < callers; i++ {
		go func() {
			v, e := controller.resolveApproverProvider(context.Background(), idp.Name)
			following <- result{v, e}
		}()
	}
	close(release)
	original := <-first
	require.NoError(t, original.err)
	current := <-following
	require.NoError(t, current.err)
	require.NotSame(t, original.resolver, current.resolver)
	for i := 1; i < callers; i++ {
		v := <-following
		require.NoError(t, v.err)
		require.Same(t, current.resolver, v.resolver)
	}
	require.Equal(t, "rotated", controller.approverResolvers[idp.Name].config.keycloak.ClientSecret)
	latest, err := controller.resolveApproverProvider(context.Background(), idp.Name)
	require.NoError(t, err)
	require.Same(t, current.resolver, latest)
}
