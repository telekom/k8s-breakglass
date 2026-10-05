// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func TestClientProviderRealAPI(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("envtest assets required; run make test-cluster-clients")
	}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	environment := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	live, err := client.NewWithWatch(config, client.Options{Scheme: scheme})
	require.NoError(t, err)
	mgr, err := ctrl.NewManager(config, ctrl.Options{
		Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
	})
	require.NoError(t, err)
	provider := NewClientProvider(mgr.GetClient(), zaptest.NewLogger(t).Sugar()).WithLiveReader(mgr.GetAPIReader())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	require.NoError(t, RegisterInvalidationHandlers(ctx, mgr, provider, zaptest.NewLogger(t).Sugar()))
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("manager did not stop")
		}
	})
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))

	newNamespace := func(t *testing.T, name string) string {
		t.Helper()
		require.NoError(t, live.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}))
		return name
	}
	kubeconfig := func(t *testing.T, host string) []byte {
		t.Helper()
		raw, err := clientcmd.Write(clientcmdapi.Config{
			Clusters: map[string]*clientcmdapi.Cluster{"target": {
				Server: host, CertificateAuthorityData: config.CAData,
			}},
			AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {
				ClientCertificateData: config.CertData, ClientKeyData: config.KeyData,
			}},
			Contexts:       map[string]*clientcmdapi.Context{"target": {Cluster: "target", AuthInfo: "admin"}},
			CurrentContext: "target",
		})
		require.NoError(t, err)
		return raw
	}
	newSecret := func(t *testing.T, namespace, name, host string) *corev1.Secret {
		t.Helper()
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Data: map[string][]byte{"value": kubeconfig(t, host)}}
		require.NoError(t, live.Create(ctx, secret))
		return secret
	}
	newCluster := func(t *testing.T, namespace, name, secret string) *breakglassv1alpha1.ClusterConfig {
		t.Helper()
		cc := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Namespace: namespace, Name: secret,
			}},
		}
		require.NoError(t, live.Create(ctx, cc))
		require.Eventually(t, func() bool {
			var cached breakglassv1alpha1.ClusterConfig
			return mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(cc), &cached) == nil && cached.ResourceVersion == cc.ResourceVersion
		}, 10*time.Second, 10*time.Millisecond)
		return cc
	}
	waitEvicted := func(t *testing.T, keys ...string) {
		t.Helper()
		require.Eventually(t, func() bool {
			provider.mu.RLock()
			defer provider.mu.RUnlock()
			for _, key := range keys {
				if provider.rest[key] != nil || provider.clientsets[key] != nil {
					return false
				}
			}
			return true
		}, 10*time.Second, 10*time.Millisecond)
	}

	t.Run("Secret rotation fans out and removes bare aliases and clientsets", func(t *testing.T) {
		ns := newNamespace(t, "remote-fanout")
		secret := newSecret(t, ns, "shared", config.Host)
		a := newCluster(t, ns, "fanout-a", secret.Name)
		b := newCluster(t, ns, "fanout-b", secret.Name)
		keys := []string{a.Name, cacheKey(ns, a.Name), cacheKey(ns, b.Name)}
		before, err := provider.GetClientset(ctx, a.Name)
		require.NoError(t, err)
		namespaces, err := before.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		require.NoError(t, err)
		require.NotEmpty(t, namespaces.Items, "Secret-derived client must actually reach the API server")
		_, err = provider.GetClientset(ctx, cacheKey(ns, b.Name))
		require.NoError(t, err)
		require.True(t, provider.IsSecretTracked(ns, secret.Name))
		secret.Data["value"] = kubeconfig(t, config.Host+"/rotated")
		require.NoError(t, live.Update(ctx, secret))
		waitEvicted(t, keys...)
		require.False(t, provider.IsSecretTracked(ns, secret.Name))
		for _, key := range keys {
			cfg, err := provider.GetRESTConfig(ctx, key)
			require.NoError(t, err)
			require.Equal(t, config.Host+"/rotated", cfg.Host)
		}
		after, err := provider.GetClientset(ctx, a.Name)
		require.NoError(t, err)
		require.NotSame(t, before, after)
		require.NoError(t, live.Delete(ctx, secret))
		waitEvicted(t, keys...)
		_, err = provider.GetRESTConfig(ctx, a.Name)
		require.ErrorContains(t, err, "fetch kubeconfig secret")
	})

	t.Run("ClusterConfig reference changes and deletion invalidate all layers", func(t *testing.T) {
		ns := newNamespace(t, "remote-reference")
		old := newSecret(t, ns, "old", config.Host)
		replacement := newSecret(t, ns, "new", config.Host+"/new")
		cc := newCluster(t, ns, "reference-target", old.Name)
		_, err := provider.GetClientset(ctx, cc.Name)
		require.NoError(t, err)
		cc.Spec.KubeconfigSecretRef.Name = replacement.Name
		require.NoError(t, live.Update(ctx, cc))
		waitEvicted(t, cc.Name, cacheKey(ns, cc.Name))
		cfg, err := provider.GetRESTConfig(ctx, cc.Name)
		require.NoError(t, err)
		require.Equal(t, config.Host+"/new", cfg.Host)
		require.False(t, provider.IsSecretTracked(ns, old.Name))
		require.True(t, provider.IsSecretTracked(ns, replacement.Name))
		require.NoError(t, live.Delete(ctx, cc))
		waitEvicted(t, cc.Name, cacheKey(ns, cc.Name))
		_, err = provider.GetRESTConfig(ctx, cc.Name)
		require.ErrorIs(t, err, ErrClusterConfigNotFound)
	})

	t.Run("privileged client snapshot rejects Secret and ClusterConfig version changes", func(t *testing.T) {
		ns := newNamespace(t, "remote-fence")
		secret := newSecret(t, ns, "credentials", config.Host)
		cc := newCluster(t, ns, "fenced-target", secret.Name)
		// No watchers: the live fence must work even while the provider cache is stale.
		fenced := NewClientProvider(live, zaptest.NewLogger(t).Sugar()).WithLiveReader(live)
		target, snapshot, err := fenced.GetClientForPrivilegedOperation(ctx, cacheKey(ns, cc.Name))
		require.NoError(t, err)
		defer fenced.ReleasePrivilegedOperationClusterConfig(snapshot)
		require.NoError(t, target.Get(ctx, client.ObjectKey{Name: ns}, &corev1.Namespace{}))
		require.NoError(t, fenced.ValidatePrivilegedOperationClusterConfig(ctx, snapshot))
		secret.Annotations = map[string]string{"rotation": "1"}
		require.NoError(t, live.Update(ctx, secret))
		require.ErrorContains(t, fenced.ValidatePrivilegedOperationClusterConfig(ctx, snapshot), "privileged input")
		_, next, err := fenced.GetRESTConfigForPrivilegedOperation(ctx, cacheKey(ns, cc.Name))
		require.NoError(t, err)
		defer fenced.ReleasePrivilegedOperationClusterConfig(next)
		cc.Annotations = map[string]string{"version": "changed"}
		require.NoError(t, live.Update(ctx, cc))
		require.ErrorContains(t, fenced.ValidatePrivilegedOperationClusterConfig(ctx, next), "resource version changed")
		require.NoError(t, live.Delete(ctx, cc))
		require.Error(t, fenced.ValidatePrivilegedOperationClusterConfig(ctx, next))
		recreated := cc.DeepCopy()
		recreated.ResourceVersion, recreated.UID = "", ""
		require.NoError(t, live.Create(ctx, recreated))
		require.NotEqual(t, next.UID, recreated.UID)
		require.ErrorContains(t, fenced.ValidatePrivilegedOperationClusterConfig(ctx, next), "was replaced")
	})

	t.Run("privileged rebuild rejects rotation between live input snapshots", func(t *testing.T) {
		ns := newNamespace(t, "remote-rebuild-fence")
		secret := newSecret(t, ns, "credentials", config.Host)
		cc := newCluster(t, ns, "rebuild-target", secret.Name)
		reads := 0
		rotating := interceptor.NewClient(live, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				err := c.Get(ctx, key, obj, opts...)
				if _, ok := obj.(*corev1.Secret); ok && err == nil {
					reads++
					// Initial resolution, cached input snapshot, then fenced rebuild.
					if reads == 3 {
						secret.Annotations = map[string]string{"rotated-during-build": "true"}
						return live.Update(ctx, secret)
					}
				}
				return err
			},
		})
		fenced := NewClientProvider(rotating, zaptest.NewLogger(t).Sugar()).WithLiveReader(live)
		cfg, snapshot, err := fenced.GetRESTConfigForPrivilegedOperation(ctx, cacheKey(ns, cc.Name))
		require.ErrorContains(t, err, "privileged client inputs changed while building target config")
		require.Nil(t, cfg)
		require.Nil(t, snapshot)
		require.Equal(t, 3, reads)
	})

	t.Run("invalidation waits for in-flight refresh and removes its stale completion", func(t *testing.T) {
		ns := newNamespace(t, "remote-ordering")
		secret := newSecret(t, ns, "credentials", config.Host)
		cc := newCluster(t, ns, "ordering-target", secret.Name)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		blocked := interceptor.NewClient(live, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				err := c.Get(ctx, key, obj, opts...)
				if _, ok := obj.(*corev1.Secret); ok && key == client.ObjectKeyFromObject(secret) {
					once.Do(func() { close(entered); <-release })
				}
				return err
			},
		})
		p := NewClientProvider(blocked, zaptest.NewLogger(t).Sugar())
		result := make(chan error, 1)
		go func() {
			_, err := p.GetRESTConfig(ctx, cc.Name)
			result <- err
		}()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("refresh did not read Secret")
		}
		secret.Data["value"] = kubeconfig(t, config.Host+"/new-generation")
		err = live.Update(ctx, secret)
		if err != nil {
			close(release)
			require.NoError(t, err)
		}
		invalidated := make(chan struct{})
		go func() { p.InvalidateSecret(ns, secret.Name); close(invalidated) }()
		close(release)
		require.NoError(t, <-result)
		select {
		case <-invalidated:
		case <-time.After(10 * time.Second):
			t.Fatal("invalidation did not complete")
		}
		p.mu.RLock()
		staleAlias, staleCanonical := p.rest[cc.Name], p.rest[cacheKey(ns, cc.Name)]
		p.mu.RUnlock()
		require.Nil(t, staleAlias)
		require.Nil(t, staleCanonical)
		fresh, err := p.GetRESTConfig(ctx, cc.Name)
		require.NoError(t, err)
		require.Equal(t, config.Host+"/new-generation", fresh.Host)
	})

	t.Run("OIDC Secret rotation refreshes token injection and dependency tracking", func(t *testing.T) {
		ns := newNamespace(t, "remote-oidc")
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(oidcDiscovery{Issuer: "https://" + r.Host, TokenEndpoint: "https://" + r.Host + "/token"})
		})
		mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: r.Form.Get("client_secret"), TokenType: "Bearer", ExpiresIn: 3600})
		})
		mux.HandleFunc("/spoke", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.Header.Get("Authorization")))
		})
		server := httptest.NewTLSServer(mux)
		defer server.Close()
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		caSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "oidc-ca"}, Data: map[string][]byte{"ca.crt": ca}}
		require.NoError(t, live.Create(ctx, caSecret))
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "oidc-credentials"}, Data: map[string][]byte{"client-secret": []byte("first")}}
		require.NoError(t, live.Create(ctx, secret))
		cc := &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "oidc-target"},
			Spec: breakglassv1alpha1.ClusterConfigSpec{
				AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
				OIDCAuth: &breakglassv1alpha1.OIDCAuthConfig{
					IssuerURL: server.URL, ClientID: "test-client", Server: server.URL,
					CertificateAuthority: string(ca),
					CASecretRef:          &breakglassv1alpha1.SecretKeyReference{Namespace: ns, Name: caSecret.Name, Key: "ca.crt"},
					ClientSecretRef:      &breakglassv1alpha1.SecretKeyReference{Namespace: ns, Name: secret.Name, Key: "client-secret"},
				},
			},
		}
		require.NoError(t, live.Create(ctx, cc))
		require.Eventually(t, func() bool {
			return mgr.GetClient().Get(ctx, client.ObjectKeyFromObject(cc), &breakglassv1alpha1.ClusterConfig{}) == nil
		}, 10*time.Second, 10*time.Millisecond)
		checkToken := func(expected string) *rest.Config {
			t.Helper()
			cfg, err := provider.GetRESTConfig(ctx, cc.Name)
			require.NoError(t, err)
			httpClient, err := rest.HTTPClientFor(cfg)
			require.NoError(t, err)
			response, err := httpClient.Get(server.URL + "/spoke")
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, http.StatusOK, response.StatusCode)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, "Bearer "+expected, string(body))
			return cfg
		}
		before := checkToken("first")
		require.True(t, provider.IsOIDCSecretTracked(ns, secret.Name))
		require.True(t, provider.IsOIDCSecretTracked(ns, caSecret.Name))
		secret.Data["client-secret"] = []byte("second")
		require.NoError(t, live.Update(ctx, secret))
		waitEvicted(t, cc.Name, cacheKey(ns, cc.Name))
		after := checkToken("second")
		require.NotSame(t, before, after)
		_, _, rotatedCA := generateTestCACert(t)
		caSecret.Data["ca.crt"] = rotatedCA
		require.NoError(t, live.Update(ctx, caSecret))
		waitEvicted(t, cc.Name, cacheKey(ns, cc.Name))
		rotated, err := provider.GetRESTConfig(ctx, cc.Name)
		require.NoError(t, err)
		require.NotSame(t, after, rotated)
		require.Equal(t, rotatedCA, rotated.CAData)
		httpClient, err := rest.HTTPClientFor(rotated)
		require.NoError(t, err)
		response, err := httpClient.Get(server.URL + "/spoke")
		if response != nil {
			require.NoError(t, response.Body.Close())
		}
		require.ErrorContains(t, err, "certificate signed by unknown authority")
		caSecret.Data["ca.crt"] = ca
		require.NoError(t, live.Update(ctx, caSecret))
		waitEvicted(t, cc.Name, cacheKey(ns, cc.Name))
		require.Equal(t, ca, checkToken("second").CAData)
		require.NoError(t, live.Delete(ctx, secret))
		waitEvicted(t, cc.Name, cacheKey(ns, cc.Name))
		cfg, err := provider.GetRESTConfig(ctx, cc.Name)
		require.NoError(t, err, "OIDC token errors are deferred to the transport")
		httpClient, err = rest.HTTPClientFor(cfg)
		require.NoError(t, err)
		response, err = httpClient.Get(server.URL + "/spoke")
		if response != nil {
			require.NoError(t, response.Body.Close())
		}
		require.Error(t, err, "deleted OIDC credentials must not authorize a request with the cached token")
	})
}
