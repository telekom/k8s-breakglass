package cluster

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name       string
		envKey     string
		envValue   string
		defaultVal time.Duration
		expected   time.Duration
	}{
		{
			name:       "valid duration 10m",
			envKey:     "TEST_DURATION_10M",
			envValue:   "10m",
			defaultVal: 5 * time.Minute,
			expected:   10 * time.Minute,
		},
		{
			name:       "valid duration 300s",
			envKey:     "TEST_DURATION_300S",
			envValue:   "300s",
			defaultVal: 5 * time.Minute,
			expected:   300 * time.Second,
		},
		{
			name:       "valid duration 1h30m",
			envKey:     "TEST_DURATION_1H30M",
			envValue:   "1h30m",
			defaultVal: time.Hour,
			expected:   90 * time.Minute,
		},
		{
			name:       "env not set returns default",
			envKey:     "TEST_DURATION_NOT_SET",
			envValue:   "", // not set
			defaultVal: 15 * time.Minute,
			expected:   15 * time.Minute,
		},
		{
			name:       "invalid duration returns default",
			envKey:     "TEST_DURATION_INVALID",
			envValue:   "not-a-duration",
			defaultVal: 5 * time.Minute,
			expected:   5 * time.Minute,
		},
		{
			name:       "empty string returns default",
			envKey:     "TEST_DURATION_EMPTY",
			envValue:   "",
			defaultVal: 10 * time.Minute,
			expected:   10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set or unset the env variable
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			} else {
				os.Unsetenv(tt.envKey)
			}

			result := getEnvDuration(tt.envKey, tt.defaultVal)
			assert.Equal(t, tt.expected, result, "getEnvDuration should return expected duration")
		})
	}
}

func TestNewClientProvider(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fakeClient := fake.NewClientBuilder().Build()

	provider := NewClientProvider(fakeClient, logger.Sugar())

	assert.NotNil(t, provider)
	assert.NotNil(t, provider.k8s)
	assert.NotNil(t, provider.log)
	assert.NotNil(t, provider.data)
	assert.NotNil(t, provider.rest)
	assert.Empty(t, provider.data)
	assert.Empty(t, provider.rest)
}

// Note: More comprehensive tests require adding the API types to the scheme
// so the fake client can store/retrieve ClusterConfig objects. The tests below
// exercise REST config parsing, loopback host rewriting and caching behavior.

func mustBuildKubeconfigYAML(host string) []byte {
	// Build a minimal kubeconfig using the typed clientcmd API and marshal it
	cfg := clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{"test": {Server: host}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"user": {}},
		Contexts:       map[string]*clientcmdapi.Context{"ctx": {Cluster: "test", AuthInfo: "user"}},
		CurrentContext: "ctx",
	}

	b, err := clientcmd.Write(cfg)
	if err != nil {
		panic(err)
	}
	return b
}

func TestGetRESTConfig_RewritesLoopbackHostAndCaches(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://127.0.0.1:6443")

	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kube-secret", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	cfg, err := provider.GetRESTConfig(context.Background(), "default/my-cluster")
	assert.NoError(t, err)
	// loopback should be rewritten to cluster DNS
	assert.Equal(t, "https://kubernetes.default.svc", cfg.Host)

	// second call should return cached pointer
	cfg2, err2 := provider.GetRESTConfig(context.Background(), "default/my-cluster")
	assert.NoError(t, err2)
	assert.Same(t, cfg, cfg2)
}

func TestGetRESTConfigForPrivilegedOperationCapturesExactLiveClusterConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	qps := int32(25)
	spec := breakglassv1alpha1.ClusterConfigSpec{
		KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kube-secret", Namespace: "default"},
		QPS:                 &qps,
	}
	cached := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "default", UID: "cluster-uid", ResourceVersion: "1"},
		Spec:       spec,
	}
	live := cached.DeepCopy()
	live.ResourceVersion = "2"
	live.Labels = map[string]string{"source": "uncached"}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": mustBuildKubeconfigYAML("https://10.0.0.10:6443")},
	}
	cachedClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cached, secret).Build()
	liveReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(live, secret.DeepCopy()).Build()
	provider := NewClientProvider(cachedClient, zaptest.NewLogger(t).Sugar()).WithLiveReader(liveReader)

	_, snapshot, err := provider.GetRESTConfigForPrivilegedOperation(context.Background(), "default/privileged")
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	assert.Equal(t, types.UID("cluster-uid"), snapshot.UID)
	assert.Equal(t, "2", snapshot.ResourceVersion)
	assert.Equal(t, "uncached", snapshot.Labels["source"])
	assert.Equal(t, spec, snapshot.Spec)
}

func TestValidatePrivilegedOperationClusterConfigRejectsCredentialSecretChange(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "default", UID: "cluster-uid"},
		Spec:       breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kube-secret", Namespace: "default"}},
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default", ResourceVersion: "1"}, Data: map[string][]byte{"value": mustBuildKubeconfigYAML("https://10.0.0.10:6443")}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cc.DeepCopy(), secret.DeepCopy()).Build()
	provider := NewClientProvider(client, zaptest.NewLogger(t).Sugar()).WithLiveReader(client)
	_, snapshot, err := provider.GetRESTConfigForPrivilegedOperation(context.Background(), "default/privileged")
	require.NoError(t, err)
	changed := &corev1.Secret{}
	require.NoError(t, client.Get(context.Background(), ctrlclient.ObjectKeyFromObject(secret), changed))
	changed.Data["value"] = []byte("changed")
	require.NoError(t, client.Update(context.Background(), changed))
	err = provider.ValidatePrivilegedOperationClusterConfig(context.Background(), snapshot)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "privileged input secret/default/kube-secret changed")
}

func TestValidatePrivilegedOperationClusterConfigRejectsLiveChanges(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	qps := int32(25)
	snapshot := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "default", UID: "cluster-uid"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kube-secret", Namespace: "default"},
			QPS:                 &qps,
		},
	}
	now := metav1.Now()
	tests := []struct {
		name string
		live *breakglassv1alpha1.ClusterConfig
		want string
	}{
		{name: "deleted", want: "not found"},
		{name: "deleting", live: func() *breakglassv1alpha1.ClusterConfig {
			object := snapshot.DeepCopy()
			object.Finalizers = []string{"test.example/finalizer"}
			object.DeletionTimestamp = &now
			return object
		}(), want: "being deleted"},
		{name: "replaced", live: func() *breakglassv1alpha1.ClusterConfig {
			object := snapshot.DeepCopy()
			object.UID = "replacement-uid"
			return object
		}(), want: "was replaced"},
		{name: "spec changed", live: func() *breakglassv1alpha1.ClusterConfig {
			object := snapshot.DeepCopy()
			changedQPS := int32(50)
			object.Spec.QPS = &changedQPS
			return object
		}(), want: "spec changed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.live != nil {
				builder = builder.WithObjects(tt.live)
			}
			liveReader := builder.Build()
			provider := NewClientProvider(liveReader, zaptest.NewLogger(t).Sugar()).WithLiveReader(liveReader)

			err := provider.ValidatePrivilegedOperationClusterConfig(context.Background(), snapshot)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestGetRESTConfig_MissingSecretKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// secret contains default key, but ClusterConfig points to a different key
	kubeYAML := mustBuildKubeconfigYAML("https://example.com:6443")
	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "c2", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kube-secret-2", Namespace: "default", Key: "nonexistent"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret-2", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	_, err := provider.GetRESTConfig(context.Background(), "default/c2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing key")
}

func TestGet_CachingAndNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	first, err := provider.GetInNamespace(ctx, "default", "c1")
	assert.NoError(t, err)
	assert.Equal(t, "c1", first.Name)

	second, err2 := provider.GetInNamespace(ctx, "default", "c1")
	assert.NoError(t, err2)
	// Should return the same cached pointer
	assert.Same(t, first, second)

	// Non-existent cluster should return an error
	_, err3 := provider.GetInNamespace(ctx, "default", "does-not-exist")
	assert.Error(t, err3)
}

func TestInvalidate_ClearsCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ci1", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	first, err := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err)
	// cache hit
	second, err2 := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err2)
	assert.Same(t, first, second)

	// Invalidate and ensure subsequent Get produces a different pointer
	provider.Invalidate("default", "ci1")
	third, err3 := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err3)
	if first == third {
		t.Fatalf("expected different pointer after Invalidate, got same")
	}
}

func TestInvalidateSecret_EvictsTrackedEntries(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://kind-control-plane:6443")
	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "kind", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kind-kube", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kind-kube", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	firstCfg, err := provider.GetRESTConfig(ctx, "default/kind")
	assert.NoError(t, err)
	assert.True(t, provider.IsSecretTracked("default", "kind-kube"))

	provider.InvalidateSecret("default", "kind-kube")
	assert.False(t, provider.IsSecretTracked("default", "kind-kube"))

	secondCfg, err := provider.GetRESTConfig(ctx, "default/kind")
	assert.NoError(t, err)
	assert.NotSame(t, firstCfg, secondCfg, "expected rest config to be rebuilt after secret invalidation")
}

func TestIsSecretTracked_FalseForUnknownSecret(t *testing.T) {
	provider := NewClientProvider(fake.NewClientBuilder().Build(), zaptest.NewLogger(t).Sugar())
	assert.False(t, provider.IsSecretTracked("default", "missing"))
}

func TestTrackOIDCSecrets_TracksImplicitKeycloakSecret(t *testing.T) {
	for _, mode := range []string{"inherited", "refresh fallback", "refresh warn", "refresh empty", "refresh none", "explicit override"} {
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
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if r.Form.Get("grant_type") == "refresh_token" && mode != "refresh empty" && mode != "refresh none" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
					return
				}
				if r.Form.Get("grant_type") != "refresh_token" {
					grants <- r.Form.Get("client_secret")
				}
				_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600,"token_type":"Bearer"}`))
			}))
			defer server.Close()
			issuer = server.URL
			scheme := runtime.NewScheme()
			require.NoError(t, clientgoscheme.AddToScheme(scheme))
			require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
			idp := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared-idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{
				OIDC:     breakglassv1alpha1.OIDCConfig{Authority: issuer, ClientID: "client"},
				Keycloak: &breakglassv1alpha1.KeycloakGroupSync{ClientID: "service", ClientSecretRef: breakglassv1alpha1.SecretKeyReference{Name: "keycloak-secret", Namespace: "identity", Key: "value"}},
			}}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "keycloak-secret", Namespace: "identity"}, Data: map[string][]byte{"value": []byte("inherited-secret")}}
			explicit := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "explicit-secret", Namespace: "workloads"}, Data: map[string][]byte{"value": []byte("explicit-secret")}}
			refresh := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "refresh", Namespace: "workloads"}, Data: map[string][]byte{"token": []byte("expired-refresh")}}
			ref := &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: idp.Name, Server: issuer, InsecureSkipTLSVerify: true}
			if strings.HasPrefix(mode, "refresh ") {
				ref.RefreshTokenSecretRef = &breakglassv1alpha1.SecretKeyReference{Name: "refresh", Namespace: "workloads", Key: "token"}
				if mode == "refresh fallback" {
					ref.FallbackPolicy = breakglassv1alpha1.FallbackPolicyAuto
				}
				if mode == "refresh warn" {
					ref.FallbackPolicy = breakglassv1alpha1.FallbackPolicyWarn
				}
				if mode == "refresh none" {
					ref.FallbackPolicy = breakglassv1alpha1.FallbackPolicyNone
				}
			}
			if mode == "explicit override" {
				ref.ClientSecretRef = &breakglassv1alpha1.SecretKeyReference{Name: explicit.Name, Namespace: explicit.Namespace, Key: "value"}
			}
			cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "workloads"}, Spec: breakglassv1alpha1.ClusterConfigSpec{AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC, OIDCFromIdentityProvider: ref}}
			provider := NewClientProvider(fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp, secret, explicit, refresh, cc).Build(), zaptest.NewLogger(t).Sugar())
			_, err := provider.GetRESTConfig(context.Background(), "workloads/cluster")
			require.NoError(t, err)
			expected := "inherited-secret"
			if mode == "explicit override" {
				expected = "explicit-secret"
			}
			expectFallback := mode == "inherited" || mode == "refresh fallback" || mode == "refresh warn" || mode == "explicit override"
			select {
			case actual := <-grants:
				if !expectFallback {
					t.Fatalf("unexpected fallback client credential grant: %q", actual)
				}
				require.Equal(t, expected, actual)
			default:
				if expectFallback {
					t.Fatal("real credential resolution did not obtain a token")
				}
			}
			require.Equal(t, mode == "inherited" || mode == "refresh fallback" || mode == "refresh warn", provider.IsOIDCSecretTracked("identity", "keycloak-secret"))
			require.NotNil(t, provider.rest["workloads/cluster"])
			require.NotNil(t, provider.oidcProvider.tokens["workloads/cluster"])
			provider.InvalidateOIDCSecrets("identity", "keycloak-secret")
			if mode == "inherited" || mode == "refresh fallback" || mode == "refresh warn" {
				require.Nil(t, provider.rest["workloads/cluster"])
				require.Nil(t, provider.oidcProvider.tokens["workloads/cluster"])
			} else {
				require.NotNil(t, provider.rest["workloads/cluster"])
				require.NotNil(t, provider.oidcProvider.tokens["workloads/cluster"])
			}
			if strings.HasPrefix(mode, "refresh ") {
				provider.InvalidateOIDCSecrets("workloads", "refresh")
				require.Nil(t, provider.rest["workloads/cluster"])
				require.Nil(t, provider.oidcProvider.tokens["workloads/cluster"])
			}
		})
	}
}

func TestTrackOIDCSecrets_RefreshAutoToNoneClearsFallback(t *testing.T) {
	var issuer string
	refreshSucceeds := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "openid-configuration") {
			_, _ = fmt.Fprintf(w, `{"token_endpoint":%q}`, issuer+"/token")
			return
		}
		if r.FormValue("grant_type") == "refresh_token" && !refreshSucceeds {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"access","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()
	issuer = server.URL
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	idp := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared-idp"}, Spec: breakglassv1alpha1.IdentityProviderSpec{
		OIDC:     breakglassv1alpha1.OIDCConfig{Authority: issuer, ClientID: "client"},
		Keycloak: &breakglassv1alpha1.KeycloakGroupSync{ClientID: "service", ClientSecretRef: breakglassv1alpha1.SecretKeyReference{Name: "keycloak-secret", Namespace: "identity", Key: "value"}},
	}}
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "workloads"}, Spec: breakglassv1alpha1.ClusterConfigSpec{
		AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
		OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{Name: idp.Name, Server: issuer, InsecureSkipTLSVerify: true, FallbackPolicy: breakglassv1alpha1.FallbackPolicyAuto,
			RefreshTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "refresh", Namespace: "workloads", Key: "token"}},
	}}
	objects := []runtime.Object{idp, cc, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "keycloak-secret", Namespace: "identity"}, Data: map[string][]byte{"value": []byte("sa")}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "refresh", Namespace: "workloads"}, Data: map[string][]byte{"token": []byte("expired")}}}
	client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
	provider := NewClientProvider(client, zaptest.NewLogger(t).Sugar())
	_, err := provider.GetRESTConfig(context.Background(), "workloads/cluster")
	require.NoError(t, err)
	require.True(t, provider.IsOIDCSecretTracked("identity", "keycloak-secret"))
	cc.Spec.OIDCFromIdentityProvider.FallbackPolicy = breakglassv1alpha1.FallbackPolicyNone
	require.NoError(t, client.Update(context.Background(), cc))
	provider.Invalidate("workloads", "cluster")
	refreshSucceeds = true
	_, err = provider.GetRESTConfig(context.Background(), "workloads/cluster")
	require.NoError(t, err)
	require.False(t, provider.IsOIDCSecretTracked("identity", "keycloak-secret"))
	provider.oidcProvider.fallbackMu.RLock()
	_, fallbackPresent := provider.oidcProvider.fallbackCreds["workloads/cluster"]
	provider.oidcProvider.fallbackMu.RUnlock()
	require.False(t, fallbackPresent)
	require.NotNil(t, provider.rest["workloads/cluster"])
	provider.InvalidateOIDCSecrets("identity", "keycloak-secret")
	require.NotNil(t, provider.rest["workloads/cluster"])
	provider.InvalidateOIDCSecrets("workloads", "refresh")
	require.Nil(t, provider.rest["workloads/cluster"])
}

func TestOIDCGetRESTConfig_DirectTransitionClearsInheritedFallback(t *testing.T) {
	clientCredentialSecrets := make(chan string, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "openid-configuration") {
			issuer := "https://" + r.Host
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, issuer, issuer+"/token")
			return
		}
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		switch r.FormValue("grant_type") {
		case "refresh_token":
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		case "client_credentials":
			clientCredentialSecrets <- r.FormValue("client_secret")
			_, _ = fmt.Fprint(w, `{"access_token":"fallback-token","expires_in":3600,"token_type":"Bearer"}`)
		default:
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
		}
	}))
	defer server.Close()
	issuer := server.URL

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{Authority: issuer, ClientID: "refresh-client"},
			Keycloak: &breakglassv1alpha1.KeycloakGroupSync{
				ClientID: "service-account",
				ClientSecretRef: breakglassv1alpha1.SecretKeyReference{
					Name: "keycloak-secret", Namespace: "identity", Key: "value",
				},
			},
		},
	}
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster", Namespace: "workloads"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			AuthType: breakglassv1alpha1.ClusterAuthTypeOIDC,
			OIDCFromIdentityProvider: &breakglassv1alpha1.OIDCFromIdentityProviderConfig{
				Name: "shared-idp", Server: issuer, InsecureSkipTLSVerify: true,
				RefreshTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "refresh", Namespace: "workloads", Key: "token"},
				FallbackPolicy:        breakglassv1alpha1.FallbackPolicyAuto,
			},
		},
	}
	objects := []runtime.Object{
		idp,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "keycloak-secret", Namespace: "identity"}, Data: map[string][]byte{"value": []byte("old-sa-secret")}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "refresh", Namespace: "workloads"}, Data: map[string][]byte{"token": []byte("expired-refresh")}},
	}
	provider := NewOIDCTokenProvider(fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build(), zaptest.NewLogger(t).Sugar())

	_, err := provider.GetRESTConfig(context.Background(), cc)
	require.NoError(t, err)
	select {
	case secret := <-clientCredentialSecrets:
		require.Equal(t, "old-sa-secret", secret)
	default:
		t.Fatal("inherited configuration did not use its fallback credential")
	}

	key := tokenCacheKey(cc.Namespace, cc.Name)
	provider.mu.Lock()
	provider.tokens[key].expiresAt = time.Time{}
	provider.mu.Unlock()
	cc.Spec.OIDCFromIdentityProvider = nil
	cc.Spec.OIDCAuth = &breakglassv1alpha1.OIDCAuthConfig{
		IssuerURL: issuer, ClientID: "direct-client", Server: issuer,
		InsecureSkipTLSVerify: true,
		RefreshTokenSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "refresh", Namespace: "workloads", Key: "token"},
		FallbackPolicy:        breakglassv1alpha1.FallbackPolicyAuto,
	}

	_, err = provider.GetRESTConfig(context.Background(), cc)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrRefreshTokenExpired)
	select {
	case secret := <-clientCredentialSecrets:
		t.Fatalf("direct OIDC configuration reused a fallback credential: %q", secret)
	default:
	}
}

func TestGetAcrossAllNamespaces_DoesNotMatchSimilarNames(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	// Create clusters with similar names
	ccProd := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}
	ccMyProd := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-prod", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}
	ccTestProd := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-prod", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&ccProd, &ccMyProd, &ccTestProd).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// Fetch "my-prod" to cache it
	result, err := provider.GetAcrossAllNamespaces(ctx, "my-prod")
	assert.NoError(t, err)
	assert.Equal(t, "my-prod", result.Name, "should return exact match")

	// Now fetch "prod" - should NOT return "my-prod" from cache
	resultProd, err := provider.GetAcrossAllNamespaces(ctx, "prod")
	assert.NoError(t, err)
	assert.Equal(t, "prod", resultProd.Name, "should return exact match for 'prod', not 'my-prod'")

	// Fetch "test-prod" - should NOT return "prod" or "my-prod"
	resultTestProd, err := provider.GetAcrossAllNamespaces(ctx, "test-prod")
	assert.NoError(t, err)
	assert.Equal(t, "test-prod", resultTestProd.Name, "should return exact match for 'test-prod'")
}

func TestGetClientset_EmptyName(t *testing.T) {
	provider := NewClientProvider(fake.NewClientBuilder().Build(), zaptest.NewLogger(t).Sugar())
	cs, err := provider.GetClientset(context.Background(), "")
	assert.Error(t, err)
	assert.Nil(t, cs)
	assert.Contains(t, err.Error(), "cluster name must not be empty")
}

func TestGetClientset_CacheHitAndMiss(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://10.0.0.1:6443")

	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cs-cluster", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "cs-secret", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cs-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// First call: cache miss, creates clientset
	cs1, err := provider.GetClientset(ctx, "default/cs-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs1)

	// Second call: cache hit, returns same clientset
	cs2, err := provider.GetClientset(ctx, "default/cs-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs2)
	assert.Same(t, cs1, cs2, "second call should return cached clientset")
}

func TestGetClientset_BareVsNamespacedKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://10.0.0.3:6443")

	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "canon-cluster", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "canon-secret", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "canon-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// First call with bare name
	cs1, err := provider.GetClientset(ctx, "canon-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs1)

	// Second call with namespaced name — should return the same cached clientset
	cs2, err := provider.GetClientset(ctx, "default/canon-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs2)
	assert.Same(t, cs1, cs2, "bare name and namespaced name should resolve to the same cached clientset")

	// Reverse order: namespaced first, then bare
	provider2 := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	cs3, err := provider2.GetClientset(ctx, "default/canon-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs3)

	cs4, err := provider2.GetClientset(ctx, "canon-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs4)
	assert.Same(t, cs3, cs4, "namespaced name then bare name should resolve to the same cached clientset")
}

func TestGetClientset_EvictionClearsClientset(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://10.0.0.2:6443")

	cc := breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "evict-cluster", Namespace: "ns1"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "evict-secret", Namespace: "ns1"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "evict-secret", Namespace: "ns1"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// Populate clientset cache
	cs1, err := provider.GetClientset(ctx, "ns1/evict-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs1)

	// Verify it's cached
	provider.mu.RLock()
	_, cached := provider.clientsets[cacheKey("ns1", "evict-cluster")]
	provider.mu.RUnlock()
	assert.True(t, cached, "clientset should be in cache")

	// Invalidate the cluster → should clear clientset too
	provider.Invalidate("ns1", "evict-cluster")

	// Verify clientset was evicted
	provider.mu.RLock()
	_, stillCached := provider.clientsets[cacheKey("ns1", "evict-cluster")]
	provider.mu.RUnlock()
	assert.False(t, stillCached, "clientset should be evicted after Invalidate")

	// Next call should re-create the clientset
	cs3, err := provider.GetClientset(ctx, "ns1/evict-cluster")
	assert.NoError(t, err)
	assert.NotNil(t, cs3)
	assert.NotSame(t, cs1, cs3, "new clientset should be different after eviction")
}

func TestGetClientset_MissingClusterConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	cs, err := provider.GetClientset(context.Background(), "default/nonexistent")
	assert.Error(t, err)
	assert.Nil(t, cs)
	assert.Contains(t, err.Error(), "get REST config for clientset")
}
