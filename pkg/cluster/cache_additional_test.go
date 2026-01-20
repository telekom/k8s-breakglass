package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// getRESTConfigFromOIDC Tests
// ============================================================================

func TestGetRESTConfigFromOIDC_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create mock OIDC server
	tokenResp := tokenResponse{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create client secret
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("test-secret")},
	}

	// Create ClusterConfig with OIDC auth
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.oidc-cluster.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name: "oidc-secret", Namespace: "default", Key: "client-secret",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, clientSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	cfg, err := provider.GetRESTConfig(ctx, "oidc-cluster")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "https://api.oidc-cluster.example.com:6443", cfg.Host)
	assert.NotNil(t, cfg.WrapTransport, "WrapTransport should be set for OIDC auth")
}

func TestGetRESTConfigFromOIDC_NilOIDCProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://auth.example.com",
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cc).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	// Set oidcProvider to nil to test error handling
	provider.oidcProvider = nil

	ctx := context.Background()
	_, err := provider.getRESTConfigFromOIDC(ctx, cc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC provider not initialized")
}

func TestGetRESTConfig_OIDCWithCaching(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create mock OIDC server
	tokenCallCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCallCount++
		tokenResp := tokenResponse{AccessToken: "token", ExpiresIn: 3600}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("secret")},
	}

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cached-oidc-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name: "oidc-secret", Namespace: "default", Key: "client-secret",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, clientSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// First call - should cache the config
	cfg1, err := provider.GetRESTConfig(ctx, "cached-oidc-cluster")
	require.NoError(t, err)

	// Second call - should return cached config
	cfg2, err := provider.GetRESTConfig(ctx, "cached-oidc-cluster")
	require.NoError(t, err)

	// Should be the same pointer (cached)
	assert.Same(t, cfg1, cfg2)
}

func TestGetRESTConfig_InferOIDCAuthType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenResp := tokenResponse{AccessToken: "token", ExpiresIn: 3600}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("secret")},
	}

	// ClusterConfig without explicit authType but with OIDCAuth - should infer OIDC
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "inferred-oidc-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			// No AuthType specified - should be inferred from OIDCAuth
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name: "oidc-secret", Namespace: "default", Key: "client-secret",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, clientSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	cfg, err := provider.GetRESTConfig(ctx, "inferred-oidc-cluster")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.WrapTransport, "Should use OIDC auth (inferred)")
}

func TestGetRESTConfig_InferKubeconfigAuthType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://api.example.com:6443")

	// ClusterConfig without explicit authType but with KubeconfigSecretRef - should infer Kubeconfig
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "inferred-kube-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			// No AuthType specified - should be inferred from KubeconfigSecretRef
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "kube-secret", Namespace: "default",
			},
		},
	}

	kubeSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, &kubeSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	cfg, err := provider.GetRESTConfig(ctx, "inferred-kube-cluster")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Nil(t, cfg.WrapTransport, "Should use Kubeconfig auth (no WrapTransport)")
}

func TestGetRESTConfig_NoAuthMethodConfigured(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// ClusterConfig without any auth configuration
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "no-auth-cluster", Namespace: "default"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{
			// No AuthType, no OIDCAuth, no KubeconfigSecretRef
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.GetRESTConfig(ctx, "no-auth-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication method configured")
}

func TestGetRESTConfig_UnsupportedAuthType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// ClusterConfig with unsupported auth type
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "unsupported-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: "UnsupportedType",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.GetRESTConfig(ctx, "unsupported-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth type")
}

func TestGetRESTConfig_OIDCWithQPSAndBurst(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenResp := tokenResponse{AccessToken: "token", ExpiresIn: 3600}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-secret", Namespace: "default"},
		Data:       map[string][]byte{"client-secret": []byte("secret")},
	}

	qps := int32(100)
	burst := int32(200)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-qps-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			QPS:      &qps,
			Burst:    &burst,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name: "oidc-secret", Namespace: "default", Key: "client-secret",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, clientSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	cfg, err := provider.GetRESTConfig(ctx, "oidc-qps-cluster")
	require.NoError(t, err)
	assert.Equal(t, float32(100), cfg.QPS)
	assert.Equal(t, 200, cfg.Burst)
}

// ============================================================================
// Invalidation and Cache Eviction Tests
// ============================================================================

func TestEvictClusterLocked_RemovesAllRelatedData(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://api.example.com:6443")

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "evict-test", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "kube-secret", Namespace: "default",
			},
		},
	}

	kubeSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, &kubeSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// Load the config to populate caches
	_, err := provider.GetRESTConfig(ctx, "evict-test")
	require.NoError(t, err)
	_, err = provider.GetInNamespace(ctx, "default", "evict-test")
	require.NoError(t, err)

	// Verify caches are populated
	provider.mu.RLock()
	assert.NotEmpty(t, provider.data)
	assert.NotEmpty(t, provider.rest)
	assert.True(t, provider.IsSecretTracked("default", "kube-secret"))
	provider.mu.RUnlock()

	// Evict the cluster
	provider.Invalidate("evict-test")

	// Verify caches are cleared
	provider.mu.RLock()
	defer provider.mu.RUnlock()

	// The data map should be empty for this cluster
	for k := range provider.data {
		assert.NotContains(t, k, "evict-test")
	}
	_, hasRest := provider.rest["evict-test"]
	assert.False(t, hasRest)
}

func TestInvalidateSecret_RemovesMultipleClusters(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://api.example.com:6443")

	// Two clusters using the same secret
	cc1 := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-1", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "shared-secret", Namespace: "default",
			},
		},
	}
	cc2 := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-2", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "shared-secret", Namespace: "default",
			},
		},
	}

	sharedSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc1, &cc2, &sharedSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// Load both configs
	_, err := provider.GetRESTConfig(ctx, "cluster-1")
	require.NoError(t, err)
	_, err = provider.GetRESTConfig(ctx, "cluster-2")
	require.NoError(t, err)

	// Both should be tracked
	assert.True(t, provider.IsSecretTracked("default", "shared-secret"))

	// Invalidate the shared secret
	provider.InvalidateSecret("default", "shared-secret")

	// Both clusters should be evicted
	provider.mu.RLock()
	_, hasCluster1 := provider.rest["cluster-1"]
	_, hasCluster2 := provider.rest["cluster-2"]
	provider.mu.RUnlock()

	assert.False(t, hasCluster1)
	assert.False(t, hasCluster2)
	assert.False(t, provider.IsSecretTracked("default", "shared-secret"))
}

// ============================================================================
// getRESTConfigFromKubeconfig Edge Cases
// ============================================================================

func TestGetRESTConfigFromKubeconfig_CustomSecretKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://api.example.com:6443")

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-key-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "kube-secret",
				Namespace: "default",
				Key:       "custom-kubeconfig-key",
			},
		},
	}

	kubeSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"custom-kubeconfig-key": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, &kubeSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	cfg, err := provider.GetRESTConfig(ctx, "custom-key-cluster")
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com:6443", cfg.Host)
}

func TestGetRESTConfigFromKubeconfig_WithQPSAndBurst(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://api.example.com:6443")

	qps := int32(50)
	burst := int32(100)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "qps-burst-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			QPS:   &qps,
			Burst: &burst,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "kube-secret", Namespace: "default",
			},
		},
	}

	kubeSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, &kubeSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	cfg, err := provider.GetRESTConfig(ctx, "qps-burst-cluster")
	require.NoError(t, err)
	assert.Equal(t, float32(50), cfg.QPS)
	assert.Equal(t, 100, cfg.Burst)
}

func TestGetRESTConfigFromKubeconfig_InvalidKubeconfig(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-kube-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "kube-secret", Namespace: "default",
			},
		},
	}

	kubeSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": []byte("invalid-kubeconfig-yaml")},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, &kubeSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.GetRESTConfig(ctx, "invalid-kube-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse kubeconfig")
}

func TestGetRESTConfigFromKubeconfig_SecretNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-secret-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "non-existent-secret", Namespace: "default",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.GetRESTConfig(ctx, "missing-secret-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch kubeconfig secret")
}

func TestGetRESTConfigFromKubeconfig_MissingKubeconfigSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "no-ref-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			// KubeconfigSecretRef is nil
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.getRESTConfigFromKubeconfig(ctx, cc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kubeconfigSecretRef is required")
}

// ============================================================================
// GetAcrossAllNamespaces Tests
// ============================================================================

func TestGetAcrossAllNamespaces_CachesResult(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "any-ns-cluster", Namespace: "some-namespace"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "secret", Namespace: "some-namespace",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// First call - should fetch from API
	result1, err := provider.GetAcrossAllNamespaces(ctx, "any-ns-cluster")
	require.NoError(t, err)
	assert.Equal(t, "any-ns-cluster", result1.Name)
	assert.Equal(t, "some-namespace", result1.Namespace)

	// Second call - should return cached
	result2, err := provider.GetAcrossAllNamespaces(ctx, "any-ns-cluster")
	require.NoError(t, err)

	// Note: With legacy behavior (empty namespace key), pointers may differ
	// but the data should be the same
	assert.Equal(t, result1.Name, result2.Name)
	assert.Equal(t, result1.Namespace, result2.Namespace)
}

func TestGetAcrossAllNamespaces_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.GetAcrossAllNamespaces(ctx, "non-existent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClusterConfigNotFound)
}

// ============================================================================
// Cache TTL Tests
// ============================================================================

func TestRESTConfigCacheTTL_Expiry(t *testing.T) {
	// Test that cache entries have proper expiry times set
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://api.example.com:6443")

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ttl-test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "kube-secret", Namespace: "default",
			},
		},
	}

	kubeSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&cc, &kubeSecret).
		Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	_, err := provider.GetRESTConfig(ctx, "ttl-test-cluster")
	require.NoError(t, err)

	// Check that the cache entry has an expiry time
	provider.mu.RLock()
	cached, ok := provider.rest["ttl-test-cluster"]
	provider.mu.RUnlock()

	require.True(t, ok)
	assert.False(t, cached.expiresAt.IsZero())
	assert.True(t, cached.expiresAt.After(time.Now()))
}
