/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestOIDCTokenProvider_NewProvider(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(client, log)

	assert.NotNil(t, provider)
	assert.NotNil(t, provider.k8s)
	assert.NotNil(t, provider.log)
	assert.NotNil(t, provider.tokens)
}

func TestOIDCTokenProvider_GetRESTConfig_MissingOIDCAuth(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(client, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec:       telekomv1alpha1.ClusterConfigSpec{
			// OIDCAuth not set
		},
	}

	_, err := provider.GetRESTConfig(context.Background(), cc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either oidcAuth or oidcFromIdentityProvider configuration is required")
}

func TestOIDCTokenProvider_GetRESTConfig_WithMockedOIDCServer(t *testing.T) {
	// Create a mock OIDC server
	tokenResponse := tokenResponse{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	discoveryResponse := oidcDiscovery{
		Issuer:                "http://localhost",
		TokenEndpoint:         "http://localhost/token",
		AuthorizationEndpoint: "http://localhost/auth",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Update discovery response with actual server URL
	discoveryResponse.Issuer = server.URL
	discoveryResponse.TokenEndpoint = server.URL + "/token"

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create client secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("test-secret"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(client, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
			},
		},
	}

	cfg, err := provider.GetRESTConfig(context.Background(), cc)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Equal(t, "https://api.example.com:6443", cfg.Host)

	// With WrapTransport, BearerToken is empty - tokens are injected per-request
	assert.Empty(t, cfg.BearerToken, "BearerToken should be empty when using WrapTransport")
	assert.NotNil(t, cfg.WrapTransport, "WrapTransport should be set for dynamic token injection")

	// Verify token injection by wrapping a mock transport and making a request
	var capturedAuthHeader string
	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		capturedAuthHeader = req.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	wrappedTransport := cfg.WrapTransport(mockTransport)
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com:6443/api", nil)
	resp, _ := wrappedTransport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	assert.Equal(t, "Bearer test-access-token", capturedAuthHeader)
}

// roundTripperFunc is a function type that implements http.RoundTripper
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestOIDCTokenProvider_GetRESTConfig_MissingClientSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create mock OIDC server for discovery
	discoveryResponse := oidcDiscovery{
		Issuer:        "http://localhost",
		TokenEndpoint: "http://localhost/token",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error": "invalid_client"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	discoveryResponse.Issuer = server.URL
	discoveryResponse.TokenEndpoint = server.URL + "/token"

	// No secret created - should fail when fetching
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(client, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "missing-secret",
					Namespace: "default",
				},
			},
		},
	}

	// With WrapTransport, GetRESTConfig succeeds - error occurs on first request
	cfg, err := provider.GetRESTConfig(context.Background(), cc)
	require.NoError(t, err, "Config creation should succeed - error is deferred to request time")
	assert.NotNil(t, cfg.WrapTransport)

	// Error occurs when the transport tries to get a token
	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatal("Should not reach here - token acquisition should fail first")
		return nil, nil
	})
	wrappedTransport := cfg.WrapTransport(mockTransport)
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com:6443/api", nil)
	resp, err := wrappedTransport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client secret")
}

func TestOIDCTokenProvider_ConfiguresTLS(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create CA secret
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-ca",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"ca.crt": []byte("-----BEGIN CERTIFICATE-----\ntest-ca-cert\n-----END CERTIFICATE-----"),
		},
	}

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("test-secret"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(caSecret, clientSecret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(client, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
				CASecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "cluster-ca",
					Namespace: "default",
					Key:       "ca.crt",
				},
			},
		},
	}

	// With WrapTransport, GetRESTConfig succeeds - TLS is configured synchronously
	cfg, err := provider.GetRESTConfig(context.Background(), cc)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.WrapTransport, "WrapTransport should be set")
	// TLS CA data should be configured from the secret
	assert.NotEmpty(t, cfg.TLSClientConfig.CAData, "CAData should be set from caSecretRef")
}

func TestOIDCTokenProvider_ConfiguresTLS_InsecureSkipVerify(t *testing.T) {
	// Test that insecureSkipTLSVerify on OIDCAuthConfig sets Insecure on rest.Config
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create only client secret (no CA secret - we're using insecure)
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("test-secret"),
		},
	}

	// Create a mock OIDC server
	discoveryResponse := oidcDiscovery{
		Issuer:        "http://localhost",
		TokenEndpoint: "http://localhost/token",
	}
	tokenResp := tokenResponse{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	discoveryResponse.Issuer = server.URL
	discoveryResponse.TokenEndpoint = server.URL + "/token"

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientSecret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(client, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeOIDC,
			OIDCAuth: &telekomv1alpha1.OIDCAuthConfig{
				IssuerURL: server.URL,
				ClientID:  "test-client",
				Server:    "https://api.example.com:6443",
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "oidc-secret",
					Namespace: "default",
					Key:       "client-secret",
				},
				InsecureSkipTLSVerify: true,
			},
		},
	}

	cfg, err := provider.GetRESTConfig(context.Background(), cc)
	require.NoError(t, err, "GetRESTConfig should succeed with mock OIDC server")

	// Verify that TLS insecure is set
	assert.True(t, cfg.TLSClientConfig.Insecure, "TLSClientConfig.Insecure should be true when InsecureSkipTLSVerify is enabled")
	assert.Equal(t, "https://api.example.com:6443", cfg.Host)

	// With WrapTransport, BearerToken is empty - verify token is injected via transport
	assert.Empty(t, cfg.BearerToken, "BearerToken should be empty when using WrapTransport")
	assert.NotNil(t, cfg.WrapTransport, "WrapTransport should be set for dynamic token injection")

	// Verify token injection works
	var capturedAuthHeader string
	mockTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		capturedAuthHeader = req.Header.Get("Authorization")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	wrappedTransport := cfg.WrapTransport(mockTransport)
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com:6443/api", nil)
	resp, _ := wrappedTransport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	assert.Equal(t, "Bearer test-access-token", capturedAuthHeader)
}

func TestOIDCTokenProvider_RefreshToken(t *testing.T) {
	// Create a mock OIDC server that supports refresh tokens
	initialToken := tokenResponse{
		AccessToken:  "initial-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	refreshedToken := tokenResponse{
		AccessToken:  "refreshed-access-token",
		RefreshToken: "new-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	discoveryResponse := oidcDiscovery{
		Issuer:        "http://localhost",
		TokenEndpoint: "http://localhost/token",
	}

	tokenCallCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryResponse)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		grantType := r.Form.Get("grant_type")
		tokenCallCount++

		if grantType == "refresh_token" {
			// Verify refresh token was sent
			assert.Equal(t, "test-refresh-token", r.Form.Get("refresh_token"))
			_ = json.NewEncoder(w).Encode(refreshedToken)
		} else {
			_ = json.NewEncoder(w).Encode(initialToken)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	discoveryResponse.Issuer = server.URL
	discoveryResponse.TokenEndpoint = server.URL + "/token"

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create client secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("test-secret"),
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name:      "oidc-secret",
			Namespace: "default",
			Key:       "client-secret",
		},
	}

	// First call - should use client credentials
	token1, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	require.NoError(t, err)
	assert.Equal(t, "initial-access-token", token1)
	assert.Equal(t, 1, tokenCallCount)

	// Verify token is cached with refresh token
	provider.mu.RLock()
	cached := provider.tokens["default/test-cluster"]
	provider.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Equal(t, "test-refresh-token", cached.refreshToken)

	// Simulate token expiry by manually modifying the cache
	provider.mu.Lock()
	provider.tokens["default/test-cluster"].expiresAt = provider.tokens["default/test-cluster"].expiresAt.Add(-2 * time.Hour)
	provider.mu.Unlock()

	// Second call - should use refresh token
	token2, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	require.NoError(t, err)
	assert.Equal(t, "refreshed-access-token", token2)
	assert.Equal(t, 2, tokenCallCount) // One more call for refresh
}

func TestOIDCTokenProvider_TOFUCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Verify TOFU map is initialized
	assert.NotNil(t, provider.tofuCAs)

	// Test InvalidateTOFU
	provider.tofuMu.Lock()
	provider.tofuCAs["https://test-api:6443"] = []byte("test-ca")
	provider.tofuMu.Unlock()

	provider.InvalidateTOFU("https://test-api:6443")

	provider.tofuMu.RLock()
	_, exists := provider.tofuCAs["https://test-api:6443"]
	provider.tofuMu.RUnlock()

	assert.False(t, exists, "TOFU CA should be invalidated")
}

func TestOIDCTokenProvider_CacheToken(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Test caching a token with refresh token - this deprecated method
	// stores with empty namespace prefix, resulting in "/cluster-name" key
	token := &tokenResponse{
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
		ExpiresIn:    3600,
	}

	provider.cacheToken("test-cluster", token)

	provider.mu.RLock()
	cached := provider.tokens["/test-cluster"]
	provider.mu.RUnlock()

	require.NotNil(t, cached, "Token should be cached at key '/test-cluster' (empty namespace prefix)")
	assert.Equal(t, "test-access", cached.accessToken)
	assert.Equal(t, "test-refresh", cached.refreshToken)
	assert.WithinDuration(t, time.Now().Add(3600*time.Second), cached.expiresAt, 5*time.Second)
}

func TestOIDCTokenProvider_CacheTokenWithNamespaceExplicit(t *testing.T) {
	// This test verifies the primary use case for cacheTokenWithNamespace()
	// with an explicit namespace, ensuring namespace/name format is used
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	token := &tokenResponse{
		AccessToken:  "explicit-ns-token",
		RefreshToken: "explicit-refresh",
		ExpiresIn:    7200,
	}

	// Use explicit namespace
	provider.cacheTokenWithNamespace("production", "my-cluster", token)

	provider.mu.RLock()
	cached := provider.tokens["production/my-cluster"]
	provider.mu.RUnlock()

	require.NotNil(t, cached, "Token should be cached at 'production/my-cluster'")
	assert.Equal(t, "explicit-ns-token", cached.accessToken)
	assert.Equal(t, "explicit-refresh", cached.refreshToken)
	assert.WithinDuration(t, time.Now().Add(7200*time.Second), cached.expiresAt, 5*time.Second)
}

func TestOIDCTokenProvider_CacheTokenWithNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Cache tokens for the same cluster name in different namespaces
	token1 := &tokenResponse{AccessToken: "token-ns1", ExpiresIn: 3600}
	token2 := &tokenResponse{AccessToken: "token-ns2", ExpiresIn: 3600}

	provider.cacheTokenWithNamespace("namespace1", "cluster", token1)
	provider.cacheTokenWithNamespace("namespace2", "cluster", token2)

	provider.mu.RLock()
	cached1 := provider.tokens["namespace1/cluster"]
	cached2 := provider.tokens["namespace2/cluster"]
	provider.mu.RUnlock()

	require.NotNil(t, cached1, "Token for namespace1/cluster should exist")
	require.NotNil(t, cached2, "Token for namespace2/cluster should exist")
	assert.Equal(t, "token-ns1", cached1.accessToken)
	assert.Equal(t, "token-ns2", cached2.accessToken)
}

func TestOIDCTokenProvider_InvalidateDoesNotMatchSimilarNames(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Cache tokens for clusters with similar names
	token := &tokenResponse{AccessToken: "test", ExpiresIn: 3600}
	provider.cacheTokenWithNamespace("default", "prod", token)
	provider.cacheTokenWithNamespace("default", "my-prod", token)
	provider.cacheTokenWithNamespace("default", "test-prod", token)

	// Invalidate "prod" - should NOT affect "my-prod" or "test-prod"
	provider.Invalidate("prod")

	provider.mu.RLock()
	_, hasProd := provider.tokens["default/prod"]
	_, hasMyProd := provider.tokens["default/my-prod"]
	_, hasTestProd := provider.tokens["default/test-prod"]
	provider.mu.RUnlock()

	assert.False(t, hasProd, "default/prod should be invalidated")
	assert.True(t, hasMyProd, "default/my-prod should NOT be invalidated by Invalidate('prod')")
	assert.True(t, hasTestProd, "default/test-prod should NOT be invalidated by Invalidate('prod')")
}

func TestOIDCTokenProvider_InvalidateWithNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Cache tokens for the same cluster in different namespaces
	token := &tokenResponse{AccessToken: "test", ExpiresIn: 3600}
	provider.cacheTokenWithNamespace("ns1", "cluster", token)
	provider.cacheTokenWithNamespace("ns2", "cluster", token)

	// Invalidate only ns1/cluster
	provider.InvalidateWithNamespace("ns1", "cluster")

	provider.mu.RLock()
	_, hasNs1 := provider.tokens["ns1/cluster"]
	_, hasNs2 := provider.tokens["ns2/cluster"]
	provider.mu.RUnlock()

	assert.False(t, hasNs1, "ns1/cluster should be invalidated")
	assert.True(t, hasNs2, "ns2/cluster should NOT be invalidated")
}

func TestOIDCTokenProvider_OIDCFromIdentityProvider_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "non-existent-idp",
				Server: "https://api.cluster.example.com:6443",
			},
		},
	}

	_, err := provider.GetRESTConfig(context.Background(), cc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IdentityProvider \"non-existent-idp\" not found")
}

func TestOIDCTokenProvider_OIDCFromIdentityProvider_Disabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			OIDC: telekomv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Disabled: true,
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "disabled-idp",
				Server: "https://api.cluster.example.com:6443",
			},
		},
	}

	_, err := provider.GetRESTConfig(context.Background(), cc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IdentityProvider \"disabled-idp\" is disabled")
}

func TestOIDCTokenProvider_OIDCFromIdentityProvider_MissingClientSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			OIDC: telekomv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			// No Keycloak config, so no service account credentials
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "test-idp",
				Server: "https://api.cluster.example.com:6443",
				// No clientSecretRef provided either
			},
		},
	}

	_, err := provider.GetRESTConfig(context.Background(), cc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "clientSecretRef is required")
}

func TestOIDCTokenProvider_TokenExchange(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Token exchange call counter
	exchangeCallCount := 0

	// Create a mock OIDC server that supports token exchange
	oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			// Return discovery document
			discovery := map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)
			return
		}

		if r.URL.Path == "/token" && r.Method == http.MethodPost {
			_ = r.ParseForm()

			// Check this is a token exchange request
			if r.Form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange" {
				exchangeCallCount++

				// Verify required parameters
				subjectToken := r.Form.Get("subject_token")
				subjectTokenType := r.Form.Get("subject_token_type")
				clientID := r.Form.Get("client_id")

				if subjectToken == "" || clientID == "" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
					return
				}

				// Return exchanged token
				token := tokenResponse{
					AccessToken: "exchanged-access-token-" + subjectToken[:8],
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}

				// Log for debugging
				t.Logf("Token exchange: subject_token_type=%s, client_id=%s", subjectTokenType, clientID)

				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(token)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer oidcServer.Close()

	// Create secrets for subject token and client secret
	subjectTokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "subject-token-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"token": []byte("test-subject-token-12345"),
		},
	}

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-client-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("test-client-secret"),
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(subjectTokenSecret, clientSecret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: oidcServer.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name:      "oidc-client-secret",
			Namespace: "default",
			Key:       "client-secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "subject-token-secret",
				Namespace: "default",
				Key:       "token",
			},
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
			RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			Resource:           "https://api.example.com",
		},
	}

	// Call getToken - should use token exchange
	token, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	require.NoError(t, err)
	assert.Contains(t, token, "exchanged-access-token-test-sub")
	assert.Equal(t, 1, exchangeCallCount)

	// Verify token is cached
	provider.mu.RLock()
	cached := provider.tokens["default/test-cluster"]
	provider.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Contains(t, cached.accessToken, "exchanged-access-token")
}

func TestOIDCTokenProvider_TokenExchange_MissingSubjectTokenSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create mock OIDC server for discovery
	oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			discovery := map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(discovery)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer oidcServer.Close()

	// Only create client secret, not subject token secret
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "oidc-client-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("test-client-secret"),
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientSecret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: oidcServer.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name:      "oidc-client-secret",
			Namespace: "default",
			Key:       "client-secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "missing-subject-token",
				Namespace: "default",
				Key:       "token",
			},
		},
	}

	// Call getToken - should fail because subject token secret is missing
	_, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get subject token from secret")
}

func TestOIDCTokenProvider_TokenExchange_MissingSubjectTokenSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: "https://auth.example.com",
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name:      "oidc-client-secret",
			Namespace: "default",
			Key:       "client-secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled: true,
			// Missing SubjectTokenSecretRef
		},
	}

	// Call getToken - should fail because subjectTokenSecretRef is required
	_, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subjectTokenSecretRef")
}

func TestOIDCTokenProvider_PerformTOFU_UsesVerifyPeerCertificate(t *testing.T) {
	// This test verifies that performTOFU uses VerifyPeerCertificate callback
	// instead of InsecureSkipVerify, addressing the CodeQL security finding.
	// Since we can't easily mock TLS connections, this test verifies the
	// function gracefully handles invalid URLs and connection failures.

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	t.Run("invalid URL", func(t *testing.T) {
		_, err := provider.performTOFU(context.Background(), "://invalid-url")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid API server URL")
	})

	t.Run("connection failure", func(t *testing.T) {
		// Use a non-routable IP to ensure connection fails
		_, err := provider.performTOFU(context.Background(), "https://192.0.2.1:6443")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect to API server for TOFU")
	})

	t.Run("localhost connection timeout", func(t *testing.T) {
		// Use a localhost port that's unlikely to be in use
		_, err := provider.performTOFU(context.Background(), "https://localhost:9999")
		require.Error(t, err)
		// Should fail to connect (not hanging indefinitely due to proper timeout)
		assert.Contains(t, err.Error(), "failed to connect to API server for TOFU")
	})
}

func TestOIDCTokenProvider_Invalidate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Add tokens with both old-style (no namespace) and new-style (namespaced) keys
	// to verify backward compatibility
	provider.mu.Lock()
	// Old-style key (legacy format, no namespace)
	provider.tokens["cluster1"] = &cachedToken{accessToken: "old-style-token"}
	// New-style keys (namespace/name format)
	provider.tokens["ns1/cluster1"] = &cachedToken{accessToken: "ns1-token"}
	provider.tokens["ns2/cluster1"] = &cachedToken{accessToken: "ns2-token"}
	// Different cluster to verify no false matches
	provider.tokens["default/cluster2"] = &cachedToken{accessToken: "cluster2-token"}
	provider.mu.Unlock()

	// Verify all tokens exist before invalidation
	provider.mu.RLock()
	assert.NotNil(t, provider.tokens["cluster1"])
	assert.NotNil(t, provider.tokens["ns1/cluster1"])
	assert.NotNil(t, provider.tokens["ns2/cluster1"])
	assert.NotNil(t, provider.tokens["default/cluster2"])
	provider.mu.RUnlock()

	// Invalidate cluster1 - should remove both old-style and all namespaced entries
	provider.Invalidate("cluster1")

	// Verify: old-style "cluster1" and new-style "*/cluster1" entries are gone,
	// but cluster2 remains
	provider.mu.RLock()
	assert.Nil(t, provider.tokens["cluster1"], "Old-style key should be invalidated")
	assert.Nil(t, provider.tokens["ns1/cluster1"], "Namespaced ns1/cluster1 should be invalidated")
	assert.Nil(t, provider.tokens["ns2/cluster1"], "Namespaced ns2/cluster1 should be invalidated")
	assert.NotNil(t, provider.tokens["default/cluster2"], "cluster2 should NOT be affected")
	provider.mu.RUnlock()
}

func TestOIDCTokenProvider_InvalidateAll(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Add multiple tokens to the cache
	provider.mu.Lock()
	provider.tokens["cluster1"] = &cachedToken{accessToken: "test-token-1"}
	provider.tokens["cluster2"] = &cachedToken{accessToken: "test-token-2"}
	provider.tokens["cluster3"] = &cachedToken{accessToken: "test-token-3"}
	provider.mu.Unlock()

	// Verify tokens exist
	provider.mu.RLock()
	assert.Len(t, provider.tokens, 3)
	provider.mu.RUnlock()

	// Invalidate all
	provider.InvalidateAll()

	// Verify all tokens are gone
	provider.mu.RLock()
	assert.Len(t, provider.tokens, 0)
	provider.mu.RUnlock()
}

func TestOIDCTokenProvider_InvalidateTOFU(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewOIDCTokenProvider(k8sClient, log)

	// Add TOFU CAs to the cache
	provider.tofuMu.Lock()
	provider.tofuCAs["https://api.cluster1.example.com:6443"] = []byte("ca-1")
	provider.tofuCAs["https://api.cluster2.example.com:6443"] = []byte("ca-2")
	provider.tofuMu.Unlock()

	// Verify TOFU CAs exist
	provider.tofuMu.RLock()
	assert.NotNil(t, provider.tofuCAs["https://api.cluster1.example.com:6443"])
	assert.NotNil(t, provider.tofuCAs["https://api.cluster2.example.com:6443"])
	provider.tofuMu.RUnlock()

	// Invalidate one cluster
	provider.InvalidateTOFU("https://api.cluster1.example.com:6443")

	// Verify cluster1 TOFU is gone but cluster2 remains
	provider.tofuMu.RLock()
	assert.Nil(t, provider.tofuCAs["https://api.cluster1.example.com:6443"])
	assert.NotNil(t, provider.tofuCAs["https://api.cluster2.example.com:6443"])
	provider.tofuMu.RUnlock()
}
