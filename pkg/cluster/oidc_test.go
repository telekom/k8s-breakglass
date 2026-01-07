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
	"net/http"
	"net/http/httptest"
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
	assert.Equal(t, "test-access-token", cfg.BearerToken)
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

	_, err := provider.GetRESTConfig(context.Background(), cc)
	assert.Error(t, err)
	// Should fail when trying to fetch the missing secret
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

	// This will fail at token fetch, but we can verify the TLS config path
	_, err := provider.GetRESTConfig(context.Background(), cc)
	// Error expected due to missing OIDC server, but TLS config should be set up
	assert.Error(t, err)
	// The error should be about token fetch, not TLS
	assert.Contains(t, err.Error(), "token")
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
	cached := provider.tokens["test-cluster"]
	provider.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Equal(t, "test-refresh-token", cached.refreshToken)

	// Simulate token expiry by manually modifying the cache
	provider.mu.Lock()
	provider.tokens["test-cluster"].expiresAt = provider.tokens["test-cluster"].expiresAt.Add(-2 * time.Hour)
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

	// Test caching a token with refresh token
	token := &tokenResponse{
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
		ExpiresIn:    3600,
	}

	provider.cacheToken("test-cluster", token)

	provider.mu.RLock()
	cached := provider.tokens["test-cluster"]
	provider.mu.RUnlock()

	require.NotNil(t, cached)
	assert.Equal(t, "test-access", cached.accessToken)
	assert.Equal(t, "test-refresh", cached.refreshToken)
	assert.WithinDuration(t, time.Now().Add(3600*time.Second), cached.expiresAt, 5*time.Second)
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
	cached := provider.tokens["test-cluster"]
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
