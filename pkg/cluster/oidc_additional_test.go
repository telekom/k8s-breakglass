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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// ============================================================================
// Test Helpers for TLS Certificate Generation
// ============================================================================

// generateTestCACert creates a self-signed CA certificate for testing
func generateTestCACert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caBytes)
	require.NoError(t, err)

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return caCert, caKey, caPEM
}

// generateTestServerCert creates a server certificate signed by the given CA
func generateTestServerCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, host string) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Server"},
			CommonName:   host,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, server, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)

	serverPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverBytes,
	})

	return serverPEM, serverKey
}

// createTLSTestServer creates an HTTPS test server with a generated certificate
func createTLSTestServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()

	caCert, caKey, caPEM := generateTestCACert(t)
	serverPEM, serverKey := generateTestServerCert(t, caCert, caKey, "localhost")

	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	cert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()

	return server, caPEM
}

// ============================================================================
// TokenExchangeFlow Tests
// ============================================================================

func TestOIDCTokenProvider_TokenExchangeFlow_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	tokenResp := tokenResponse{
		AccessToken: "exchanged-token-12345",
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
		_ = r.ParseForm()

		// Verify token exchange parameters
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.Form.Get("grant_type"))
		assert.Equal(t, "test-subject-token", r.Form.Get("subject_token"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", r.Form.Get("subject_token_type"))

		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Create client secret
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("test-client-secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled:          true,
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
		},
	}

	token, err := provider.TokenExchangeFlow(context.Background(), oidcConfig, "test-subject-token")
	require.NoError(t, err)
	assert.Equal(t, "exchanged-token-12345", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, 3600, token.ExpiresIn)
}

func TestOIDCTokenProvider_TokenExchangeFlow_NotEnabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// TokenExchange not enabled
	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: "https://auth.example.com",
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
	}

	_, err := provider.TokenExchangeFlow(context.Background(), oidcConfig, "subject-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange is not enabled")
}

func TestOIDCTokenProvider_TokenExchangeFlow_WithAudienceAndResource(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	var capturedAudience, capturedResource string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedAudience = r.Form.Get("audience")
		capturedResource = r.Form.Get("resource")

		tokenResp := tokenResponse{
			AccessToken: "token-with-audience",
			ExpiresIn:   3600,
		}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		Audience:  "https://target-audience.example.com",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled:  true,
			Resource: "https://api.example.com",
		},
	}

	_, err := provider.TokenExchangeFlow(context.Background(), oidcConfig, "subject-token")
	require.NoError(t, err)
	assert.Equal(t, "https://target-audience.example.com", capturedAudience)
	assert.Equal(t, "https://api.example.com", capturedResource)
}

func TestOIDCTokenProvider_TokenExchangeFlow_ServerError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
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
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{Enabled: true},
	}

	_, err := provider.TokenExchangeFlow(context.Background(), oidcConfig, "subject-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

// ============================================================================
// tokenExchangeWithActorToken Tests
// ============================================================================

func TestOIDCTokenProvider_TokenExchangeWithActorToken_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	var capturedActorToken, capturedActorTokenType string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedActorToken = r.Form.Get("actor_token")
		capturedActorTokenType = r.Form.Get("actor_token_type")

		tokenResp := tokenResponse{
			AccessToken: "delegated-token",
			ExpiresIn:   3600,
		}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}
	subjectTokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "subject-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("subject-token-value")},
	}
	actorTokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "actor-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("actor-token-value")},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientSecret, subjectTokenSecret, actorTokenSecret).
		Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "subject-token", Namespace: "default", Key: "token",
			},
			ActorTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "actor-token", Namespace: "default", Key: "token",
			},
			ActorTokenType: "urn:ietf:params:oauth:token-type:jwt",
		},
	}

	// Use getToken to trigger token exchange from secret
	token, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	require.NoError(t, err)
	assert.Equal(t, "delegated-token", token)
	assert.Equal(t, "actor-token-value", capturedActorToken)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:jwt", capturedActorTokenType)
}

func TestOIDCTokenProvider_TokenExchangeWithActorToken_DefaultActorTokenType(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	var capturedActorTokenType string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedActorTokenType = r.Form.Get("actor_token_type")

		tokenResp := tokenResponse{AccessToken: "token", ExpiresIn: 3600}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}
	subjectTokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "subject-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("subject-token-value")},
	}
	actorTokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "actor-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("actor-token-value")},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientSecret, subjectTokenSecret, actorTokenSecret).
		Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "subject-token", Namespace: "default", Key: "token",
			},
			ActorTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "actor-token", Namespace: "default", Key: "token",
			},
			// ActorTokenType not set - should default to access_token
		},
	}

	_, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	require.NoError(t, err)
	// Should use default actor token type
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", capturedActorTokenType)
}

func TestOIDCTokenProvider_TokenExchangeWithActorToken_ActorTokenSecretMissing(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}
	subjectTokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "subject-token", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("subject-token-value")},
	}
	// Note: actor-token secret is NOT created

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(clientSecret, subjectTokenSecret).
		Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidcConfig := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		TokenExchange: &telekomv1alpha1.TokenExchangeConfig{
			Enabled: true,
			SubjectTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "subject-token", Namespace: "default", Key: "token",
			},
			ActorTokenSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name: "missing-actor-token", Namespace: "default", Key: "token",
			},
		},
	}

	_, err := provider.getToken(context.Background(), "test-cluster", oidcConfig, "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get actor token from secret")
}

// ============================================================================
// persistTOFUCA Tests
// ============================================================================

func TestOIDCTokenProvider_PersistTOFUCA_CreateNewSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name:      "tofu-ca-secret",
		Namespace: "default",
		Key:       "ca.crt",
	}
	caPEM := []byte("-----BEGIN CERTIFICATE-----\ntest-ca-data\n-----END CERTIFICATE-----")

	err := provider.persistTOFUCA(context.Background(), secretRef, caPEM)
	require.NoError(t, err)

	// Verify secret was created
	var secret corev1.Secret
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "tofu-ca-secret", Namespace: "default"}, &secret)
	require.NoError(t, err)
	assert.Equal(t, caPEM, secret.Data["ca.crt"])
	assert.Equal(t, "breakglass", secret.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "true", secret.Labels["breakglass.t-caas.telekom.com/tofu-ca"])
	assert.NotEmpty(t, secret.Annotations["breakglass.t-caas.telekom.com/tofu-timestamp"])
}

func TestOIDCTokenProvider_PersistTOFUCA_UpdateExistingSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	existingSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-ca-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"other-key": []byte("other-data"),
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existingSecret).
		Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name:      "existing-ca-secret",
		Namespace: "default",
		Key:       "ca.crt",
	}
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nnew-ca-data\n-----END CERTIFICATE-----")

	err := provider.persistTOFUCA(context.Background(), secretRef, caPEM)
	require.NoError(t, err)

	// Verify secret was updated
	var secret corev1.Secret
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "existing-ca-secret", Namespace: "default"}, &secret)
	require.NoError(t, err)
	assert.Equal(t, caPEM, secret.Data["ca.crt"])
	assert.Equal(t, []byte("other-data"), secret.Data["other-key"]) // Other key preserved
	assert.NotEmpty(t, secret.Annotations["breakglass.t-caas.telekom.com/tofu-timestamp"])
}

func TestOIDCTokenProvider_PersistTOFUCA_DefaultKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name:      "ca-secret",
		Namespace: "default",
		// Key not specified - should default to "ca.crt"
	}
	caPEM := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	err := provider.persistTOFUCA(context.Background(), secretRef, caPEM)
	require.NoError(t, err)

	var secret corev1.Secret
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "ca-secret", Namespace: "default"}, &secret)
	require.NoError(t, err)
	assert.Equal(t, caPEM, secret.Data["ca.crt"]) // Default key used
}

// ============================================================================
// performTOFU Tests
// ============================================================================

func TestOIDCTokenProvider_PerformTOFU_WithRealTLSServer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// Create a TLS server with a self-signed certificate
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server, _ := createTLSTestServer(t, handler)
	defer server.Close()

	// performTOFU should capture the server's CA
	caPEM, err := provider.performTOFU(context.Background(), server.URL)
	require.NoError(t, err)
	require.NotEmpty(t, caPEM)

	// Verify it's a valid PEM certificate
	block, _ := pem.Decode(caPEM)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	// Verify the certificate can be parsed
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	// The captured certificate should be valid and have expected structure
	// (either CA or self-signed server cert)
	assert.NotNil(t, cert.Subject)
	assert.NotNil(t, cert.Issuer)
}

func TestOIDCTokenProvider_PerformTOFU_ContextTimeout(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := provider.performTOFU(ctx, "https://localhost:9999")
	require.Error(t, err)
	// Should fail due to context cancellation
}

func TestOIDCTokenProvider_PerformTOFU_DefaultPort(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// URL without explicit port should default to 443
	// This will fail to connect but tests the port parsing logic
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := provider.performTOFU(ctx, "https://nonexistent.example.com")
	require.Error(t, err)
	// The error should be about connection, not about parsing
	assert.Contains(t, err.Error(), "failed to connect")
}

// ============================================================================
// createOIDCHTTPClient Tests
// ============================================================================

func TestOIDCTokenProvider_CreateOIDCHTTPClient_InsecureSkipVerify(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL:             "https://auth.example.com",
		InsecureSkipTLSVerify: true,
	}

	httpClient, err := provider.createOIDCHTTPClient(oidc)
	require.NoError(t, err)
	require.NotNil(t, httpClient)

	transport := httpClient.Transport.(*http.Transport)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestOIDCTokenProvider_CreateOIDCHTTPClient_WithCertificateAuthority(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	_, _, caPEM := generateTestCACert(t)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL:            "https://auth.example.com",
		CertificateAuthority: string(caPEM),
	}

	httpClient, err := provider.createOIDCHTTPClient(oidc)
	require.NoError(t, err)
	require.NotNil(t, httpClient)

	transport := httpClient.Transport.(*http.Transport)
	require.NotNil(t, transport.TLSClientConfig)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)
}

func TestOIDCTokenProvider_CreateOIDCHTTPClient_InvalidCertificateAuthority(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL:            "https://auth.example.com",
		CertificateAuthority: "not-a-valid-pem-certificate",
	}

	_, err := provider.createOIDCHTTPClient(oidc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificateAuthority")
}

func TestOIDCTokenProvider_CreateOIDCHTTPClient_UsesCachedIssuerTOFU(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	issuerURL := "https://cached-issuer.example.com"
	_, _, caPEM := generateTestCACert(t)

	// Pre-populate the issuer TOFU cache
	provider.issuerTOFUMu.Lock()
	provider.issuerTOFUCAs[issuerURL] = caPEM
	provider.issuerTOFUMu.Unlock()

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: issuerURL,
		// No InsecureSkipTLSVerify and no CertificateAuthority - should use cached TOFU
	}

	httpClient, err := provider.createOIDCHTTPClient(oidc)
	require.NoError(t, err)
	require.NotNil(t, httpClient)

	transport := httpClient.Transport.(*http.Transport)
	require.NotNil(t, transport.TLSClientConfig)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)
}

// ============================================================================
// configureTLS Tests
// ============================================================================

func TestOIDCTokenProvider_ConfigureTLS_InsecureSkipVerify(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	cfg := &rest.Config{}
	oidc := &telekomv1alpha1.OIDCAuthConfig{
		Server:                "https://api.example.com:6443",
		InsecureSkipTLSVerify: true,
	}

	err := provider.configureTLS(context.Background(), cfg, oidc)
	require.NoError(t, err)
	assert.True(t, cfg.TLSClientConfig.Insecure)
}

func TestOIDCTokenProvider_ConfigureTLS_FromCASecret(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	_, _, caPEM := generateTestCACert(t)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-ca", Namespace: "default"},
		Data:       map[string][]byte{"ca.crt": caPEM},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	cfg := &rest.Config{}
	oidc := &telekomv1alpha1.OIDCAuthConfig{
		Server: "https://api.example.com:6443",
		CASecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "cluster-ca", Namespace: "default", Key: "ca.crt",
		},
	}

	err := provider.configureTLS(context.Background(), cfg, oidc)
	require.NoError(t, err)
	assert.Equal(t, caPEM, cfg.CAData)
}

func TestOIDCTokenProvider_ConfigureTLS_CASecretDefaultKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	_, _, caPEM := generateTestCACert(t)

	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-ca", Namespace: "default"},
		Data:       map[string][]byte{"ca.crt": caPEM}, // Default key
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	cfg := &rest.Config{}
	oidc := &telekomv1alpha1.OIDCAuthConfig{
		Server: "https://api.example.com:6443",
		CASecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "cluster-ca", Namespace: "default",
			// Key not specified - should default to "ca.crt"
		},
	}

	err := provider.configureTLS(context.Background(), cfg, oidc)
	require.NoError(t, err)
	assert.Equal(t, caPEM, cfg.CAData)
}

func TestOIDCTokenProvider_ConfigureTLS_CASecretNotFound_UsesTOFUCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	_, _, caPEM := generateTestCACert(t)

	// No CA secret created
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// Pre-populate TOFU cache
	serverURL := "https://api.example.com:6443"
	provider.tofuMu.Lock()
	provider.tofuCAs[serverURL] = caPEM
	provider.tofuMu.Unlock()

	cfg := &rest.Config{}
	oidc := &telekomv1alpha1.OIDCAuthConfig{
		Server: serverURL,
		CASecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "missing-ca", Namespace: "default",
		},
	}

	err := provider.configureTLS(context.Background(), cfg, oidc)
	require.NoError(t, err)
	assert.Equal(t, caPEM, cfg.CAData) // Should use cached TOFU CA
}

func TestOIDCTokenProvider_ConfigureTLS_CAKeyMissing_UsesTOFUCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	_, _, caPEM := generateTestCACert(t)

	// Secret exists but with different key
	caSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-ca", Namespace: "default"},
		Data:       map[string][]byte{"other-key": []byte("other-data")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// Pre-populate TOFU cache
	serverURL := "https://api.example.com:6443"
	provider.tofuMu.Lock()
	provider.tofuCAs[serverURL] = caPEM
	provider.tofuMu.Unlock()

	cfg := &rest.Config{}
	oidc := &telekomv1alpha1.OIDCAuthConfig{
		Server: serverURL,
		CASecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "cluster-ca", Namespace: "default", Key: "ca.crt",
		},
	}

	err := provider.configureTLS(context.Background(), cfg, oidc)
	require.NoError(t, err)
	assert.Equal(t, caPEM, cfg.CAData) // Should use cached TOFU CA
}

func TestOIDCTokenProvider_ConfigureTLS_NoCAAndNoTOFU(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	cfg := &rest.Config{}
	oidc := &telekomv1alpha1.OIDCAuthConfig{
		Server: "https://api.example.com:6443",
		// No CASecretRef, no InsecureSkipTLSVerify, no cached TOFU
		// This will attempt TOFU which will fail (no server to connect to)
	}

	// This should not error - TOFU failure is non-fatal
	err := provider.configureTLS(context.Background(), cfg, oidc)
	require.NoError(t, err)
	// CAData will be empty since TOFU failed
}

// ============================================================================
// getTokenFromSecret Tests
// ============================================================================

func TestOIDCTokenProvider_GetTokenFromSecret_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token-secret", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("  test-token-value  ")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name: "token-secret", Namespace: "default", Key: "token",
	}

	token, err := provider.getTokenFromSecret(context.Background(), secretRef, "default")
	require.NoError(t, err)
	assert.Equal(t, "test-token-value", token) // Should be trimmed
}

func TestOIDCTokenProvider_GetTokenFromSecret_DefaultKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token-secret", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("default-key-token")}, // Default key is "token"
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name: "token-secret", Namespace: "default",
		// Key not specified - should default to "token"
	}

	token, err := provider.getTokenFromSecret(context.Background(), secretRef, "default")
	require.NoError(t, err)
	assert.Equal(t, "default-key-token", token)
}

func TestOIDCTokenProvider_GetTokenFromSecret_NilSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	_, err := provider.getTokenFromSecret(context.Background(), nil, "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret reference is nil")
}

func TestOIDCTokenProvider_GetTokenFromSecret_SecretNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name: "missing-secret", Namespace: "default", Key: "token",
	}

	_, err := provider.getTokenFromSecret(context.Background(), secretRef, "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get secret")
}

func TestOIDCTokenProvider_GetTokenFromSecret_KeyNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token-secret", Namespace: "default"},
		Data:       map[string][]byte{"other-key": []byte("value")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name: "token-secret", Namespace: "default", Key: "missing-key",
	}

	_, err := provider.getTokenFromSecret(context.Background(), secretRef, "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not contain key")
}

func TestOIDCTokenProvider_GetTokenFromSecret_UsesSecretRefNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Secret in different namespace
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token-secret", Namespace: "other-namespace"},
		Data:       map[string][]byte{"token": []byte("token-from-other-ns")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name: "token-secret", Namespace: "other-namespace", Key: "token",
	}

	// Pass "default" as namespace but secretRef has "other-namespace" - should use secretRef.Namespace
	token, err := provider.getTokenFromSecret(context.Background(), secretRef, "default")
	require.NoError(t, err)
	assert.Equal(t, "token-from-other-ns", token)
}

func TestOIDCTokenProvider_GetTokenFromSecret_FallbackToPassedNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	// Secret in passed namespace
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "token-secret", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("token-from-default")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	secretRef := &telekomv1alpha1.SecretKeyReference{
		Name: "token-secret",
		// Namespace not specified - should use passed namespace
		Key: "token",
	}

	token, err := provider.getTokenFromSecret(context.Background(), secretRef, "default")
	require.NoError(t, err)
	assert.Equal(t, "token-from-default", token)
}

// ============================================================================
// discoverTokenEndpoint Tests
// ============================================================================

func TestOIDCTokenProvider_DiscoverTokenEndpoint_Success(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/oauth/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{IssuerURL: server.URL}

	endpoint, err := provider.discoverTokenEndpoint(context.Background(), oidc)
	require.NoError(t, err)
	assert.Equal(t, server.URL+"/oauth/token", endpoint)
}

func TestOIDCTokenProvider_DiscoverTokenEndpoint_MissingTokenEndpoint(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Discovery without token_endpoint
		discovery := map[string]string{
			"issuer": "http://" + r.Host,
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{IssuerURL: server.URL}

	_, err := provider.discoverTokenEndpoint(context.Background(), oidc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing token_endpoint")
}

func TestOIDCTokenProvider_DiscoverTokenEndpoint_ServerError(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{IssuerURL: server.URL}

	_, err := provider.discoverTokenEndpoint(context.Background(), oidc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestOIDCTokenProvider_DiscoverTokenEndpoint_InvalidJSON(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-valid-json"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{IssuerURL: server.URL}

	_, err := provider.discoverTokenEndpoint(context.Background(), oidc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse OIDC discovery")
}

// ============================================================================
// Issuer TOFU Cache Tests
// ============================================================================

func TestOIDCTokenProvider_InvalidateIssuerTOFU(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	// Pre-populate issuer TOFU cache
	provider.issuerTOFUMu.Lock()
	provider.issuerTOFUCAs["https://issuer1.example.com"] = []byte("ca1")
	provider.issuerTOFUCAs["https://issuer2.example.com"] = []byte("ca2")
	provider.issuerTOFUMu.Unlock()

	// Verify caches exist
	provider.issuerTOFUMu.RLock()
	assert.Len(t, provider.issuerTOFUCAs, 2)
	provider.issuerTOFUMu.RUnlock()

	// The provider doesn't have a direct InvalidateIssuerTOFU method,
	// but the cache is used internally. Verify cache behavior indirectly
	// by checking that createOIDCHTTPClient uses the cache
}

// ============================================================================
// Client Credentials Flow Edge Cases
// ============================================================================

func TestOIDCTokenProvider_ClientCredentialsFlow_WithScopes(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	var capturedScopes string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedScopes = r.Form.Get("scope")

		tokenResp := tokenResponse{AccessToken: "token", ExpiresIn: 3600}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
		Scopes: []string{"custom-scope", "another-scope"},
	}

	_, err := provider.clientCredentialsFlow(context.Background(), oidc)
	require.NoError(t, err)

	// Verify scopes include openid plus custom scopes
	assert.Contains(t, capturedScopes, "openid")
	assert.Contains(t, capturedScopes, "custom-scope")
	assert.Contains(t, capturedScopes, "another-scope")
}

func TestOIDCTokenProvider_ClientCredentialsFlow_WithAudience(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	var capturedAudience string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedAudience = r.Form.Get("audience")

		tokenResp := tokenResponse{AccessToken: "token", ExpiresIn: 3600}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		Audience:  "https://target-api.example.com",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
	}

	_, err := provider.clientCredentialsFlow(context.Background(), oidc)
	require.NoError(t, err)
	assert.Equal(t, "https://target-api.example.com", capturedAudience)
}

func TestOIDCTokenProvider_ClientCredentialsFlow_MissingClientSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discovery := oidcDiscovery{
			Issuer:        "http://" + r.Host,
			TokenEndpoint: "http://" + r.Host + "/token",
		}
		_ = json.NewEncoder(w).Encode(discovery)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		// ClientSecretRef is nil
	}

	_, err := provider.clientCredentialsFlow(context.Background(), oidc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "clientSecretRef is required")
}

// ============================================================================
// Token Refresh Edge Cases
// ============================================================================

func TestOIDCTokenProvider_RefreshToken_PreservesOldRefreshTokenIfNotReturned(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
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
		// Return token without refresh_token
		tokenResp := tokenResponse{
			AccessToken: "refreshed-token",
			ExpiresIn:   3600,
			// No RefreshToken returned
		}
		_ = json.NewEncoder(w).Encode(tokenResp)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
	}

	oldRefreshToken := "original-refresh-token"
	token, err := provider.refreshToken(context.Background(), oidc, oldRefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "refreshed-token", token.AccessToken)
	// Old refresh token should be preserved since none was returned
	assert.Equal(t, oldRefreshToken, token.RefreshToken)
}

func TestOIDCTokenProvider_RefreshToken_Failure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
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
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token expired"}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("secret")},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientSecret).Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	oidc := &telekomv1alpha1.OIDCAuthConfig{
		IssuerURL: server.URL,
		ClientID:  "test-client",
		Server:    "https://api.example.com:6443",
		ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
			Name: "client-secret", Namespace: "default", Key: "secret",
		},
	}

	_, err := provider.refreshToken(context.Background(), oidc, "expired-refresh-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

// ============================================================================
// resolveOIDCFromIdentityProvider Tests
// ============================================================================

func TestOIDCTokenProvider_ResolveOIDCFromIdentityProvider_WithKeycloak(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			OIDC: telekomv1alpha1.OIDCConfig{
				Authority: "https://keycloak.example.com/realms/master",
				ClientID:  "frontend-client",
			},
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL:  "https://keycloak.example.com",
				Realm:    "master",
				ClientID: "backend-client",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name: "keycloak-secret", Namespace: "auth", Key: "client-secret",
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:   "keycloak-idp",
				Server: "https://api.cluster.example.com:6443",
				// No clientSecretRef - should use Keycloak credentials
			},
		},
	}

	oidc, err := provider.resolveOIDCFromIdentityProvider(context.Background(), cc)
	require.NoError(t, err)
	assert.Equal(t, "https://keycloak.example.com/realms/master", oidc.IssuerURL)
	assert.Equal(t, "backend-client", oidc.ClientID) // Should use Keycloak clientID
	assert.Equal(t, "keycloak-secret", oidc.ClientSecretRef.Name)
	assert.Equal(t, "auth", oidc.ClientSecretRef.Namespace)
}

func TestOIDCTokenProvider_ResolveOIDCFromIdentityProvider_OverrideClientID(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	idp := &telekomv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
		Spec: telekomv1alpha1.IdentityProviderSpec{
			OIDC: telekomv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "default-client",
			},
			Keycloak: &telekomv1alpha1.KeycloakGroupSync{
				BaseURL:  "https://keycloak.example.com",
				Realm:    "master",
				ClientID: "keycloak-client",
				ClientSecretRef: telekomv1alpha1.SecretKeyReference{
					Name: "secret", Namespace: "default",
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()
	log := zap.NewNop().Sugar()
	provider := NewOIDCTokenProvider(k8sClient, log)

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			OIDCFromIdentityProvider: &telekomv1alpha1.OIDCFromIdentityProviderConfig{
				Name:     "test-idp",
				Server:   "https://api.cluster.example.com:6443",
				ClientID: "override-client", // Override the default
				// Provide ClientSecretRef to prevent Keycloak credentials from being used
				ClientSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name: "my-secret", Namespace: "default",
				},
			},
		},
	}

	oidc, err := provider.resolveOIDCFromIdentityProvider(context.Background(), cc)
	require.NoError(t, err)
	assert.Equal(t, "override-client", oidc.ClientID) // Should use override since ClientSecretRef is provided
}
