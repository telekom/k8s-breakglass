package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "missing server",
			opts:    []Option{},
			wantErr: true,
		},
		{
			name: "valid config",
			opts: []Option{
				WithServer("https://example.com"),
				WithToken("test-token"),
			},
			wantErr: false,
		},
		{
			name: "with custom user agent",
			opts: []Option{
				WithServer("https://example.com"),
				WithUserAgent("test-agent"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.opts...)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, client)
			} else {
				require.NoError(t, err)
				require.NotNil(t, client)
			}
		})
	}
}

func TestClientDo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		require.Equal(t, "Bearer test-token", auth)

		ua := r.Header.Get("User-Agent")
		require.Equal(t, "test-agent", ua)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client, err := New(
		WithServer(server.URL),
		WithToken("test-token"),
		WithUserAgent("test-agent"),
	)
	require.NoError(t, err)

	var result map[string]string
	err = client.do(context.Background(), http.MethodGet, "/test", nil, &result)
	require.NoError(t, err)
	require.Equal(t, "ok", result["status"])
}

func TestClientDoError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	client, err := New(WithServer(server.URL))
	require.NoError(t, err)

	err = client.do(context.Background(), http.MethodGet, "/missing", nil, nil)
	require.Error(t, err)

	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusNotFound, httpErr.StatusCode)
	require.Contains(t, httpErr.Message, "not found")
}

func TestHTTPError(t *testing.T) {
	err := &HTTPError{
		StatusCode: http.StatusForbidden,
		Message:    "access denied",
	}
	require.Equal(t, "request failed (403): access denied", err.Error())
}

func TestWithTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			name:    "positive timeout",
			timeout: 30 * time.Second,
			want:    30 * time.Second,
		},
		{
			name:    "zero timeout keeps default",
			timeout: 0,
			want:    DefaultTimeout,
		},
		{
			name:    "negative timeout keeps default",
			timeout: -1 * time.Second,
			want:    DefaultTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(
				WithServer("https://example.com"),
				WithTimeout(tt.timeout),
			)
			require.NoError(t, err)
			require.Equal(t, tt.want, client.timeout)
		})
	}
}

func TestWithTLSConfig_InsecureSkipVerify(t *testing.T) {
	// Test with insecureSkipTLSVerify = true and no CA file
	client, err := New(
		WithServer("https://example.com"),
		WithTLSConfig("", true),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify the transport was set up
	transport, ok := client.http.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	require.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestWithTLSConfig_CAFile(t *testing.T) {
	// Create a temporary CA file with valid PEM content
	tmpFile, err := os.CreateTemp("", "ca-*.crt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Generate a self-signed CA certificate for testing
	testCertPEM := generateTestCertPEM(t)
	_, err = tmpFile.WriteString(testCertPEM)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	client, err := New(
		WithServer("https://example.com"),
		WithTLSConfig(tmpFile.Name(), false),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify the transport was set up with CA pool
	transport, ok := client.http.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	require.NotNil(t, transport.TLSClientConfig.RootCAs)
	require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestWithTLSConfig_CAFileNotFound(t *testing.T) {
	_, err := New(
		WithServer("https://example.com"),
		WithTLSConfig("/nonexistent/ca.crt", false),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read CA file")
}

func TestWithTLSConfig_InvalidPEM(t *testing.T) {
	// Create a temporary file with invalid PEM content
	tmpFile, err := os.CreateTemp("", "invalid-*.crt")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("not a valid certificate")
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	_, err = New(
		WithServer("https://example.com"),
		WithTLSConfig(tmpFile.Name(), false),
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse CA file")
}

func TestLoadTLSConfig(t *testing.T) {
	tests := []struct {
		name     string
		caFile   string
		insecure bool
		wantErr  bool
	}{
		{
			name:     "empty CA file with insecure",
			caFile:   "",
			insecure: true,
			wantErr:  false,
		},
		{
			name:     "empty CA file without insecure",
			caFile:   "",
			insecure: false,
			wantErr:  false,
		},
		{
			name:     "nonexistent CA file",
			caFile:   "/nonexistent/path/ca.crt",
			insecure: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := loadTLSConfig(tt.caFile, tt.insecure)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, tlsConfig)
				require.Equal(t, tt.insecure, tlsConfig.InsecureSkipVerify)
			}
		})
	}
}

// generateTestCertPEM generates a self-signed certificate for testing purposes
func generateTestCertPEM(t *testing.T) string {
	t.Helper()

	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Encode to PEM
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return string(pemBlock)
}
