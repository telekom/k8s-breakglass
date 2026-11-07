package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) clientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestServerTLSConfigClientAuth runs a real HTTPS handshake against the TLS
// policy that Listen installs.
func TestServerTLSConfigClientAuth(t *testing.T) {
	trusted := newTestCA(t, "trusted-client-ca")
	other := newTestCA(t, "other-client-ca")
	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	require.NoError(t, os.WriteFile(caFile, trusted.pem, 0o600))

	start := func(t *testing.T, mode string) *httptest.Server {
		t.Helper()
		cfg := config.Server{TLSCertFile: "unused.crt", TLSKeyFile: "unused.key", ClientAuth: mode}
		if mode == config.ClientAuthRequire || mode == config.ClientAuthVerifyIfGiven {
			cfg.ClientCAFile = caFile
		}
		tlsCfg, err := serverTLSConfig(cfg)
		require.NoError(t, err)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		srv.TLS = tlsCfg
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	get := func(srv *httptest.Server, cert *tls.Certificate) error {
		client := srv.Client()
		transport := client.Transport.(*http.Transport).Clone()
		if cert != nil {
			// Always present the certificate. With Certificates, crypto/tls
			// silently omits a certificate whose issuer is not in the server's
			// acceptable-CA list, which would not exercise server verification.
			transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return cert, nil
			}
		}
		client.Transport = transport
		resp, err := client.Get(srv.URL)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		return nil
	}
	trustedCert := trusted.clientCert(t)
	otherCert := other.clientCert(t)

	tests := []struct {
		name      string
		mode      string
		cert      *tls.Certificate
		wantError bool
	}{
		{name: "require/trusted", mode: config.ClientAuthRequire, cert: &trustedCert},
		{name: "require/other-ca", mode: config.ClientAuthRequire, cert: &otherCert, wantError: true},
		{name: "require/no-cert", mode: config.ClientAuthRequire, cert: nil, wantError: true},
		{name: "verifyIfGiven/trusted", mode: config.ClientAuthVerifyIfGiven, cert: &trustedCert},
		{name: "verifyIfGiven/other-ca", mode: config.ClientAuthVerifyIfGiven, cert: &otherCert, wantError: true},
		{name: "verifyIfGiven/no-cert", mode: config.ClientAuthVerifyIfGiven, cert: nil},
		{name: "request/other-ca", mode: config.ClientAuthRequest, cert: &otherCert},
		{name: "none/no-cert", mode: config.ClientAuthNone, cert: nil},
		{name: "unset/other-ca", mode: "", cert: &otherCert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := get(start(t, tt.mode), tt.cert)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
