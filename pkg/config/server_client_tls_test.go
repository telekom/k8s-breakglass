package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestServerClientTLSParsing(t *testing.T) {
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(`
server:
  tlsCertFile: /tls/tls.crt
  tlsKeyFile: /tls/tls.key
  clientCAFile: /tls/client-ca.pem
  clientAuth: verifyIfGiven
`), &cfg))
	assert.Equal(t, "/tls/client-ca.pem", cfg.Server.ClientCAFile)
	assert.Equal(t, ClientAuthVerifyIfGiven, cfg.Server.ClientAuth)
}

func TestServerClientTLS(t *testing.T) {
	ca := writeTestCA(t)
	notPEM := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))
	withTLS := func(s Server) Server { s.TLSCertFile, s.TLSKeyFile = "/tls.crt", "/tls.key"; return s }

	tests := []struct {
		name    string
		server  Server
		want    tls.ClientAuthType
		wantCAs bool
		wantErr string
	}{
		{name: "unset keeps today's behaviour without TLS", server: Server{}, want: tls.NoClientCert},
		{name: "unset keeps today's behaviour with TLS", server: withTLS(Server{}), want: tls.NoClientCert},
		{name: "none", server: withTLS(Server{ClientAuth: "none"}), want: tls.NoClientCert},
		{name: "request without CA", server: withTLS(Server{ClientAuth: "request"}), want: tls.RequestClientCert},
		{name: "verifyIfGiven", server: withTLS(Server{ClientAuth: "verifyIfGiven", ClientCAFile: ca}), want: tls.VerifyClientCertIfGiven, wantCAs: true},
		{name: "require", server: withTLS(Server{ClientAuth: "require", ClientCAFile: ca}), want: tls.RequireAndVerifyClientCert, wantCAs: true},
		{name: "require without CA", server: withTLS(Server{ClientAuth: "require"}), wantErr: "needs server.clientCAFile"},
		{name: "verifyIfGiven without CA", server: withTLS(Server{ClientAuth: "verifyIfGiven"}), wantErr: "needs server.clientCAFile"},
		{name: "CA without verifying mode", server: withTLS(Server{ClientCAFile: ca}), wantErr: "clientCAFile is set"},
		{name: "CA with request", server: withTLS(Server{ClientAuth: "request", ClientCAFile: ca}), wantErr: "clientCAFile is set"},
		{name: "unknown mode", server: withTLS(Server{ClientAuth: "Require"}), wantErr: "want one of"},
		{name: "client auth without server TLS", server: Server{ClientAuth: "require", ClientCAFile: ca}, wantErr: "needs server.tlsCertFile"},
		{name: "missing CA file", server: withTLS(Server{ClientAuth: "require", ClientCAFile: "/does/not/exist"}), wantErr: "read server.clientCAFile"},
		{name: "CA file without certificates", server: withTLS(Server{ClientAuth: "require", ClientCAFile: notPEM}), wantErr: "no PEM certificates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pool, err := tt.server.ClientTLS()
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantCAs, pool != nil)
		})
	}
}
