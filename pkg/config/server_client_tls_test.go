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

func TestServerWebhookParsing(t *testing.T) {
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(`
server:
  webhook:
    listenAddress: ":8443"
    clientAuth: require
    clientCAFile: /tls/apiserver-ca.pem
    requireCommonNameMatch: false
    disableOnMainListener: true
`), &cfg))
	w := cfg.Server.Webhook
	assert.Equal(t, ":8443", w.ListenAddress)
	assert.Equal(t, ClientAuthRequire, w.ClientAuth)
	assert.Equal(t, "/tls/apiserver-ca.pem", w.ClientCAFile)
	require.NotNil(t, w.RequireCommonNameMatch)
	assert.False(t, w.IdentityRequired())
	assert.True(t, w.DisableOnMainListener)
}

func TestServerWebhookIdentityRequiredDefault(t *testing.T) {
	on, off := true, false
	for mode, want := range map[string]bool{"": false, "none": false, "request": false, "verifyIfGiven": false, "require": true} {
		assert.Equal(t, want, ServerWebhook{ClientAuth: mode}.IdentityRequired(), "clientAuth %q", mode)
	}
	assert.False(t, ServerWebhook{ClientAuth: "require", RequireCommonNameMatch: &off}.IdentityRequired())
	assert.True(t, ServerWebhook{ClientAuth: "verifyIfGiven", RequireCommonNameMatch: &on}.IdentityRequired())
}

func TestServerValidateWebhook(t *testing.T) {
	ca := writeTestCA(t)
	on, off := true, false
	withTLS := func(w ServerWebhook) Server {
		return Server{ListenAddress: ":8080", TLSCertFile: "/tls.crt", TLSKeyFile: "/tls.key", Webhook: w}
	}
	tests := []struct {
		name    string
		server  Server
		wantErr string
	}{
		{name: "unset keeps today's behaviour", server: Server{}},
		{name: "require", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "require", ClientCAFile: ca})},
		{name: "require and disabled on main", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "require", ClientCAFile: ca, DisableOnMainListener: true})},
		{name: "require without name match", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "require", ClientCAFile: ca, RequireCommonNameMatch: &off})},
		{name: "verifyIfGiven with name match", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "verifyIfGiven", ClientCAFile: ca, RequireCommonNameMatch: &on})},
		{name: "no client auth", server: withTLS(ServerWebhook{ListenAddress: ":8443"})},
		{name: "settings without listener", server: withTLS(ServerWebhook{ClientAuth: "require", ClientCAFile: ca}), wantErr: "need server.webhook.listenAddress"},
		{name: "disable main without listener", server: withTLS(ServerWebhook{DisableOnMainListener: true}), wantErr: "need server.webhook.listenAddress"},
		{name: "listener without server TLS", server: Server{Webhook: ServerWebhook{ListenAddress: ":8443"}}, wantErr: "needs server.tlsCertFile"},
		{name: "same address as main", server: withTLS(ServerWebhook{ListenAddress: ":8080"}), wantErr: "must differ from server.listenAddress"},
		{name: "require without CA", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "require"}), wantErr: "server.webhook.clientAuth \"require\" needs server.webhook.clientCAFile"},
		{name: "unknown mode", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "mutual"}), wantErr: "server.webhook.clientAuth \"mutual\": want one of"},
		{name: "missing CA file", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "require", ClientCAFile: "/does/not/exist"}), wantErr: "read server.webhook.clientCAFile"},
		{name: "name match without verification", server: withTLS(ServerWebhook{ListenAddress: ":8443", ClientAuth: "request", RequireCommonNameMatch: &on}), wantErr: "requireCommonNameMatch needs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.server.ValidateWebhook()
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
