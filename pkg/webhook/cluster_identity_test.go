package webhook

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestCertificateNamesCluster(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		dns     []string
		uris    []string
		ips     []string
		emails  []string
		cluster string
		want    bool
	}{
		{name: "SAN match", cn: "ignored", dns: []string{"other", "prod-eu"}, cluster: "prod-eu", want: true},
		{name: "SAN mismatch ignores matching CN", cn: "prod-eu", dns: []string{"prod-us"}, cluster: "prod-eu", want: false},
		{name: "CN fallback without any SANs", cn: "prod-eu", cluster: "prod-eu", want: true},
		{name: "URI SAN only ignores matching CN", cn: "prod-eu", uris: []string{"spiffe://example.org/prod-eu"}, cluster: "prod-eu", want: false},
		{name: "IP SAN only ignores matching CN", cn: "prod-eu", ips: []string{"10.0.0.1"}, cluster: "prod-eu", want: false},
		{name: "email SAN only ignores matching CN", cn: "prod-eu", emails: []string{"apiserver@example.org"}, cluster: "prod-eu", want: false},
		{name: "CN mismatch", cn: "prod-us", cluster: "prod-eu", want: false},
		{name: "exact match only", cn: "Prod-EU", cluster: "prod-eu", want: false},
		{name: "empty cluster", cn: "", cluster: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: tt.cn}, DNSNames: tt.dns, EmailAddresses: tt.emails}
			for _, raw := range tt.uris {
				u, err := url.Parse(raw)
				require.NoError(t, err)
				cert.URIs = append(cert.URIs, u)
			}
			for _, ip := range tt.ips {
				cert.IPAddresses = append(cert.IPAddresses, net.ParseIP(ip))
			}
			assert.Equal(t, tt.want, CertificateNamesCluster(cert, tt.cluster))
		})
	}
}

// TestRequireClusterIdentity runs the middleware in front of a stub
// authorize handler on the dedicated listener's route.
func TestRequireClusterIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	verified := func(cn string, dns ...string) *tls.ConnectionState {
		leaf := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}
		return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	}
	tests := []struct {
		name  string
		state *tls.ConnectionState
		want  int
	}{
		{name: "plain HTTP", state: nil, want: http.StatusOK},
		{name: "no client certificate", state: &tls.ConnectionState{}, want: http.StatusOK},
		{name: "unverified certificate is not an identity", state: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "other"}}},
		}, want: http.StatusOK},
		{name: "own cluster by SAN", state: verified("apiserver", "prod-eu"), want: http.StatusOK},
		{name: "own cluster by CN", state: verified("prod-eu"), want: http.StatusOK},
		{name: "other cluster by SAN", state: verified("prod-eu", "prod-us"), want: http.StatusForbidden},
		{name: "other cluster by CN", state: verified("prod-us"), want: http.StatusForbidden},
		{name: "URI SAN only with matching CN", state: func() *tls.ConnectionState {
			leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "prod-eu"}, URIs: []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/prod-eu"}}}
			return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		}(), want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached := false
			r := gin.New()
			r.POST("/authorize/:cluster_name", RequireClusterIdentity(zap.NewNop().Sugar()), func(c *gin.Context) {
				reached = true
				c.Status(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodPost, "/authorize/prod-eu", nil)
			req.TLS = tt.state
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tt.want, w.Code)
			assert.Equal(t, tt.want == http.StatusOK, reached, "authorize handler reached")
		})
	}
}

// TestCertificateNamesClusterUnparsedSAN uses a parsed certificate whose only
// SAN is a registeredID, which crypto/x509 does not expose in any field: the
// SAN extension alone must still disable the CN fallback.
func TestCertificateNamesClusterUnparsedSAN(t *testing.T) {
	newCert := func(t *testing.T, extra []pkix.Extension) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			Subject:         pkix.Name{CommonName: "prod-eu"},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: extra,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}
	oid, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1})
	require.NoError(t, err)
	// GeneralNames ::= SEQUENCE OF GeneralName; registeredID is [8] IMPLICIT OID.
	san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: oid[2:]}})
	require.NoError(t, err)

	registeredID := newCert(t, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}})
	require.Empty(t, registeredID.DNSNames)
	require.Empty(t, registeredID.URIs)
	require.Empty(t, registeredID.IPAddresses)
	require.Empty(t, registeredID.EmailAddresses)
	assert.False(t, CertificateNamesCluster(registeredID, "prod-eu"), "registeredID-only SAN must not fall back to the CN")

	assert.True(t, CertificateNamesCluster(newCert(t, nil), "prod-eu"), "a certificate without SANs is matched by its CN")
}
