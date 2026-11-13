package webhook

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestCertificateNamesCluster(t *testing.T) {
	tests := []struct {
		name    string
		cn      string
		dns     []string
		cluster string
		want    bool
	}{
		{name: "SAN match", cn: "ignored", dns: []string{"other", "prod-eu"}, cluster: "prod-eu", want: true},
		{name: "SAN mismatch ignores matching CN", cn: "prod-eu", dns: []string{"prod-us"}, cluster: "prod-eu", want: false},
		{name: "CN fallback without SANs", cn: "prod-eu", cluster: "prod-eu", want: true},
		{name: "CN mismatch", cn: "prod-us", cluster: "prod-eu", want: false},
		{name: "exact match only", cn: "Prod-EU", cluster: "prod-eu", want: false},
		{name: "empty cluster", cn: "", cluster: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: tt.cn}, DNSNames: tt.dns}
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
