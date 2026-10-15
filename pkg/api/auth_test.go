package api

import (
	"context"
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
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	upstreamoidc "github.com/telekom/k8s-breakglass/pkg/oidc"
	"go.uber.org/zap/zaptest"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
)

type staticIdentityProviderByIssuerLoader struct {
	cfg *config.IdentityProviderConfig
	err error
}

func TestInstallTargetIdentityResolverArbitraryClaimAndPrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := newSignedOIDCServer(t)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	auth := NewAuth(zaptest.NewLogger(t).Sugar(), config.Config{})
	t.Cleanup(auth.Close)
	token := server.token(t, server.key, jwt.MapClaims{
		"iss": server.server.URL, "aud": "breakglass", "employee_id": "k834798",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	auth.installTargetIdentityResolver(c, token, &config.IdentityProviderConfig{
		Issuer:               server.server.URL,
		Authority:            server.server.URL,
		ExpectedAudience:     "breakglass",
		CertificateAuthority: server.caPEM,
		UserIdentifierClaim:  "employee_id",
		UserIdentifierPrefix: "tdi_security_oidc:",
	})
	raw, exists := c.Get(upstreamoidc.TargetIdentityResolverKey)
	require.True(t, exists)
	resolver, ok := raw.(upstreamoidc.TargetIdentityResolver)
	require.True(t, ok)
	identity, err := resolver(context.Background(), nil, "")
	require.NoError(t, err)
	require.Equal(t, "tdi_security_oidc:k834798", identity.User.GetName())
}

func TestProviderEngineCacheReusesAndInvalidatesByConnectionPolicy(t *testing.T) {
	auth := NewAuth(zaptest.NewLogger(t).Sugar(), config.Config{})
	cfg := &config.IdentityProviderConfig{
		Issuer:               "https://issuer.example",
		JWKSURL:              "https://issuer.example/keys",
		SupportedSigningAlgs: []string{"RS256"},
	}
	policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: cfg.Issuer, Audiences: []string{"aud"}}}
	algorithms := []string{"RS256"}
	first, err := auth.providerEngine(policy, cfg, algorithms)
	require.NoError(t, err)
	second, err := auth.providerEngine(policy, cfg, algorithms)
	require.NoError(t, err)
	require.Same(t, first, second)
	cfg.JWKSURL = "https://issuer.example/rotated-keys"
	third, err := auth.providerEngine(policy, cfg, algorithms)
	require.NoError(t, err)
	require.NotSame(t, first, third)
	auth.Close()
	_, err = auth.providerEngine(policy, cfg, algorithms)
	require.ErrorContains(t, err, "closed")
	auth.Close()
}

func (s staticIdentityProviderByIssuerLoader) LoadIdentityProviderByIssuer(context.Context, string) (*config.IdentityProviderConfig, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.cfg, nil
}

func TestAuthHandler_Middleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a mock auth handler for testing
	authHandler := &AuthHandler{}

	tests := []struct {
		name           string
		method         string
		authHeader     string
		expectedStatus int
		expectNext     bool
		description    string
	}{
		{
			name:           "OPTIONS request should pass through",
			method:         "OPTIONS",
			authHeader:     "",
			expectedStatus: http.StatusOK,
			expectNext:     true,
			description:    "OPTIONS requests should be allowed through without auth check",
		},
		{
			name:           "Missing Authorization header",
			method:         "GET",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectNext:     false,
			description:    "Requests without Authorization header should be rejected",
		},
		{
			name:           "Invalid Authorization header format",
			method:         "GET",
			authHeader:     "Basic dGVzdA==",
			expectedStatus: http.StatusUnauthorized,
			expectNext:     false,
			description:    "Non-Bearer authorization headers should be rejected",
		},
		{
			name:           "Bearer token without actual token",
			method:         "GET",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusUnauthorized,
			expectNext:     false,
			description:    "Bearer header without token should be rejected",
		},
		{
			name:           "Invalid JWT token",
			method:         "GET",
			authHeader:     "Bearer invalid.jwt.token",
			expectedStatus: http.StatusUnauthorized,
			expectNext:     false,
			description:    "Invalid JWT tokens should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test router with the middleware
			router := gin.New()

			// Track if the next handler was called
			nextCalled := false

			router.Use(authHandler.Middleware())
			router.Any("/test", func(c *gin.Context) {
				nextCalled = true
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			// Create test request
			req, err := http.NewRequest(tt.method, "/test", nil)
			assert.NoError(t, err)

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Record the response
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Verify results
			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
			assert.Equal(t, tt.expectNext, nextCalled, "Next handler call expectation for: %s", tt.description)

			// Verify that Authorization header is removed from request
			if tt.method != "OPTIONS" {
				assert.Empty(t, req.Header.Get("Authorization"), "Authorization header should be removed")
			}
		})
	}
}

func TestNewAuth_DefaultHTTPClient(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	handler := NewAuth(log, config.Config{})

	require.NotNil(t, handler.defaultHTTPClient, "defaultHTTPClient must be initialized")
	assert.Equal(t, defaultOIDCTimeout, handler.defaultHTTPClient.Timeout)

	transport, ok := handler.defaultHTTPClient.Transport.(*http.Transport)
	require.True(t, ok, "transport must be *http.Transport")
	assert.GreaterOrEqual(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12),
		"TLS minimum version must be at least 1.2")

	// Verify the transport inherits DefaultTransport settings (proxy, timeouts)
	defaultT, dtOK := http.DefaultTransport.(*http.Transport)
	if dtOK {
		assert.NotNil(t, transport.Proxy, "transport should inherit proxy from DefaultTransport")
		assert.Equal(t, defaultT.MaxIdleConns, transport.MaxIdleConns)
		assert.Equal(t, defaultT.IdleConnTimeout, transport.IdleConnTimeout)
	}
}

func TestDefaultOIDCTransport(t *testing.T) {
	transport := defaultOIDCTransport()
	require.NotNil(t, transport)
	assert.GreaterOrEqual(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12),
		"TLS minimum version must be at least 1.2")

	defaultT, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		assert.Equal(t, defaultT.MaxIdleConns, transport.MaxIdleConns)
		assert.Equal(t, defaultT.IdleConnTimeout, transport.IdleConnTimeout)
	}
}

func TestAuthHeaderKey(t *testing.T) {
	assert.Equal(t, "Authorization", AuthHeaderKey, "AuthHeaderKey should be 'Authorization'")
}

func TestAuthHandler_MiddlewareErrorResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authHandler := &AuthHandler{}

	tests := []struct {
		name         string
		authHeader   string
		expectedBody string
	}{
		{
			name:         "No Bearer token error",
			authHeader:   "Basic test",
			expectedBody: `{"error":"No Bearer token provided in Authorization header","code":"UNAUTHORIZED"}`,
		},
		{
			name:         "Empty header error",
			authHeader:   "",
			expectedBody: `{"error":"No Bearer token provided in Authorization header","code":"UNAUTHORIZED"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(authHandler.Middleware())
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, err := http.NewRequest(http.MethodGet, "/test", nil)
			assert.NoError(t, err)

			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.JSONEq(t, tt.expectedBody, w.Body.String())
		})
	}
}

func TestAuthHandler_MiddlewareHeaderRemoval(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authHandler := &AuthHandler{}

	router := gin.New()
	router.Use(authHandler.Middleware())
	router.GET("/test", func(c *gin.Context) {
		// This should not be reached due to auth failure, but we can test header removal
		authHeader := c.Request.Header.Get("Authorization")
		c.JSON(http.StatusOK, gin.H{"auth_header": authHeader})
	})

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify header was removed
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestBuildCertPoolFromPEM(t *testing.T) {
	// Generate a valid test certificate dynamically
	validCertPEM := generateTestCertPEM(t)

	tests := []struct {
		name      string
		pemData   string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid certificate",
			pemData: validCertPEM,
			wantErr: false,
		},
		{
			name:      "invalid PEM data",
			pemData:   "not a valid certificate",
			wantErr:   true,
			errSubstr: "failed to append certificates",
		},
		{
			name:      "empty PEM data",
			pemData:   "",
			wantErr:   true,
			errSubstr: "failed to append certificates",
		},
		{
			name: "PEM with no certificate block",
			pemData: `-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA
-----END PRIVATE KEY-----`,
			wantErr:   true,
			errSubstr: "failed to append certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := buildCertPoolFromPEM(tt.pemData)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errSubstr != "" {
					assert.Contains(t, err.Error(), tt.errSubstr)
				}
				assert.Nil(t, pool)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pool)
			}
		})
	}
}

// generateTestCertPEM generates a valid self-signed certificate PEM for testing
func generateTestCertPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM)
}

// --- SEC-003: isValidIssuerURL tests ---

func TestIsValidIssuerURL(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		valid  bool
	}{
		{name: "valid HTTPS issuer", issuer: "https://auth.example.com", valid: true},
		{name: "valid HTTPS with path", issuer: "https://keycloak.example.com/realms/myrealm", valid: true},
		{name: "valid HTTPS with port", issuer: "https://auth.example.com:8443", valid: true},
		{name: "HTTP issuer rejected", issuer: "http://auth.example.com", valid: false},
		{name: "empty string", issuer: "", valid: false},
		{name: "random string", issuer: "not-a-url", valid: false},
		{name: "file scheme", issuer: "file:///etc/passwd", valid: false},
		{name: "javascript scheme", issuer: "javascript:alert(1)", valid: false},
		{name: "no scheme", issuer: "auth.example.com", valid: false},
		{name: "ftp scheme", issuer: "ftp://auth.example.com", valid: false},
		{name: "https without host", issuer: "https://", valid: false},
		{name: "extremely long issuer", issuer: "https://auth.example.com/" + strings.Repeat("a", maxIssuerLength), valid: false},
		{name: "HTTPS with fragment", issuer: "https://auth.example.com#fragment", valid: false},
		{name: "HTTPS with query", issuer: "https://auth.example.com?q=1", valid: false},
		{name: "HTTPS with userinfo", issuer: "https://user:pass@auth.example.com", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidIssuerURL(tt.issuer)
			assert.Equal(t, tt.valid, got, "isValidIssuerURL(%q)", tt.issuer)
		})
	}
}

// --- SEC-003: Middleware rejects invalid issuer format ---

func TestAuthMiddleware_RejectsInvalidIssuerFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	auth := &AuthHandler{log: zaptest.NewLogger(t).Sugar()}
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	tests := []struct {
		name           string
		issuer         string
		expectedStatus int
	}{
		{name: "HTTP issuer rejected", issuer: "http://evil.com", expectedStatus: http.StatusUnauthorized},
		{name: "file issuer rejected", issuer: "file:///etc/passwd", expectedStatus: http.StatusUnauthorized},
		{name: "empty issuer fails closed without a verifier", issuer: "", expectedStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"sub": "user-123",
				"exp": time.Now().Add(time.Minute).Unix(),
			}
			if tt.issuer != "" {
				claims["iss"] = tt.issuer
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokStr, signErr := tok.SignedString([]byte("test-key"))
			require.NoError(t, signErr)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokStr)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
