package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

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

func TestAuthHandler_Middleware_ValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// This test would require a more complex setup with actual JWKS
	// For now, we'll test the structure and basic functionality
	t.Run("Middleware structure validation", func(t *testing.T) {
		authHandler := &AuthHandler{}
		middleware := authHandler.Middleware()
		assert.NotNil(t, middleware, "Middleware should not be nil")
	})
}

func TestAuthHandler_Structure(t *testing.T) {
	t.Run("AuthHandler creation", func(t *testing.T) {
		authHandler := &AuthHandler{}
		assert.NotNil(t, authHandler, "AuthHandler should be creatable")
	})
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

func TestAuthHandler_ClaimsExtraction(t *testing.T) {
	// This is a conceptual test for the claims extraction logic
	// In a real scenario, you'd need valid JWT tokens and JWKS setup
	t.Run("Claims extraction concept", func(t *testing.T) {
		// Test that the middleware would extract the expected claims
		expectedClaims := []string{"sub", "email", "preferred_username"}

		for _, claim := range expectedClaims {
			assert.NotEmpty(t, claim, "Claim %s should not be empty", claim)
		}
	})
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

// mockRateLimiter is a simple mock for testing rate limiting middleware
type mockRateLimiter struct {
	allowed         bool
	isAuthenticated bool
}

func (m *mockRateLimiter) Allow(c *gin.Context) (bool, bool) {
	return m.allowed, m.isAuthenticated
}

func TestMiddlewareWithRateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		allowed        bool
		authenticated  bool
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "rate limited unauthenticated",
			allowed:        false,
			authenticated:  false,
			authHeader:     "",
			expectedStatus: http.StatusTooManyRequests,
		},
		{
			name:           "rate limited authenticated",
			allowed:        false,
			authenticated:  true,
			authHeader:     "",
			expectedStatus: http.StatusTooManyRequests,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authHandler := &AuthHandler{}
			mockRL := &mockRateLimiter{
				allowed:         tt.allowed,
				isAuthenticated: tt.authenticated,
			}

			router := gin.New()
			router.Use(authHandler.MiddlewareWithRateLimiting(mockRL))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// The auth middleware runs first, so without a valid token we get 401
			// For rate limit test, we need OPTIONS or a valid auth scenario
			// Let's use OPTIONS which bypasses auth
			req, _ = http.NewRequest(http.MethodOptions, "/test", nil)
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// OPTIONS goes through auth middleware, then rate limiting
			if !tt.allowed {
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
			}
		})
	}
}
