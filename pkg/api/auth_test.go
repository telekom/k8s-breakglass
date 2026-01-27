package api

import (
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
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
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

	// Note: Comprehensive JWT validation tests with actual JWKS verification
	// are in auth_jwt_test.go (TestAuthMiddleware_ExposesTokenAndRawClaims,
	// TestAuthMiddleware_GroupNormalizationCases, etc.) and auth_jwt_negative_test.go.
	// This test only validates the middleware function signature and basic structure.
	t.Run("Middleware structure validation", func(t *testing.T) {
		authHandler := &AuthHandler{}
		middleware := authHandler.Middleware()
		assert.NotNil(t, middleware, "Middleware should not be nil")
		// Verify it's a valid Gin handler function
		var handler gin.HandlerFunc = middleware
		assert.NotNil(t, handler, "Middleware should be a gin.HandlerFunc")
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
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	assert.NoError(t, err)
	defer jwks.EndBackground()

	authHandler := &AuthHandler{jwks: jwks, log: zaptest.NewLogger(t).Sugar()}

	router := gin.New()
	router.Use(authHandler.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"email":    c.GetString("email"),
			"username": c.GetString("username"),
			"user_id":  c.GetString("user_id"),
		})
	})

	claims := jwt.MapClaims{
		"sub":                "user-123",
		"email":              "user@example.com",
		"preferred_username": "tester",
		"exp":                time.Now().Add(time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	tokStr, err := tok.SignedString(priv)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokStr)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]string
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "user@example.com", body["email"])
	assert.Equal(t, "tester", body["username"])
	assert.Equal(t, "user-123", body["user_id"])
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

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.Get(srv.URL, keyfunc.Options{RefreshInterval: time.Hour})
	assert.NoError(t, err)
	defer jwks.EndBackground()

	tests := []struct {
		name           string
		allowed        bool
		authenticated  bool
		authHeader     string
		expectedStatus int
		method         string
		expectedAuth   bool
	}{
		{
			name:           "rate limited unauthenticated",
			allowed:        false,
			authenticated:  false,
			authHeader:     "",
			expectedStatus: http.StatusTooManyRequests,
			method:         http.MethodOptions,
			expectedAuth:   false,
		},
		{
			name:           "rate limited authenticated",
			allowed:        false,
			authenticated:  true,
			authHeader:     "",
			expectedStatus: http.StatusTooManyRequests,
			method:         http.MethodGet,
			expectedAuth:   true,
		},
		{
			name:           "allowed authenticated",
			allowed:        true,
			authenticated:  true,
			authHeader:     "",
			expectedStatus: http.StatusOK,
			method:         http.MethodGet,
			expectedAuth:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authHandler := &AuthHandler{jwks: jwks, log: zaptest.NewLogger(t).Sugar()}
			mockRL := &mockRateLimiter{
				allowed:         tt.allowed,
				isAuthenticated: tt.authenticated,
			}

			router := gin.New()
			router.Use(authHandler.MiddlewareWithRateLimiting(mockRL))
			router.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			var tokenHeader string
			if tt.method == http.MethodGet {
				claims := jwt.MapClaims{
					"sub": "rl-user",
					"exp": time.Now().Add(time.Minute).Unix(),
				}
				tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tok.Header["kid"] = kid
				tokStr, signErr := tok.SignedString(priv)
				assert.NoError(t, signErr)
				tokenHeader = "Bearer " + tokStr
			}

			req, _ := http.NewRequest(tt.method, "/test", nil)
			if tokenHeader != "" {
				req.Header.Set("Authorization", tokenHeader)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedStatus == http.StatusTooManyRequests {
				var body map[string]interface{}
				assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				assert.Equal(t, tt.expectedAuth, body["authenticated"])
			}
		})
	}
}
