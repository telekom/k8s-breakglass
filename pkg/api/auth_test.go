package api

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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

func TestAuthHandler_ClaimsExtraction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.NewDefaultCtx(t.Context(), []string{srv.URL})
	assert.NoError(t, err)

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

	jwks, err := keyfunc.NewDefaultCtx(t.Context(), []string{srv.URL})
	assert.NoError(t, err)

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

// --- SEC-003: isValidIssuer tests ---

func TestIsValidIssuer(t *testing.T) {
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
			got := isValidIssuer(tt.issuer)
			assert.Equal(t, tt.valid, got, "isValidIssuer(%q)", tt.issuer)
		})
	}
}

// --- SEC-003: Middleware rejects invalid issuer format ---

func TestAuthMiddleware_RejectsInvalidIssuerFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.NewDefaultCtx(t.Context(), []string{srv.URL})
	require.NoError(t, err)

	auth := &AuthHandler{jwks: jwks, log: zaptest.NewLogger(t).Sugar()}
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
		{name: "empty issuer allowed (single-IDP fallback)", issuer: "", expectedStatus: http.StatusOK},
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
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = kid
			tokStr, signErr := tok.SignedString(priv)
			require.NoError(t, signErr)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokStr)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// --- SEC-004: Per-issuer JWKS fetch rate limiting ---

func TestJWKSFetchRateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Use a real IdentityProviderLoader with a fake k8s client so
	// that getJWKSForIssuer enters the multi-IDP code path.
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	loader := config.NewIdentityProviderLoader(fakeClient)

	auth := &AuthHandler{
		jwksCache:   make(map[string]*list.Element),
		jwksLRUList: list.New(),
		log:         zaptest.NewLogger(t).Sugar(),
		idpLoader:   loader,
	}

	issuer := "https://auth.example.com"

	// Pre-populate the limiter with a very recent fetch
	auth.jwksFetchLimiter.Store(issuer, time.Now())

	// Call getJWKSForIssuer — should return rate-limit error because
	// the cooldown has not elapsed
	_, _, err := auth.getJWKSForIssuer(t.Context(), issuer)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")

	// Verify that an unknown issuer (not in the rate limiter) passes the
	// rate-limit check and proceeds to IDP resolution (which fails with a
	// different error because we have no real k8s client).
	unknownIssuer := "https://unknown.example.com"
	_, _, err = auth.getJWKSForIssuer(t.Context(), unknownIssuer)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "rate limited",
		"unknown issuer should not be rate-limited on first attempt")

	// Verify that after the cooldown, the same issuer is no longer rate-limited
	// (it proceeds to IDP resolution which fails differently).
	auth.jwksFetchLimiter.Store(issuer, time.Now().Add(-jwksFetchMinInterval-time.Second))
	_, _, err = auth.getJWKSForIssuer(t.Context(), issuer)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "rate limited",
		"issuer should not be rate-limited after cooldown expires")
}

// --- SEC-005: Audience claim validation ---

func TestAuthMiddleware_AudienceValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv, priv, kid := setupTestJWKSServer(t)
	defer srv.Close()

	jwks, err := keyfunc.NewDefaultCtx(t.Context(), []string{srv.URL})
	require.NoError(t, err)

	// Single-IDP mode: audience validation is not applied (no idpLoader)
	auth := &AuthHandler{jwks: jwks, log: zaptest.NewLogger(t).Sugar()}
	router := gin.New()
	router.Use(auth.Middleware())
	router.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	t.Run("single-IDP mode: no audience check", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user-123",
			"exp": time.Now().Add(time.Minute).Unix(),
			"aud": "some-other-service",
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tokStr, signErr := tok.SignedString(priv)
		require.NoError(t, signErr)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokStr)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should pass because single-IDP mode doesn't enforce audience
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("multi-IDP mode: audience mismatch rejected", func(t *testing.T) {
		// Set up multi-IDP mode with a cached JWKS entry that has expectedAudience
		multiScheme := runtime.NewScheme()
		require.NoError(t, breakglassv1alpha1.AddToScheme(multiScheme))
		multiClient := fake.NewClientBuilder().WithScheme(multiScheme).Build()
		multiAuth := &AuthHandler{
			jwksCache:   make(map[string]*list.Element),
			jwksLRUList: list.New(),
			log:         zaptest.NewLogger(t).Sugar(),
			idpLoader:   config.NewIdentityProviderLoader(multiClient),
		}

		// Use an HTTPS issuer that passes isValidIssuer validation
		testIssuer := "https://test-idp.example.com"
		entry := &jwksCacheEntry{
			issuer:           testIssuer,
			expectedAudience: "my-breakglass-client",
			jwks:             jwks,
		}
		elem := multiAuth.jwksLRUList.PushFront(entry)
		multiAuth.jwksCache[testIssuer] = elem

		multiRouter := gin.New()
		multiRouter.Use(multiAuth.Middleware())
		multiRouter.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Token with wrong audience
		claims := jwt.MapClaims{
			"sub": "user-123",
			"exp": time.Now().Add(time.Minute).Unix(),
			"iss": testIssuer,
			"aud": "wrong-audience",
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tokStr, signErr := tok.SignedString(priv)
		require.NoError(t, signErr)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokStr)
		w := httptest.NewRecorder()
		multiRouter.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code, "wrong audience should be rejected in multi-IDP mode")
	})

	t.Run("multi-IDP mode: matching audience accepted", func(t *testing.T) {
		multiScheme2 := runtime.NewScheme()
		require.NoError(t, breakglassv1alpha1.AddToScheme(multiScheme2))
		multiClient2 := fake.NewClientBuilder().WithScheme(multiScheme2).Build()
		multiAuth := &AuthHandler{
			jwksCache:   make(map[string]*list.Element),
			jwksLRUList: list.New(),
			log:         zaptest.NewLogger(t).Sugar(),
			idpLoader:   config.NewIdentityProviderLoader(multiClient2),
		}

		testIssuer := "https://test-idp.example.com"
		entry := &jwksCacheEntry{
			issuer:           testIssuer,
			expectedAudience: "my-breakglass-client",
			jwks:             jwks,
		}
		elem := multiAuth.jwksLRUList.PushFront(entry)
		multiAuth.jwksCache[testIssuer] = elem

		multiRouter := gin.New()
		multiRouter.Use(multiAuth.Middleware())
		multiRouter.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

		// Token with correct audience
		claims := jwt.MapClaims{
			"sub": "user-123",
			"exp": time.Now().Add(time.Minute).Unix(),
			"iss": testIssuer,
			"aud": "my-breakglass-client",
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		tokStr, signErr := tok.SignedString(priv)
		require.NoError(t, signErr)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokStr)
		w := httptest.NewRecorder()
		multiRouter.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "matching audience should be accepted")
	})
}
