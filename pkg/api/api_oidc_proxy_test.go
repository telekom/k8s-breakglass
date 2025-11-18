package api

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

// TestOIDCProxyPathValidation tests that invalid proxy paths are rejected to prevent SSRF and path traversal attacks
func TestOIDCProxyPathValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Test",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://keycloak.example.com/auth/realms/master",
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	// Create a test OIDC authority URL
	keycloakURL, err := url.Parse("https://keycloak.example.com")
	require.NoError(t, err)

	auth := &AuthHandler{} // Mock auth handler
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
	}

	tests := []struct {
		name           string
		proxyPath      string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Valid path: well-known endpoint",
			proxyPath:      "/.well-known/openid-configuration",
			expectedStatus: http.StatusBadGateway, // Expected because we can't connect to real keycloak
			expectedError:  "",
		},
		{
			name:           "Valid path: JWKS endpoint",
			proxyPath:      "/.well-known/jwks.json",
			expectedStatus: http.StatusBadGateway,
			expectedError:  "",
		},
		{
			name:           "Valid path: with query params",
			proxyPath:      "/token?code=abc&state=xyz",
			expectedStatus: http.StatusBadGateway,
			expectedError:  "",
		},
		{
			name:           "Invalid: contains scheme (SSRF attempt)",
			proxyPath:      "https://evil.com/",
			expectedStatus: http.StatusForbidden,
			expectedError:  "requested path is not an allowed OIDC endpoint",
		},
		{
			name:           "Invalid: network-path (SSRF attempt)",
			proxyPath:      "//evil.com/",
			expectedStatus: http.StatusForbidden,
			expectedError:  "requested path is not an allowed OIDC endpoint",
		},
		{
			name:           "Invalid: path traversal (..) attempt",
			proxyPath:      "/../admin/",
			expectedStatus: http.StatusForbidden,
			expectedError:  "requested path is not an allowed OIDC endpoint",
		},
		{
			name:           "Invalid: path traversal with multiple components",
			proxyPath:      "/token/../../admin",
			expectedStatus: http.StatusForbidden,
			expectedError:  "invalid proxy path: absolute URLs and path traversal not allowed",
		},
		{
			name:           "Invalid: contains both scheme and path",
			proxyPath:      "http://evil.com/path",
			expectedStatus: http.StatusForbidden,
			expectedError:  "requested path is not an allowed OIDC endpoint",
		},
		{
			name:           "Invalid: URL with fragment (potential XSS via URL routing)",
			proxyPath:      "/token#admin",
			expectedStatus: http.StatusBadGateway, // Fragment is stripped by browser before sending, so /token is valid; 502 because no real upstream
			expectedError:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Gin context with the test proxyPath
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{{Key: "proxyPath", Value: tt.proxyPath}}

			// Call the handler
			server.handleOIDCProxy(c)

			// Verify response status
			assert.Equal(t, tt.expectedStatus, w.Code, "expected status %d but got %d", tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError, "response should contain error message")
			}
		})
	}
}

// TestOIDCProxyMultiIDPValidation tests that the X-OIDC-Authority header is properly validated
func TestOIDCProxyMultiIDPValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a mock keycloak server for testing
	mockKeycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":"https://keycloak.example.com","authorization_endpoint":"https://keycloak.example.com/auth"}`)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockKeycloak.Close()

	mockKeycloakURL, err := url.Parse(mockKeycloak.URL)
	require.NoError(t, err)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Test",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          mockKeycloak.URL,
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: mockKeycloakURL,
		log:           logger,
		auth:          auth,
	}

	tests := []struct {
		name               string
		proxyPath          string
		customAuthority    string
		expectedStatus     int
		shouldContainError bool
	}{
		{
			name:               "Default authority (no header)",
			proxyPath:          "/.well-known/openid-configuration",
			customAuthority:    "",
			expectedStatus:     http.StatusOK,
			shouldContainError: false,
		},
		{
			name:               "Unknown authority in header (blocked for SSRF prevention)",
			proxyPath:          "/.well-known/openid-configuration",
			customAuthority:    "https://unknown.example.com",
			expectedStatus:     http.StatusForbidden,
			shouldContainError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
			if tt.customAuthority != "" {
				req.Header.Set("X-OIDC-Authority", tt.customAuthority)
			}

			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{{Key: "proxyPath", Value: tt.proxyPath}}

			// Call the handler
			server.handleOIDCProxy(c)

			// Verify response
			assert.Equal(t, tt.expectedStatus, w.Code, "expected status %d for test %s", tt.expectedStatus, tt.name)
			if tt.shouldContainError {
				assert.Contains(t, w.Body.String(), "error", "response should contain error")
			}
		})
	}
}

// TestOIDCProxyPathTrustedIDPs tests that known IDP authorities are properly recognized and untrusted ones are rejected
func TestOIDCProxyPathTrustedIDPs(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Test",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://keycloak.example.com/auth/realms/master",
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	defaultKeycloakURL, err := url.Parse("https://keycloak.example.com")
	require.NoError(t, err)

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: defaultKeycloakURL,
		log:           logger,
		auth:          auth,
	}

	tests := []struct {
		name            string
		proxyPath       string
		isValidPath     bool
		expectingBadReq bool
	}{
		{
			name:            "Simple path",
			proxyPath:       "/.well-known/openid-configuration",
			isValidPath:     true,
			expectingBadReq: false,
		},
		{
			name:            "Path with multiple segments",
			proxyPath:       "/auth/realms/master/.well-known/openid-configuration",
			isValidPath:     true,
			expectingBadReq: false,
		},
		{
			name:            "Encoded query string",
			proxyPath:       "/.well-known/openid-configuration?foo=bar&baz=qux",
			isValidPath:     true,
			expectingBadReq: false,
		},
		{
			name:            "Path traversal attempt",
			proxyPath:       "/.well-known/../admin",
			isValidPath:     false,
			expectingBadReq: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{{Key: "proxyPath", Value: tt.proxyPath}}

			server.handleOIDCProxy(c)

			if tt.expectingBadReq {
				assert.Equal(t, http.StatusForbidden, w.Code, "path traversal should be rejected with Forbidden")
			}
		})
	}
}

// TestOIDCProxyPathEncoding tests URL-encoded characters in paths
func TestOIDCProxyPathEncoding(t *testing.T) {
	logger := zaptest.NewLogger(t)

	keycloakURL, err := url.Parse("https://keycloak.example.com")
	require.NoError(t, err)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Test",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://keycloak.example.com/auth/realms/master",
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
	}

	tests := []struct {
		name       string
		proxyPath  string
		shouldFail bool
	}{
		{
			name:       "URL-encoded slash (%2F)",
			proxyPath:  "/.well-known%2Fopenid-configuration",
			shouldFail: true, // Encoded paths don't match whitelist and are rejected for security
		},
		{
			name:       "URL-encoded dot (.)",
			proxyPath:  "/.well-known/openid%2Econfiguration",
			shouldFail: true, // Encoded dots don't match whitelist and are rejected for security
		},
		{
			name:       "Double-dot encoded (%2E%2E)",
			proxyPath:  "/token%2F..%2Fadmin",
			shouldFail: true, // Our check catches .. even if URL-encoded, which is more conservative and secure
		},
		{
			name:       "Literal double-dot",
			proxyPath:  "/token/../admin",
			shouldFail: true, // Literal .. should be rejected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{{Key: "proxyPath", Value: tt.proxyPath}}

			server.handleOIDCProxy(c)

			if tt.shouldFail {
				assert.Equal(t, http.StatusForbidden, w.Code, "invalid path should be rejected")
			} else {
				// Valid paths should either succeed (200 OK from upstream) or fail with BadGateway (no real upstream)
				assert.NotEqual(t, http.StatusForbidden, w.Code, "valid path should not return Forbidden")
			}
		})
	}
}

// TestOIDCProxyPortBinding tests that the OIDC proxy correctly validates ports to prevent port-based attacks
func TestOIDCProxyPortBinding(t *testing.T) {
	logger := zaptest.NewLogger(t)

	keycloakURL, err := url.Parse("https://keycloak.example.com:8443")
	require.NoError(t, err)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Test",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://keycloak.example.com:8443/auth/realms/master",
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
	}

	tests := []struct {
		name       string
		proxyPath  string
		shouldFail bool
	}{
		{
			name:       "Standard path to configured port",
			proxyPath:  "/.well-known/openid-configuration",
			shouldFail: false,
		},
		{
			name:       "Path with colon (potential port override attempt)",
			proxyPath:  "/:9999/",
			shouldFail: false, // Literal colon in path component is allowed, but won't override the URL's port
		},
		{
			name:       "Path with @ symbol (potential userinfo override attempt)",
			proxyPath:  "/@admin",
			shouldFail: false, // @ is allowed in path component
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{{Key: "proxyPath", Value: tt.proxyPath}}

			server.handleOIDCProxy(c)

			if tt.shouldFail {
				assert.Equal(t, http.StatusBadRequest, w.Code, "invalid path should be rejected")
			} else {
				// Should not be BadRequest (may be BadGateway due to no real upstream)
				assert.NotEqual(t, http.StatusBadRequest, w.Code, "valid path should not be rejected with BadRequest")
			}
		})
	}
}

// TestOIDCProxyLocalhostBinding tests that localhost/127.0.0.1 addresses cannot be used for SSRF
func TestOIDCProxyLocalhostBinding(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Simulate localhost keycloak
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	keycloakURL, err := url.Parse("https://localhost:8443")
	require.NoError(t, err)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Test",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://localhost:8443/auth/realms/master",
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
	}

	// Test that localhost authority is configured and won't be overridden
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/oidc/authority/.well-known/openid-configuration", nil)
	// Try to inject a different authority - should be rejected
	req.Header.Set("X-OIDC-Authority", fmt.Sprintf("http://%s", addr))

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "proxyPath", Value: "/.well-known/openid-configuration"}}

	server.handleOIDCProxy(c)

	// Unknown authority should be rejected
	assert.Equal(t, http.StatusForbidden, w.Code, "unknown authority should be rejected")
}
