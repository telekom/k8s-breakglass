package api

import (
	"encoding/pem"
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
		idpConfig: &config.IdentityProviderConfig{
			Authority:          "https://keycloak.example.com/auth/realms/master",
			InsecureSkipVerify: true,
		},
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
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
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

func TestValidateOIDCProxyPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		shouldPass bool
	}{
		{"allows well-known endpoint", "/.well-known/openid-configuration", true},
		{"rejects disallowed prefix", "/not-allowed", false},
		{"rejects suspicious absolute", "http://evil", false},
		{"rejects encoded traversal", "/protocol/openid-connect/%2e%2e/%2e%2e/admin", false},
		{"rejects double encoded traversal", "/protocol/openid-connect/%252e%252e/%252e%252e/admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, err := validateOIDCProxyPath(tt.path)
			if tt.shouldPass {
				require.NoError(t, err)
				require.NotEmpty(t, normalized)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestSelectOIDCProxyAuthority(t *testing.T) {
	defaultURL, err := url.Parse("https://default.example.com")
	require.NoError(t, err)
	server := &Server{
		oidcAuthority: defaultURL,
		idpConfig: &config.IdentityProviderConfig{
			Authority: defaultURL.String(),
		},
	}

	t.Run("returns clone for default", func(t *testing.T) {
		selected, err := server.selectOIDCProxyAuthority("")
		require.NoError(t, err)
		require.Equal(t, defaultURL.String(), selected.String())
		require.True(t, defaultURL != selected)
	})

	t.Run("rejects invalid header", func(t *testing.T) {
		_, err := server.selectOIDCProxyAuthority("::::")
		require.ErrorIs(t, err, errInvalidAuthorityHeader)
	})

	t.Run("rejects unknown authority", func(t *testing.T) {
		_, err := server.selectOIDCProxyAuthority("https://unknown.example.com")
		require.ErrorIs(t, err, errUnknownOIDCAuthority)
	})

	t.Run("accepts known authority", func(t *testing.T) {
		selected, err := server.selectOIDCProxyAuthority(defaultURL.String())
		require.NoError(t, err)
		require.Equal(t, defaultURL.String(), selected.String())
	})
}

// TestOIDCProxyMultiIDPValidation tests that the X-OIDC-Authority header is properly validated
func TestOIDCProxyMultiIDPValidation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a mock keycloak server for testing
	mockKeycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"issuer":"https://keycloak.example.com","authorization_endpoint":"https://keycloak.example.com/auth"}`)
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
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: mockKeycloakURL,
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority:          mockKeycloak.URL,
			InsecureSkipVerify: true,
		},
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
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
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

func TestOIDCProxyResponseHeaderAllowlist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)
	mockAuthority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Secret", "should-not-leak")
		_, _ = w.Write([]byte(`{"issuer":"https://example.com"}`))
	}))
	defer mockAuthority.Close()

	parsed, err := url.Parse(mockAuthority.URL)
	require.NoError(t, err)
	server := &Server{
		log:           logger,
		auth:          &AuthHandler{},
		config:        config.Config{},
		idpConfig:     &config.IdentityProviderConfig{Authority: mockAuthority.URL, InsecureSkipVerify: true},
		oidcAuthority: parsed,
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/authority/.well-known/openid-configuration", nil)
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "proxyPath", Value: "/.well-known/openid-configuration"}}

	server.handleOIDCProxy(c)

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.Equal(t, "", w.Header().Get("X-Upstream-Secret"))
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
	}

	defaultKeycloakURL, err := url.Parse("https://keycloak.example.com")
	require.NoError(t, err)

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: defaultKeycloakURL,
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority:          "https://keycloak.example.com/auth/realms/master",
			InsecureSkipVerify: true,
		},
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
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
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
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority:          "https://keycloak.example.com/auth/realms/master",
			InsecureSkipVerify: true,
		},
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
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
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
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority: "https://keycloak.example.com:8443/auth/realms/master",
		},
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
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)
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
	_ = listener.Close()

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
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: keycloakURL,
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority:          "https://localhost:8443/auth/realms/master",
			InsecureSkipVerify: true,
		},
	}

	// Test that localhost authority is configured and won't be overridden
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/authority/.well-known/openid-configuration", nil)
	// Try to inject a different authority - should be rejected
	req.Header.Set("X-OIDC-Authority", fmt.Sprintf("http://%s", addr))

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "proxyPath", Value: "/.well-known/openid-configuration"}}

	server.handleOIDCProxy(c)

	// Unknown authority should be rejected
	assert.Equal(t, http.StatusForbidden, w.Code, "unknown authority should be rejected")
}

// TestOIDCProxyMultiIDPWithRealmPath tests that X-OIDC-Authority with realm path is correctly resolved
// This covers the scenario where frontend sends: X-OIDC-Authority: https://keycloak.das-schiff.telekom.de/auth/realms/schiff
// and we need to correctly resolve /.well-known/openid-configuration to:
// https://keycloak.das-schiff.telekom.de/auth/realms/schiff/.well-known/openid-configuration
func TestOIDCProxyMultiIDPWithRealmPath(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create a mock Keycloak server that expects the full realm path
	mockKeycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The request should come in with the full realm path
		expectedPath := "/auth/realms/schiff/.well-known/openid-configuration"
		if r.URL.Path == expectedPath {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{
				"issuer":"https://keycloak.das-schiff.telekom.de/auth/realms/schiff",
				"authorization_endpoint":"https://keycloak.das-schiff.telekom.de/auth/realms/schiff/protocol/openid-connect/auth",
				"token_endpoint":"https://keycloak.das-schiff.telekom.de/auth/realms/schiff/protocol/openid-connect/token"
			}`)
			return
		}
		// If we get a request without the realm path, that's the bug we're fixing
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, "Forbidden: realm path required")
			return
		}
		http.NotFound(w, r)
	}))
	defer mockKeycloak.Close()

	// Set up a server with authority that includes realm path
	authorityWithRealm, err := url.Parse(mockKeycloak.URL + "/auth/realms/schiff")
	require.NoError(t, err)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://breakglass.example.com",
			BrandingName: "Test",
		},
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: authorityWithRealm, // Authority includes the realm path
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority:          mockKeycloak.URL + "/auth/realms/schiff",
			InsecureSkipVerify: true,
		},
	}

	tests := []struct {
		name                string
		proxyPath           string
		expectedStatus      int
		shouldContainIssuer bool
		description         string
	}{
		{
			name:                "Proxy request with realm path in authority",
			proxyPath:           "/.well-known/openid-configuration",
			expectedStatus:      http.StatusOK,
			shouldContainIssuer: true,
			description:         "When oidcAuthority includes /auth/realms/schiff, the proxy request should go to /auth/realms/schiff/.well-known/openid-configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oidc/authority%s", tt.proxyPath), nil)

			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = gin.Params{{Key: "proxyPath", Value: tt.proxyPath}}

			server.handleOIDCProxy(c)

			assert.Equal(t, tt.expectedStatus, w.Code,
				"test: %s, expected status %d but got %d\n%s\nResponse: %s",
				tt.name, tt.expectedStatus, w.Code, tt.description, w.Body.String())

			if tt.shouldContainIssuer {
				bodyStr := w.Body.String()
				assert.Contains(t, bodyStr, "das-schiff.telekom.de/auth/realms/schiff",
					"response should contain the issuer with realm path, got: %s", bodyStr)
			}
		})
	}
}

// TestOIDCProxyRealmPathIntegration tests the full OIDC discovery flow with realm paths
// Scenario: Frontend requests /.well-known/openid-configuration via /api/oidc/authority
// with authority pointing to a Keycloak realm, and backend should:
// 1. Preserve the realm path when constructing the upstream request
// 2. Return the OIDC metadata with the correct issuer URL including the realm
// 3. Preserve headers like Content-Type and Cache-Control
func TestOIDCProxyRealmPathIntegration(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Track what URL the mock server receives
	var receivedPath string

	// Create a realistic mock Keycloak server
	mockKeycloak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path

		// Only respond to requests with the full realm path
		if r.URL.Path == "/auth/realms/production/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			// Build response - get base URL from the request itself
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			actualBaseURL := scheme + "://" + r.Host
			fmt.Fprintf(w, `{
				"issuer": "%s/auth/realms/production",
				"authorization_endpoint": "%s/auth/realms/production/protocol/openid-connect/auth",
				"token_endpoint": "%s/auth/realms/production/protocol/openid-connect/token",
				"userinfo_endpoint": "%s/auth/realms/production/protocol/openid-connect/userinfo",
				"jwks_uri": "%s/auth/realms/production/protocol/openid-connect/certs"
			}`, actualBaseURL, actualBaseURL, actualBaseURL, actualBaseURL, actualBaseURL)
			return
		}

		// Return 404 for requests without the realm path (the bug scenario)
		http.NotFound(w, r)
	}))
	defer mockKeycloak.Close()

	// Parse the authority with realm path
	authorityWithRealm, err := url.Parse(mockKeycloak.URL + "/auth/realms/production")
	require.NoError(t, err)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			BaseURL:      "https://breakglass.example.com",
			BrandingName: "Test",
		},
	}

	auth := &AuthHandler{}
	server := &Server{
		config:        cfg,
		oidcAuthority: authorityWithRealm,
		log:           logger,
		auth:          auth,
		idpConfig: &config.IdentityProviderConfig{
			Authority:          mockKeycloak.URL + "/auth/realms/production",
			InsecureSkipVerify: true,
		},
	}

	t.Run("Full OIDC discovery flow with realm path preservation", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/oidc/authority/.well-known/openid-configuration", nil)

		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "proxyPath", Value: "/.well-known/openid-configuration"}}

		// Execute the proxy handler
		server.handleOIDCProxy(c)

		// Verify response status
		assert.Equal(t, http.StatusOK, w.Code,
			"Expected 200 OK, got %d\nResponse: %s\nReceived path: %s",
			w.Code, w.Body.String(), receivedPath)

		// Verify the correct path was called on the upstream server
		assert.Equal(t, "/auth/realms/production/.well-known/openid-configuration", receivedPath,
			"Upstream should receive request with realm path preserved")

		// Verify response contains valid OIDC metadata
		assert.Contains(t, w.Body.String(), "authorization_endpoint",
			"Response should contain authorization_endpoint")
		assert.Contains(t, w.Body.String(), "token_endpoint",
			"Response should contain token_endpoint")
		assert.Contains(t, w.Body.String(), mockKeycloak.URL+"/auth/realms/production",
			"Response should contain issuer with realm path")

		// Verify Content-Type is preserved from upstream
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"),
			"Response should have correct Content-Type")

		// Verify Cache-Control header is preserved
		assert.Equal(t, "public, max-age=3600", w.Header().Get("Cache-Control"),
			"Response should preserve Cache-Control header")
	})

	t.Run("Query parameters are preserved in realm path scenario", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/oidc/authority/.well-known/openid-configuration?foo=bar", nil)

		c, _ := gin.CreateTestContext(w)
		c.Request = req
		c.Params = gin.Params{{Key: "proxyPath", Value: "/.well-known/openid-configuration?foo=bar"}}

		server.handleOIDCProxy(c)

		// Verify response is still successful
		assert.NotEqual(t, http.StatusNotFound, w.Code,
			"Request with query params should not return 404")
		assert.Equal(t, http.StatusOK, w.Code,
			"Request should succeed with query params")
	})
}

func TestNewOIDCProxyHTTPClientTLSModes(t *testing.T) {
	logger := zaptest.NewLogger(t)

	t.Run("https defaults to system roots when no custom CA", func(t *testing.T) {
		server := &Server{
			log: logger,
			idpConfig: &config.IdentityProviderConfig{
				Name:      "test",
				Authority: "https://keycloak.example.com",
			},
		}
		client, err := server.newOIDCProxyHTTPClient(true)
		require.NoError(t, err)
		transport := client.Transport.(*http.Transport)
		require.NotNil(t, transport.TLSClientConfig)
		require.NotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("allows insecure flag explicitly", func(t *testing.T) {
		server := &Server{
			log: logger,
			idpConfig: &config.IdentityProviderConfig{
				Name:               "test",
				Authority:          "https://keycloak.example.com",
				InsecureSkipVerify: true,
			},
		}
		client, err := server.newOIDCProxyHTTPClient(true)
		require.NoError(t, err)
		transport := client.Transport.(*http.Transport)
		require.NotNil(t, transport.TLSClientConfig)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("uses provided certificate authority", func(t *testing.T) {
		server := &Server{
			log: logger,
			idpConfig: &config.IdentityProviderConfig{
				Name:                 "test",
				Authority:            "https://keycloak.example.com",
				CertificateAuthority: testCertificatePEM(t),
			},
		}
		client, err := server.newOIDCProxyHTTPClient(true)
		require.NoError(t, err)
		transport := client.Transport.(*http.Transport)
		require.NotNil(t, transport.TLSClientConfig)
		require.NotNil(t, transport.TLSClientConfig.RootCAs)
	})

	t.Run("http targets skip tls setup", func(t *testing.T) {
		server := &Server{
			log: logger,
			idpConfig: &config.IdentityProviderConfig{
				Name:      "test",
				Authority: "https://keycloak.example.com",
			},
		}
		client, err := server.newOIDCProxyHTTPClient(false)
		require.NoError(t, err)
		transport := client.Transport.(*http.Transport)
		assert.Nil(t, transport.TLSClientConfig)
	})
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cert := server.Certificate()
	server.Close()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return string(pem.EncodeToMemory(block))
}
