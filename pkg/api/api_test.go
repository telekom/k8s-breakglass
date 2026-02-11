package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

func TestNewServer(t *testing.T) {
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

	tests := []struct {
		name  string
		debug bool
		auth  *AuthHandler
	}{
		{
			name:  "Create server in debug mode with custom auth",
			debug: true,
			auth:  &AuthHandler{}, // Provide a mock auth handler to avoid JWKS fetch
		},
		{
			name:  "Create server in production mode with custom auth",
			debug: false,
			auth:  &AuthHandler{}, // Provide a mock auth handler to avoid JWKS fetch
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(logger, cfg, tt.debug, tt.auth)

			assert.NotNil(t, server)
			assert.NotNil(t, server.gin)
			assert.Equal(t, cfg, server.config)
			assert.NotNil(t, server.auth)
		})
	}
}

func TestServer_getConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := config.Config{
		Frontend: config.Frontend{
			BaseURL:      "https://example.com",
			BrandingName: "Das SCHIFF Breakglass",
		},
	}

	server := &Server{
		config: cfg,
		idpConfig: &config.IdentityProviderConfig{
			Authority: "https://auth.example.com",
			ClientID:  "test-client-id",
		},
	}
	router := gin.New()
	router.GET("/config", server.getConfig)

	req, err := http.NewRequest(http.MethodGet, "/config", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var response PublicConfig
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check that IdentityProvider config is exposed in frontend config
	assert.Equal(t, "https://auth.example.com", response.Frontend.OIDCAuthority)
	assert.Equal(t, "test-client-id", response.Frontend.OIDCClientID)
	// Branding should be propagated to the public config
	assert.Equal(t, cfg.Frontend.BrandingName, response.Frontend.BrandingName)
}

func TestServer_getIdentityProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
		idpConfig: &config.IdentityProviderConfig{
			Type:      "OIDC",
			Authority: "https://auth.example.com",
			ClientID:  "test-client-id",
			// ClientSecret should NOT be exposed
			ClientSecret: "this-should-not-be-exposed",
		},
	}

	router := gin.New()
	router.GET("/identity-provider", server.getIdentityProvider)

	req, err := http.NewRequest(http.MethodGet, "/identity-provider", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var response IdentityProviderResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify expected fields are exposed
	assert.Equal(t, "OIDC", response.Type)
	assert.Equal(t, "https://auth.example.com", response.Authority)
	assert.Equal(t, "test-client-id", response.ClientID)
	// Verify response body does NOT contain the secret
	assert.NotContains(t, w.Body.String(), "this-should-not-be-exposed")
}

func TestServer_getIdentityProvider_WithKeycloak(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
		idpConfig: &config.IdentityProviderConfig{
			Type:      "Keycloak",
			Authority: "https://keycloak.example.com/auth/realms/master",
			ClientID:  "keycloak-client",
			Keycloak: &config.KeycloakRuntimeConfig{
				BaseURL:             "https://keycloak.example.com",
				Realm:               "master",
				ClientSecret:        "secret-should-not-expose",
				ServiceAccountToken: "token-should-not-expose",
			},
		},
	}

	router := gin.New()
	router.GET("/identity-provider", server.getIdentityProvider)

	req, err := http.NewRequest(http.MethodGet, "/identity-provider", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var response IdentityProviderResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify Keycloak metadata is exposed (non-secrets only)
	assert.Equal(t, "Keycloak", response.Type)
	assert.NotNil(t, response.KeycloakMetadata)
	assert.Equal(t, "https://keycloak.example.com", response.KeycloakMetadata.BaseURL)
	assert.Equal(t, "master", response.KeycloakMetadata.Realm)

	// Verify secrets are NOT exposed
	responseBody := w.Body.String()
	assert.NotContains(t, responseBody, "secret-should-not-expose")
	assert.NotContains(t, responseBody, "token-should-not-expose")
}

func TestServer_getIdentityProvider_NotConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	server := &Server{
		log:       logger,
		idpConfig: nil, // No IDP configured
	}

	router := gin.New()
	router.GET("/identity-provider", server.getIdentityProvider)

	req, err := http.NewRequest(http.MethodGet, "/identity-provider", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	var response gin.H
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "not configured")
}

func TestServer_SetIdentityProvider(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := config.Config{}
	server := &Server{
		config: cfg,
		log:    logger,
	}

	// Initially nil
	assert.Nil(t, server.idpConfig)

	// Set identity provider
	idpConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://example.com",
		ClientID:  "test",
	}
	server.SetIdentityProvider(idpConfig)

	// Now it should be set
	assert.NotNil(t, server.idpConfig)
	assert.Equal(t, "OIDC", server.idpConfig.Type)
	assert.Equal(t, "https://example.com", server.idpConfig.Authority)
}

func TestServer_getConfig_WithoutIdentityProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Config with no IdentityProvider set
	cfg := config.Config{
		Frontend: config.Frontend{
			BrandingName: "Test Brand",
		},
	}

	server := &Server{
		config:    cfg,
		idpConfig: nil, // No provider loaded
	}
	router := gin.New()
	router.GET("/config", server.getConfig)

	req, err := http.NewRequest(http.MethodGet, "/config", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var response PublicConfig
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// When no provider is loaded, OIDC fields should be empty
	assert.Equal(t, "", response.Frontend.OIDCAuthority)
	assert.Equal(t, "", response.Frontend.OIDCClientID)
	// But branding should still be present
	assert.Equal(t, "Test Brand", response.Frontend.BrandingName)
}

func TestServer_getIdentityProvider_EmptyKeycloakConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := zaptest.NewLogger(t)
	// Provider with partial Keycloak config (should not expose metadata)
	server := &Server{
		log: logger,
		idpConfig: &config.IdentityProviderConfig{
			Type:      "Keycloak",
			Authority: "https://keycloak.example.com",
			ClientID:  "client",
			Keycloak:  nil, // No keycloak metadata
		},
	}

	router := gin.New()
	router.GET("/identity-provider", server.getIdentityProvider)

	req, err := http.NewRequest(http.MethodGet, "/identity-provider", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var response IdentityProviderResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, "Keycloak", response.Type)
	assert.Nil(t, response.KeycloakMetadata) // Should be nil when not configured
}

func TestServer_getIdentityProvider_AllProviderTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)

	testCases := []string{"OIDC", "Keycloak", "LDAP", "AzureAD"}

	for _, providerType := range testCases {
		t.Run(providerType, func(t *testing.T) {
			server := &Server{
				log: logger,
				idpConfig: &config.IdentityProviderConfig{
					Type:      providerType,
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			}

			router := gin.New()
			router.GET("/identity-provider", server.getIdentityProvider)

			req, err := http.NewRequest(http.MethodGet, "/identity-provider", nil)
			assert.NoError(t, err)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)

			var response IdentityProviderResponse
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, providerType, response.Type)
			assert.Equal(t, "https://auth.example.com", response.Authority)
			assert.Equal(t, "test-client", response.ClientID)
		})
	}
}

func TestOriginValidationMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)
	cfg := config.Config{
		Server: config.Server{
			AllowedOrigins: []string{"https://allowed.example.com"},
		},
	}
	server := NewServer(logger, cfg, true, &AuthHandler{})
	server.gin.GET("/api/probe", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	server.gin.OPTIONS("/api/probe", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	makeRequest := func(method, origin string) *httptest.ResponseRecorder {
		req, err := http.NewRequest(method, "/api/probe", nil)
		require.NoError(t, err)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		server.gin.ServeHTTP(w, req)
		return w
	}

	t.Run("allows configured origin", func(t *testing.T) {
		resp := makeRequest(http.MethodGet, "https://allowed.example.com")
		require.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("blocks disallowed origin", func(t *testing.T) {
		resp := makeRequest(http.MethodGet, "https://evil.example.com")
		require.Equal(t, http.StatusForbidden, resp.Code)
	})

	t.Run("skips when origin header missing", func(t *testing.T) {
		resp := makeRequest(http.MethodGet, "")
		require.Equal(t, http.StatusOK, resp.Code)
	})

	t.Run("skips validation for OPTIONS preflight", func(t *testing.T) {
		resp := makeRequest(http.MethodOptions, "https://evil.example.com")
		require.Equal(t, http.StatusForbidden, resp.Code)
		require.Empty(t, resp.Body.String(), "response should come from CORS middleware, not origin validator")
	})
}

func TestServer_RegisterAll(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)
	cfg := config.Config{
		Server: config.Server{
			AllowedOrigins: []string{"https://test.example.com"},
		},
	}

	// Use mock auth handler to avoid JWKS fetching
	mockAuth := &AuthHandler{}
	server := NewServer(logger, cfg, true, mockAuth)

	// Create mock controller
	mockController := &mockAPIController{
		basePath: "/test",
		handlers: []gin.HandlerFunc{},
	}

	controllers := []APIController{mockController}

	err := server.RegisterAll(controllers)
	assert.NoError(t, err)
	assert.True(t, mockController.registerCalled)
}

func TestFrontendConfig(t *testing.T) {
	config := FrontendConfig{
		OIDCAuthority: "https://auth.example.com",
		OIDCClientID:  "test-client-id",
	}

	assert.Equal(t, "https://auth.example.com", config.OIDCAuthority)
	assert.Equal(t, "test-client-id", config.OIDCClientID)
}

// Mock implementation of APIController for testing
type mockAPIController struct {
	basePath       string
	handlers       []gin.HandlerFunc
	registerCalled bool
}

func (m *mockAPIController) BasePath() string {
	return m.basePath
}

func (m *mockAPIController) Register(rg *gin.RouterGroup) error {
	m.registerCalled = true
	return nil
}

func (m *mockAPIController) Handlers() []gin.HandlerFunc {
	return m.handlers
}

func TestServerConfig_Structure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := config.Config{}
	auth := &AuthHandler{}

	serverConfig := ServerConfig{
		Auth:  auth,
		Log:   logger,
		Cfg:   cfg,
		Debug: true,
	}

	assert.Equal(t, auth, serverConfig.Auth)
	assert.Equal(t, logger, serverConfig.Log)
	assert.Equal(t, cfg, serverConfig.Cfg)
	assert.True(t, serverConfig.Debug)
}

func TestServer_RegisterAll_Error(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)
	cfg := config.Config{
		Server: config.Server{
			AllowedOrigins: []string{"https://test.example.com"},
		},
	}

	// Use mock auth handler to avoid JWKS fetching
	mockAuth := &AuthHandler{}
	server := NewServer(logger, cfg, true, mockAuth)

	// Create mock controller that returns error
	mockController := &mockAPIControllerWithError{
		basePath: "/test",
		handlers: []gin.HandlerFunc{},
	}

	controllers := []APIController{mockController}

	err := server.RegisterAll(controllers)
	assert.Error(t, err)
	assert.Equal(t, "registration failed", err.Error())
}

func TestServer_NoRoute_API_Json404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)
	cfg := config.Config{
		Server: config.Server{
			AllowedOrigins: []string{"https://test.example.com"},
		},
	}
	server := NewServer(logger, cfg, true, &AuthHandler{})

	// Use the engine directly and perform a request to an unknown /api/ path
	req, err := http.NewRequest(http.MethodGet, "/api/unknown/thing", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	server.gin.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	// Response should be JSON containing error and path
	var body map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &body)
	assert.NoError(t, err)
	assert.Contains(t, body, "error")
	assert.Contains(t, body, "path")
	assert.Equal(t, "/api/unknown/thing", body["path"])
}

func TestServer_NoRoute_SPA_Fallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// no need to create a full Server; test ServeSPA handler directly
	// Create a temporary directory to act as SPA dist with an index.html
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "index.html")
	err := os.WriteFile(indexPath, []byte("<html>ok</html>"), 0644)
	assert.NoError(t, err)

	// Replace ServeSPA call by calling the handler directly: NoRoute uses ServeSPA "/", "./frontend/dist/"
	// We'll attach a NoRoute that points at our temp dir to emulate the SPA fallback
	engine := gin.New()
	engine.NoRoute(ServeSPA("/", tmpDir))

	req, err := http.NewRequest(http.MethodGet, "/some/page", nil)
	assert.NoError(t, err)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<html>ok</html>")
}

// Mock implementation that returns error
type mockAPIControllerWithError struct {
	basePath string
	handlers []gin.HandlerFunc
}

func (m *mockAPIControllerWithError) BasePath() string {
	return m.basePath
}

func (m *mockAPIControllerWithError) Register(rg *gin.RouterGroup) error {
	return errors.New("registration failed")
}

func (m *mockAPIControllerWithError) Handlers() []gin.HandlerFunc {
	return m.handlers
}

func TestSetIdentityProvider_OIDCOnly(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com",
		ClientID:  "oidc-client",
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.Equal(t, "OIDC", server.idpConfig.Type)
	assert.Equal(t, "https://auth.example.com", server.idpConfig.Authority)
	assert.NotNil(t, server.oidcAuthority)
	assert.Equal(t, "https", server.oidcAuthority.Scheme)
	assert.Equal(t, "auth.example.com", server.oidcAuthority.Host)
}

func TestSetIdentityProvider_KeycloakWithAuthPath(t *testing.T) {
	// Test case with /auth in the baseURL (like the actual Keycloak deployment)
	// Config: baseURL="https://keycloak.das-schiff.telekom.de/auth", realm="schiff"
	// Expected authority: "https://keycloak.das-schiff.telekom.de/auth/realms/schiff"
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://keycloak.das-schiff.telekom.de/auth/realms/schiff",
		ClientID:  "breakglass-ui",
		Keycloak: &config.KeycloakRuntimeConfig{
			BaseURL:  "https://keycloak.das-schiff.telekom.de/auth",
			Realm:    "schiff",
			ClientID: "breakglass-controller",
		},
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.Equal(t, "Keycloak", server.idpConfig.Type)
	assert.NotNil(t, server.oidcAuthority)
	// Verify the constructed URL matches the expected Keycloak realm authority
	expectedURL := "https://keycloak.das-schiff.telekom.de/auth/realms/schiff"
	assert.Equal(t, expectedURL, server.oidcAuthority.String())
	assert.Equal(t, "https", server.oidcAuthority.Scheme)
	assert.Equal(t, "keycloak.das-schiff.telekom.de", server.oidcAuthority.Host)
	assert.Equal(t, "/auth/realms/schiff", server.oidcAuthority.Path)
}

func TestSetIdentityProvider_KeycloakWithoutAuthPath(t *testing.T) {
	// Test case without /auth in the baseURL (alternative Keycloak deployment)
	// Config: baseURL="https://keycloak.example.com", realm="mycompany"
	// Expected authority: "https://keycloak.example.com/realms/mycompany"
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://keycloak.example.com/realms/mycompany",
		ClientID:  "app-client",
		Keycloak: &config.KeycloakRuntimeConfig{
			BaseURL:  "https://keycloak.example.com",
			Realm:    "mycompany",
			ClientID: "app-service-account",
		},
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.Equal(t, "Keycloak", server.idpConfig.Type)
	assert.NotNil(t, server.oidcAuthority)
	// Verify the constructed URL matches the expected Keycloak realm authority
	expectedURL := "https://keycloak.example.com/realms/mycompany"
	assert.Equal(t, expectedURL, server.oidcAuthority.String())
	assert.Equal(t, "https", server.oidcAuthority.Scheme)
	assert.Equal(t, "keycloak.example.com", server.oidcAuthority.Host)
	assert.Equal(t, "/realms/mycompany", server.oidcAuthority.Path)
}

func TestSetIdentityProvider_KeycloakWithTrailingSlash(t *testing.T) {
	// Test case with trailing slash in baseURL (should be trimmed)
	// Config: baseURL="https://keycloak.example.com/", realm="test"
	// Expected authority: "https://keycloak.example.com/realms/test"
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://keycloak.example.com/realms/test",
		ClientID:  "test-client",
		Keycloak: &config.KeycloakRuntimeConfig{
			BaseURL:  "https://keycloak.example.com/",
			Realm:    "test",
			ClientID: "test-service-account",
		},
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.NotNil(t, server.oidcAuthority)
	// Verify trailing slash is handled correctly
	expectedURL := "https://keycloak.example.com/realms/test"
	assert.Equal(t, expectedURL, server.oidcAuthority.String())
}

func TestSetIdentityProvider_KeycloakMissingRealm(t *testing.T) {
	// Test case with Keycloak config but missing realm (should fall back to Authority)
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://keycloak.example.com/realms/fallback",
		ClientID:  "test-client",
		Keycloak: &config.KeycloakRuntimeConfig{
			BaseURL:  "https://keycloak.example.com",
			Realm:    "", // Missing realm
			ClientID: "test-service-account",
		},
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.NotNil(t, server.oidcAuthority)
	// Should fall back to the Authority field
	assert.Equal(t, "https://keycloak.example.com/realms/fallback", server.oidcAuthority.String())
}

func TestSetIdentityProvider_KeycloakMissingBaseURL(t *testing.T) {
	// Test case with Keycloak config but missing baseURL (should fall back to Authority)
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://keycloak.example.com/realms/fallback",
		ClientID:  "test-client",
		Keycloak: &config.KeycloakRuntimeConfig{
			BaseURL:  "", // Missing baseURL
			Realm:    "test",
			ClientID: "test-service-account",
		},
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.NotNil(t, server.oidcAuthority)
	// Should fall back to the Authority field
	assert.Equal(t, "https://keycloak.example.com/realms/fallback", server.oidcAuthority.String())
}

func TestSetIdentityProvider_NilKeycloak(t *testing.T) {
	// Test case with nil Keycloak config (should use Authority)
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	idpConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com",
		ClientID:  "oidc-client",
		Keycloak:  nil,
	}

	server.SetIdentityProvider(idpConfig)

	assert.NotNil(t, server.idpConfig)
	assert.NotNil(t, server.oidcAuthority)
	assert.Equal(t, "https://auth.example.com", server.oidcAuthority.String())
}

func TestBuildCSP_WithoutOIDC(t *testing.T) {
	server := &Server{}

	csp := server.buildCSP()

	// Should have frame-src 'none' when no OIDC configured
	assert.Contains(t, csp, "frame-src 'none'")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "connect-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
}

func TestBuildCSP_WithOIDC(t *testing.T) {
	logger := zaptest.NewLogger(t)
	server := &Server{
		log: logger,
	}

	// Set an OIDC provider
	idpConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://keycloak.example.com/realms/test",
		ClientID:  "test-client",
	}
	server.SetIdentityProvider(idpConfig)

	csp := server.buildCSP()

	// Should include 'self' and the OIDC authority in frame-src for silent refresh
	// 'self' is needed because the silent renew callback (/auth/silent-renew) is on the same origin
	assert.Contains(t, csp, "frame-src 'self' https://keycloak.example.com")
	assert.Contains(t, csp, "connect-src 'self' https://keycloak.example.com")
	// Should still have frame-ancestors 'none' to prevent us being embedded
	assert.Contains(t, csp, "frame-ancestors 'none'")
}

func TestNormalizeOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"strips_default_https_port", "HTTPS://Example.com:443/", "https://example.com"},
		{"strips_default_http_port", "http://Example.com:80", "http://example.com"},
		{"preserves_non_default_port", "http://example.com:8080", "http://example.com:8080"},
		{"handles_ipv6_default_port", "https://[2001:db8::1]:443", "https://[2001:db8::1]"},
		{"returns_trimmed_when_invalid", "example.com", "example.com"},
		{"empty_string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, normalizeOrigin(tt.input))
		})
	}
}

func TestBuildAllowedOrigins(t *testing.T) {
	t.Run("custom server origins do not auto-include frontend", func(t *testing.T) {
		cfg := config.Config{
			Server: config.Server{
				AllowedOrigins: []string{
					"https://Example.com",
					"https://example.com:443/",
					"https://example.com:4443",
					"http://localhost:5173",
				},
			},
			Frontend: config.Frontend{BaseURL: "https://ui.example.com/"},
		}

		origins := buildAllowedOrigins(cfg)
		require.NotEmpty(t, origins)
		seen := make(map[string]struct{}, len(origins))
		for _, origin := range origins {
			seen[origin] = struct{}{}
		}
		require.Len(t, seen, len(origins), "expected unique origins")
		require.Contains(t, origins, "https://example.com")
		require.Contains(t, origins, "https://example.com:4443")
		require.NotContains(t, origins, "https://ui.example.com")
	})

	t.Run("defaults include frontend base URL when provided", func(t *testing.T) {
		os.Setenv("BREAKGLASS_ALLOW_DEFAULT_ORIGINS", "true")
		t.Cleanup(func() { os.Unsetenv("BREAKGLASS_ALLOW_DEFAULT_ORIGINS") })
		cfg := config.Config{
			Frontend: config.Frontend{BaseURL: "https://ui.example.com"},
		}
		origins := buildAllowedOrigins(cfg)
		expected := append([]string{}, defaultAllowedOrigins...)
		expected = append(expected, "https://ui.example.com")
		require.ElementsMatch(t, expected, origins)
	})

	t.Run("empty config yields empty allowlist unless defaults enabled", func(t *testing.T) {
		os.Unsetenv("BREAKGLASS_ALLOW_DEFAULT_ORIGINS")
		defaults := buildAllowedOrigins(config.Config{})
		require.Empty(t, defaults)
	})
}

func TestSecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress:  ":8080",
			AllowedOrigins: []string{"https://test.example.com"},
		},
	}

	server := NewServer(logger, cfg, true, &AuthHandler{})
	require.NotNil(t, server)

	// Make a request to check security headers are present
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	w := httptest.NewRecorder()
	server.gin.ServeHTTP(w, req)

	// Verify security headers are set
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"),
		"X-Content-Type-Options header should be set to 'nosniff'")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"),
		"X-Frame-Options header should be set to 'DENY'")
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"),
		"X-XSS-Protection header should be set")
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"),
		"Referrer-Policy header should be set")
	assert.NotEmpty(t, w.Header().Get("Permissions-Policy"),
		"Permissions-Policy header should be set")
	assert.NotEmpty(t, w.Header().Get("Content-Security-Policy"),
		"Content-Security-Policy header should be set")

	// Verify CSP contains expected directives
	csp := w.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Contains(t, csp, "frame-src")
}

func TestHSTSHeaderBehindProxy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress:  ":8080",
			AllowedOrigins: []string{"https://test.example.com"},
		},
	}

	server := NewServer(logger, cfg, true, &AuthHandler{})
	require.NotNil(t, server)

	tests := []struct {
		name           string
		headers        map[string]string
		expectHSTS     bool
		expectedHeader string
	}{
		{
			name:       "no proxy headers - no HSTS",
			headers:    nil,
			expectHSTS: false,
		},
		{
			name: "X-Forwarded-Proto https - HSTS enabled",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			expectHSTS:     true,
			expectedHeader: "max-age=31536000; includeSubDomains",
		},
		{
			name: "X-Forwarded-Proto http - no HSTS",
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			expectHSTS: false,
		},
		{
			name: "X-Forwarded-Ssl on - HSTS enabled",
			headers: map[string]string{
				"X-Forwarded-Ssl": "on",
			},
			expectHSTS:     true,
			expectedHeader: "max-age=31536000; includeSubDomains",
		},
		{
			name: "X-Forwarded-Ssl off - no HSTS",
			headers: map[string]string{
				"X-Forwarded-Ssl": "off",
			},
			expectHSTS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			server.gin.ServeHTTP(w, req)

			hstsHeader := w.Header().Get("Strict-Transport-Security")
			if tt.expectHSTS {
				assert.Equal(t, tt.expectedHeader, hstsHeader,
					"HSTS header should be set correctly when behind HTTPS proxy")
			} else {
				assert.Empty(t, hstsHeader,
					"HSTS header should not be set for non-HTTPS requests")
			}
		})
	}
}

// TestRespondHelpers_JSONErrorShape verifies that error response helpers produce
// the standardized JSON error body with both "error" and "code" fields.
func TestRespondHelpers_JSONErrorShape(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		handler      func(c *gin.Context)
		expectedCode int
		expectedJSON map[string]string
	}{
		{
			name:         "RespondNotFoundSimple",
			handler:      func(c *gin.Context) { RespondNotFoundSimple(c, "resource not found") },
			expectedCode: http.StatusNotFound,
			expectedJSON: map[string]string{"error": "resource not found", "code": "NOT_FOUND"},
		},
		{
			name:         "RespondBadRequest",
			handler:      func(c *gin.Context) { RespondBadRequest(c, "invalid input") },
			expectedCode: http.StatusBadRequest,
			expectedJSON: map[string]string{"error": "invalid input", "code": "BAD_REQUEST"},
		},
		{
			name:         "RespondForbidden",
			handler:      func(c *gin.Context) { RespondForbidden(c, "access denied") },
			expectedCode: http.StatusForbidden,
			expectedJSON: map[string]string{"error": "access denied", "code": "FORBIDDEN"},
		},
		{
			name:         "RespondInternalErrorSimple",
			handler:      func(c *gin.Context) { RespondInternalErrorSimple(c, "something went wrong") },
			expectedCode: http.StatusInternalServerError,
			expectedJSON: map[string]string{"error": "something went wrong", "code": "INTERNAL_ERROR"},
		},
		{
			name:         "RespondUnauthorized",
			handler:      func(c *gin.Context) { RespondUnauthorized(c) },
			expectedCode: http.StatusUnauthorized,
			expectedJSON: map[string]string{"error": "user not authenticated", "code": "UNAUTHORIZED"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test", tt.handler)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)

			var body map[string]string
			err := json.Unmarshal(w.Body.Bytes(), &body)
			require.NoError(t, err, "response body should be valid JSON")

			assert.Equal(t, tt.expectedJSON["error"], body["error"],
				"error field must match")
			assert.Equal(t, tt.expectedJSON["code"], body["code"],
				"code field must be present and match")
		})
	}
}
