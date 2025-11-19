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

	req, err := http.NewRequest("GET", "/config", nil)
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

	req, err := http.NewRequest("GET", "/identity-provider", nil)
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

	req, err := http.NewRequest("GET", "/identity-provider", nil)
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

	req, err := http.NewRequest("GET", "/identity-provider", nil)
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

	req, err := http.NewRequest("GET", "/config", nil)
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

	req, err := http.NewRequest("GET", "/identity-provider", nil)
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

			req, err := http.NewRequest("GET", "/identity-provider", nil)
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

func TestServer_RegisterAll(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t)
	cfg := config.Config{}

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
	cfg := config.Config{}

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
	cfg := config.Config{}
	server := NewServer(logger, cfg, true, &AuthHandler{})

	// Use the engine directly and perform a request to an unknown /api/ path
	req, err := http.NewRequest("GET", "/api/unknown/thing", nil)
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

	req, err := http.NewRequest("GET", "/some/page", nil)
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
