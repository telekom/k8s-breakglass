// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/telekom/das-schiff-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

func TestNewServer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":8080",
		},
		Frontend: config.Frontend{
			OIDCAuthority: "https://auth.example.com",
			OIDCClientID:  "test-client-id",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://auth.example.com",
			JWKSEndpoint: ".well-known/jwks.json",
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
			OIDCAuthority: "https://auth.example.com",
			OIDCClientID:  "test-client-id",
		},
		AuthorizationServer: config.AuthorizationServer{
			URL:          "https://auth.example.com",
			JWKSEndpoint: ".well-known/jwks.json",
		},
	}

	server := &Server{config: cfg}
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

	assert.Equal(t, cfg.Frontend.OIDCAuthority, response.Frontend.OIDCAuthority)
	assert.Equal(t, cfg.Frontend.OIDCClientID, response.Frontend.OIDCClientID)
	assert.Equal(t, cfg.AuthorizationServer.URL, response.AuthorizationServer.URL)
	assert.Equal(t, cfg.AuthorizationServer.JWKSEndpoint, response.AuthorizationServer.JWKSEndpoint)
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
