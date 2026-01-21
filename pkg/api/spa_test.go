package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestServeSPA(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir, err := os.MkdirTemp("", "spa-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create test files
	indexContent := `<!DOCTYPE html><html><body>Index Page</body></html>`
	cssContent := `body { color: red; }`

	err = os.WriteFile(filepath.Join(tempDir, "index.html"), []byte(indexContent), 0644)
	assert.NoError(t, err)

	err = os.Mkdir(filepath.Join(tempDir, "assets"), 0755)
	assert.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "assets", "style.css"), []byte(cssContent), 0644)
	assert.NoError(t, err)

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		urlPrefix      string
		requestPath    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Serve existing file",
			urlPrefix:      "/",
			requestPath:    "/assets/style.css",
			expectedStatus: http.StatusOK,
			expectedBody:   cssContent,
		},
		{
			name:           "Serve index for non-existing path",
			urlPrefix:      "/",
			requestPath:    "/some/non/existing/path",
			expectedStatus: http.StatusOK,
			expectedBody:   indexContent,
		},
		{
			name:           "Serve index for root path",
			urlPrefix:      "/",
			requestPath:    "/",
			expectedStatus: http.StatusOK,
			expectedBody:   indexContent,
		},
		{
			name:           "Serve with different prefix",
			urlPrefix:      "/app",
			requestPath:    "/app/",
			expectedStatus: http.StatusOK,
			expectedBody:   indexContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.NoRoute(ServeSPA(tt.urlPrefix, tempDir))

			req, err := http.NewRequest(http.MethodGet, tt.requestPath, nil)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
		})
	}
}

func TestServeSPA_EmptyPrefix(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "spa-test-empty")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create test index file
	indexContent := `<!DOCTYPE html><html><body>Empty Prefix Test</body></html>`
	err = os.WriteFile(filepath.Join(tempDir, "index.html"), []byte(indexContent), 0644)
	assert.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.NoRoute(ServeSPA("", tempDir))

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), indexContent)
}

func TestServeSPA_NonExistentDirectory(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test with non-existent directory
	router := gin.New()
	router.NoRoute(ServeSPA("/", "/non/existent/directory"))

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return some kind of error status (404 or 500)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestServeSPA_CacheHeaders(t *testing.T) {
	// Create a temporary directory structure for testing
	tempDir, err := os.MkdirTemp("", "spa-cache-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create test files simulating Vite build output
	indexContent := `<!DOCTYPE html><html><body>Index</body></html>`
	jsContent := `console.log("app")`
	cssContent := `body { color: red; }`
	fontContent := `fake-font-data`

	err = os.WriteFile(filepath.Join(tempDir, "index.html"), []byte(indexContent), 0644)
	assert.NoError(t, err)

	err = os.Mkdir(filepath.Join(tempDir, "assets"), 0755)
	assert.NoError(t, err)

	// Hashed assets (Vite puts these in /assets/)
	err = os.WriteFile(filepath.Join(tempDir, "assets", "index-abc123.js"), []byte(jsContent), 0644)
	assert.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "assets", "style-def456.css"), []byte(cssContent), 0644)
	assert.NoError(t, err)

	// Non-hashed file at root
	err = os.WriteFile(filepath.Join(tempDir, "font.woff2"), []byte(fontContent), 0644)
	assert.NoError(t, err)

	gin.SetMode(gin.TestMode)

	tests := []struct {
		name                 string
		requestPath          string
		expectedCacheControl string
	}{
		{
			name:                 "index.html should have no-cache",
			requestPath:          "/",
			expectedCacheControl: "no-cache, must-revalidate",
		},
		{
			name:                 "SPA fallback should have no-cache",
			requestPath:          "/some/route",
			expectedCacheControl: "no-cache, must-revalidate",
		},
		{
			name:                 "hashed JS in assets should be immutable",
			requestPath:          "/assets/index-abc123.js",
			expectedCacheControl: "public, max-age=31536000, immutable",
		},
		{
			name:                 "hashed CSS in assets should be immutable",
			requestPath:          "/assets/style-def456.css",
			expectedCacheControl: "public, max-age=31536000, immutable",
		},
		{
			name:                 "non-hashed files should have short cache with revalidate",
			requestPath:          "/font.woff2",
			expectedCacheControl: "public, max-age=3600, must-revalidate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.NoRoute(ServeSPA("/", tempDir))

			req, err := http.NewRequest(http.MethodGet, tt.requestPath, nil)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tt.expectedCacheControl, w.Header().Get("Cache-Control"),
				"Cache-Control header mismatch for %s", tt.requestPath)
		})
	}
}
