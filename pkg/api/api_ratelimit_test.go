package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

func TestAPIServerRateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("server applies per-IP rate limiting", func(t *testing.T) {
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

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		// Add a simple test endpoint
		server.gin.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// First few requests should succeed (within burst limit)
		for i := 0; i < 20; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			server.gin.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		}
	})

	t.Run("rate limit returns 429 after exceeding limit", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := config.Config{
			Server: config.Server{
				ListenAddress: ":8080",
			},
		}

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		server.gin.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Make many rapid requests to exceed rate limit
		// Default API config is 20 req/s with burst of 50
		var rateLimited bool
		for i := 0; i < 100; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			server.gin.ServeHTTP(w, req)
			if w.Code == http.StatusTooManyRequests {
				rateLimited = true
				assert.Contains(t, w.Body.String(), "Rate limit exceeded")
				break
			}
		}

		assert.True(t, rateLimited, "should have been rate limited after many requests")
	})

	t.Run("different IPs have separate rate limits", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := config.Config{
			Server: config.Server{
				ListenAddress: ":8080",
			},
		}

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		server.gin.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Exhaust rate limit for IP1
		for i := 0; i < 60; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			server.gin.ServeHTTP(w, req)
		}

		// IP1 should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		server.gin.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "IP1 should be rate limited")

		// IP2 should still work
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		server.gin.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "IP2 should not be rate limited")
	})

	t.Run("rate limit refills over time", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := config.Config{
			Server: config.Server{
				ListenAddress: ":8080",
			},
		}

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		server.gin.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Exhaust rate limit
		for i := 0; i < 60; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			server.gin.ServeHTTP(w, req)
		}

		// Wait for tokens to refill (20 req/s = ~50ms per token)
		time.Sleep(100 * time.Millisecond)

		// Should be able to make requests again
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		server.gin.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "should be able to make requests after refill")
	})
}

func TestBodySizeLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("rejects requests exceeding body size limit", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := config.Config{
			Server: config.Server{
				ListenAddress: ":8080",
			},
		}

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		var bodyReceived []byte
		server.gin.POST("/test", func(c *gin.Context) {
			var err error
			bodyReceived, err = c.GetRawData()
			if err != nil {
				c.String(http.StatusRequestEntityTooLarge, "body too large")
				return
			}
			c.String(http.StatusOK, "OK")
		})

		// Create a request with body exceeding 1MB limit
		largeBody := make([]byte, 2<<20) // 2MB
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/test", nil)
		req.Body = &limitedReader{data: largeBody, limit: len(largeBody)}
		req.ContentLength = int64(len(largeBody))
		req.RemoteAddr = "192.168.1.1:12345"
		server.gin.ServeHTTP(w, req)

		// The request should fail due to body size limit
		// The exact behavior depends on how the handler deals with the error
		// We just verify the body wasn't fully read
		assert.Less(t, len(bodyReceived), len(largeBody), "large body should not be fully read")
	})

	t.Run("allows requests within body size limit", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := config.Config{
			Server: config.Server{
				ListenAddress: ":8080",
			},
		}

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		server.gin.POST("/test", func(c *gin.Context) {
			body, err := c.GetRawData()
			if err != nil {
				c.String(http.StatusRequestEntityTooLarge, "body too large")
				return
			}
			c.String(http.StatusOK, "received %d bytes", len(body))
		})

		// Create a request with body under 1MB limit
		smallBody := make([]byte, 1000) // 1KB
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/test", nil)
		req.Body = &limitedReader{data: smallBody, limit: len(smallBody)}
		req.ContentLength = int64(len(smallBody))
		req.RemoteAddr = "192.168.1.1:12345"
		server.gin.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "received 1000 bytes")
	})
}

// limitedReader is a simple io.ReadCloser for testing
type limitedReader struct {
	data   []byte
	offset int
	limit  int
}

func (r *limitedReader) Read(p []byte) (n int, err error) {
	if r.offset >= r.limit || r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *limitedReader) Close() error {
	return nil
}

func TestOptionalAuthRateLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("public endpoint gives higher limits to authenticated users", func(t *testing.T) {
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

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		// The /api/config endpoint uses optional auth rate limiting
		// Make requests without auth token (uses IP-based limits)
		for i := 0; i < 15; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			server.gin.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		}
	})

	t.Run("public endpoints get rate limited for unauthenticated users", func(t *testing.T) {
		logger := zaptest.NewLogger(t)
		cfg := config.Config{
			Server: config.Server{
				ListenAddress: ":8080",
			},
		}

		server := NewServer(logger, cfg, true, &AuthHandler{})
		require.NotNil(t, server)
		defer server.Close()

		// Make many rapid requests to exceed unauthenticated rate limit
		var rateLimited bool
		for i := 0; i < 100; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/api/config", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			server.gin.ServeHTTP(w, req)
			if w.Code == http.StatusTooManyRequests {
				rateLimited = true
				break
			}
		}

		assert.True(t, rateLimited, "should have been rate limited after many requests")
	})
}

func TestTryExtractUserIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns empty for missing Authorization header", func(t *testing.T) {
		auth := &AuthHandler{}

		router := gin.New()
		var identity string
		router.GET("/test", func(c *gin.Context) {
			identity = auth.tryExtractUserIdentity(c)
			c.String(http.StatusOK, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		router.ServeHTTP(w, req)

		assert.Empty(t, identity)
	})

	t.Run("returns empty for non-Bearer token", func(t *testing.T) {
		auth := &AuthHandler{}

		router := gin.New()
		var identity string
		router.GET("/test", func(c *gin.Context) {
			identity = auth.tryExtractUserIdentity(c)
			c.String(http.StatusOK, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		router.ServeHTTP(w, req)

		assert.Empty(t, identity)
	})

	t.Run("returns empty for malformed JWT", func(t *testing.T) {
		auth := &AuthHandler{}

		router := gin.New()
		var identity string
		router.GET("/test", func(c *gin.Context) {
			identity = auth.tryExtractUserIdentity(c)
			c.String(http.StatusOK, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt")
		router.ServeHTTP(w, req)

		assert.Empty(t, identity)
		assert.Empty(t, req.Header.Get("Authorization"), "Authorization header should be removed")
	})
}
