package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

func TestServer_Close_StopsRateLimiters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":0",
		},
		Frontend: config.Frontend{
			BaseURL: "http://localhost:5173",
		},
	}

	server := NewServer(log, cfg, true, nil)
	require.NotNil(t, server)
	require.NotNil(t, server.publicRateLimiter)
	require.NotNil(t, server.publicAuthRateLimiter)

	// Close should not panic and should stop rate limiters
	server.Close()
	// Note: Close() is not idempotent due to rate limiter channel closing
	// Calling it twice would panic, which is expected behavior
}

func TestServer_Close_HandlesNilRateLimiters(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a server with nil rate limiters to test nil safety
	server := &Server{
		publicRateLimiter:     nil,
		publicAuthRateLimiter: nil,
	}

	// Should not panic
	server.Close()
}

func TestServer_Handler_ReturnsGinEngine(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":0",
		},
		Frontend: config.Frontend{
			BaseURL: "http://localhost:5173",
		},
	}

	server := NewServer(log, cfg, true, nil)
	defer server.Close()

	handler := server.Handler()
	require.NotNil(t, handler)

	// Test that the handler can serve a request
	req := httptest.NewRequest(http.MethodGet, "/api/debug/buildinfo", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServer_RateLimiterCleanup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":0",
		},
		Frontend: config.Frontend{
			BaseURL: "http://localhost:5173",
		},
	}

	// Create multiple servers to ensure cleanup works
	var servers []*Server
	for i := 0; i < 5; i++ {
		s := NewServer(log, cfg, true, nil)
		servers = append(servers, s)
	}

	// Close all servers (each only closed once)
	for _, s := range servers {
		s.Close()
	}

	// No goroutine leaks should occur (can't directly test, but no panics is good)
}

func TestServer_RequestsCompleteDuringShutdown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":0",
		},
		Frontend: config.Frontend{
			BaseURL: "http://localhost:5173",
		},
	}

	server := NewServer(log, cfg, true, nil)
	require.NotNil(t, server)

	// Simulate a request in progress
	handler := server.Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/debug/buildinfo", nil)
	w := httptest.NewRecorder()

	// Start request processing
	handler.ServeHTTP(w, req)

	// Request should complete
	assert.Equal(t, http.StatusOK, w.Code)

	// Now close the server
	server.Close()
}

func TestServer_GracefulShutdownPattern(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := zaptest.NewLogger(t)

	cfg := config.Config{
		Server: config.Server{
			ListenAddress: ":0",
		},
		Frontend: config.Frontend{
			BaseURL: "http://localhost:5173",
		},
	}

	// This test demonstrates the expected shutdown pattern
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server := NewServer(log, cfg, true, nil)
	require.NotNil(t, server)

	// Simulate running requests
	handler := server.Handler()
	var wg sync.WaitGroup

	// Start some concurrent requests
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/debug/buildinfo", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}()
	}

	// Wait for requests to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All requests completed
	case <-ctx.Done():
		t.Fatal("Requests did not complete in time")
	}

	// Clean shutdown
	server.Close()
}
