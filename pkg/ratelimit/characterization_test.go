// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestPlatformRateLimitIdentityResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := Config{Rate: 0.0001, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Minute}
	limiter := NewAuthenticated(AuthenticatedConfig{Unauthenticated: cfg, Authenticated: cfg, UserIdentityKey: "identity"})
	t.Cleanup(limiter.Stop)
	engine := gin.New()
	require.NoError(t, engine.SetTrustedProxies(nil))
	engine.Use(func(c *gin.Context) {
		if identity := c.GetHeader("X-Test-Identity"); identity != "" {
			c.Set("identity", identity)
		}
		c.Next()
	}, limiter.Middleware())
	handlerCalls := 0
	engine.GET("/limited", func(c *gin.Context) { handlerCalls++; c.Status(http.StatusNoContent) })
	request := func(ip, identity string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		req.RemoteAddr = ip + ":12345"
		req.Header.Set("X-Test-Identity", identity)
		req.Header.Set("X-Forwarded-For", "198.51.100.99")
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, req)
		return response
	}
	require.Equal(t, http.StatusNoContent, request("192.0.2.1", "").Code)
	unauthenticated := request("192.0.2.1", "")
	require.Equal(t, http.StatusTooManyRequests, unauthenticated.Code)
	require.JSONEq(t, `{"error":"Rate limit exceeded. Please authenticate for higher limits.","authenticated":false}`, unauthenticated.Body.String())
	require.Empty(t, unauthenticated.Header().Get("Retry-After"), "general middleware has no retry header")
	require.Equal(t, http.StatusNoContent, request("192.0.2.2", "").Code, "untrusted forwarding header cannot share IP buckets")
	require.Equal(t, http.StatusNoContent, request("192.0.2.1", "alice").Code, "identity and anonymous buckets are separate")
	authenticated := request("192.0.2.2", "alice")
	require.Equal(t, http.StatusTooManyRequests, authenticated.Code, "identity bucket follows the user across IPs")
	require.JSONEq(t, `{"error":"Rate limit exceeded, please try again later","authenticated":true}`, authenticated.Body.String())
	require.Equal(t, http.StatusNoContent, request("192.0.2.1", "bob").Code, "users on the same IP are isolated")
	require.Equal(t, 4, handlerCalls, "denied requests abort downstream handlers")
	require.Equal(t, 2, limiter.IPLen())
	require.Equal(t, 2, limiter.UserLen())
}

func TestPlatformRateLimitEvictionAndRetry(t *testing.T) {
	limiter := New(Config{Rate: 0.0001, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Minute})
	t.Cleanup(limiter.Stop)
	allowed, delay := limiter.AllowWithRetryAfter("stale")
	require.True(t, allowed)
	require.Zero(t, delay)
	allowed, firstDelay := limiter.AllowWithRetryAfter("stale")
	require.False(t, allowed)
	require.InDelta(t, 10000, firstDelay.Seconds(), 1)
	allowed, nextDelay := limiter.AllowWithRetryAfter("stale")
	require.False(t, allowed)
	require.LessOrEqual(t, nextDelay, firstDelay, "denial cancels the reservation instead of accumulating token debt")
	require.True(t, limiter.Allow("active"))
	limiter.mu.Lock()
	limiter.entries["stale"].lastAccess = time.Now().Add(-2 * time.Minute)
	limiter.entries["active"].lastAccess = time.Now().Add(-2 * time.Minute)
	limiter.mu.Unlock()
	require.False(t, limiter.Allow("active"), "denied requests refresh idle age")
	limiter.cleanupStaleEntries()
	require.Equal(t, 1, limiter.Len())
	require.False(t, limiter.Allow("active"), "active entries preserve exhausted buckets")
	require.True(t, limiter.Allow("stale"), "idle eviction restores a fresh burst")
	require.Equal(t, 2, limiter.Len())
	zeroBurst := New(Config{Rate: 1, Burst: 0})
	t.Cleanup(zeroBurst.Stop)
	allowed, delay = zeroBurst.AllowWithRetryAfter("invalid")
	require.False(t, allowed)
	require.Equal(t, time.Minute, delay)
}
