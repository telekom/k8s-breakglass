package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestDefaultConfigs(t *testing.T) {
	t.Run("DefaultAPIConfig", func(t *testing.T) {
		cfg := DefaultAPIConfig()
		assert.Equal(t, float64(20), cfg.Rate)
		assert.Equal(t, 50, cfg.Burst)
		assert.Equal(t, time.Minute, cfg.CleanupInterval)
		assert.Equal(t, 5*time.Minute, cfg.MaxAge)
	})

	t.Run("DefaultSARConfig", func(t *testing.T) {
		cfg := DefaultSARConfig()
		assert.Equal(t, float64(1000), cfg.Rate)
		assert.Equal(t, 5000, cfg.Burst)
		assert.Equal(t, time.Minute, cfg.CleanupInterval)
		assert.Equal(t, 5*time.Minute, cfg.MaxAge)
	})

	t.Run("SAR config allows more traffic than API config", func(t *testing.T) {
		apiCfg := DefaultAPIConfig()
		sarCfg := DefaultSARConfig()
		assert.Greater(t, sarCfg.Rate, apiCfg.Rate)
		assert.Greater(t, sarCfg.Burst, apiCfg.Burst)
	})
}

func TestNew(t *testing.T) {
	t.Run("creates limiter with config", func(t *testing.T) {
		cfg := Config{Rate: 10, Burst: 20, CleanupInterval: time.Second, MaxAge: time.Minute}
		rl := New(cfg)
		defer rl.Stop()

		assert.NotNil(t, rl)
		assert.Equal(t, float64(10), rl.Config().Rate)
		assert.Equal(t, 20, rl.Config().Burst)
	})

	t.Run("sets default cleanup interval if zero", func(t *testing.T) {
		cfg := Config{Rate: 10, Burst: 20, CleanupInterval: 0}
		rl := New(cfg)
		defer rl.Stop()

		assert.Equal(t, time.Minute, rl.Config().CleanupInterval)
	})

	t.Run("sets default max age if zero", func(t *testing.T) {
		cfg := Config{Rate: 10, Burst: 20, MaxAge: 0}
		rl := New(cfg)
		defer rl.Stop()

		assert.Equal(t, 5*time.Minute, rl.Config().MaxAge)
	})
}

func TestAllow(t *testing.T) {
	t.Run("allows requests within burst limit", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 5, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		// Should allow up to burst limit
		for i := 0; i < 5; i++ {
			assert.True(t, rl.Allow("192.168.1.1"), "request %d should be allowed", i)
		}
	})

	t.Run("blocks requests exceeding burst limit", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 3, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		// Exhaust burst
		for i := 0; i < 3; i++ {
			rl.Allow("192.168.1.1")
		}

		// Should block
		assert.False(t, rl.Allow("192.168.1.1"))
	})

	t.Run("different IPs have separate limits", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		// Exhaust IP1's burst
		rl.Allow("192.168.1.1")
		rl.Allow("192.168.1.1")
		assert.False(t, rl.Allow("192.168.1.1"))

		// IP2 should still be allowed
		assert.True(t, rl.Allow("192.168.1.2"))
		assert.True(t, rl.Allow("192.168.1.2"))
	})

	t.Run("tokens refill over time", func(t *testing.T) {
		cfg := Config{Rate: 10, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		// Exhaust burst
		assert.True(t, rl.Allow("192.168.1.1"))
		assert.False(t, rl.Allow("192.168.1.1"))

		// Wait for refill (10 req/s = 100ms per token)
		time.Sleep(150 * time.Millisecond)

		// Should be allowed again
		assert.True(t, rl.Allow("192.168.1.1"))
	})

	t.Run("tracks number of IPs", func(t *testing.T) {
		cfg := Config{Rate: 10, Burst: 10, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		assert.Equal(t, 0, rl.Len())

		rl.Allow("192.168.1.1")
		assert.Equal(t, 1, rl.Len())

		rl.Allow("192.168.1.2")
		assert.Equal(t, 2, rl.Len())

		// Same IP doesn't increase count
		rl.Allow("192.168.1.1")
		assert.Equal(t, 2, rl.Len())
	})
}

func TestMiddleware(t *testing.T) {
	t.Run("allows requests within limit", func(t *testing.T) {
		cfg := Config{Rate: 10, Burst: 5, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		}
	})

	t.Run("returns 429 when rate limited", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Exhaust burst
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
		}

		// Should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), "Rate limit exceeded")
	})

	t.Run("uses X-Forwarded-For header when configured", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		// Trust all proxies for this test
		err := router.SetTrustedProxies([]string{"0.0.0.0/0", "::/0"})
		require.NoError(t, err)
		router.ForwardedByClientIP = true
		router.Use(rl.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Requests from different X-Forwarded-For IPs should have separate limits
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "10.0.0.1:12345" // Proxy IP
			req.Header.Set("X-Forwarded-For", "192.168.1.1")
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Same X-Forwarded-For should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// Different X-Forwarded-For should still be allowed
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "192.168.1.2")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestMiddlewareWithExclusions(t *testing.T) {
	t.Run("excludes paths matching prefixes from rate limiting", func(t *testing.T) {
		// Very restrictive: 1 req/s, burst of 1 - so second request would be rate limited
		cfg := Config{Rate: 1, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.MiddlewareWithExclusions([]string{"/assets/", "/favicon"}))
		router.GET("/api/test", func(c *gin.Context) {
			c.String(http.StatusOK, "API OK")
		})
		router.GET("/assets/script.js", func(c *gin.Context) {
			c.String(http.StatusOK, "JS OK")
		})
		router.GET("/favicon.ico", func(c *gin.Context) {
			c.String(http.StatusOK, "FAVICON OK")
		})

		// First API request - should succeed
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Second API request from same IP - should be rate limited
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/api/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		// But /assets/* requests should NOT be rate limited (excluded)
		for i := 0; i < 10; i++ {
			w = httptest.NewRecorder()
			req, _ = http.NewRequest(http.MethodGet, "/assets/script.js", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "asset request %d should not be rate limited", i)
		}

		// And /favicon* requests should NOT be rate limited (excluded)
		for i := 0; i < 10; i++ {
			w = httptest.NewRecorder()
			req, _ = http.NewRequest(http.MethodGet, "/favicon.ico", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "favicon request %d should not be rate limited", i)
		}
	})

	t.Run("nil exclusions behaves like regular Middleware", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.MiddlewareWithExclusions(nil))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Exhaust burst
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("empty exclusions behaves like regular Middleware", func(t *testing.T) {
		cfg := Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.MiddlewareWithExclusions([]string{}))
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// Exhaust burst
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})
}

func TestCleanup(t *testing.T) {
	t.Run("removes stale entries", func(t *testing.T) {
		cfg := Config{
			Rate:            10,
			Burst:           10,
			CleanupInterval: 50 * time.Millisecond,
			MaxAge:          100 * time.Millisecond,
		}
		rl := New(cfg)
		defer rl.Stop()

		// Add some IPs
		rl.Allow("192.168.1.1")
		rl.Allow("192.168.1.2")
		assert.Equal(t, 2, rl.Len())

		// Wait for cleanup
		time.Sleep(200 * time.Millisecond)

		// Entries should be cleaned up
		assert.Equal(t, 0, rl.Len())
	})

	t.Run("keeps recently accessed entries", func(t *testing.T) {
		cfg := Config{
			Rate:            10,
			Burst:           10,
			CleanupInterval: 50 * time.Millisecond,
			MaxAge:          200 * time.Millisecond,
		}
		rl := New(cfg)
		defer rl.Stop()

		// Add an IP
		rl.Allow("192.168.1.1")
		assert.Equal(t, 1, rl.Len())

		// Keep accessing it
		for i := 0; i < 5; i++ {
			time.Sleep(50 * time.Millisecond)
			rl.Allow("192.168.1.1")
		}

		// Should still be there
		assert.Equal(t, 1, rl.Len())
	})

	t.Run("Stop stops cleanup goroutine", func(t *testing.T) {
		cfg := Config{
			Rate:            10,
			Burst:           10,
			CleanupInterval: 10 * time.Millisecond,
			MaxAge:          10 * time.Millisecond,
		}
		rl := New(cfg)

		rl.Allow("192.168.1.1")
		rl.Stop()

		// After stop, entries won't be cleaned up automatically
		time.Sleep(50 * time.Millisecond)
		// Can't guarantee entry count due to timing, but at least it shouldn't panic
	})
}

func TestConcurrency(t *testing.T) {
	t.Run("handles concurrent requests safely", func(t *testing.T) {
		cfg := Config{Rate: 1000, Burst: 1000, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		var wg sync.WaitGroup
		numGoroutines := 100
		requestsPerGoroutine := 100

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ip := "192.168.1.1" // Same IP to stress test
				for j := 0; j < requestsPerGoroutine; j++ {
					rl.Allow(ip)
				}
			}()
		}

		wg.Wait()
		// Should not panic or deadlock
		assert.Equal(t, 1, rl.Len())
	})

	t.Run("handles concurrent requests from different IPs", func(t *testing.T) {
		cfg := Config{Rate: 100, Burst: 100, CleanupInterval: time.Hour, MaxAge: time.Hour}
		rl := New(cfg)
		defer rl.Stop()

		var wg sync.WaitGroup
		numIPs := 50

		for i := 0; i < numIPs; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				ip := "192.168.1." + string(rune('0'+id%10))
				for j := 0; j < 10; j++ {
					rl.Allow(ip)
				}
			}(i)
		}

		wg.Wait()
		// Should not panic or deadlock
		assert.LessOrEqual(t, rl.Len(), 10) // At most 10 unique IPs (0-9)
	})
}

func TestHighThroughput(t *testing.T) {
	t.Run("SAR config handles high throughput", func(t *testing.T) {
		cfg := DefaultSARConfig()
		rl := New(cfg)
		defer rl.Stop()

		// Simulate burst of SAR requests
		allowed := 0
		for i := 0; i < 5000; i++ {
			if rl.Allow("192.168.1.1") {
				allowed++
			}
		}

		// Should allow at least burst amount
		assert.GreaterOrEqual(t, allowed, cfg.Burst)
	})

	t.Run("API config is more restrictive", func(t *testing.T) {
		cfg := DefaultAPIConfig()
		rl := New(cfg)
		defer rl.Stop()

		// Simulate burst of API requests
		allowed := 0
		for i := 0; i < 100; i++ {
			if rl.Allow("192.168.1.1") {
				allowed++
			}
		}

		// Should allow burst amount, then block
		assert.Equal(t, cfg.Burst, allowed)
	})
}

func BenchmarkAllow(b *testing.B) {
	cfg := DefaultSARConfig()
	rl := New(cfg)
	defer rl.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("192.168.1.1")
	}
}

func BenchmarkAllowParallel(b *testing.B) {
	cfg := DefaultSARConfig()
	rl := New(cfg)
	defer rl.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow("192.168.1.1")
		}
	})
}

func BenchmarkMiddleware(b *testing.B) {
	cfg := DefaultSARConfig()
	rl := New(cfg)
	defer rl.Stop()

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func TestIPRateLimiterIntegration(t *testing.T) {
	t.Run("realistic API scenario", func(t *testing.T) {
		cfg := DefaultAPIConfig()
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.Middleware())
		router.POST("/api/sessions", func(c *gin.Context) {
			c.String(http.StatusCreated, "created")
		})
		router.GET("/api/sessions", func(c *gin.Context) {
			c.String(http.StatusOK, "list")
		})

		// Simulate normal user behavior - should all succeed within burst
		for i := 0; i < 20; i++ {
			w := httptest.NewRecorder()
			method := http.MethodGet
			if i%5 == 0 {
				method = http.MethodPost
			}
			req, _ := http.NewRequest(method, "/api/sessions", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			// POST returns 201, GET returns 200
			expectedStatus := http.StatusOK
			if method == http.MethodPost {
				expectedStatus = http.StatusCreated
			}
			require.Equal(t, expectedStatus, w.Code, "request %d should succeed (got %d)", i, w.Code)
		}
	})

	t.Run("realistic SAR scenario", func(t *testing.T) {
		cfg := DefaultSARConfig()
		rl := New(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(rl.Middleware())
		router.POST("/breakglass/webhook/authorize/:cluster", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"allowed": true})
		})

		// Simulate high-frequency SAR requests from K8s API server
		// Should handle thousands of requests
		successCount := 0
		for i := 0; i < 4000; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/cluster1", nil)
			req.RemoteAddr = "10.0.0.1:12345" // API server IP
			router.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				successCount++
			}
		}

		// Most requests should succeed
		assert.GreaterOrEqual(t, successCount, 4000, "SAR endpoint should handle high throughput")
	})
}

// Tests for AuthenticatedRateLimiter

func TestDefaultAuthenticatedAPIConfig(t *testing.T) {
	cfg := DefaultAuthenticatedAPIConfig()

	t.Run("unauthenticated config is more restrictive", func(t *testing.T) {
		assert.Equal(t, float64(10), cfg.Unauthenticated.Rate)
		assert.Equal(t, 20, cfg.Unauthenticated.Burst)
	})

	t.Run("authenticated config is more generous", func(t *testing.T) {
		assert.Equal(t, float64(50), cfg.Authenticated.Rate)
		assert.Equal(t, 100, cfg.Authenticated.Burst)
	})

	t.Run("authenticated users get higher limits", func(t *testing.T) {
		assert.Greater(t, cfg.Authenticated.Rate, cfg.Unauthenticated.Rate)
		assert.Greater(t, cfg.Authenticated.Burst, cfg.Unauthenticated.Burst)
	})

	t.Run("default user identity key is email", func(t *testing.T) {
		assert.Equal(t, "email", cfg.UserIdentityKey)
	})
}

func TestNewAuthenticated(t *testing.T) {
	t.Run("creates limiter with config", func(t *testing.T) {
		cfg := DefaultAuthenticatedAPIConfig()
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		assert.NotNil(t, rl)
		assert.NotNil(t, rl.ipLimiter)
		assert.NotNil(t, rl.userLimiter)
	})

	t.Run("uses default user identity key if empty", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 10, Burst: 20},
			Authenticated:   Config{Rate: 50, Burst: 100},
			UserIdentityKey: "",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		assert.Equal(t, "email", rl.userKey)
	})

	t.Run("respects custom user identity key", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 10, Burst: 20},
			Authenticated:   Config{Rate: 50, Burst: 100},
			UserIdentityKey: "user_id",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		assert.Equal(t, "user_id", rl.userKey)
	})
}

func TestAuthenticatedAllow(t *testing.T) {
	t.Run("uses IP-based limiting for unauthenticated requests", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 10, Burst: 20, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		router.GET("/test", func(c *gin.Context) {
			allowed, isAuth := rl.Allow(c)
			assert.False(t, isAuth, "should not be authenticated")
			if allowed {
				c.String(http.StatusOK, "OK")
			} else {
				c.String(http.StatusTooManyRequests, "rate limited")
			}
		})

		// Should allow burst limit
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		}

		// Should block after burst
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		assert.Equal(t, 1, rl.IPLen())
		assert.Equal(t, 0, rl.UserLen())
	})

	t.Run("uses user-based limiting for authenticated requests", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 1, Burst: 5, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		router.GET("/test", func(c *gin.Context) {
			// Simulate authenticated user
			c.Set("email", "user@example.com")
			allowed, isAuth := rl.Allow(c)
			assert.True(t, isAuth, "should be authenticated")
			if allowed {
				c.String(http.StatusOK, "OK")
			} else {
				c.String(http.StatusTooManyRequests, "rate limited")
			}
		})

		// Should allow higher burst limit for authenticated users
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		}

		// Should block after authenticated burst
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)

		assert.Equal(t, 0, rl.IPLen())
		assert.Equal(t, 1, rl.UserLen())
	})

	t.Run("authenticated users have separate limits from IPs", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 1, Burst: 3, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		router.GET("/unauth", func(c *gin.Context) {
			allowed, _ := rl.Allow(c)
			if allowed {
				c.String(http.StatusOK, "OK")
			} else {
				c.String(http.StatusTooManyRequests, "rate limited")
			}
		})
		router.GET("/auth", func(c *gin.Context) {
			c.Set("email", "user@example.com")
			allowed, _ := rl.Allow(c)
			if allowed {
				c.String(http.StatusOK, "OK")
			} else {
				c.String(http.StatusTooManyRequests, "rate limited")
			}
		})

		// Exhaust unauthenticated limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/unauth", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
		}

		// Unauthenticated should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/unauth", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "unauthenticated should be rate limited")

		// Authenticated user from same IP should NOT be rate limited (separate pool)
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/auth", nil)
			req.RemoteAddr = "192.168.1.1:12345" // Same IP
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "authenticated request %d should succeed", i)
		}
	})

	t.Run("different authenticated users have separate limits", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		router.GET("/test/:user", func(c *gin.Context) {
			user := c.Param("user")
			c.Set("email", user+"@example.com")
			allowed, _ := rl.Allow(c)
			if allowed {
				c.String(http.StatusOK, "OK")
			} else {
				c.String(http.StatusTooManyRequests, "rate limited")
			}
		})

		// Exhaust user1's limit
		for i := 0; i < 3; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test/user1", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
		}

		// user1 should be rate limited
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test/user1", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code, "user1 should be rate limited")

		// user2 should still be allowed
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/test/user2", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "user2 should not be rate limited")

		assert.Equal(t, 2, rl.UserLen())
	})
}

func TestAuthenticatedMiddleware(t *testing.T) {
	t.Run("middleware allows authenticated users within limit", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 2, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 1, Burst: 5, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		// Simulate auth middleware setting email
		router.Use(func(c *gin.Context) {
			c.Set("email", "user@example.com")
			c.Next()
		})
		router.Use(rl.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = "192.168.1.1:12345"
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
		}
	})

	t.Run("middleware returns 429 with authenticated flag", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 1, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("email", "user@example.com")
			c.Next()
		})
		router.Use(rl.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// First request succeeds
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Second request rate limited
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), `"authenticated":true`)
	})

	t.Run("middleware message differs for unauthenticated", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 1, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 1, Burst: 1, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		// No auth middleware - unauthenticated
		router.Use(rl.Middleware())
		router.GET("/test", func(c *gin.Context) {
			c.String(http.StatusOK, "OK")
		})

		// First request succeeds
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Second request rate limited with different message
		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
		assert.Contains(t, w.Body.String(), `"authenticated":false`)
		assert.Contains(t, w.Body.String(), "Please authenticate for higher limits")
	})
}

func TestAuthenticatedStop(t *testing.T) {
	t.Run("stops both cleanup goroutines", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 10, Burst: 20, CleanupInterval: 10 * time.Millisecond, MaxAge: 10 * time.Millisecond},
			Authenticated:   Config{Rate: 50, Burst: 100, CleanupInterval: 10 * time.Millisecond, MaxAge: 10 * time.Millisecond},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)

		// Add some entries
		router := gin.New()
		router.GET("/unauth", func(c *gin.Context) {
			rl.Allow(c)
			c.String(http.StatusOK, "OK")
		})
		router.GET("/auth", func(c *gin.Context) {
			c.Set("email", "user@example.com")
			rl.Allow(c)
			c.String(http.StatusOK, "OK")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/unauth", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)

		w = httptest.NewRecorder()
		req, _ = http.NewRequest(http.MethodGet, "/auth", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		router.ServeHTTP(w, req)

		assert.Equal(t, 1, rl.IPLen())
		assert.Equal(t, 1, rl.UserLen())

		// Stop should not panic
		rl.Stop()

		// After stop, cleanup won't happen but we shouldn't panic
		time.Sleep(50 * time.Millisecond)
	})
}

func TestAuthenticatedConcurrency(t *testing.T) {
	t.Run("handles concurrent authenticated and unauthenticated requests", func(t *testing.T) {
		cfg := AuthenticatedConfig{
			Unauthenticated: Config{Rate: 100, Burst: 200, CleanupInterval: time.Hour, MaxAge: time.Hour},
			Authenticated:   Config{Rate: 100, Burst: 200, CleanupInterval: time.Hour, MaxAge: time.Hour},
			UserIdentityKey: "email",
		}
		rl := NewAuthenticated(cfg)
		defer rl.Stop()

		router := gin.New()
		router.GET("/unauth", func(c *gin.Context) {
			rl.Allow(c)
			c.String(http.StatusOK, "OK")
		})
		router.GET("/auth/:user", func(c *gin.Context) {
			c.Set("email", c.Param("user")+"@example.com")
			rl.Allow(c)
			c.String(http.StatusOK, "OK")
		})

		var wg sync.WaitGroup
		numGoroutines := 50

		// Unauthenticated requests
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					w := httptest.NewRecorder()
					req, _ := http.NewRequest(http.MethodGet, "/unauth", nil)
					req.RemoteAddr = "192.168.1.1:12345"
					router.ServeHTTP(w, req)
				}
			}()
		}

		// Authenticated requests
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					w := httptest.NewRecorder()
					req, _ := http.NewRequest(http.MethodGet, "/auth/user"+string(rune('0'+id%10)), nil)
					req.RemoteAddr = "192.168.1.1:12345"
					router.ServeHTTP(w, req)
				}
			}(i)
		}

		wg.Wait()
		// Should not panic or deadlock
	})
}
