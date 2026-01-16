// Package ratelimit provides per-IP and per-user rate limiting middleware for HTTP servers.
package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Config holds rate limiter configuration
type Config struct {
	// Rate is the number of requests allowed per second
	Rate float64
	// Burst is the maximum number of requests allowed in a burst
	Burst int
	// CleanupInterval is how often to clean up stale entries
	CleanupInterval time.Duration
	// MaxAge is how long to keep an entry after last access
	MaxAge time.Duration
}

// AuthenticatedConfig holds separate rate limits for authenticated and unauthenticated users
type AuthenticatedConfig struct {
	// UnauthenticatedRate applies to requests without a valid user identity (per-IP)
	Unauthenticated Config
	// AuthenticatedRate applies to requests with a valid user identity (per-user)
	Authenticated Config
	// UserIdentityKey is the gin context key to look up the user identity (e.g., "email", "user_id")
	UserIdentityKey string
}

// DefaultAPIConfig returns default config for API endpoints
// More restrictive: 20 req/s per IP, burst of 50
func DefaultAPIConfig() Config {
	return Config{
		Rate:            20,
		Burst:           50,
		CleanupInterval: time.Minute,
		MaxAge:          5 * time.Minute,
	}
}

// DefaultAuthenticatedAPIConfig returns default config for API endpoints with auth differentiation
// Unauthenticated: 10 req/s per IP, burst of 20 (more restrictive)
// Authenticated: 50 req/s per user, burst of 100 (more generous)
func DefaultAuthenticatedAPIConfig() AuthenticatedConfig {
	return AuthenticatedConfig{
		Unauthenticated: Config{
			Rate:            10,
			Burst:           20,
			CleanupInterval: time.Minute,
			MaxAge:          5 * time.Minute,
		},
		Authenticated: Config{
			Rate:            50,
			Burst:           100,
			CleanupInterval: time.Minute,
			MaxAge:          10 * time.Minute,
		},
		UserIdentityKey: "email",
	}
}

// DefaultSARConfig returns default config for SAR (SubjectAccessReview) endpoints
// Much higher limits: 1000 req/s per IP, burst of 5000
// SARs are called very frequently by the Kubernetes API server
func DefaultSARConfig() Config {
	return Config{
		Rate:            1000,
		Burst:           5000,
		CleanupInterval: time.Minute,
		MaxAge:          5 * time.Minute,
	}
}

// entry holds rate limiter and last access time for an IP or user
type entry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// IPRateLimiter implements per-IP rate limiting with automatic cleanup
type IPRateLimiter struct {
	mu      sync.RWMutex
	entries map[string]*entry
	config  Config
	done    chan struct{}
}

// New creates a new per-IP rate limiter with the given configuration
func New(cfg Config) *IPRateLimiter {
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 5 * time.Minute
	}

	rl := &IPRateLimiter{
		entries: make(map[string]*entry),
		config:  cfg,
		done:    make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given IP should be allowed
func (rl *IPRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, exists := rl.entries[ip]
	if !exists {
		e = &entry{
			limiter: rate.NewLimiter(rate.Limit(rl.config.Rate), rl.config.Burst),
		}
		rl.entries[ip] = e
	}
	e.lastAccess = time.Now()

	return e.limiter.Allow()
}

// Middleware returns a Gin middleware that applies per-IP rate limiting
func (rl *IPRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded, please try again later",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Stop stops the cleanup goroutine
func (rl *IPRateLimiter) Stop() {
	close(rl.done)
}

// cleanup periodically removes stale entries
func (rl *IPRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.cleanupStaleEntries()
		}
	}
}

// cleanupStaleEntries removes entries that haven't been accessed recently
func (rl *IPRateLimiter) cleanupStaleEntries() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, e := range rl.entries {
		if now.Sub(e.lastAccess) > rl.config.MaxAge {
			delete(rl.entries, ip)
		}
	}
}

// Len returns the current number of tracked IPs (for testing/metrics)
func (rl *IPRateLimiter) Len() int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return len(rl.entries)
}

// AuthenticatedRateLimiter implements separate rate limiting for authenticated and unauthenticated users
// Authenticated users are tracked by user identity (e.g., email) and get higher limits
// Unauthenticated users are tracked by IP and get lower limits
type AuthenticatedRateLimiter struct {
	ipLimiter   *IPRateLimiter // For unauthenticated requests (per-IP)
	userLimiter *IPRateLimiter // For authenticated requests (per-user identity)
	userKey     string         // The gin context key to look up user identity
}

// NewAuthenticated creates a new rate limiter that differentiates between authenticated and unauthenticated users
func NewAuthenticated(cfg AuthenticatedConfig) *AuthenticatedRateLimiter {
	if cfg.UserIdentityKey == "" {
		cfg.UserIdentityKey = "email"
	}

	return &AuthenticatedRateLimiter{
		ipLimiter:   New(cfg.Unauthenticated),
		userLimiter: New(cfg.Authenticated),
		userKey:     cfg.UserIdentityKey,
	}
}

// Allow checks if a request should be allowed based on user identity or IP
// Returns (allowed, isAuthenticated)
func (arl *AuthenticatedRateLimiter) Allow(c *gin.Context) (bool, bool) {
	// Check if user is authenticated by looking for user identity in context
	if userID, exists := c.Get(arl.userKey); exists {
		if userStr, ok := userID.(string); ok && userStr != "" {
			// User is authenticated - use per-user rate limit
			return arl.userLimiter.Allow(userStr), true
		}
	}

	// User is not authenticated - use per-IP rate limit
	ip := c.ClientIP()
	return arl.ipLimiter.Allow(ip), false
}

// Middleware returns a Gin middleware that applies differentiated rate limiting
// This middleware should be applied AFTER authentication middleware
func (arl *AuthenticatedRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		allowed, isAuthenticated := arl.Allow(c)
		if !allowed {
			msg := "Rate limit exceeded, please try again later"
			if !isAuthenticated {
				msg = "Rate limit exceeded. Please authenticate for higher limits."
			}
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":         msg,
				"authenticated": isAuthenticated,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Stop stops both cleanup goroutines
func (arl *AuthenticatedRateLimiter) Stop() {
	arl.ipLimiter.Stop()
	arl.userLimiter.Stop()
}

// IPLen returns the current number of tracked IPs (for testing/metrics)
func (arl *AuthenticatedRateLimiter) IPLen() int {
	return arl.ipLimiter.Len()
}

// UserLen returns the current number of tracked users (for testing/metrics)
func (arl *AuthenticatedRateLimiter) UserLen() int {
	return arl.userLimiter.Len()
}

// Config returns a copy of the current configuration (for testing)
func (rl *IPRateLimiter) Config() Config {
	return rl.config
}
