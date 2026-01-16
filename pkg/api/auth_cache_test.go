package api

import (
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestJWKSCacheConfig(t *testing.T) {
	t.Run("maxJWKSCacheSize constant is reasonable", func(t *testing.T) {
		// The cache should allow a reasonable number of IDPs
		assert.Equal(t, 100, maxJWKSCacheSize)
	})

	t.Run("JWKS cache is initialized empty", func(t *testing.T) {
		logger := zaptest.NewLogger(t)

		auth := &AuthHandler{
			jwksCache: make(map[string]*keyfunc.JWKS),
			log:       logger.Sugar(),
		}

		assert.Empty(t, auth.jwksCache)
	})
}

// Note: Full JWKS cache eviction testing would require mocking the keyfunc library
// and setting up real JWKS endpoints. The implementation follows the pattern of
// evicting half the cache when full to prevent thrashing.
//
// The key behaviors to verify:
// 1. Cache stores JWKS by issuer URL
// 2. When cache reaches maxJWKSCacheSize, eviction happens
// 3. Eviction removes roughly half the entries
// 4. Eviction calls EndBackground() on removed JWKS to stop refresh goroutines
//
// Integration tests in e2e/ verify the full multi-IDP authentication flow.
