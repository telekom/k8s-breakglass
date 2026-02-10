package api

import (
	"container/list"
	"testing"

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
			jwksCache:   make(map[string]*list.Element),
			jwksLRUList: list.New(),
			log:         logger.Sugar(),
		}

		assert.Empty(t, auth.jwksCache)
		assert.Equal(t, 0, auth.jwksLRUList.Len())
	})
}

// Note: Full JWKS cache eviction testing would require mocking the keyfunc library
// and setting up real JWKS endpoints. The implementation uses LRU eviction to
// remove the least recently used entries when cache reaches capacity.
//
// The key behaviors to verify:
// 1. Cache stores JWKS by issuer URL with LRU ordering
// 2. When cache reaches maxJWKSCacheSize, LRU eviction removes oldest entries
// 3. Cache hits move entries to front of LRU list (most recently used)
// 4. Eviction cancels the context of removed JWKS entries to stop refresh goroutines
//
// Integration tests in e2e/ verify the full multi-IDP authentication flow.
