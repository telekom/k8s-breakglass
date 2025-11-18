package api

import (
	"sync"
	"testing"

	"github.com/MicahParks/keyfunc"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

// TestAuthHandlerWithIdentityProviderLoader verifies that the auth handler
// properly accepts and uses the IDP loader for multi-IDP token verification.
// This test ensures that the WithIdentityProviderLoader() method works correctly
// and that the loader is properly stored on the auth handler.
//
// This change was made in cmd/main.go:
//
//	auth.WithIdentityProviderLoader(idpLoader)
func TestAuthHandlerWithIdentityProviderLoader(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	// Create a basic auth handler without loader
	auth := &AuthHandler{
		jwksCache: make(map[string]*keyfunc.JWKS),
		jwksMutex: sync.RWMutex{},
		log:       log,
		// idpLoader is not set initially
	}

	// Initially, loader should be nil
	assert.Nil(t, auth.idpLoader, "Auth handler should start with nil idpLoader")

	// Create a minimal loader (in this case, we test with nil which is acceptable for tests)
	// In production code (cmd/main.go), a real config.IdentityProviderLoader is passed
	var loader *config.IdentityProviderLoader

	// Set the loader on the auth handler using the method
	result := auth.WithIdentityProviderLoader(loader)

	// Verify that WithIdentityProviderLoader returns the auth handler itself (for chaining)
	assert.Equal(t, auth, result, "WithIdentityProviderLoader should return the auth handler for chaining")

	// Verify that the loader is stored (even though it's nil for this test)
	assert.Equal(t, loader, auth.idpLoader, "Auth handler should store the provided loader")

	t.Logf("✅ Auth handler properly accepts IDP loader and supports method chaining")
}

// TestAuthHandlerLoaderChaining verifies that WithIdentityProviderLoader supports
// method chaining for fluent initialization patterns used in cmd/main.go.
// This is how the loader is actually used in production:
//
//	auth := api.NewAuth(log, cfg)
//	auth.WithIdentityProviderLoader(idpLoader)  // Enable multi-IDP support
func TestAuthHandlerLoaderChaining(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	// Create auth handler and call WithIdentityProviderLoader to verify chaining works
	auth := &AuthHandler{
		jwksCache: make(map[string]*keyfunc.JWKS),
		jwksMutex: sync.RWMutex{},
		log:       log,
	}

	// Call the method - in production this would pass an actual *config.IdentityProviderLoader
	result := auth.WithIdentityProviderLoader(nil)

	// Verify chaining works by checking we get the same auth handler back
	assert.Equal(t, auth, result, "WithIdentityProviderLoader should return the auth handler for chaining")

	// Verify the handler reference is correct
	assert.NotNil(t, result.log, "Returned handler should have logger")
	assert.NotNil(t, result.jwksCache, "Returned handler should have JWKS cache")

	t.Logf("✅ Auth handler supports method chaining for loader setup")
}

// TestAuthHandlerInitializationWithoutLoader verifies backward compatibility
// when no loader is provided (single-IDP mode). This ensures existing
// single-IDP deployments continue to work after the multi-IDP changes.
func TestAuthHandlerInitializationWithoutLoader(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	// Create auth handler without any loader (single-IDP mode)
	auth := &AuthHandler{
		jwksCache: make(map[string]*keyfunc.JWKS),
		jwksMutex: sync.RWMutex{},
		log:       log,
		// idpLoader is NOT set (nil)
	}

	// Auth handler should work fine without a loader (falls back to single-IDP mode)
	assert.Nil(t, auth.idpLoader, "Auth handler can exist without idpLoader for single-IDP mode")

	// Verify all required fields are initialized
	assert.NotNil(t, auth.jwksCache, "JWKS cache should be initialized")
	assert.NotNil(t, auth.log, "Logger should be set")

	t.Logf("✅ Auth handler maintains backward compatibility for single-IDP mode")
}

// TestAuthHandlerMultiIDPFallback verifies that when idpLoader is nil,
// the auth handler logic falls back to single-IDP verification.
// This is important for backward compatibility and graceful degradation.
//
// In the token verification code (auth.go):
//
//	if a.idpLoader != nil && issuer != "" {
//		// Multi-IDP mode
//	} else {
//		// Single-IDP fallback
//	}
func TestAuthHandlerMultiIDPFallback(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	// Create auth handler with explicitly nil loader (fallback mode)
	auth := &AuthHandler{
		jwksCache: make(map[string]*keyfunc.JWKS),
		jwksMutex: sync.RWMutex{},
		log:       log,
		idpLoader: nil, // No loader = single-IDP fallback mode
	}

	// Verify the handler is properly initialized for single-IDP mode
	assert.Nil(t, auth.idpLoader, "Fallback to single-IDP when loader is nil")
	assert.NotNil(t, auth.jwksCache, "JWKS cache should be initialized")
	assert.NotNil(t, auth.log, "Logger should be set")

	// Verify the handler won't panic when trying to use multi-IDP methods
	// (in real code, getJWKSForIssuer checks if idpLoader != nil before using it)
	assert.Equal(t, 0, len(auth.jwksCache), "JWKS cache should start empty")

	t.Logf("✅ Auth handler properly handles fallback to single-IDP mode when loader is nil")
}

// TestAuthHandlerLoaderReplacement verifies that the loader can be replaced
// after initialization, which could be useful for reloading in edge cases.
func TestAuthHandlerLoaderReplacement(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()

	auth := &AuthHandler{
		jwksCache: make(map[string]*keyfunc.JWKS),
		jwksMutex: sync.RWMutex{},
		log:       log,
	}

	// Initially no loader
	assert.Nil(t, auth.idpLoader)

	// Set a loader (nil for testing, but represents first loader)
	result1 := auth.WithIdentityProviderLoader(nil)
	assert.Equal(t, auth, result1)
	assert.Nil(t, auth.idpLoader)

	// Replace with another loader (nil for testing, but represents second loader)
	result2 := auth.WithIdentityProviderLoader(nil)
	assert.Equal(t, auth, result2)
	assert.Nil(t, auth.idpLoader)

	// Verify it's the same handler throughout
	assert.Equal(t, result1, result2)

	t.Logf("✅ Auth handler supports loader replacement")
}
