package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

// createTestToken creates a JWT token string with the given claims for testing
func createTestToken(claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Use a test secret - the token just needs to be parseable, not verified
	signedToken, _ := token.SignedString([]byte("test-secret"))
	return signedToken
}

func TestResolveUserFromToken_ParsesClaims(t *testing.T) {
	t.Run("extracts email claim", func(t *testing.T) {
		token := createTestToken(jwt.MapClaims{
			"email": "user@example.com",
			"sub":   "user123",
			"exp":   time.Now().Add(time.Hour).Unix(),
		})

		// Create a minimal runtime state with the token override
		rt := &runtimeState{
			tokenOverride: token,
		}

		result := resolveUserFromToken(rt, context.Background())
		assert.Equal(t, "user@example.com", result)
	})

	t.Run("extracts preferred_username when no email", func(t *testing.T) {
		token := createTestToken(jwt.MapClaims{
			"preferred_username": "testuser",
			"sub":                "user123",
			"exp":                time.Now().Add(time.Hour).Unix(),
		})

		rt := &runtimeState{
			tokenOverride: token,
		}

		result := resolveUserFromToken(rt, context.Background())
		assert.Equal(t, "testuser", result)
	})

	t.Run("extracts sub when no email or username", func(t *testing.T) {
		token := createTestToken(jwt.MapClaims{
			"sub": "user-subject-123",
			"exp": time.Now().Add(time.Hour).Unix(),
		})

		rt := &runtimeState{
			tokenOverride: token,
		}

		result := resolveUserFromToken(rt, context.Background())
		assert.Equal(t, "user-subject-123", result)
	})

	t.Run("returns empty string for empty token", func(t *testing.T) {
		rt := &runtimeState{
			tokenOverride: "",
		}

		result := resolveUserFromToken(rt, context.Background())
		assert.Empty(t, result)
	})

	t.Run("returns empty string for invalid token", func(t *testing.T) {
		rt := &runtimeState{
			tokenOverride: "not-a-valid-jwt-token",
		}

		result := resolveUserFromToken(rt, context.Background())
		assert.Empty(t, result)
	})

	t.Run("email takes precedence over username", func(t *testing.T) {
		token := createTestToken(jwt.MapClaims{
			"email":              "email@example.com",
			"preferred_username": "username",
			"sub":                "subject",
			"exp":                time.Now().Add(time.Hour).Unix(),
		})

		rt := &runtimeState{
			tokenOverride: token,
		}

		result := resolveUserFromToken(rt, context.Background())
		assert.Equal(t, "email@example.com", result)
	})
}

func TestResolveProviderKey(t *testing.T) {
	t.Run("generates provider key", func(t *testing.T) {
		ctxCfg := &config.Context{
			Name: "test-context",
		}
		resolved := &config.ResolvedOIDC{
			ClientID:  "test-client",
			Authority: "https://auth.example.com",
		}

		key := resolveProviderKey(ctxCfg, resolved)
		require.NotEmpty(t, key)
	})
}

func TestTokenManager_Integration(t *testing.T) {
	t.Run("manager can be created with default path", func(t *testing.T) {
		manager := auth.TokenManager{CachePath: config.DefaultTokenPath(), StorageMode: "file"}
		require.NotNil(t, manager)
	})
}
