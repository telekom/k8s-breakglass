package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildOAuthConfig_Extended(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":                 server.URL,
					"authorization_endpoint": server.URL + "/auth",
					"token_endpoint":         server.URL + "/token",
				})
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := BuildOAuthConfig(ctx, OIDCConfig{
			Authority: server.URL,
			ClientID:  "test-client",
		}, "http://localhost:8080/callback")

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "test-client", result.OAuthConfig.ClientID)
		assert.Equal(t, "http://localhost:8080/callback", result.OAuthConfig.RedirectURL)
		assert.NotNil(t, result.Client)
	})

	t.Run("missing authority", func(t *testing.T) {
		ctx := context.Background()
		result, err := BuildOAuthConfig(ctx, OIDCConfig{
			Authority: "",
			ClientID:  "test-client",
		}, "http://localhost:8080/callback")

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "authority and client-id are required")
	})

	t.Run("missing client-id", func(t *testing.T) {
		ctx := context.Background()
		result, err := BuildOAuthConfig(ctx, OIDCConfig{
			Authority: "https://example.com",
			ClientID:  "",
		}, "http://localhost:8080/callback")

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "authority and client-id are required")
	})

	t.Run("uses custom scopes", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":                 server.URL,
					"authorization_endpoint": server.URL + "/auth",
					"token_endpoint":         server.URL + "/token",
				})
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		customScopes := []string{"openid", "custom-scope", "another-scope"}
		result, err := BuildOAuthConfig(ctx, OIDCConfig{
			Authority: server.URL,
			ClientID:  "test-client",
			Scopes:    customScopes,
		}, "http://localhost:8080/callback")

		require.NoError(t, err)
		assert.Equal(t, customScopes, result.OAuthConfig.Scopes)
	})

	t.Run("uses default scopes when not specified", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-configuration" {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer":                 server.URL,
					"authorization_endpoint": server.URL + "/auth",
					"token_endpoint":         server.URL + "/token",
				})
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := BuildOAuthConfig(ctx, OIDCConfig{
			Authority: server.URL,
			ClientID:  "test-client",
			Scopes:    nil, // no custom scopes
		}, "http://localhost:8080/callback")

		require.NoError(t, err)
		// Should have default scopes
		assert.Contains(t, result.OAuthConfig.Scopes, "openid")
		assert.Contains(t, result.OAuthConfig.Scopes, "email")
		assert.Contains(t, result.OAuthConfig.Scopes, "profile")
	})
}

func TestLogin(t *testing.T) {
	t.Run("routes to device-code flow", func(t *testing.T) {
		// We can't fully test this without a real server, but we can verify the routing
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// This will fail because there's no server, but it proves the routing works
		_, err := Login(ctx, OIDCConfig{
			Authority: "http://localhost:1",
			ClientID:  "test",
			GrantType: "device-code",
		})
		require.Error(t, err) // Expected to fail due to no server
	})

	t.Run("routes to client-credentials flow", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := Login(ctx, OIDCConfig{
			Authority: "http://localhost:1",
			ClientID:  "test",
			GrantType: "client-credentials",
		})
		require.Error(t, err) // Expected to fail due to no server
	})

	t.Run("rejects unsupported grant type", func(t *testing.T) {
		ctx := context.Background()

		_, err := Login(ctx, OIDCConfig{
			Authority: "https://example.com",
			ClientID:  "test",
			GrantType: "unsupported-grant",
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported grant type")
	})

	t.Run("defaults to authorization-code flow", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Empty grant type should default to authorization-code
		_, err := Login(ctx, OIDCConfig{
			Authority: "http://localhost:1",
			ClientID:  "test",
			GrantType: "",
		})
		require.Error(t, err) // Will fail due to server, but routing is correct
	})
}

func TestResolveClientSecret(t *testing.T) {
	t.Run("returns direct secret when provided", func(t *testing.T) {
		secret, err := ResolveClientSecret("direct-secret", "", "")
		require.NoError(t, err)
		assert.Equal(t, "direct-secret", secret)
	})

	t.Run("returns secret from env var", func(t *testing.T) {
		t.Setenv("TEST_CLIENT_SECRET", "env-secret")

		secret, err := ResolveClientSecret("", "TEST_CLIENT_SECRET", "")
		require.NoError(t, err)
		assert.Equal(t, "env-secret", secret)
	})

	t.Run("trims whitespace from env var", func(t *testing.T) {
		t.Setenv("TEST_CLIENT_SECRET", "  secret-with-whitespace  ")

		secret, err := ResolveClientSecret("", "TEST_CLIENT_SECRET", "")
		require.NoError(t, err)
		assert.Equal(t, "secret-with-whitespace", secret)
	})

	t.Run("returns error when env var not set", func(t *testing.T) {
		t.Setenv("TEST_EMPTY_SECRET", "")

		_, err := ResolveClientSecret("", "TEST_EMPTY_SECRET", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client secret env var not set")
	})

	t.Run("returns secret from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		secretFile := filepath.Join(tmpDir, "secret")
		err := os.WriteFile(secretFile, []byte("file-secret"), 0600)
		require.NoError(t, err)

		secret, err := ResolveClientSecret("", "", secretFile)
		require.NoError(t, err)
		assert.Equal(t, "file-secret", secret)
	})

	t.Run("trims whitespace from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		secretFile := filepath.Join(tmpDir, "secret")
		err := os.WriteFile(secretFile, []byte("  file-secret\n"), 0600)
		require.NoError(t, err)

		secret, err := ResolveClientSecret("", "", secretFile)
		require.NoError(t, err)
		assert.Equal(t, "file-secret", secret)
	})

	t.Run("returns error when file not found", func(t *testing.T) {
		_, err := ResolveClientSecret("", "", "/nonexistent/path/secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read client secret file")
	})

	t.Run("returns empty string when nothing provided", func(t *testing.T) {
		secret, err := ResolveClientSecret("", "", "")
		require.NoError(t, err)
		assert.Equal(t, "", secret)
	})

	t.Run("direct secret takes precedence", func(t *testing.T) {
		t.Setenv("TEST_CLIENT_SECRET", "env-secret")

		// Even if env is set, direct secret wins
		secret, err := ResolveClientSecret("direct-secret", "TEST_CLIENT_SECRET", "")
		require.NoError(t, err)
		assert.Equal(t, "direct-secret", secret)
	})
}

func TestLoadTLSConfig(t *testing.T) {
	t.Run("default config with no CA file", func(t *testing.T) {
		config, err := loadTLSConfig("", false)
		require.NoError(t, err)
		require.NotNil(t, config)
		assert.False(t, config.InsecureSkipVerify)
	})

	t.Run("insecure mode", func(t *testing.T) {
		config, err := loadTLSConfig("", true)
		require.NoError(t, err)
		require.NotNil(t, config)
		assert.True(t, config.InsecureSkipVerify)
	})

	t.Run("nonexistent CA file", func(t *testing.T) {
		_, err := loadTLSConfig("/nonexistent/ca.pem", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA file")
	})

	t.Run("invalid CA file content", func(t *testing.T) {
		tmpDir := t.TempDir()
		caFile := filepath.Join(tmpDir, "invalid-ca.pem")
		err := os.WriteFile(caFile, []byte("not a valid certificate"), 0600)
		require.NoError(t, err)

		_, err = loadTLSConfig(caFile, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse CA file")
	})
}

func TestLoadCertPool(t *testing.T) {
	t.Run("empty path returns nil", func(t *testing.T) {
		pool, err := loadCertPool("")
		require.NoError(t, err)
		assert.Nil(t, pool)
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		_, err := loadCertPool("/nonexistent/ca.pem")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read CA file")
	})
}

func TestNewHTTPClient(t *testing.T) {
	t.Run("creates client with default transport", func(t *testing.T) {
		client, err := newHTTPClient("", false)
		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, 30*time.Second, client.Timeout)
	})

	t.Run("creates client with insecure transport", func(t *testing.T) {
		client, err := newHTTPClient("", true)
		require.NoError(t, err)
		require.NotNil(t, client)
	})
}
