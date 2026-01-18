package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientCredentialsLogin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token_endpoint":         server.URL + "/token",
					"authorization_endpoint": server.URL + "/auth",
					"issuer":                 server.URL,
				})
			case "/token":
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "client-creds-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
					"id_token":     "test-id-token",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := ClientCredentialsLogin(ctx, OIDCConfig{
			Authority:    server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scopes:       []string{"openid"},
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "client-creds-token", result.Token.AccessToken)
		assert.Equal(t, "test-id-token", result.IDToken)
	})

	t.Run("missing authority", func(t *testing.T) {
		ctx := context.Background()
		result, err := ClientCredentialsLogin(ctx, OIDCConfig{
			Authority: "",
			ClientID:  "test-client",
		})

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "authority and client-id are required")
	})

	t.Run("missing client-id", func(t *testing.T) {
		ctx := context.Background()
		result, err := ClientCredentialsLogin(ctx, OIDCConfig{
			Authority: "https://example.com",
			ClientID:  "",
		})

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "authority and client-id are required")
	})

	t.Run("token endpoint failure", func(t *testing.T) {
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_ = json.NewEncoder(w).Encode(map[string]string{
					"token_endpoint":         server.URL + "/token",
					"authorization_endpoint": server.URL + "/auth",
					"issuer":                 server.URL,
				})
			case "/token":
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_client",
					"error_description": "Client authentication failed",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := ClientCredentialsLogin(ctx, OIDCConfig{
			Authority:    server.URL,
			ClientID:     "bad-client",
			ClientSecret: "bad-secret",
		})

		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "client credentials token failed")
	})
}
