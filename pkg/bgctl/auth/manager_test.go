/*
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestTokenManager_GetToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	// Test getting token when cache doesn't exist
	mgr := &TokenManager{CachePath: path, StorageMode: tokenStoreFile}
	token, found, err := mgr.GetToken("provider")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, token.AccessToken)

	// Save a token and verify we can retrieve it
	testToken := StoredToken{
		AccessToken:  "test-access",
		RefreshToken: "test-refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	require.NoError(t, mgr.SaveToken("provider", testToken))

	token, found, err = mgr.GetToken("provider")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "test-access", token.AccessToken)
	assert.Equal(t, "test-refresh", token.RefreshToken)
}

func TestTokenManager_SaveToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	mgr := &TokenManager{CachePath: path, StorageMode: tokenStoreFile}

	// Save first token
	token1 := StoredToken{
		AccessToken: "token1",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	require.NoError(t, mgr.SaveToken("provider1", token1))

	// Save second token (should not overwrite first)
	token2 := StoredToken{
		AccessToken: "token2",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}
	require.NoError(t, mgr.SaveToken("provider2", token2))

	// Verify both tokens exist
	t1, found, err := mgr.GetToken("provider1")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "token1", t1.AccessToken)

	t2, found, err := mgr.GetToken("provider2")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "token2", t2.AccessToken)
}

func TestTokenManager_DeleteToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	mgr := &TokenManager{CachePath: path, StorageMode: tokenStoreFile}

	// Save a token
	testToken := StoredToken{
		AccessToken: "to-delete",
		TokenType:   "Bearer",
	}
	require.NoError(t, mgr.SaveToken("provider", testToken))

	// Verify it exists
	_, found, err := mgr.GetToken("provider")
	require.NoError(t, err)
	assert.True(t, found)

	// Delete it
	require.NoError(t, mgr.DeleteToken("provider"))

	// Verify it's gone
	_, found, err = mgr.GetToken("provider")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestTokenManager_RefreshIfNeeded_TokenNotExpiring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	mgr := &TokenManager{CachePath: path, StorageMode: tokenStoreFile}

	// Token not expiring soon - should not refresh
	testToken := StoredToken{
		AccessToken:  "valid-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour), // Expires in 1 hour
	}
	require.NoError(t, mgr.SaveToken("provider", testToken))

	oauthCfg := oauth2.Config{}
	token, refreshed, err := mgr.RefreshIfNeeded(context.Background(), "provider", oauthCfg)
	require.NoError(t, err)
	assert.False(t, refreshed)
	assert.Equal(t, "valid-token", token.AccessToken)
}

func TestTokenManager_RefreshIfNeeded_TokenExpired_NoRefreshToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	mgr := &TokenManager{CachePath: path, StorageMode: tokenStoreFile}

	// Token expired and no refresh token - should error
	testToken := StoredToken{
		AccessToken: "expired-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Second), // Expires in 1 second
	}
	require.NoError(t, mgr.SaveToken("provider", testToken))

	oauthCfg := oauth2.Config{}
	_, _, err := mgr.RefreshIfNeeded(context.Background(), "provider", oauthCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no refresh token")
}

func TestTokenManager_RefreshIfNeeded_TokenNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	mgr := &TokenManager{CachePath: path, StorageMode: tokenStoreFile}

	oauthCfg := oauth2.Config{}
	_, found, err := mgr.RefreshIfNeeded(context.Background(), "nonexistent", oauthCfg)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestBuildOAuthConfig(t *testing.T) {
	// Create a test server with a fixed URL for OIDC discovery
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The issuer must match the server URL exactly (including scheme)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 serverURL,
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
		})
	})
	server := httptest.NewServer(mux)
	serverURL = server.URL
	defer server.Close()

	cfg := OIDCConfig{
		Authority: server.URL,
		ClientID:  "test-client",
	}

	result, err := BuildOAuthConfig(context.Background(), cfg, "http://localhost:8080/callback")
	require.NoError(t, err)
	assert.Equal(t, "test-client", result.OAuthConfig.ClientID)
	assert.NotNil(t, result.Client)
}

func TestBuildOAuthConfig_MissingAuthority(t *testing.T) {
	cfg := OIDCConfig{
		ClientID: "test-client",
	}

	_, err := BuildOAuthConfig(context.Background(), cfg, "http://localhost:8080/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestBuildOAuthConfig_MissingClientID(t *testing.T) {
	cfg := OIDCConfig{
		Authority: "https://example.com",
	}

	_, err := BuildOAuthConfig(context.Background(), cfg, "http://localhost:8080/callback")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestLogin_UnsupportedGrantType(t *testing.T) {
	cfg := OIDCConfig{
		Authority: "https://example.com",
		ClientID:  "test-client",
		GrantType: "unsupported-grant",
	}

	_, err := Login(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported grant type")
}

func TestLogin_MissingAuthority(t *testing.T) {
	cfg := OIDCConfig{
		ClientID:  "test-client",
		GrantType: "authorization-code",
	}

	_, err := Login(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}
