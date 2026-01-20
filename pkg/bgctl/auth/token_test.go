package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	cache := &TokenCache{Tokens: map[string]StoredToken{}}
	token := StoredToken{AccessToken: "abc", RefreshToken: "def", TokenType: "Bearer", Expiry: time.Now().UTC()}
	cache.Tokens["provider"] = token

	require.NoError(t, SaveTokenCache(path, cache))

	loaded, err := LoadTokenCache(path)
	require.NoError(t, err)
	require.Equal(t, token.AccessToken, loaded.Tokens["provider"].AccessToken)
}

func TestLoadTokenCacheErrors(t *testing.T) {
	_, err := LoadTokenCache(filepath.Join(t.TempDir(), "missing.json"))
	require.Error(t, err)

	path := filepath.Join(t.TempDir(), "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("{bad json"), 0o600))
	_, err = LoadTokenCache(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse token cache")
}

func TestSaveTokenCacheNil(t *testing.T) {
	err := SaveTokenCache(filepath.Join(t.TempDir(), "tokens.json"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token cache is nil")
}

func TestSaveTokenCacheInitializesMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	cache := &TokenCache{}
	require.NoError(t, SaveTokenCache(path, cache))

	loaded, err := LoadTokenCache(path)
	require.NoError(t, err)
	assert.NotNil(t, loaded.Tokens)
}
