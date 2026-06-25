package auth

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestSaveTokenCacheTightensExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	cache := &TokenCache{Tokens: map[string]StoredToken{
		"provider": {
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			TokenType:    "Bearer",
			Expiry:       time.Now().UTC(),
		},
	}}
	require.NoError(t, SaveTokenCache(path, cache))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestSaveTokenCacheExistingWritableFileInReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write permission semantics differ on Windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	require.NoError(t, os.Chmod(path, 0o600))
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})

	cache := &TokenCache{Tokens: map[string]StoredToken{
		"provider": {
			AccessToken: "access-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().UTC(),
		},
	}}
	require.NoError(t, SaveTokenCache(path, cache))

	loaded, err := LoadTokenCache(path)
	require.NoError(t, err)
	require.Equal(t, "access-token", loaded.Tokens["provider"].AccessToken)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
