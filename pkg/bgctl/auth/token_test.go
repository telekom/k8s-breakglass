package auth

import (
	"path/filepath"
	"testing"
	"time"

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
