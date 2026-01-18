package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type StoredToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
}

type TokenCache struct {
	Tokens map[string]StoredToken `json:"tokens"`
}

func LoadTokenCache(path string) (*TokenCache, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cache TokenCache
	if err := json.Unmarshal(content, &cache); err != nil {
		return nil, fmt.Errorf("failed to parse token cache: %w", err)
	}
	if cache.Tokens == nil {
		cache.Tokens = map[string]StoredToken{}
	}
	return &cache, nil
}

func SaveTokenCache(path string, cache *TokenCache) error {
	if cache == nil {
		return errors.New("token cache is nil")
	}
	if cache.Tokens == nil {
		cache.Tokens = map[string]StoredToken{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create token dir: %w", err)
	}
	content, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token cache: %w", err)
	}
	return os.WriteFile(path, content, 0o600)
}
