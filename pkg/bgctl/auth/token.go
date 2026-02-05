package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	tokenStoreKeychain = "keychain"
	tokenStoreFile     = "file"
	keychainService    = "breakglass-bgctl"
	keychainKey        = "tokens"
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

type TokenStore interface {
	Load() (*TokenCache, error)
	Save(cache *TokenCache) error
	Delete() error
}

type FileTokenStore struct {
	Path string
}

func (s FileTokenStore) Load() (*TokenCache, error) {
	return LoadTokenCache(s.Path)
}

func (s FileTokenStore) Save(cache *TokenCache) error {
	return SaveTokenCache(s.Path, cache)
}

func (s FileTokenStore) Delete() error {
	return os.Remove(s.Path)
}

type KeychainTokenStore struct{}

func (s KeychainTokenStore) Load() (*TokenCache, error) {
	content, err := keyring.Get(keychainService, keychainKey)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read token cache from keychain: %w", err)
	}
	var cache TokenCache
	if err := json.Unmarshal([]byte(content), &cache); err != nil {
		return nil, fmt.Errorf("failed to parse token cache: %w", err)
	}
	if cache.Tokens == nil {
		cache.Tokens = map[string]StoredToken{}
	}
	return &cache, nil
}

func (s KeychainTokenStore) Save(cache *TokenCache) error {
	if cache == nil {
		return errors.New("token cache is nil")
	}
	if cache.Tokens == nil {
		cache.Tokens = map[string]StoredToken{}
	}
	content, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token cache: %w", err)
	}
	if err := keyring.Set(keychainService, keychainKey, string(content)); err != nil {
		return fmt.Errorf("failed to write token cache to keychain: %w", err)
	}
	return nil
}

func (s KeychainTokenStore) Delete() error {
	if err := keyring.Delete(keychainService, keychainKey); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("failed to delete token cache from keychain: %w", err)
	}
	return nil
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

func normalizeTokenStorage(mode string) string {
	val := strings.TrimSpace(strings.ToLower(mode))
	if val == "" {
		return tokenStoreKeychain
	}
	return val
}
