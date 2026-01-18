package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/oauth2"
)

type TokenManager struct {
	CachePath string
}

func (m *TokenManager) GetToken(providerName string) (StoredToken, bool, error) {
	cache, err := LoadTokenCache(m.CachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return StoredToken{}, false, nil
		}
		return StoredToken{}, false, err
	}
	token, ok := cache.Tokens[providerName]
	return token, ok, nil
}

func (m *TokenManager) SaveToken(providerName string, token StoredToken) error {
	cache, err := LoadTokenCache(m.CachePath)
	if err != nil {
		cache = &TokenCache{Tokens: map[string]StoredToken{}}
	}
	cache.Tokens[providerName] = token
	return SaveTokenCache(m.CachePath, cache)
}

func (m *TokenManager) DeleteToken(providerName string) error {
	cache, err := LoadTokenCache(m.CachePath)
	if err != nil {
		return err
	}
	delete(cache.Tokens, providerName)
	return SaveTokenCache(m.CachePath, cache)
}

func (m *TokenManager) RefreshIfNeeded(ctx context.Context, providerName string, oauthCfg oauth2.Config) (StoredToken, bool, error) {
	token, ok, err := m.GetToken(providerName)
	if err != nil || !ok {
		return token, ok, err
	}
	if token.Expiry.IsZero() || time.Until(token.Expiry) > 2*time.Minute {
		return token, false, nil
	}
	if token.RefreshToken == "" {
		return token, false, errors.New("token expired and no refresh token available")
	}
	src := oauthCfg.TokenSource(ctx, &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	})
	refreshed, err := src.Token()
	if err != nil {
		return token, false, fmt.Errorf("failed to refresh token: %w", err)
	}
	stored := StoredToken{
		AccessToken:  refreshed.AccessToken,
		RefreshToken: refreshed.RefreshToken,
		TokenType:    refreshed.TokenType,
		Expiry:       refreshed.Expiry,
	}
	if idToken, ok := refreshed.Extra("id_token").(string); ok {
		stored.IDToken = idToken
	} else {
		stored.IDToken = token.IDToken
	}
	if err := m.SaveToken(providerName, stored); err != nil {
		return stored, true, err
	}
	return stored, true, nil
}
