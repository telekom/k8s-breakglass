package auth

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2/clientcredentials"
)

func ClientCredentialsLogin(ctx context.Context, cfg OIDCConfig) (*LoginResult, error) {
	if cfg.Authority == "" || cfg.ClientID == "" {
		return nil, errors.New("authority and client-id are required")
	}
	result, err := BuildOAuthConfig(ctx, cfg, "")
	if err != nil {
		return nil, err
	}
	cc := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     result.OAuthConfig.Endpoint.TokenURL,
		Scopes:       cfg.Scopes,
	}
	token, err := cc.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("client credentials token failed: %w", err)
	}
	idToken, _ := token.Extra("id_token").(string)
	return &LoginResult{Token: token, IDToken: idToken}, nil
}
