package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func buildClient(cmdCtx context.Context, rt *runtimeState) (*client.Client, error) {
	if err := rt.EnsureConfigLoaded(); err != nil {
		return nil, err
	}
	ctxCfg, err := rt.ResolveContext()
	if err != nil {
		return nil, err
	}
	server := rt.resolveServer(ctxCfg)
	if server == "" {
		return nil, errors.New("server is required")
	}

	token := rt.resolveToken()
	if token == "" {
		token, err = resolveTokenFromCache(cmdCtx, rt, ctxCfg)
		if err != nil {
			return nil, err
		}
	}
	options := []client.Option{
		client.WithServer(server),
		client.WithToken(token),
		client.WithUserAgent("bgctl"),
		client.WithTLSConfig(resolveCAFile(ctxCfg, rt), ctxCfg.InsecureSkipTLSVerify),
	}
	return client.New(options...)
}

func resolveCAFile(ctxCfg *config.Context, rt *runtimeState) string {
	if ctxCfg == nil {
		return ""
	}
	if ctxCfg.CAFile != "" {
		return ctxCfg.CAFile
	}
	resolved, err := rt.cfg.ResolveOIDC(ctxCfg)
	if err == nil && resolved.CAFile != "" {
		return resolved.CAFile
	}
	return ""
}

func resolveTokenFromCache(cmdCtx context.Context, rt *runtimeState, ctxCfg *config.Context) (string, error) {
	resolved, err := rt.cfg.ResolveOIDC(ctxCfg)
	if err != nil {
		return "", err
	}
	providerKey := resolveProviderKey(ctxCfg, resolved)
	manager := auth.TokenManager{CachePath: config.DefaultTokenPath()}
	token, ok, err := manager.GetToken(providerKey)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("not authenticated; run 'bgctl auth login'")
	}

	grantType := resolved.GrantType
	if resolved.DeviceCodeFlow && grantType == "" {
		grantType = "device-code"
	}
	secret, err := auth.ResolveClientSecret(resolved.ClientSecret, resolved.ClientSecretEnv, resolved.ClientSecretFile)
	if err != nil {
		return "", err
	}
	oauthResult, err := auth.BuildOAuthConfig(cmdCtx, auth.OIDCConfig{
		Authority:       resolved.Authority,
		ClientID:        resolved.ClientID,
		ClientSecret:    secret,
		Scopes:          resolved.Scopes,
		GrantType:       grantType,
		CAFile:          resolved.CAFile,
		InsecureSkipTLS: resolved.InsecureSkipTLS,
		ExtraAuthParams: resolved.ExtraAuthParams,
	}, "")
	if err != nil {
		return "", err
	}
	if _, refreshed, err := manager.RefreshIfNeeded(cmdCtx, providerKey, oauthResult.OAuthConfig); err != nil {
		if grantType == "client-credentials" {
			loginResult, loginErr := auth.ClientCredentialsLogin(cmdCtx, auth.OIDCConfig{
				Authority:       resolved.Authority,
				ClientID:        resolved.ClientID,
				ClientSecret:    secret,
				Scopes:          resolved.Scopes,
				GrantType:       grantType,
				CAFile:          resolved.CAFile,
				InsecureSkipTLS: resolved.InsecureSkipTLS,
				ExtraAuthParams: resolved.ExtraAuthParams,
			})
			if loginErr != nil {
				return "", loginErr
			}
			_ = manager.SaveToken(providerKey, auth.StoredToken{
				AccessToken:  loginResult.Token.AccessToken,
				RefreshToken: loginResult.Token.RefreshToken,
				TokenType:    loginResult.Token.TokenType,
				Expiry:       loginResult.Token.Expiry,
				IDToken:      loginResult.IDToken,
			})
			return loginResult.Token.AccessToken, nil
		}
		return "", err
	} else if refreshed {
		token, _, _ = manager.GetToken(providerKey)
	}
	return token.AccessToken, nil
}
