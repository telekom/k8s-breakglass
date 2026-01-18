package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with Breakglass",
	}
	cmd.AddCommand(
		newAuthLoginCommand(),
		newAuthStatusCommand(),
		newAuthLogoutCommand(),
	)
	return cmd
}

func newAuthLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Login via OIDC",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			ctxCfg, err := rt.ResolveContext()
			if err != nil {
				return err
			}
			resolved, err := rt.cfg.ResolveOIDC(ctxCfg)
			if err != nil {
				return err
			}
			grantType := resolved.GrantType
			if resolved.DeviceCodeFlow && grantType == "" {
				grantType = "device-code"
			}
			secret, err := auth.ResolveClientSecret(resolved.ClientSecret, resolved.ClientSecretEnv, resolved.ClientSecretFile)
			if err != nil {
				return err
			}
			loginCfg := auth.OIDCConfig{
				Authority:       resolved.Authority,
				ClientID:        resolved.ClientID,
				ClientSecret:    secret,
				Scopes:          resolved.Scopes,
				GrantType:       grantType,
				CAFile:          resolved.CAFile,
				InsecureSkipTLS: resolved.InsecureSkipTLS,
				ExtraAuthParams: resolved.ExtraAuthParams,
			}
			result, err := auth.Login(context.Background(), loginCfg)
			if err != nil {
				return err
			}
			providerKey := resolveProviderKey(ctxCfg, resolved)
			manager := auth.TokenManager{CachePath: config.DefaultTokenPath()}
			stored := auth.StoredToken{
				AccessToken:  result.Token.AccessToken,
				RefreshToken: result.Token.RefreshToken,
				TokenType:    result.Token.TokenType,
				Expiry:       result.Token.Expiry,
				IDToken:      result.IDToken,
			}
			if err := manager.SaveToken(providerKey, stored); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Authenticated. Token expires at %s\n", stored.Expiry.UTC().Format(time.RFC3339))
			return nil
		},
	}
}

func newAuthStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			ctxCfg, err := rt.ResolveContext()
			if err != nil {
				return err
			}
			resolved, err := rt.cfg.ResolveOIDC(ctxCfg)
			if err != nil {
				return err
			}
			grantType := resolved.GrantType
			if resolved.DeviceCodeFlow && grantType == "" {
				grantType = "device-code"
			}
			secret, err := auth.ResolveClientSecret(resolved.ClientSecret, resolved.ClientSecretEnv, resolved.ClientSecretFile)
			if err != nil {
				return err
			}
			providerKey := resolveProviderKey(ctxCfg, resolved)
			manager := auth.TokenManager{CachePath: config.DefaultTokenPath()}
			token, ok, err := manager.GetToken(providerKey)
			if err != nil {
				return err
			}
			if !ok {
				_, _ = fmt.Fprintln(rt.Writer(), "Not authenticated")
				return nil
			}
			oauthResult, err := auth.BuildOAuthConfig(context.Background(), auth.OIDCConfig{
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
				return err
			}
			if _, refreshed, err := manager.RefreshIfNeeded(context.Background(), providerKey, oauthResult.OAuthConfig); err != nil {
				if resolved.GrantType == "client-credentials" {
					loginResult, loginErr := auth.ClientCredentialsLogin(context.Background(), auth.OIDCConfig{
						Authority:       resolved.Authority,
						ClientID:        resolved.ClientID,
						ClientSecret:    secret,
						Scopes:          resolved.Scopes,
						GrantType:       resolved.GrantType,
						CAFile:          resolved.CAFile,
						InsecureSkipTLS: resolved.InsecureSkipTLS,
						ExtraAuthParams: resolved.ExtraAuthParams,
					})
					if loginErr != nil {
						return loginErr
					}
					_ = manager.SaveToken(providerKey, auth.StoredToken{
						AccessToken:  loginResult.Token.AccessToken,
						RefreshToken: loginResult.Token.RefreshToken,
						TokenType:    loginResult.Token.TokenType,
						Expiry:       loginResult.Token.Expiry,
						IDToken:      loginResult.IDToken,
					})
					_, _ = fmt.Fprintf(rt.Writer(), "Authenticated. Token expires at %s\n", loginResult.Token.Expiry.UTC().Format(time.RFC3339))
					return nil
				}
				return err
			} else if refreshed {
				token, _, _ = manager.GetToken(providerKey)
			}
			_, _ = fmt.Fprintf(rt.Writer(), "Authenticated. Token expires at %s\n", token.Expiry.UTC().Format(time.RFC3339))
			return nil
		},
	}
}

func newAuthLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove cached token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rt, err := getRuntime(cmd)
			if err != nil {
				return err
			}
			if err := rt.EnsureConfigLoaded(); err != nil {
				return err
			}
			ctxCfg, err := rt.ResolveContext()
			if err != nil {
				return err
			}
			resolved, err := rt.cfg.ResolveOIDC(ctxCfg)
			if err != nil {
				return err
			}
			providerKey := resolveProviderKey(ctxCfg, resolved)
			manager := auth.TokenManager{CachePath: config.DefaultTokenPath()}
			if err := manager.DeleteToken(providerKey); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(rt.Writer(), "Logged out")
			return nil
		},
	}
}

func resolveProviderKey(ctxCfg *config.Context, resolved *config.ResolvedOIDC) string {
	if resolved != nil && resolved.ProviderName != "" {
		return resolved.ProviderName
	}
	if ctxCfg != nil {
		return "inline:" + ctxCfg.Name
	}
	return "default"
}
