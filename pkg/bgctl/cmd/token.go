package cmd

import (
	"context"

	"github.com/golang-jwt/jwt/v4"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func resolveUserFromToken(rt *runtimeState, ctx context.Context) string {
	token := rt.resolveToken()
	if token == "" {
		ctxCfg, err := rt.ResolveContext()
		if err == nil {
			resolved, err := rt.cfg.ResolveOIDC(ctxCfg)
			if err == nil {
				providerKey := resolveProviderKey(ctxCfg, resolved)
				manager := auth.TokenManager{CachePath: config.DefaultTokenPath()}
				stored, ok, _ := manager.GetToken(providerKey)
				if ok {
					token = stored.IDToken
					if token == "" {
						token = stored.AccessToken
					}
				}
			}
		}
	}
	if token == "" {
		return ""
	}
	parser := jwt.Parser{}
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return ""
	}
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	if username, ok := claims["preferred_username"].(string); ok && username != "" {
		return username
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	return ""
}
