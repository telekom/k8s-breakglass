package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func TestBuildClientWithOverrides(t *testing.T) {
	rt := &runtimeState{
		serverOverride: "https://example.com",
		tokenOverride:  "token",
		cfg: &config.Config{
			Settings: config.Settings{Timeout: "2s"},
		},
	}

	client, err := buildClient(context.Background(), rt)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestBuildClientWithInvalidTimeoutStillSucceeds(t *testing.T) {
	rt := &runtimeState{
		serverOverride: "https://example.com",
		tokenOverride:  "token",
		cfg: &config.Config{
			Settings: config.Settings{Timeout: "invalid"},
		},
	}

	client, err := buildClient(context.Background(), rt)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestResolveTokenFromCache_NotAuthenticated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	rt := &runtimeState{
		cfg: &config.Config{
			Contexts: []config.Context{
				{
					Name:   "ctx",
					Server: "https://example.com",
					OIDC: &config.InlineOIDC{
						Authority: "https://idp.example.com",
						ClientID:  "client",
					},
				},
			},
			CurrentContext: "ctx",
		},
		tokenStorageOverride: "file", // Use file storage to avoid keychain dependency in tests
	}

	ctxCfg, err := rt.cfg.FindContext("ctx")
	require.NoError(t, err)

	_, err = resolveTokenFromCache(context.Background(), rt, ctxCfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authenticated")
}

func TestResolveTokenFromCache_ResolveOIDCError(t *testing.T) {
	rt := &runtimeState{
		cfg: &config.Config{
			Contexts:       []config.Context{{Name: "ctx", Server: "https://example.com"}},
			CurrentContext: "ctx",
		},
	}

	ctxCfg, err := rt.cfg.FindContext("ctx")
	require.NoError(t, err)

	_, err = resolveTokenFromCache(context.Background(), rt, ctxCfg)
	require.Error(t, err)
}
