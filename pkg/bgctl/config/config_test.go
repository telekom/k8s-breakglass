package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	cfg := DefaultConfig()
	cfg.CurrentContext = "prod"
	cfg.Contexts = []Context{
		{
			Name:                  "prod",
			Server:                "https://breakglass.example.com",
			OIDCProvider:          "corp",
			InsecureSkipTLSVerify: false,
		},
	}
	cfg.OIDCProviders = []OIDCProvider{
		{
			Name:      "corp",
			Authority: "https://idp.example.com/realms/prod",
			ClientID:  "bgctl",
		},
	}

	require.NoError(t, Save(path, &cfg))
	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, cfg.CurrentContext, loaded.CurrentContext)
	require.Len(t, loaded.Contexts, 1)
	require.Len(t, loaded.OIDCProviders, 1)
	require.Equal(t, cfg.Contexts[0].Server, loaded.Contexts[0].Server)
}

func TestResolveOIDCInline(t *testing.T) {
	cfg := DefaultConfig()
	ctx := Context{
		Name:   "local",
		Server: "https://localhost:8443",
		OIDC: &InlineOIDC{
			Authority: "https://localhost:9443/realms/test",
			ClientID:  "bgctl",
		},
	}
	cfg.Contexts = []Context{ctx}

	resolved, err := cfg.ResolveOIDC(&ctx)
	require.NoError(t, err)
	require.Equal(t, ctx.OIDC.Authority, resolved.Authority)
	require.Equal(t, ctx.OIDC.ClientID, resolved.ClientID)
}

func TestResolveOIDCProvider(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OIDCProviders = []OIDCProvider{{
		Name:      "corp",
		Authority: "https://idp.example.com",
		ClientID:  "bgctl",
	}}
	ctx := Context{
		Name:         "prod",
		Server:       "https://breakglass.example.com",
		OIDCProvider: "corp",
	}

	resolved, err := cfg.ResolveOIDC(&ctx)
	require.NoError(t, err)
	require.Equal(t, "corp", resolved.ProviderName)
	require.Equal(t, "https://idp.example.com", resolved.Authority)
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
	require.True(t, os.IsNotExist(err))
}
