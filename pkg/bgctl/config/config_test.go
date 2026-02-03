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

func TestLoadEmptyPath(t *testing.T) {
	_, err := Load("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "config path is required")
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.yaml")
	require.NoError(t, os.WriteFile(path, []byte("invalid: [yaml: content"), 0o600))
	_, err := Load(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse config")
}

func TestSaveNilConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	err := Save(path, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "config is nil")
}

func TestSaveDefaultsVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := &Config{} // No version set
	require.NoError(t, Save(path, cfg))
	loaded, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, VersionV1, loaded.Version)
}

func TestFindContext(t *testing.T) {
	cfg := &Config{
		Contexts: []Context{
			{Name: "prod", Server: "https://prod.example.com"},
			{Name: "dev", Server: "https://dev.example.com"},
		},
	}

	t.Run("finds existing context", func(t *testing.T) {
		ctx, err := cfg.FindContext("prod")
		require.NoError(t, err)
		require.Equal(t, "prod", ctx.Name)
		require.Equal(t, "https://prod.example.com", ctx.Server)
	})

	t.Run("returns error for non-existent context", func(t *testing.T) {
		_, err := cfg.FindContext("staging")
		require.Error(t, err)
		require.Contains(t, err.Error(), "context not found")
	})
}

func TestFindOIDCProvider(t *testing.T) {
	cfg := &Config{
		OIDCProviders: []OIDCProvider{
			{Name: "corp", Authority: "https://idp.example.com"},
			{Name: "local", Authority: "https://localhost:9443"},
		},
	}

	t.Run("finds existing provider", func(t *testing.T) {
		provider, err := cfg.FindOIDCProvider("corp")
		require.NoError(t, err)
		require.Equal(t, "corp", provider.Name)
	})

	t.Run("returns error for non-existent provider", func(t *testing.T) {
		_, err := cfg.FindOIDCProvider("missing")
		require.Error(t, err)
		require.Contains(t, err.Error(), "oidc provider not found")
	})
}

func TestCurrentContextOrDefault(t *testing.T) {
	t.Run("returns current context when set", func(t *testing.T) {
		cfg := &Config{
			CurrentContext: "prod",
			Contexts:       []Context{{Name: "dev"}, {Name: "prod"}},
		}
		require.Equal(t, "prod", cfg.CurrentContextOrDefault())
	})

	t.Run("returns first context when current not set", func(t *testing.T) {
		cfg := &Config{
			Contexts: []Context{{Name: "dev"}, {Name: "prod"}},
		}
		require.Equal(t, "dev", cfg.CurrentContextOrDefault())
	})

	t.Run("returns empty string when no contexts", func(t *testing.T) {
		cfg := &Config{}
		require.Equal(t, "", cfg.CurrentContextOrDefault())
	})
}

func TestValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			Version: VersionV1,
			Contexts: []Context{
				{Name: "prod", Server: "https://example.com"},
			},
		}
		require.NoError(t, cfg.Validate())
	})

	t.Run("missing version", func(t *testing.T) {
		cfg := &Config{Version: ""}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "config version missing")
	})

	t.Run("empty context name", func(t *testing.T) {
		cfg := &Config{
			Version:  VersionV1,
			Contexts: []Context{{Name: "  ", Server: "https://example.com"}},
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "context name cannot be empty")
	})

	t.Run("empty context server", func(t *testing.T) {
		cfg := &Config{
			Version:  VersionV1,
			Contexts: []Context{{Name: "prod", Server: "  "}},
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "server is required")
	})
}

func TestResolveOIDCErrors(t *testing.T) {
	cfg := &Config{}

	t.Run("nil context", func(t *testing.T) {
		_, err := cfg.ResolveOIDC(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "context is nil")
	})

	t.Run("no oidc configured", func(t *testing.T) {
		ctx := &Context{Name: "test", Server: "https://example.com"}
		_, err := cfg.ResolveOIDC(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no oidc provider configured")
	})

	t.Run("oidc provider not found", func(t *testing.T) {
		ctx := &Context{Name: "test", Server: "https://example.com", OIDCProvider: "missing"}
		_, err := cfg.ResolveOIDC(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "oidc provider not found")
	})
}

func TestResolveOIDCWithAllFields(t *testing.T) {
	cfg := &Config{
		OIDCProviders: []OIDCProvider{{
			Name:             "corp",
			Authority:        "https://idp.example.com",
			ClientID:         "bgctl",
			ClientSecret:     "secret",
			ClientSecretEnv:  "SECRET_ENV",
			ClientSecretFile: "/path/to/secret",
			GrantType:        "authorization_code",
			Scopes:           []string{"openid", "profile"},
			CAFile:           "/path/to/ca.crt",
			DeviceCodeFlow:   true,
			InsecureSkipTLS:  true,
			ExtraAuthParams:  map[string]string{"audience": "api"},
		}},
	}
	ctx := &Context{Name: "test", Server: "https://example.com", OIDCProvider: "corp"}

	resolved, err := cfg.ResolveOIDC(ctx)
	require.NoError(t, err)
	require.Equal(t, "corp", resolved.ProviderName)
	require.Equal(t, "https://idp.example.com", resolved.Authority)
	require.Equal(t, "bgctl", resolved.ClientID)
	require.Equal(t, "secret", resolved.ClientSecret)
	require.Equal(t, "SECRET_ENV", resolved.ClientSecretEnv)
	require.Equal(t, "/path/to/secret", resolved.ClientSecretFile)
	require.Equal(t, "authorization_code", resolved.GrantType)
	require.Equal(t, []string{"openid", "profile"}, resolved.Scopes)
	require.Equal(t, "/path/to/ca.crt", resolved.CAFile)
	require.True(t, resolved.DeviceCodeFlow)
	require.True(t, resolved.InsecureSkipTLS)
	require.Equal(t, map[string]string{"audience": "api"}, resolved.ExtraAuthParams)
}
