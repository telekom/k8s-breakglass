package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func TestConfigGetContextsAndCurrent(t *testing.T) {
	buf := &bytes.Buffer{}
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.CurrentContext = "ctx-2"
	cfg.Contexts = []config.Context{
		{Name: "ctx-1", Server: "https://one.example"},
		{Name: "ctx-2", Server: "https://two.example"},
	}
	require.NoError(t, config.Save(path, &cfg))

	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "get-contexts"})
	require.NoError(t, root.Execute())

	output := buf.String()
	assert.Contains(t, output, "* ctx-2\thttps://two.example")
	assert.Contains(t, output, "  ctx-1\thttps://one.example")

	buf.Reset()
	root = NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "current-context"})
	require.NoError(t, root.Execute())
	assert.Equal(t, "ctx-2\n", buf.String())
}

func TestConfigSetContextUpdatesConfig(t *testing.T) {
	buf := &bytes.Buffer{}
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.CurrentContext = "ctx-1"
	cfg.Contexts = []config.Context{
		{Name: "ctx-1", Server: "https://one.example"},
		{Name: "ctx-2", Server: "https://two.example"},
	}
	require.NoError(t, config.Save(path, &cfg))

	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "set-context", "ctx-2"})
	require.NoError(t, root.Execute())
	assert.Equal(t, "ctx-2\n", buf.String())

	updated, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "ctx-2", updated.CurrentContext)
}

func TestConfigSetValueCommands(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.Contexts = []config.Context{{Name: "ctx", Server: "https://example"}}
	cfg.CurrentContext = "ctx"
	require.NoError(t, config.Save(path, &cfg))

	buf := &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "set", "settings.output-format", "json"})
	require.NoError(t, root.Execute())

	updated, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "json", updated.Settings.OutputFormat)

	buf.Reset()
	root = NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "set", "settings.page-size", "invalid"})
	err = root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid page size")
}

func TestConfigAddContextInlineOIDC(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.Contexts = []config.Context{{Name: "existing", Server: "https://existing.example"}}
	cfg.CurrentContext = "existing"
	require.NoError(t, config.Save(path, &cfg))

	buf := &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{
		"config", "add-context", "new",
		"--server", "https://new.example",
		"--oidc-authority", "https://idp.example.com",
		"--oidc-client-id", "client",
	})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "Added context new")

	updated, err := config.Load(path)
	require.NoError(t, err)
	_, err = updated.FindContext("new")
	require.NoError(t, err)
}

func TestConfigAddContextRequiresOIDC(t *testing.T) {
	path := configPathForTest(t)
	require.NoError(t, config.Save(path, &config.Config{Version: config.VersionV1}))

	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: &bytes.Buffer{}})
	root.SetArgs([]string{"config", "add-context", "new", "--server", "https://new.example"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc-authority")
}

func TestConfigAddAndListOIDCProvider(t *testing.T) {
	path := configPathForTest(t)
	require.NoError(t, config.Save(path, &config.Config{Version: config.VersionV1}))

	buf := &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{
		"config", "add-oidc-provider", "corp",
		"--authority", "https://idp.example.com",
		"--client-id", "client",
	})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "Added OIDC provider corp")

	buf.Reset()
	root = NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "get-oidc-providers"})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "corp\thttps://idp.example.com\tclient")
}

func TestConfigDeleteContextClearsCurrent(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.Contexts = []config.Context{{Name: "ctx", Server: "https://example"}}
	cfg.CurrentContext = "ctx"
	require.NoError(t, config.Save(path, &cfg))

	buf := &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "delete-context", "ctx"})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "Deleted context ctx")

	updated, err := config.Load(path)
	require.NoError(t, err)
	assert.Equal(t, "", updated.CurrentContext)
}

func TestConfigDeleteOIDCProviderReferenced(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.OIDCProviders = []config.OIDCProvider{{Name: "corp", Authority: "https://idp", ClientID: "client"}}
	cfg.Contexts = []config.Context{{Name: "ctx", Server: "https://example", OIDCProvider: "corp"}}
	require.NoError(t, config.Save(path, &cfg))

	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: &bytes.Buffer{}})
	root.SetArgs([]string{"config", "delete-oidc-provider", "corp"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "still referenced")
}

func TestConfigDeleteOIDCProviderSuccess(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.OIDCProviders = []config.OIDCProvider{{Name: "corp", Authority: "https://idp", ClientID: "client"}}
	require.NoError(t, config.Save(path, &cfg))

	buf := &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: buf})
	root.SetArgs([]string{"config", "delete-oidc-provider", "corp"})
	require.NoError(t, root.Execute())
	assert.Contains(t, buf.String(), "Deleted OIDC provider corp")

	updated, err := config.Load(path)
	require.NoError(t, err)
	assert.Len(t, updated.OIDCProviders, 0)
}

func TestConfigDeleteContextNotFound(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	cfg.Contexts = []config.Context{{Name: "ctx", Server: "https://example"}}
	require.NoError(t, config.Save(path, &cfg))

	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: &bytes.Buffer{}})
	root.SetArgs([]string{"config", "delete-context", "missing"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "context not found")
}

func TestConfigDeleteOIDCProviderNotFound(t *testing.T) {
	path := configPathForTest(t)

	cfg := config.DefaultConfig()
	require.NoError(t, config.Save(path, &cfg))

	root := NewRootCommand(Config{ConfigPath: path, OutputWriter: &bytes.Buffer{}})
	root.SetArgs([]string{"config", "delete-oidc-provider", "missing"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oidc provider not found")
}

func configPathForTest(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/config.yaml"
}
