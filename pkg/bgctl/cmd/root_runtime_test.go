package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func TestRuntimeStateResolveContextName(t *testing.T) {
	rt := &runtimeState{contextOverride: "override"}
	require.Equal(t, "override", rt.ResolveContextName())

	rt = &runtimeState{cfg: &config.Config{CurrentContext: "ctx"}}
	require.Equal(t, "ctx", rt.ResolveContextName())
}

func TestRuntimeStateOutputFormat(t *testing.T) {
	rt := &runtimeState{outputFormat: "json"}
	require.Equal(t, "json", rt.OutputFormat())

	rt = &runtimeState{cfg: &config.Config{Settings: config.Settings{OutputFormat: "yaml"}}}
	require.Equal(t, "yaml", rt.OutputFormat())

	rt = &runtimeState{}
	require.Equal(t, "table", rt.OutputFormat())
}

func TestEnsureConfigLoaded(t *testing.T) {
	path := configPathForTest(t)
	cfg := config.DefaultConfig()
	cfg.Contexts = []config.Context{{Name: "ctx", Server: "https://example.com"}}
	require.NoError(t, config.Save(path, &cfg))

	rt := &runtimeState{configPath: path}
	require.NoError(t, rt.EnsureConfigLoaded())
	require.NotNil(t, rt.cfg)
}

func TestResolveContextErrors(t *testing.T) {
	rt := &runtimeState{}
	_, err := rt.ResolveContext()
	require.Error(t, err)

	rt = &runtimeState{cfg: &config.Config{}}
	_, err = rt.ResolveContext()
	require.Error(t, err)
}
