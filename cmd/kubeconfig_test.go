package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestGetKubeConfig(t *testing.T) {
	// Create a dummy kubeconfig file
	kubeConfigFile, err := os.CreateTemp("", "kubeconfig")
	require.NoError(t, err)
	defer os.Remove(kubeConfigFile.Name())

	config := api.NewConfig()
	config.CurrentContext = "default-ctx"
	config.Contexts["default-ctx"] = &api.Context{Cluster: "default-cluster", AuthInfo: "default-user"}
	config.Contexts["custom-ctx"] = &api.Context{Cluster: "custom-cluster", AuthInfo: "custom-user"}

	config.Clusters["default-cluster"] = &api.Cluster{Server: "https://default"}
	config.Clusters["custom-cluster"] = &api.Cluster{Server: "https://custom"}

	config.AuthInfos["default-user"] = &api.AuthInfo{Token: "default"}
	config.AuthInfos["custom-user"] = &api.AuthInfo{Token: "custom"}

	err = clientcmd.WriteToFile(*config, kubeConfigFile.Name())
	require.NoError(t, err)

	os.Setenv("KUBECONFIG", kubeConfigFile.Name())
	defer os.Unsetenv("KUBECONFIG")

	t.Run("empty context uses default", func(t *testing.T) {
		cfg, err := getKubeConfig("")
		require.NoError(t, err)
		assert.Equal(t, "https://default", cfg.Host)
	})

	t.Run("explicit context uses that context", func(t *testing.T) {
		cfg, err := getKubeConfig("custom-ctx")
		require.NoError(t, err)
		assert.Equal(t, "https://custom", cfg.Host)
	})

	t.Run("invalid context fails gracefully", func(t *testing.T) {
		_, err := getKubeConfig("missing-ctx")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing-ctx")
	})
}
