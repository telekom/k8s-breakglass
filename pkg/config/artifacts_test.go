// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"gopkg.in/yaml.v2"
)

func TestArtifactsCollectorImagePullSecretsConfiguration(t *testing.T) {
	var cfg config.Config
	require.NoError(t, yaml.Unmarshal([]byte(`
artifacts:
  collectorImage: registry.example/collector@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  collectorImagePullSecrets:
    - name: collector-registry
    - name: fallback-registry
`), &cfg))
	data, err := yaml.Marshal(cfg.Artifacts)
	require.NoError(t, err)
	var fields map[string]interface{}
	require.NoError(t, yaml.Unmarshal(data, &fields))
	require.Equal(t, []interface{}{
		map[interface{}]interface{}{"name": "collector-registry"},
		map[interface{}]interface{}{"name": "fallback-registry"},
	}, fields["collectorImagePullSecrets"])
}

func TestArtifactsTerminalRecordingLimitsConfiguration(t *testing.T) {
	var cfg config.Config
	require.NoError(t, yaml.Unmarshal([]byte("artifacts:\n  terminalRecordingMaxBytes: 1048576\n  terminalRecordingMaxConcurrent: 4\n"), &cfg))
	require.Equal(t, int64(1048576), cfg.Artifacts.TerminalRecordingMaxBytes)
	require.Equal(t, 4, cfg.Artifacts.TerminalRecordingMaxConcurrent)
	var unset config.Config
	require.NoError(t, yaml.Unmarshal([]byte("artifacts: {}\n"), &unset))
	require.Zero(t, unset.Artifacts.TerminalRecordingMaxBytes)
	require.Zero(t, unset.Artifacts.TerminalRecordingMaxConcurrent)
}
