//go:build linux || darwin

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeArtifactProvisionConfig(t *testing.T, instanceID string) (string, string) {
	t.Helper()
	volume, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := fmt.Sprintf(`artifacts:
  enabled: true
  backend: local
  stagingDir: %[1]s/uploads
  local:
    privateRootAcknowledged: true
    artifactRoot: %[1]s/objects
    stagingRoot: %[1]s/staging
    instanceID: %[2]s
    expectedUID: %[3]d
    expectedGID: %[4]d
    servingReplicas: 1
    accessMode: ReadWriteOnce
    deploymentStrategy: Recreate
    encryptionAcknowledged: true
    snapshotPolicy: prohibited
`, volume, instanceID, os.Getuid(), os.Getgid())
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path, volume
}

func TestArtifactsProvisionCommand(t *testing.T) {
	configPath, volume := writeArtifactProvisionConfig(t, "cmd-test-instance-0001")

	var out bytes.Buffer
	require.NoError(t, runArtifactsCommand([]string{"provision", "--config-path", configPath}, &out))
	require.Equal(t, "local artifact storage provisioned (instance cmd-test-instance-0001)\n", out.String())
	for _, dir := range []string{"objects", "staging", "uploads"} {
		info, err := os.Stat(filepath.Join(volume, dir))
		require.NoError(t, err)
		require.Equal(t, os.ModeDir|0o700, info.Mode()&(os.ModeDir|os.ModePerm), dir)
	}

	out.Reset()
	t.Setenv("BREAKGLASS_CONFIG_PATH", configPath)
	require.NoError(t, runArtifactsCommand([]string{"provision"}, &out))
	require.Contains(t, out.String(), "already provisioned")
}

func TestArtifactsProvisionCommandRefusesMismatchedInstance(t *testing.T) {
	configPath, volume := writeArtifactProvisionConfig(t, "cmd-test-instance-0001")
	require.NoError(t, runArtifactsCommand([]string{"provision", "--config-path", configPath}, &bytes.Buffer{}))

	content, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configPath, bytes.ReplaceAll(content, []byte("cmd-test-instance-0001"), []byte("cmd-test-instance-0002")), 0o600))
	err = runArtifactsCommand([]string{"provision", "--config-path", configPath}, &bytes.Buffer{})
	require.ErrorContains(t, err, "verify local artifact sentinel")
	sentinel, readErr := os.ReadFile(filepath.Join(volume, "objects", ".breakglass-artifact-instance-v1"))
	require.NoError(t, readErr)
	require.Equal(t, "cmd-test-instance-0001\n", string(sentinel))
}

func TestArtifactsCommandRejectsInvalidInvocations(t *testing.T) {
	configPath, _ := writeArtifactProvisionConfig(t, "cmd-test-instance-0001")
	s3Config := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(s3Config, []byte("artifacts:\n  enabled: true\n  backend: s3\n"), 0o600))
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "no subcommand", args: nil, want: errArtifactsUsage.Error()},
		{name: "unknown subcommand", args: []string{"wipe"}, want: errArtifactsUsage.Error()},
		{name: "extra argument", args: []string{"provision", "--config-path", configPath, "extra"}, want: errArtifactsUsage.Error()},
		{name: "unknown flag", args: []string{"provision", "--force"}, want: "flag provided but not defined"},
		{name: "missing config", args: []string{"provision", "--config-path", filepath.Join(t.TempDir(), "absent.yaml")}, want: "load config"},
		{name: "s3 backend", args: []string{"provision", "--config-path", s3Config}, want: "artifacts.backend must be local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, runArtifactsCommand(tt.args, &bytes.Buffer{}), tt.want)
		})
	}
}
