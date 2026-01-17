package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/version"
	"gopkg.in/yaml.v3"
)

func TestVersionCommand(t *testing.T) {
	// Save original version info
	origVersion := version.Version
	origGitCommit := version.GitCommit
	origBuildDate := version.BuildDate
	defer func() {
		version.Version = origVersion
		version.GitCommit = origGitCommit
		version.BuildDate = origBuildDate
	}()

	// Set test version info
	version.Version = "v1.2.3"
	version.GitCommit = "abc123-dirty"
	version.BuildDate = "2026-01-17T15:00:00Z"

	tests := []struct {
		name           string
		args           []string
		wantContains   []string
		wantNotContain []string
		validateJSON   bool
		validateYAML   bool
	}{
		{
			name:         "default output format",
			args:         []string{},
			wantContains: []string{"bgctl v1.2.3", "commit: abc123-dirty", "built: 2026-01-17T15:00:00Z"},
		},
		{
			name:         "json output format",
			args:         []string{"-o", "json"},
			validateJSON: true,
			wantContains: []string{"v1.2.3", "abc123-dirty", "2026-01-17T15:00:00Z"},
		},
		{
			name:         "yaml output format",
			args:         []string{"-o", "yaml"},
			validateYAML: true,
			wantContains: []string{"version: v1.2.3", "gitcommit: abc123-dirty", "builddate: \"2026-01-17T15:00:00Z\""},
		},
		{
			name:         "long output flag",
			args:         []string{"--output", "json"},
			validateJSON: true,
			wantContains: []string{"v1.2.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			cmd := NewVersionCommand()
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			require.NoError(t, err)

			output := buf.String()

			// Validate JSON structure if requested
			if tt.validateJSON {
				var buildInfo version.BuildInfo
				err := json.Unmarshal(buf.Bytes(), &buildInfo)
				require.NoError(t, err, "output should be valid JSON")
				require.Equal(t, "v1.2.3", buildInfo.Version)
				require.Equal(t, "abc123-dirty", buildInfo.GitCommit)
				require.Equal(t, "2026-01-17T15:00:00Z", buildInfo.BuildDate)
				require.NotEmpty(t, buildInfo.GoVersion)
				require.NotEmpty(t, buildInfo.Platform)
			}

			// Validate YAML structure if requested
			if tt.validateYAML {
				var buildInfo version.BuildInfo
				err := yaml.Unmarshal(buf.Bytes(), &buildInfo)
				require.NoError(t, err, "output should be valid YAML")
				require.Equal(t, "v1.2.3", buildInfo.Version)
				require.Equal(t, "abc123-dirty", buildInfo.GitCommit)
			}

			// Check for expected strings
			for _, want := range tt.wantContains {
				require.Contains(t, output, want, "output should contain %q", want)
			}

			// Check for unwanted strings
			for _, unwant := range tt.wantNotContain {
				require.NotContains(t, output, unwant, "output should not contain %q", unwant)
			}
		})
	}
}

func TestVersionCommandWithoutConfig(t *testing.T) {
	// This test ensures version command works without config file or runtime
	// Save original version info
	origVersion := version.Version
	origGitCommit := version.GitCommit
	origBuildDate := version.BuildDate
	defer func() {
		version.Version = origVersion
		version.GitCommit = origGitCommit
		version.BuildDate = origBuildDate
	}()

	version.Version = "v0.0.1"
	version.GitCommit = "test123"
	version.BuildDate = "2026-01-01T00:00:00Z"

	buf := &bytes.Buffer{}
	cmd := NewVersionCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Execute without any context or config
	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	require.Contains(t, output, "bgctl v0.0.1")
	require.Contains(t, output, "commit: test123")
	require.Contains(t, output, "built: 2026-01-01T00:00:00Z")
}

func TestVersionCommandDevBuild(t *testing.T) {
	// Test that dev builds show proper version info
	origVersion := version.Version
	origGitCommit := version.GitCommit
	origBuildDate := version.BuildDate
	defer func() {
		version.Version = origVersion
		version.GitCommit = origGitCommit
		version.BuildDate = origBuildDate
	}()

	// Simulate dev build with dirty working tree
	version.Version = "dev"
	version.GitCommit = "18ac0d6-dirty"
	version.BuildDate = "2026-01-17T15:15:52Z"

	buf := &bytes.Buffer{}
	cmd := NewVersionCommand()
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	require.Contains(t, output, "bgctl dev")
	require.Contains(t, output, "-dirty", "dev build should show dirty flag")
}

func TestVersionCommandJSONStructure(t *testing.T) {
	// Detailed test of JSON output structure
	origVersion := version.Version
	defer func() { version.Version = origVersion }()
	version.Version = "v2.0.0"

	buf := &bytes.Buffer{}
	cmd := NewVersionCommand()
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"-o", "json"})

	err := cmd.Execute()
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	// Check all expected fields exist
	require.Contains(t, result, "version")
	require.Contains(t, result, "gitCommit")
	require.Contains(t, result, "buildDate")
	require.Contains(t, result, "goVersion")
	require.Contains(t, result, "platform")

	// Verify types
	require.IsType(t, "", result["version"])
	require.IsType(t, "", result["gitCommit"])
	require.IsType(t, "", result["buildDate"])
	require.IsType(t, "", result["goVersion"])
	require.IsType(t, "", result["platform"])

	// Verify goVersion starts with "go"
	goVersion, ok := result["goVersion"].(string)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(goVersion, "go"), "goVersion should start with 'go'")

	// Verify platform contains "/"
	platform, ok := result["platform"].(string)
	require.True(t, ok)
	require.Contains(t, platform, "/", "platform should be in OS/ARCH format")
}
