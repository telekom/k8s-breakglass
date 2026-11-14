// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/clustervalidator"
	"go.uber.org/zap"
)

func TestParseOptionsUsesModeSpecificDefaultReport(t *testing.T) {
	t.Setenv("VALIDATOR_MODE", "")
	t.Setenv("VALIDATOR_REPORT_PATH", "")
	t.Setenv("VALIDATOR_TIMEOUT", "")
	opts, err := parseOptions([]string{"--mode", clustervalidator.ModePostUpgrade, "--timeout", "2s"})
	require.NoError(t, err)
	require.Equal(t, clustervalidator.ModePostUpgrade, opts.mode)
	require.Equal(t, "/reports/post-upgrade.json", opts.reportPath)
	require.Equal(t, 2*time.Second, opts.timeout)
}

func TestParseOptionsRejectsInvalidValues(t *testing.T) {
	t.Setenv("VALIDATOR_TIMEOUT", "not-a-duration")
	_, err := parseOptions(nil)
	require.ErrorContains(t, err, "invalid --timeout")

	t.Setenv("VALIDATOR_TIMEOUT", "")
	_, err = parseOptions([]string{"--mode", "unsupported"})
	require.ErrorContains(t, err, "invalid mode")

	t.Setenv("VALIDATOR_INCLUDE_TIMESTAMP", "maybe")
	_, err = parseOptions(nil)
	require.ErrorContains(t, err, "invalid VALIDATOR_INCLUDE_TIMESTAMP")
}

func TestRunHelpExitsSuccessfully(t *testing.T) {
	var stdout, stderr bytes.Buffer
	require.Equal(t, 0, run([]string{"--help"}, &stdout, &stderr))
}

func TestWriteResultProducesContractAndExitCode(t *testing.T) {
	var output bytes.Buffer
	report := failureReport(clustervalidator.ModeOneTime, "configuration", "test failure", false)
	exitCode := writeResult(report, "-", &output, zap.NewNop(), 1)
	require.Equal(t, 1, exitCode)
	require.Contains(t, output.String(), `"apiVersion": "cluster-validator.telekom.com/v1alpha1"`)
	require.Contains(t, output.String(), `"status": "not-ready"`)
}

func TestRunConfigurationFailureUsesUsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"--kubeconfig", "/does/not/exist", "--report", "-"}, &stdout, &stderr)
	require.Equal(t, 2, exitCode)
	require.Contains(t, stdout.String(), `"name": "configuration"`)
	require.NotContains(t, stdout.String(), "does/not/exist")
}

func TestWriteReportProtectsOutputPathAndPermissions(t *testing.T) {
	root := t.TempDir()
	report := failureReport(clustervalidator.ModeOneTime, "configuration", "test failure", false)

	require.NoError(t, writeReportAtRoot(report, "nested/report.json", root))
	reportPath := filepath.Join(root, "nested", "report.json")
	info, err := os.Stat(reportPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	directoryInfo, err := os.Stat(filepath.Dir(reportPath))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), directoryInfo.Mode().Perm())

	for _, escapedPath := range []string{
		"../escaped.json",
		filepath.Join(root, "..", "escaped.json"),
	} {
		require.Error(t, writeReportAtRoot(report, escapedPath, root), escapedPath)
	}
}

func TestWriteReportRejectsSymlinkEscapes(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	report := failureReport(clustervalidator.ModeOneTime, "configuration", "test failure", false)

	intermediate := filepath.Join(root, "linked")
	require.NoError(t, os.Symlink(outside, intermediate))
	require.Error(t, writeReportAtRoot(report, "linked/report.json", root))
	require.NoFileExists(t, filepath.Join(outside, "report.json"))

	destination := filepath.Join(root, "destination.json")
	outsideDestination := filepath.Join(outside, "destination.json")
	require.NoError(t, os.Symlink(outsideDestination, destination))
	require.Error(t, writeReportAtRoot(report, destination, root))
	require.NoFileExists(t, outsideDestination)
}

func TestWriteReportPreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	report := failureReport(clustervalidator.ModeOneTime, "configuration", "new report", false)
	destination := filepath.Join(root, "report.json")
	require.NoError(t, os.WriteFile(destination, []byte("existing report"), 0o600))

	require.Error(t, writeReportAtRoot(report, "report.json", root))
	contents, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Equal(t, []byte("existing report"), contents)
}

// TestRunLogFormats proves the error output: plain "cluster-validator: …"
// lines by default, and one JSON object per line with --log-format=json, also
// for option errors.
func TestRunLogFormats(t *testing.T) {
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("LOG_FORMAT", "")
	args := []string{"--kubeconfig", "/does/not/exist", "--report", filepath.Join(t.TempDir(), "outside", "report.json")}

	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, run(args, &stdout, &stderr))
	require.Regexp(t, `^cluster-validator: [^\n{]+\n$`, stderr.String())
	want := strings.TrimSuffix(strings.TrimPrefix(stderr.String(), "cluster-validator: "), "\n")

	stderr.Reset()
	require.Equal(t, 2, run(append([]string{"--log-format=json"}, args...), &stdout, &stderr))
	var entry map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &entry), "stderr: %s", stderr.String())
	require.Equal(t, "error", entry["level"])
	require.Equal(t, "cluster-validator", entry["logger"])
	require.Equal(t, want, entry["msg"])

	// Option errors use the requested format too.
	stderr.Reset()
	require.Equal(t, 2, run([]string{"--log-format=json", "--mode", "unsupported"}, &stdout, &stderr))
	entry = nil
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &entry), "stderr: %s", stderr.String())
	require.Equal(t, "error", entry["level"])
	require.Contains(t, entry["msg"], `invalid mode "unsupported"`)

	// Flag syntax errors, too: the flag package itself writes nothing.
	stderr.Reset()
	realStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	exitCode := run([]string{"--log-format=json", "--skip-pods=invalid"}, &stdout, &stderr)
	os.Stderr = realStderr
	require.NoError(t, w.Close())
	direct, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, 2, exitCode)
	require.Empty(t, string(direct))
	entry = nil
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &entry), "stderr: %s", stderr.String())
	require.Contains(t, entry["msg"], `invalid boolean value "invalid" for -skip-pods`)

	stderr.Reset()
	t.Setenv("LOG_LEVEL", "verbose")
	require.Equal(t, 2, run(args, &stdout, &stderr))
	require.Contains(t, stderr.String(), `cluster-validator: invalid log level "verbose"`)
}
