// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/clustervalidator"
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

func TestWriteResultProducesContractAndExitCode(t *testing.T) {
	var output bytes.Buffer
	report := failureReport(clustervalidator.ModeOneTime, "configuration", "test failure", false)
	exitCode := writeResult(report, "-", &output, &output, 1)
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
