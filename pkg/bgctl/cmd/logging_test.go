// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogLevelAndFormat proves that diagnostics go to stderr in the selected
// format and never into the data output on stdout.
func TestLogLevelAndFormat(t *testing.T) {
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("LOG_FORMAT", "")
	t.Setenv("BGCTL_VERBOSE", "")
	server := setupMockEscalationServer(t)
	defer server.Close()

	run := func(t *testing.T, flags ...string) (stdout, stderr *bytes.Buffer) {
		t.Helper()
		stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
		root := NewRootCommand(Config{OutputWriter: stdout})
		root.SetErr(stderr)
		root.SetArgs(append([]string{"--server", server.URL, "--token", "test-token", "escalation", "list", "-o", "json"}, flags...))
		require.NoError(t, root.Execute())
		var data []map[string]any
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &data), "stdout must hold only the data: %s", stdout)
		return stdout, stderr
	}

	t.Run("default warn console logs nothing", func(t *testing.T) {
		_, stderr := run(t)
		assert.Empty(t, stderr.String())
	})

	t.Run("json debug", func(t *testing.T) {
		_, stderr := run(t, "--log-format=json", "--log-level=debug")
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		require.GreaterOrEqual(t, len(lines), 2, "request and response lines: %s", stderr)
		for _, line := range lines {
			var entry map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &entry), "not JSON: %s", line)
			assert.Equal(t, "debug", entry["level"])
			assert.Equal(t, "bgctl", entry["logger"])
			assert.Contains(t, entry["msg"], "correlationID=")
			assert.NotContains(t, line, "test-token")
		}
	})

	t.Run("verbose is debug console", func(t *testing.T) {
		_, stderr := run(t, "--verbose")
		assert.Contains(t, stderr.String(), "DEBUG\tbgctl\t")
		assert.Contains(t, stderr.String(), "GET api/breakglassEscalations")
	})

	t.Run("invalid level", func(t *testing.T) {
		var stderr bytes.Buffer
		root := NewRootCommand(Config{OutputWriter: &bytes.Buffer{}})
		root.SetErr(&stderr)
		root.SetArgs([]string{"--log-level=trace", "--server", server.URL, "--token", "t", "escalation", "list"})
		assert.ErrorContains(t, root.Execute(), `invalid log level "trace"`)
		// The parse error is printed, not swallowed.
		assert.Contains(t, stderr.String(), `invalid log level "trace"`)
	})
}
