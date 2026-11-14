// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	helperName   = "kexec-action"
	helperPrefix = "kexec-action"
)

// TestMain runs main() instead of the tests when the logging smoke test
// re-executes this test binary.
func TestMain(m *testing.M) {
	if os.Getenv("HELPER_RUN_MAIN") == "1" {
		os.Args = os.Args[:1] // no arguments: every helper rejects that
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runMain(t *testing.T, env ...string) (stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), append([]string{"HELPER_RUN_MAIN=1", "LOG_LEVEL=", "LOG_FORMAT="}, env...)...)
	var buf bytes.Buffer
	cmd.Stderr = &buf
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return buf.String(), exit.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.String(), 0
}

// TestLogFormats proves that the default output is unchanged, LOG_FORMAT=json
// writes one JSON line, LOG_LEVEL=error keeps errors, and a bad setting is
// reported on stderr with exit code 2.
func TestLogFormats(t *testing.T) {
	text, code := runMain(t)
	if code == 0 || strings.Count(text, "\n") != 1 || !strings.HasSuffix(text, "\n") {
		t.Fatalf("default: exit %d, stderr %q", code, text)
	}
	msg := strings.TrimSuffix(text, "\n")
	if helperPrefix != "" {
		if !strings.HasPrefix(msg, helperPrefix+": ") {
			t.Fatalf("default stderr %q lacks the %q prefix", text, helperPrefix)
		}
		msg = strings.TrimPrefix(msg, helperPrefix+": ")
	}

	out, jsonCode := runMain(t, "LOG_FORMAT=json")
	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &entry); err != nil || jsonCode != code {
		t.Fatalf("json: exit %d, stderr %q: %v", jsonCode, out, err)
	}
	if entry["level"] != "error" || entry["logger"] != helperName || entry["msg"] != msg {
		t.Fatalf("json fields: %v", entry)
	}
	if _, ok := entry["ts"].(float64); !ok {
		t.Fatalf("json ts: %v", entry)
	}

	if out, _ := runMain(t, "LOG_LEVEL=error"); out != text {
		t.Fatalf("LOG_LEVEL=error must keep errors: %q", out)
	}
	if out, code := runMain(t, "LOG_LEVEL=verbose"); code != 2 || !strings.Contains(out, `invalid LOG_LEVEL "verbose"`) {
		t.Fatalf("bad LOG_LEVEL: exit %d, stderr %q", code, out)
	}
	if out, code := runMain(t, "LOG_FORMAT=yaml"); code != 2 || !strings.Contains(out, `invalid LOG_FORMAT "yaml"`) {
		t.Fatalf("bad LOG_FORMAT: exit %d, stderr %q", code, out)
	}
}
