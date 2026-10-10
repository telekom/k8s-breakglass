// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreflightRejectsDuplicateOptionsBeforeExecution(t *testing.T) {
	t.Parallel()
	helper := filepath.Join("..", "..", "lib", "node-recovery-preflight.sh")
	values := map[string]string{
		"--target-node":  "node-a",
		"--interface":    "lo",
		"--evidence-dir": "/evidence",
		"--confirm":      "NODE-RECOVERY-PREFLIGHT",
	}
	for option, value := range values {
		for _, pair := range [][2]string{{value, value}, {value, ""}, {value, "different"}, {"", value}} {
			t.Run(option+"/"+pair[0]+"/"+pair[1], func(t *testing.T) {
				t.Parallel()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				// No controller context is supplied: parsing must reject the
				// duplicate before identity validation, probes or evidence writes.
				cmd := exec.CommandContext(ctx, "sh", helper, option, pair[0], option, pair[1])
				cmd.Env = []string{"PATH=/usr/bin:/bin"}
				output, err := cmd.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
					t.Fatalf("duplicate returned %v, output: %s", err, output)
				}
				expected := "node-maintenance: " + option + " may be supplied only once\n"
				if string(output) != expected {
					t.Fatalf("output = %q, want %q", output, expected)
				}
			})
		}
	}
}

func TestPreflightAcceptsEachOptionOnce(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", filepath.Join("..", "..", "lib", "node-recovery-preflight.sh"),
		"--target-node", "node-a", "--interface", "lo", "--evidence-dir", "/evidence",
		"--confirm", "NODE-RECOVERY-PREFLIGHT", "--help")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("single options failed: %v, output: %s", err, output)
	}
	if !strings.Contains(string(output), "This command is read-only.") {
		t.Fatalf("help output = %q", output)
	}
}
