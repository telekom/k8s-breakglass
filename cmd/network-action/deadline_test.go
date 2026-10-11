// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestControllerActionDeadline(t *testing.T) {
	common, err := filepath.Abs("../../utils/node-maintenance/lib/common.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		deadline string
		wantErr  bool
	}{
		{"legacy absent", "", false},
		{"future controller deadline", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10), false},
		{"expired", "1", true},
		{"non numeric", "not-a-timestamp", true},
		{"oversized", "9999999999999999999", true},
		{"option injection", "--help", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", `. "$1"; validate_action_deadline`, "deadline-proof", common)
			for _, env := range os.Environ() {
				if !strings.HasPrefix(env, "BREAKGLASS_ACTION_DEADLINE_UNIX=") {
					cmd.Env = append(cmd.Env, env)
				}
			}
			cmd.Env = append(cmd.Env, "BREAKGLASS_ACTION_DEADLINE_UNIX="+tc.deadline)
			output, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantErr {
				t.Fatalf("deadline error = %v, want error %v; output: %s", err, tc.wantErr, output)
			}
		})
	}
}
