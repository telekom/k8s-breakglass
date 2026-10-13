// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package debug

import (
	"os"
	"testing"
)

func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	t.Skip("pseudo terminal helper is Linux-only")
	return nil, nil
}
