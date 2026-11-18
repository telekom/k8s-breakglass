//go:build e2e_fault

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync/atomic"
)

// e2eTerminalOutputFault is e2e fault injection, compiled only with the
// e2e_fault build tag (e2e/build-ha-image.sh): with
// BREAKGLASS_E2E_FAIL_TERMINAL_OUTPUT_ADMISSION=N the Nth output admission of
// every recorded stream fails once, as one failed live read of the session
// would (#1760). Every other admission is unchanged.
func e2eTerminalOutputFault(admit func(context.Context) error) func(context.Context) error {
	n, err := strconv.ParseInt(os.Getenv("BREAKGLASS_E2E_FAIL_TERMINAL_OUTPUT_ADMISSION"), 10, 64)
	if err != nil || n < 1 {
		return admit
	}
	var calls atomic.Int64
	return func(ctx context.Context) error {
		if calls.Add(1) == n {
			return errors.New("read terminal session authority: e2e fault injection")
		}
		return admit(ctx)
	}
}
