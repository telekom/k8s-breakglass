//go:build !e2e_fault

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import "context"

// e2eTerminalOutputFault returns admit unchanged: the fault injection exists
// only in e2e_fault builds (terminal_recording_fault_e2e.go).
func e2eTerminalOutputFault(admit func(context.Context) error) func(context.Context) error {
	return admit
}
