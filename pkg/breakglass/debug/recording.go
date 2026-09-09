// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// rejectUnsupportedTerminalRecording rejects recording requests until the
// terminal-byte transport is configured.
func rejectUnsupportedTerminalRecording(template *breakglassv1alpha1.DebugSessionTemplate) error {
	if template != nil && template.Spec.Audit != nil && template.Spec.Audit.EnableTerminalRecording {
		return fmt.Errorf("terminal recording requested by spec.audit.enableTerminalRecording is unavailable: terminal-byte transport is not configured")
	}
	return nil
}
