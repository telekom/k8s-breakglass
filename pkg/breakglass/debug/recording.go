/*
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"fmt"
	"regexp"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

var (
	recordingAuthorizationPattern = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:[^\s,;]+\s+)?[^\s,;]+`)
	recordingBearerPattern        = regexp.MustCompile(`(?i)(\bbearer\s+)[^\s,;]+`)
	recordingSecretPattern        = regexp.MustCompile(`(?i)((?:access[_-]?token|token|password|passwd|secret)(?:[=:]\s*|\s+))[^\s,;]+`)
)

// safeRecordingFailure keeps controller status useful while preventing an
// image pull error, webhook response, or sidecar message from becoming a
// credential exfiltration channel. Callers should still prefer static errors.
func safeRecordingFailure(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "terminal recording failed"
	}
	reason = recordingAuthorizationPattern.ReplaceAllString(reason, "$1[REDACTED]")
	reason = recordingBearerPattern.ReplaceAllString(reason, "$1[REDACTED]")
	reason = recordingSecretPattern.ReplaceAllString(reason, "$1[REDACTED]")
	if len(reason) > 512 {
		reason = reason[:512] + "..."
	}
	return reason
}

// rejectUnsupportedTerminalRecording rejects recording requests until the
// terminal-byte transport is configured.
func rejectUnsupportedTerminalRecording(template *breakglassv1alpha1.DebugSessionTemplate) error {
	if template != nil && template.Spec.Audit != nil && template.Spec.Audit.EnableTerminalRecording {
		return fmt.Errorf("terminal recording is unavailable: terminal-byte transport is not configured")
	}
	return nil
}

func injectTerminalRecording(template *breakglassv1alpha1.DebugSessionTemplate) error {
	return rejectUnsupportedTerminalRecording(template)
}
