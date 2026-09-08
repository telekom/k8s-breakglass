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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

var (
	recordingAuthorizationPattern = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:[^\s,;]+\s+)?[^\s,;]+`)
	recordingBearerPattern        = regexp.MustCompile(`(?i)(\bbearer\s+)[^\s,;]+`)
	recordingSecretPattern        = regexp.MustCompile(`(?i)((?:access[_-]?token|token|password|passwd|secret)(?:[=:]\s*|\s+))[^\s,;]+`)
)

const (
	terminalRecordingVolumeName = "breakglass-terminal-recording"
	terminalRecordingMountPath  = "/var/run/breakglass/recording"
	terminalRecordingOutput     = terminalRecordingMountPath + "/session.cast"

	// These environment variables are the stable contract between the
	// controller and a recording sidecar. The sidecar image is intentionally
	// deployment supplied; the controller does not assume an internal image or
	// a command line implementation.
	TerminalRecordingEnabledEnv     = "BREAKGLASS_TERMINAL_RECORDING"
	TerminalRecordingSessionEnv     = "BREAKGLASS_RECORDING_SESSION"
	TerminalRecordingNamespaceEnv   = "BREAKGLASS_RECORDING_NAMESPACE"
	TerminalRecordingClusterEnv     = "BREAKGLASS_RECORDING_CLUSTER"
	TerminalRecordingTemplateEnv    = "BREAKGLASS_RECORDING_TEMPLATE"
	TerminalRecordingCorrelationEnv = "BREAKGLASS_RECORDING_CORRELATION_ID"
	TerminalRecordingFormatEnv      = "BREAKGLASS_RECORDING_FORMAT"
	TerminalRecordingOutputEnv      = "BREAKGLASS_RECORDING_OUTPUT"
	TerminalRecordingRetentionEnv   = "BREAKGLASS_RECORDING_RETENTION"
	TerminalRecordingRedactionEnv   = "BREAKGLASS_RECORDING_REDACT_SECRETS"
	TerminalRecordingMaxBytesEnv    = "BREAKGLASS_RECORDING_MAX_BYTES"
	TerminalRecordingFormat         = "asciicast-v2"
)

// recordingCorrelationID is stable across controller retries and contains no
// user input other than Kubernetes object identity. It is safe to put in
// status, sidecar environment, and audit request context.
func recordingCorrelationID(namespace, name string) string {
	sum := sha256.Sum256([]byte(namespace + "/" + name))
	return "dsr-" + hex.EncodeToString(sum[:12])
}

func recordingRetentionDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "90d"
	}
	d, err := breakglassv1alpha1.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("recording retention must be a positive duration: %q", value)
	}
	return d, nil
}

func validateTerminalRecordingImage(image string) error {
	image = strings.TrimSpace(image)
	if image == "" {
		return fmt.Errorf("terminal recording is enabled but no sidecar image is configured")
	}
	if strings.IndexFunc(image, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("terminal recording sidecar image contains whitespace or control characters")
	}
	digest := strings.LastIndex(image, "@sha256:")
	if digest < 0 || len(image)-digest-len("@sha256:") != 64 {
		return fmt.Errorf("terminal recording sidecar image must be pinned by a sha256 digest")
	}
	for _, r := range image[digest+len("@sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return fmt.Errorf("terminal recording sidecar image has an invalid sha256 digest")
		}
	}
	return nil
}

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

// injectTerminalRecording adds the sidecar contract and a private shared
// volume. It does not copy template headers, Secret values, or bearer tokens
// into the pod. A sidecar image must implement the contract documented in
// docs/terminal-recording.md.
func rejectUnsupportedTerminalRecording(template *breakglassv1alpha1.DebugSessionTemplate) error {
	if template != nil && template.Spec.Audit != nil && template.Spec.Audit.EnableTerminalRecording {
		return fmt.Errorf("terminal recording is unavailable: terminal-byte transport is not configured")
	}
	return nil
}

func injectTerminalRecording(spec *corev1.PodSpec, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, image string) error {
	return rejectUnsupportedTerminalRecording(template)
}
