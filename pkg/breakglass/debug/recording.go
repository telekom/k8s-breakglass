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
	"strconv"
	"strings"
	"time"
	"unicode"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

var recordingSecretPattern = regexp.MustCompile(`(?i)(bearer\s+|token|password|passwd|secret|authorization)([=:]\s*|\s+)[^\s,;]+`)

const (
	terminalRecordingVolumeName = "breakglass-terminal-recording"
	terminalRecordingMountPath  = "/var/run/breakglass/recording"
	terminalRecordingOutput     = terminalRecordingMountPath + "/session.cast"

	// These environment variables are the stable contract between the
	// controller and a recording sidecar. The sidecar image is intentionally
	// deployment supplied; the controller does not assume an internal image or
	// a command line implementation.
	TerminalRecordingEnabledEnv           = "BREAKGLASS_TERMINAL_RECORDING"
	TerminalRecordingSessionEnv           = "BREAKGLASS_RECORDING_SESSION"
	TerminalRecordingNamespaceEnv         = "BREAKGLASS_RECORDING_NAMESPACE"
	TerminalRecordingClusterEnv           = "BREAKGLASS_RECORDING_CLUSTER"
	TerminalRecordingTemplateEnv          = "BREAKGLASS_RECORDING_TEMPLATE"
	TerminalRecordingCorrelationEnv       = "BREAKGLASS_RECORDING_CORRELATION_ID"
	TerminalRecordingFormatEnv            = "BREAKGLASS_RECORDING_FORMAT"
	TerminalRecordingOutputEnv            = "BREAKGLASS_RECORDING_OUTPUT"
	TerminalRecordingRetentionEnv         = "BREAKGLASS_RECORDING_RETENTION"
	TerminalRecordingRedactionEnv         = "BREAKGLASS_RECORDING_REDACT_SECRETS"
	TerminalRecordingMaxBytesEnv          = "BREAKGLASS_RECORDING_MAX_BYTES"
	TerminalRecordingFormat               = "asciicast-v2"
	terminalRecordingMaxBytes       int64 = 512 * 1024 * 1024
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
	// time.ParseDuration deliberately has no days or years. Keep the CRD's
	// human-friendly units while doing strict overflow-safe conversion.
	if strings.HasSuffix(value, "d") || strings.HasSuffix(value, "w") || strings.HasSuffix(value, "y") {
		unit := value[len(value)-1]
		n, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("recording retention must be a positive duration: %q", value)
		}
		multiplier := int64(24 * time.Hour)
		switch unit {
		case 'w':
			multiplier *= 7
		case 'y':
			multiplier *= 365
		}
		if n > int64((time.Duration(1<<63-1))/time.Duration(multiplier)) {
			return 0, fmt.Errorf("recording retention overflows duration: %q", value)
		}
		return time.Duration(n * multiplier), nil
	}
	d, err := time.ParseDuration(value)
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
	reason = recordingSecretPattern.ReplaceAllString(reason, "$1$2[REDACTED]")
	if len(reason) > 512 {
		reason = reason[:512] + "..."
	}
	return reason
}

func sanitizedRecordingStatus(status *breakglassv1alpha1.TerminalRecordingStatus) *breakglassv1alpha1.TerminalRecordingStatus {
	if status == nil {
		return nil
	}
	sanitized := status.DeepCopy()
	sanitized.Error = safeRecordingFailure(sanitized.Error)
	return sanitized
}

// injectTerminalRecording adds the sidecar contract and a private shared
// volume. It does not copy template headers, Secret values, or bearer tokens
// into the pod. A sidecar image must implement the contract documented in
// docs/terminal-recording.md.
func injectTerminalRecording(spec *corev1.PodSpec, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, image string) error {
	if template.Spec.Audit == nil || !template.Spec.Audit.EnableTerminalRecording {
		return nil
	}
	if err := validateTerminalRecordingImage(image); err != nil {
		return err
	}
	if _, err := recordingRetentionDuration(template.Spec.Audit.RecordingRetention); err != nil {
		return err
	}
	if len(spec.Containers) == 0 {
		return fmt.Errorf("terminal recording requires at least one workload container")
	}
	for i := range spec.Volumes {
		if spec.Volumes[i].Name == terminalRecordingVolumeName {
			return fmt.Errorf("volume name %q is reserved for the terminal recording sidecar", terminalRecordingVolumeName)
		}
	}

	for i := range spec.Containers {
		// A controller-owned name makes retries idempotent without trusting a
		// user-provided environment marker on the workload container.
		if spec.Containers[i].Name == "terminal-recorder" {
			return fmt.Errorf("container name %q is reserved for the terminal recording sidecar", "terminal-recorder")
		}
	}

	correlationID := recordingCorrelationID(ds.Namespace, ds.Name)
	envs := []corev1.EnvVar{
		{Name: TerminalRecordingEnabledEnv, Value: "true"},
		{Name: TerminalRecordingSessionEnv, Value: ds.Name},
		{Name: TerminalRecordingNamespaceEnv, Value: ds.Namespace},
		{Name: TerminalRecordingClusterEnv, Value: ds.Spec.Cluster},
		{Name: TerminalRecordingTemplateEnv, Value: ds.Spec.TemplateRef},
		{Name: TerminalRecordingCorrelationEnv, Value: correlationID},
		{Name: TerminalRecordingFormatEnv, Value: TerminalRecordingFormat},
		{Name: TerminalRecordingOutputEnv, Value: terminalRecordingOutput},
		{Name: TerminalRecordingRetentionEnv, Value: defaultRecordingRetention(template.Spec.Audit.RecordingRetention)},
		{Name: TerminalRecordingRedactionEnv, Value: "true"},
		{Name: TerminalRecordingMaxBytesEnv, Value: strconv.FormatInt(terminalRecordingMaxBytes, 10)},
	}
	mount := corev1.VolumeMount{Name: terminalRecordingVolumeName, MountPath: terminalRecordingMountPath}

	spec.Volumes = upsertRecordingVolume(spec.Volumes)
	spec.Containers = append(spec.Containers, corev1.Container{
		Name:         "terminal-recorder",
		Image:        strings.TrimSpace(image),
		Env:          envs,
		Command:      nil, // Image entrypoint is the deployment-supplied contract.
		VolumeMounts: []corev1.VolumeMount{mount},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: recordingBoolPtr(false),
			ReadOnlyRootFilesystem:   recordingBoolPtr(true),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	})
	return nil
}

func recordingBoolPtr(v bool) *bool { return &v }

func defaultRecordingRetention(value string) string {
	if strings.TrimSpace(value) == "" {
		return "90d"
	}
	return strings.TrimSpace(value)
}

func upsertRecordingVolume(volumes []corev1.Volume) []corev1.Volume {
	for _, volume := range volumes {
		if volume.Name == terminalRecordingVolumeName {
			return volumes
		}
	}
	return append(volumes, corev1.Volume{
		Name: terminalRecordingVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
			SizeLimit: resource.NewQuantity(terminalRecordingMaxBytes, resource.DecimalSI),
		}},
	})
}
