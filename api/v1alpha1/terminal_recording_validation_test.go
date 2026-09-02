// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateDebugSessionTemplateRecordingRetention(t *testing.T) {
	template := &DebugSessionTemplate{Spec: DebugSessionTemplateSpec{
		PodTemplateRef: &DebugPodTemplateReference{Name: "debug-pod"},
		Audit:          &DebugSessionAuditConfig{EnableTerminalRecording: true, RecordingRetention: "not-a-duration"},
	}}
	result := ValidateDebugSessionTemplate(template)
	require.False(t, result.IsValid())
	require.Contains(t, result.ErrorMessage(), "recordingRetention")

	template.Spec.Audit.RecordingRetention = "1d12h"
	result = ValidateDebugSessionTemplate(template)
	require.True(t, result.IsValid(), result.ErrorMessage())

	template.Spec.Audit.RecordingRetention = "1w"
	result = ValidateDebugSessionTemplate(template)
	require.True(t, result.IsValid(), result.ErrorMessage())

	template.Spec.Audit.RecordingRetention = "1y"
	result = ValidateDebugSessionTemplate(template)
	require.True(t, result.IsValid(), result.ErrorMessage())
}
