// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateDebugSessionTemplateRecordingRetention(t *testing.T) {
	for _, value := range []string{"not-a-duration", "0s", "-1h"} {
		template := &DebugSessionTemplate{Spec: DebugSessionTemplateSpec{
			PodTemplateRef: &DebugPodTemplateReference{Name: "debug-pod"},
			Audit:          &DebugSessionAuditConfig{EnableTerminalRecording: true, RecordingRetention: value},
		}}
		result := ValidateDebugSessionTemplate(template)
		require.False(t, result.IsValid(), value)
		require.Contains(t, result.ErrorMessage(), "recordingRetention", value)
	}

	template := &DebugSessionTemplate{Spec: DebugSessionTemplateSpec{
		PodTemplateRef: &DebugPodTemplateReference{Name: "debug-pod"},
		Audit:          &DebugSessionAuditConfig{EnableTerminalRecording: true, RecordingRetention: "1d12h"},
	}}
	result := ValidateDebugSessionTemplate(template)
	require.True(t, result.IsValid(), result.ErrorMessage())
}
