// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateDebugSessionTemplateRecordingRetention(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, value := range []string{"not-a-duration", "0s", "-1h", "1d12h", ""} {
			template := &DebugSessionTemplate{Spec: DebugSessionTemplateSpec{
				PodTemplateRef: &DebugPodTemplateReference{Name: "debug-pod"},
				Audit:          &DebugSessionAuditConfig{EnableTerminalRecording: enabled, RecordingRetention: value},
			}}
			result := ValidateDebugSessionTemplate(template)
			if value == "1d12h" || value == "" {
				require.True(t, result.IsValid(), result.ErrorMessage())
				continue
			}
			require.Len(t, result.Errors, 1, "enabled=%t retention=%s: %s", enabled, value, result.ErrorMessage())
			require.Equal(t, "spec.audit.recordingRetention", result.Errors[0].Field)
			require.Equal(t, value, result.Errors[0].BadValue)
		}
	}
}
