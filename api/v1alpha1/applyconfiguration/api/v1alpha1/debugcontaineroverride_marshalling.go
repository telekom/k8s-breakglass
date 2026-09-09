/*
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
)

// MarshalJSON keeps explicit empty command and args slices in SSA patches.
func (b *DebugContainerOverrideApplyConfiguration) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}

	type payload struct {
		Name            *string                      `json:"name,omitempty"`
		Command         *[]string                    `json:"command,omitempty"`
		Args            *[]string                    `json:"args,omitempty"`
		SecurityContext *corev1.SecurityContext      `json:"securityContext,omitempty"`
		Resources       *corev1.ResourceRequirements `json:"resources,omitempty"`
		Env             []corev1.EnvVar              `json:"env,omitempty"`
	}
	value := payload{
		Name:            b.Name,
		SecurityContext: b.SecurityContext,
		Resources:       b.Resources,
		Env:             b.Env,
	}
	if b.Command != nil {
		command := make([]string, len(b.Command))
		copy(command, b.Command)
		value.Command = &command
	}
	if b.Args != nil {
		args := make([]string, len(b.Args))
		copy(args, b.Args)
		value.Args = &args
	}
	return json.Marshal(value)
}
