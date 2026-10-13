// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// MessageOfTheDay is operator guidance shown to requesters and session
// participants: purpose, allowed actions, safety notes and how to end the
// session, plus a link to the runbook that governs the action.
type MessageOfTheDay struct {
	// message is plain text shown verbatim in the UI, with line breaks
	// preserved.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Message string `json:"message"`

	// runbookURL links the runbook section for this action. It is rendered as a
	// link in the UI.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:Pattern=`^https://[^\s]+$`
	RunbookURL string `json:"runbookURL,omitempty"`
}

// EffectiveDebugSessionMOTD returns the binding MOTD when set, otherwise the
// template MOTD. A binding replaces the whole message so that persona-specific
// runbooks are not mixed with the shared template guidance.
func EffectiveDebugSessionMOTD(template *DebugSessionTemplateSpec, binding *DebugSessionClusterBindingSpec) *MessageOfTheDay {
	if binding != nil && binding.MOTD != nil {
		return binding.MOTD
	}
	if template != nil {
		return template.MOTD
	}
	return nil
}
