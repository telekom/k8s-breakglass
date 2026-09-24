// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

// KubernetesUsername returns the exact target identity, preserving legacy User
// behavior only for sessions created before canonical identity was captured.
func (p DebugSessionParticipant) KubernetesUsername() string {
	if p.KubernetesUser != "" {
		return p.KubernetesUser
	}
	return p.User
}
