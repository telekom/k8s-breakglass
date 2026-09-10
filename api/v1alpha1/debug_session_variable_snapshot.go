// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"encoding/json"
	"reflect"
)

// CanInitializeLegacyVariablePolicy permits only an exact copy of the already
// persisted template policy when no binding variable intersection was applied.
func CanInitializeLegacyVariablePolicy(old DebugSessionStatus, policy []ExtraDeployVariable) bool {
	if old.ResolvedTemplate == nil || old.ResolvedTemplateVariablePolicy != nil || !old.ResolvedBindingSnapshotCaptured ||
		(old.State != DebugSessionStatePending && old.State != DebugSessionStatePendingApproval) {
		return false
	}
	if !HasCompleteResolvedBindingSnapshot(old) {
		return false
	}
	if old.ResolvedBindingSpec != nil {
		var binding DebugSessionClusterBindingSpec
		if json.Unmarshal(old.ResolvedBindingSpec.Raw, &binding) != nil || len(binding.ExtraDeployVariables) != 0 {
			return false
		}
	}
	return reflect.DeepEqual(old.ResolvedTemplate.ExtraDeployVariables, policy)
}

// HasCompleteResolvedBindingSnapshot distinguishes an explicit no-binding result
// from missing or malformed persisted approval provenance.
func HasCompleteResolvedBindingSnapshot(status DebugSessionStatus) bool {
	if !status.ResolvedBindingSnapshotCaptured || (status.ResolvedBinding == nil) != (status.ResolvedBindingSpec == nil) {
		return false
	}
	if status.ResolvedBindingSpec == nil {
		return true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(status.ResolvedBindingSpec.Raw, &object) != nil || object == nil {
		return false
	}
	var binding DebugSessionClusterBindingSpec
	return json.Unmarshal(status.ResolvedBindingSpec.Raw, &binding) == nil && len(ValidateDebugSessionClusterBinding(&DebugSessionClusterBinding{Spec: binding}).Errors) == 0
}
