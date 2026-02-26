/*
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

package breakglass

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// IsBindingActive checks if a DebugSessionClusterBinding is currently active.
// A binding is considered active if:
// - It is not disabled
// - It has not expired (expiresAt is nil or in the future)
// - It is effective (effectiveFrom is nil or in the past)
func IsBindingActive(binding *breakglassv1alpha1.DebugSessionClusterBinding) bool {
	if binding.Spec.Disabled {
		return false
	}

	now := metav1.Now()

	// Check if binding has expired
	if binding.Spec.ExpiresAt != nil && binding.Spec.ExpiresAt.Before(&now) {
		return false
	}

	// Check if binding is not yet effective
	if binding.Spec.EffectiveFrom != nil && now.Before(binding.Spec.EffectiveFrom) {
		return false
	}

	return true
}
