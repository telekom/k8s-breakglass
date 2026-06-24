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

package debug

import (
	"fmt"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func effectiveDebugSessionConstraints(
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) *breakglassv1alpha1.DebugSessionConstraints {
	var constraints *breakglassv1alpha1.DebugSessionConstraints
	if template != nil && template.Spec.Constraints != nil {
		constraints = template.Spec.Constraints.DeepCopy()
	}
	if binding == nil || binding.Spec.Constraints == nil {
		return constraints
	}

	if constraints == nil {
		constraints = &breakglassv1alpha1.DebugSessionConstraints{}
	}
	bindingConstraints := binding.Spec.Constraints
	if isPositiveDebugSessionDuration(bindingConstraints.MaxDuration) {
		constraints.MaxDuration = bindingConstraints.MaxDuration
	}
	if isPositiveDebugSessionDuration(bindingConstraints.DefaultDuration) {
		constraints.DefaultDuration = bindingConstraints.DefaultDuration
	}
	if bindingConstraints.AllowRenewal != nil {
		allowRenewal := *bindingConstraints.AllowRenewal
		constraints.AllowRenewal = &allowRenewal
	}
	if bindingConstraints.MaxRenewals != nil {
		maxRenewals := *bindingConstraints.MaxRenewals
		constraints.MaxRenewals = &maxRenewals
	}
	if bindingConstraints.RenewalLimit != 0 {
		constraints.RenewalLimit = bindingConstraints.RenewalLimit
	}

	return constraints
}

func isPositiveDebugSessionDuration(value string) bool {
	if value == "" {
		return false
	}
	duration, err := breakglassv1alpha1.ParseDuration(value)
	return err == nil && duration > 0
}

func validateRequestedDebugSessionDuration(requested string, constraints *breakglassv1alpha1.DebugSessionConstraints) error {
	if requested == "" {
		return nil
	}

	requestedDuration, err := breakglassv1alpha1.ParseDuration(requested)
	if err != nil {
		return fmt.Errorf("invalid requestedDuration: %w", err)
	}
	if requestedDuration <= 0 {
		return fmt.Errorf("requestedDuration must be positive")
	}

	maxDuration, maxLabel, err := maxDebugSessionDuration(constraints)
	if err != nil {
		return err
	}
	if maxDuration > 0 && requestedDuration > maxDuration {
		return fmt.Errorf("requestedDuration %s exceeds maximum duration %s", requested, maxLabel)
	}

	return nil
}

func maxDebugSessionDuration(constraints *breakglassv1alpha1.DebugSessionConstraints) (time.Duration, string, error) {
	if constraints == nil || constraints.MaxDuration == "" {
		return 0, "", nil
	}

	maxDuration, err := breakglassv1alpha1.ParseDuration(constraints.MaxDuration)
	if err != nil || maxDuration <= 0 {
		return 0, "", nil
	}

	return maxDuration, constraints.MaxDuration, nil
}

func selectEffectiveDebugSessionBinding(
	bindingRef string,
	allowedResult ClusterAllowedResult,
) (*breakglassv1alpha1.DebugSessionClusterBinding, error) {
	if strings.TrimSpace(bindingRef) == "" {
		if allowedResult.MatchingBinding != nil {
			return allowedResult.MatchingBinding, nil
		}
		if len(allowedResult.AllBindings) > 0 {
			return &allowedResult.AllBindings[0], nil
		}
		return nil, nil
	}

	namespace, name, ok := strings.Cut(bindingRef, "/")
	if !ok || strings.TrimSpace(namespace) == "" || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("invalid bindingRef format, expected namespace/name")
	}

	for i := range allowedResult.AllBindings {
		binding := &allowedResult.AllBindings[i]
		if binding.Namespace == namespace && binding.Name == name {
			return binding, nil
		}
	}

	return nil, fmt.Errorf("binding %q does not allow the requested template and cluster", bindingRef)
}
