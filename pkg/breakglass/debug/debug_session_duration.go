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
	"sort"
	"strings"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func effectiveDebugSessionConstraints(
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) *breakglassv1alpha1.DebugSessionConstraints {
	var templateConstraints *breakglassv1alpha1.DebugSessionConstraints
	if template != nil {
		templateConstraints = template.Spec.Constraints
	}
	if binding == nil {
		return templateConstraints.DeepCopy()
	}
	return mergeDebugSessionConstraints(templateConstraints, binding.Spec.Constraints)
}

func mergeDebugSessionConstraints(template, binding *breakglassv1alpha1.DebugSessionConstraints) *breakglassv1alpha1.DebugSessionConstraints {
	if binding == nil {
		return template.DeepCopy()
	}
	merged := &breakglassv1alpha1.DebugSessionConstraints{}
	if template != nil {
		merged = template.DeepCopy()
	}
	if isPositiveDebugSessionDuration(binding.MaxDuration) && (merged.MaxDuration == "" || isShorterDebugSessionDuration(binding.MaxDuration, merged.MaxDuration)) {
		merged.MaxDuration = binding.MaxDuration
	}
	if isPositiveDebugSessionDuration(binding.DefaultDuration) && (merged.DefaultDuration == "" || isShorterDebugSessionDuration(binding.DefaultDuration, merged.DefaultDuration)) {
		merged.DefaultDuration = binding.DefaultDuration
	}
	if binding.AllowRenewal != nil && (merged.AllowRenewal == nil || !*binding.AllowRenewal) {
		allowRenewal := *binding.AllowRenewal
		merged.AllowRenewal = &allowRenewal
	}
	if binding.MaxRenewals != nil {
		effectiveMaxRenewals := int32(3)
		if merged.MaxRenewals != nil {
			effectiveMaxRenewals = *merged.MaxRenewals
		}
		if *binding.MaxRenewals < effectiveMaxRenewals {
			maxRenewals := *binding.MaxRenewals
			merged.MaxRenewals = &maxRenewals
		}
	}
	if binding.RenewalLimit > 0 && (merged.RenewalLimit == 0 || binding.RenewalLimit < merged.RenewalLimit) {
		merged.RenewalLimit = binding.RenewalLimit
	}
	if binding.MaxConcurrentSessions > 0 && (merged.MaxConcurrentSessions == 0 || binding.MaxConcurrentSessions < merged.MaxConcurrentSessions) {
		merged.MaxConcurrentSessions = binding.MaxConcurrentSessions
	}
	return merged
}

func isShorterDebugSessionDuration(candidate, current string) bool {
	candidateDuration, candidateErr := breakglassv1alpha1.ParseDuration(candidate)
	currentDuration, currentErr := breakglassv1alpha1.ParseDuration(current)
	return candidateErr == nil && currentErr == nil && candidateDuration < currentDuration
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
		trimmed := strings.TrimSpace(requested)
		if strings.ContainsAny(trimmed, "-+") {
			return fmt.Errorf("requestedDuration %q must be positive", requested)
		}
		return fmt.Errorf("invalid requestedDuration %q: %w", requested, err)
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
			bindings := append([]breakglassv1alpha1.DebugSessionClusterBinding(nil), allowedResult.AllBindings...)
			sortDebugSessionClusterBindings(bindings)
			return &bindings[0], nil
		}
		return nil, nil
	}

	namespace, name, ok := parseDebugSessionBindingRef(bindingRef)
	if !ok {
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

func sortDebugSessionClusterBindings(bindings []breakglassv1alpha1.DebugSessionClusterBinding) {
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].Namespace != bindings[j].Namespace {
			return bindings[i].Namespace < bindings[j].Namespace
		}
		return bindings[i].Name < bindings[j].Name
	})
}
