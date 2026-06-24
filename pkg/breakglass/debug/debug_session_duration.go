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
	if bindingConstraints.MaxDuration != "" {
		constraints.MaxDuration = bindingConstraints.MaxDuration
	}
	if bindingConstraints.DefaultDuration != "" {
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
	if err != nil {
		return 0, "", fmt.Errorf("configured maxDuration %q is invalid: %w", constraints.MaxDuration, err)
	}
	if maxDuration <= 0 {
		return 0, "", fmt.Errorf("configured maxDuration must be positive")
	}

	return maxDuration, constraints.MaxDuration, nil
}

func selectEffectiveDebugSessionBinding(
	bindingRef string,
	allowedResult ClusterAllowedResult,
) (*breakglassv1alpha1.DebugSessionClusterBinding, error) {
	if strings.TrimSpace(bindingRef) == "" {
		return allowedResult.MatchingBinding, nil
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
