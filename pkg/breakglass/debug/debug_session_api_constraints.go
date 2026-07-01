package debug

import (
	"fmt"
	"sort"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

type schedulingOptionRequester struct {
	Username string
	Email    string
	Groups   []string
}

type schedulingOptionAccessError struct {
	optionName string
}

func (e *schedulingOptionAccessError) Error() string {
	return fmt.Sprintf("user is not allowed to select scheduling option '%s'", e.optionName)
}

func (c *DebugSessionAPIController) resolveTargetNamespace(template *breakglassv1alpha1.DebugSessionTemplate, requestedNamespace string, binding *breakglassv1alpha1.DebugSessionClusterBinding) (string, error) {
	// Start with template's namespace constraints
	nc := template.Spec.NamespaceConstraints

	// If binding has namespace constraints, merge them without widening the template.
	if binding != nil && binding.Spec.NamespaceConstraints != nil {
		nc = c.mergeNamespaceConstraints(template.Spec.NamespaceConstraints, binding.Spec.NamespaceConstraints)
		c.log.Debugw("Merged namespace constraints from binding",
			"template", template.Name,
			"binding", binding.Name,
			"bindingNamespace", binding.Namespace,
			"mergedAllowUserNamespace", nc != nil && nc.AllowUserNamespace,
			"mergedDefaultNamespace", func() string {
				if nc != nil {
					return nc.DefaultNamespace
				}
				return ""
			}(),
		)
	}

	c.log.Debugw("Resolving target namespace",
		"template", template.Name,
		"requestedNamespace", requestedNamespace,
		"hasNamespaceConstraints", nc != nil,
	)

	// If no namespace constraints, use default behavior
	if nc == nil {
		if requestedNamespace != "" {
			c.log.Debugw("No namespace constraints, using requested namespace",
				"template", template.Name,
				"resolvedNamespace", requestedNamespace,
			)
			return requestedNamespace, nil
		}
		c.log.Debugw("No namespace constraints, using default",
			"template", template.Name,
			"resolvedNamespace", "breakglass-debug",
		)
		return "breakglass-debug", nil // Default namespace
	}

	c.log.Debugw("Namespace constraints found",
		"template", template.Name,
		"allowUserNamespace", nc.AllowUserNamespace,
		"defaultNamespace", nc.DefaultNamespace,
		"hasAllowedNamespaces", nc.AllowedNamespaces != nil && !nc.AllowedNamespaces.IsEmpty(),
		"hasDeniedNamespaces", nc.DeniedNamespaces != nil && !nc.DeniedNamespaces.IsEmpty(),
	)

	// If user didn't request a specific namespace, use the default
	if requestedNamespace == "" {
		if nc.DefaultNamespace != "" {
			if err := validateEffectiveNamespaceConstraintFilters(nc.DefaultNamespace, template, binding); err != nil {
				c.log.Debugw("Default namespace rejected by namespace constraints",
					"template", template.Name,
					"defaultNamespace", nc.DefaultNamespace,
					"bindingUsed", binding != nil,
					"error", err,
				)
				return "", err
			}
			c.log.Debugw("No namespace requested, using effective default namespace",
				"template", template.Name,
				"resolvedNamespace", nc.DefaultNamespace,
				"bindingUsed", binding != nil,
			)
			return nc.DefaultNamespace, nil
		}
		if err := validateEffectiveNamespaceConstraintFilters("breakglass-debug", template, binding); err != nil {
			c.log.Debugw("Fallback namespace rejected by namespace constraints",
				"template", template.Name,
				"fallbackNamespace", "breakglass-debug",
				"bindingUsed", binding != nil,
				"error", err,
			)
			return "", err
		}
		c.log.Debugw("No namespace requested and no template default, using fallback",
			"template", template.Name,
			"resolvedNamespace", "breakglass-debug",
		)
		return "breakglass-debug", nil
	}

	// If the requested namespace matches the default, allow it even when user namespace selection is disabled.
	// This handles the case where the frontend sends the default namespace value in the request.
	if nc.DefaultNamespace != "" && requestedNamespace == nc.DefaultNamespace {
		if err := validateEffectiveNamespaceConstraintFilters(nc.DefaultNamespace, template, binding); err != nil {
			c.log.Debugw("Requested default namespace rejected by namespace constraints",
				"template", template.Name,
				"defaultNamespace", nc.DefaultNamespace,
				"bindingUsed", binding != nil,
				"error", err,
			)
			return "", err
		}
		c.log.Debugw("Requested namespace matches default, allowing",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"defaultNamespace", nc.DefaultNamespace,
		)
		return nc.DefaultNamespace, nil
	}

	// Check if user is allowed to specify a namespace
	if !nc.AllowUserNamespace {
		c.log.Debugw("User-specified namespace not allowed by template",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"allowUserNamespace", nc.AllowUserNamespace,
		)
		return "", fmt.Errorf("template does not allow user-specified namespaces")
	}

	if err := validateEffectiveNamespaceConstraintFilters(requestedNamespace, template, binding); err != nil {
		c.log.Debugw("Namespace rejected by effective namespace constraints",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"error", err,
		)
		return "", err
	}

	return requestedNamespace, nil
}

// mergeNamespaceConstraints merges template and binding namespace constraints.
// Binding constraints can only narrow what the template allows.
// Returns a new NamespaceConstraints with merged values.
func (c *DebugSessionAPIController) mergeNamespaceConstraints(
	templateNC, bindingNC *breakglassv1alpha1.NamespaceConstraints,
) *breakglassv1alpha1.NamespaceConstraints {
	// If both are nil, return nil
	if templateNC == nil && bindingNC == nil {
		return nil
	}

	// If only one exists, use it
	if templateNC == nil {
		return bindingNC.DeepCopy()
	}
	if bindingNC == nil {
		return templateNC.DeepCopy()
	}

	// Merge both - binding narrows template permissions.
	merged := templateNC.DeepCopy()

	// AllowUserNamespace: binding cannot enable user-selected namespaces when
	// the template disabled them. A false binding value is ambiguous because it
	// is also the zero value, so it is not treated as an override here.
	merged.AllowUserNamespace = templateNC.AllowUserNamespace

	// DefaultNamespace: binding can change the default only to a namespace that
	// remains allowed by both template and binding filters.
	if bindingNC.DefaultNamespace != "" &&
		namespaceAllowedByConstraintFilters(bindingNC.DefaultNamespace, templateNC) &&
		namespaceAllowedByConstraintFilters(bindingNC.DefaultNamespace, bindingNC) {
		merged.DefaultNamespace = bindingNC.DefaultNamespace
	}

	// AllowedNamespaces: binding filters are the option-specific boundary shown
	// to clients. Runtime validation still evaluates both template and binding
	// filters separately, so bindings cannot widen the template boundary.
	if merged.AllowedNamespaces == nil || merged.AllowedNamespaces.IsEmpty() {
		merged.AllowedNamespaces = nil
	}
	if bindingNC.AllowedNamespaces != nil && !bindingNC.AllowedNamespaces.IsEmpty() {
		merged.AllowedNamespaces = bindingNC.AllowedNamespaces.DeepCopy()
	}

	// DeniedNamespaces: binding can add denies, never remove template denies.
	if bindingNC.DeniedNamespaces != nil && !bindingNC.DeniedNamespaces.IsEmpty() {
		merged.DeniedNamespaces = mergeNamespaceFilters(merged.DeniedNamespaces, bindingNC.DeniedNamespaces)
	}

	return merged
}

func mergeAllowedNamespaceFiltersForResponse(
	templateFilter, bindingFilter *breakglassv1alpha1.NamespaceFilter,
) *breakglassv1alpha1.NamespaceFilter {
	if templateFilter == nil || templateFilter.IsEmpty() {
		if bindingFilter == nil || bindingFilter.IsEmpty() {
			return nil
		}
		return bindingFilter.DeepCopy()
	}
	if bindingFilter == nil || bindingFilter.IsEmpty() {
		return templateFilter.DeepCopy()
	}

	merged := &breakglassv1alpha1.NamespaceFilter{}
	for _, pattern := range bindingFilter.Patterns {
		if namespacePatternSubsetOfAny(pattern, templateFilter.Patterns) {
			merged.Patterns = append(merged.Patterns, pattern)
		}
	}
	if merged.IsEmpty() {
		return nil
	}
	return merged
}

func namespacePatternSubsetOfAny(pattern string, allowedPatterns []string) bool {
	for _, allowed := range allowedPatterns {
		if namespacePatternSubsetOf(pattern, allowed) {
			return true
		}
	}
	return false
}

func namespacePatternSubsetOf(pattern, allowedPattern string) bool {
	if allowedPattern == "*" || pattern == allowedPattern {
		return true
	}
	if !namespacePatternHasGlob(pattern) {
		return matchPattern(allowedPattern, pattern)
	}
	allowedPrefix, allowedOK := namespaceTrailingStarPrefix(allowedPattern)
	patternPrefix, patternOK := namespaceTrailingStarPrefix(pattern)
	return allowedOK && patternOK && strings.HasPrefix(patternPrefix, allowedPrefix)
}

func namespacePatternHasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

func namespaceTrailingStarPrefix(pattern string) (string, bool) {
	if strings.Count(pattern, "*") != 1 || !strings.HasSuffix(pattern, "*") {
		return "", false
	}
	prefix := strings.TrimSuffix(pattern, "*")
	if strings.ContainsAny(prefix, "?[") {
		return "", false
	}
	return prefix, true
}

func namespaceAllowedByConstraintFilters(namespace string, constraints *breakglassv1alpha1.NamespaceConstraints) bool {
	return validateNamespaceConstraintFilters(namespace, constraints) == nil
}

func validateEffectiveNamespaceConstraintFilters(
	namespace string,
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) error {
	if template != nil {
		if err := validateNamespaceConstraintFilters(namespace, template.Spec.NamespaceConstraints); err != nil {
			return err
		}
	}
	if binding != nil {
		if err := validateNamespaceConstraintFilters(namespace, binding.Spec.NamespaceConstraints); err != nil {
			return err
		}
	}
	return nil
}

func validateNamespaceConstraintFilters(namespace string, constraints *breakglassv1alpha1.NamespaceConstraints) error {
	if constraints == nil {
		return nil
	}
	if constraints.AllowedNamespaces != nil && !constraints.AllowedNamespaces.IsEmpty() &&
		!matchNamespaceFilter(namespace, constraints.AllowedNamespaces) {
		return fmt.Errorf("namespace '%s' is not in the allowed namespaces", namespace)
	}
	if constraints.DeniedNamespaces != nil && !constraints.DeniedNamespaces.IsEmpty() &&
		matchNamespaceFilter(namespace, constraints.DeniedNamespaces) {
		return fmt.Errorf("namespace '%s' is explicitly denied", namespace)
	}
	return nil
}

func mergeNamespaceFilters(
	base, extra *breakglassv1alpha1.NamespaceFilter,
) *breakglassv1alpha1.NamespaceFilter {
	if base == nil || base.IsEmpty() {
		if extra == nil {
			return nil
		}
		return extra.DeepCopy()
	}
	if extra == nil || extra.IsEmpty() {
		return base.DeepCopy()
	}

	merged := base.DeepCopy()
	patternSet := make(map[string]bool, len(merged.Patterns))
	for _, pattern := range merged.Patterns {
		patternSet[pattern] = true
	}
	for _, pattern := range extra.Patterns {
		if !patternSet[pattern] {
			merged.Patterns = append(merged.Patterns, pattern)
		}
	}
	merged.SelectorTerms = append(merged.SelectorTerms, extra.SelectorTerms...)
	return merged
}

// matchNamespaceFilter checks if a namespace name matches a NamespaceFilter.
// Selector terms require namespace labels and are ignored by this name-only
// validation path.
func matchNamespaceFilter(namespace string, filter *breakglassv1alpha1.NamespaceFilter) bool {
	if filter == nil || filter.IsEmpty() {
		return false
	}

	for _, pattern := range filter.Patterns {
		if matchPattern(pattern, namespace) {
			return true
		}
	}

	return false
}

// resolveSchedulingConstraints validates and resolves the scheduling constraints.
// It merges the template's and binding's base constraints with the selected scheduling option.
// When a binding is provided, its base constraints are treated as mandatory additions
// on top of the template, and its scheduling options take precedence over the template's.
// Returns the merged constraints, the selected option name, and any error.
func (c *DebugSessionAPIController) resolveSchedulingConstraints(
	template *breakglassv1alpha1.DebugSessionTemplate,
	selectedOption string,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	requester schedulingOptionRequester,
) (*breakglassv1alpha1.SchedulingConstraints, string, error) {
	// Start with the template's base scheduling constraints and merge in binding-level
	// base constraints (which are documented as mandatory additions on top of the template).
	baseConstraints := template.Spec.SchedulingConstraints
	if binding != nil && binding.Spec.SchedulingConstraints != nil {
		baseConstraints = mergeSchedulingConstraints(baseConstraints, binding.Spec.SchedulingConstraints)
	}

	// Resolve effective scheduling options: binding takes precedence over template
	var effectiveOpts *breakglassv1alpha1.SchedulingOptions
	if binding != nil && binding.Spec.SchedulingOptions != nil {
		effectiveOpts = binding.Spec.SchedulingOptions
	} else if template.Spec.SchedulingOptions != nil {
		effectiveOpts = template.Spec.SchedulingOptions
	}

	// If no scheduling options defined (in template or binding), just return base constraints
	// Ignore any user-selected option since neither the template nor binding supports them.
	// This handles cases where the frontend sends a stale scheduling option
	// after switching to a template that doesn't have scheduling options.
	if effectiveOpts == nil || len(effectiveOpts.Options) == 0 {
		if selectedOption != "" {
			c.log.Debugw("Ignoring scheduling option - no options defined in template or binding",
				"template", template.Name,
				"selectedOption", selectedOption,
			)
		}
		return baseConstraints, "", nil
	}

	opts := effectiveOpts

	// If required and no option selected, find the default
	if selectedOption == "" {
		if opts.Required {
			// Find the default option
			for _, opt := range opts.Options {
				if opt.Default {
					selectedOption = opt.Name
					break
				}
			}
			if selectedOption == "" {
				return nil, "", fmt.Errorf("scheduling option is required but none selected and no default defined")
			}
		} else {
			// Not required, no selection - use base constraints only
			return baseConstraints, "", nil
		}
	}

	// Find the selected option
	var selectedOpt *breakglassv1alpha1.SchedulingOption
	for i := range opts.Options {
		if opts.Options[i].Name == selectedOption {
			selectedOpt = &opts.Options[i]
			break
		}
	}

	if selectedOpt == nil {
		return nil, "", fmt.Errorf("scheduling option '%s' not found in template or binding", selectedOption)
	}

	if !isSchedulingOptionAllowedForRequester(selectedOpt, requester) {
		return nil, "", &schedulingOptionAccessError{optionName: selectedOption}
	}

	// Merge base constraints with option's constraints
	merged := mergeSchedulingConstraints(baseConstraints, selectedOpt.SchedulingConstraints)

	return merged, selectedOption, nil
}

func isSchedulingOptionAllowedForRequester(opt *breakglassv1alpha1.SchedulingOption, requester schedulingOptionRequester) bool {
	if opt == nil || (len(opt.AllowedUsers) == 0 && len(opt.AllowedGroups) == 0) {
		return true
	}

	for _, allowedUser := range opt.AllowedUsers {
		if matchPattern(allowedUser, requester.Username) {
			return true
		}
		if requester.Email != "" && matchPattern(allowedUser, requester.Email) {
			return true
		}
	}

	for _, allowedGroup := range opt.AllowedGroups {
		for _, userGroup := range requester.Groups {
			if matchPattern(allowedGroup, userGroup) {
				return true
			}
		}
	}

	return false
}

// mergeSchedulingConstraints merges base constraints with option constraints.
// Option constraints override base constraints for conflicting keys.
func mergeSchedulingConstraints(base, option *breakglassv1alpha1.SchedulingConstraints) *breakglassv1alpha1.SchedulingConstraints {
	if base == nil && option == nil {
		return nil
	}
	if base == nil {
		return option.DeepCopy()
	}
	if option == nil {
		return base.DeepCopy()
	}

	merged := base.DeepCopy()

	// Merge nodeSelector (option overrides base on conflict)
	if len(option.NodeSelector) > 0 {
		if merged.NodeSelector == nil {
			merged.NodeSelector = make(map[string]string)
		}
		for k, v := range option.NodeSelector {
			merged.NodeSelector[k] = v
		}
	}

	// Merge deniedNodes (additive)
	if len(option.DeniedNodes) > 0 {
		merged.DeniedNodes = append(merged.DeniedNodes, option.DeniedNodes...)
	}

	// Merge deniedNodeLabels (option overrides base on conflict)
	if len(option.DeniedNodeLabels) > 0 {
		if merged.DeniedNodeLabels == nil {
			merged.DeniedNodeLabels = make(map[string]string)
		}
		for k, v := range option.DeniedNodeLabels {
			merged.DeniedNodeLabels[k] = v
		}
	}

	// Merge tolerations (additive)
	if len(option.Tolerations) > 0 {
		merged.Tolerations = append(merged.Tolerations, option.Tolerations...)
	}

	// For node affinity, option's required affinity is ANDed with base
	if option.RequiredNodeAffinity != nil {
		if merged.RequiredNodeAffinity == nil {
			merged.RequiredNodeAffinity = option.RequiredNodeAffinity.DeepCopy()
		} else {
			// AND the node selector terms
			merged.RequiredNodeAffinity.NodeSelectorTerms = append(
				merged.RequiredNodeAffinity.NodeSelectorTerms,
				option.RequiredNodeAffinity.NodeSelectorTerms...,
			)
		}
	}

	// Preferred affinities are additive
	if len(option.PreferredNodeAffinity) > 0 {
		merged.PreferredNodeAffinity = append(merged.PreferredNodeAffinity, option.PreferredNodeAffinity...)
	}

	// Pod anti-affinity is additive
	if len(option.RequiredPodAntiAffinity) > 0 {
		merged.RequiredPodAntiAffinity = append(merged.RequiredPodAntiAffinity, option.RequiredPodAntiAffinity...)
	}
	if len(option.PreferredPodAntiAffinity) > 0 {
		merged.PreferredPodAntiAffinity = append(merged.PreferredPodAntiAffinity, option.PreferredPodAntiAffinity...)
	}

	return merged
}

// resolveClusterPatterns expands cluster patterns (e.g., "*", "prod-*") to actual cluster names.
// Returns empty slice if no clusters are available for resolution.
func resolveClusterPatterns(patterns []string, allClusters []string) []string {
	if len(patterns) == 0 {
		return nil
	}
	if len(allClusters) == 0 {
		// No clusters to resolve against - return empty instead of patterns
		// This ensures the frontend shows "no clusters available" instead of pattern strings
		return nil
	}

	// Use a map to deduplicate
	resolved := make(map[string]struct{})
	for _, pattern := range patterns {
		for _, cluster := range allClusters {
			if matchPattern(pattern, cluster) {
				resolved[cluster] = struct{}{}
			}
		}
	}

	// Convert map to sorted slice for consistent output
	result := make([]string, 0, len(resolved))
	for cluster := range resolved {
		result = append(result, cluster)
	}
	// Sort for consistent ordering
	sort.Strings(result)
	return result
}

// sendDebugSessionRequestEmail sends email notification to approvers when a debug session is created
