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

package utils

import (
	"path/filepath"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// NamespaceMatcher provides namespace matching using patterns and label selectors.
// It supports both glob-style pattern matching and Kubernetes-native label selection.
type NamespaceMatcher struct {
	filter *v1alpha1.NamespaceFilter
}

// NewNamespaceMatcher creates a new NamespaceMatcher for the given filter.
// If filter is nil, the matcher will match no namespaces.
func NewNamespaceMatcher(filter *v1alpha1.NamespaceFilter) *NamespaceMatcher {
	return &NamespaceMatcher{filter: filter}
}

// Matches checks if a namespace matches the filter using only the namespace name.
// For label-based matching, use MatchesWithLabels.
// Returns true if:
// - Filter is nil or empty (matches nothing for explicit filters, depends on semantics)
// - Namespace name matches any pattern
// Note: This method cannot evaluate selectorTerms without labels.
func (m *NamespaceMatcher) Matches(namespace string) bool {
	if m.filter == nil || m.filter.IsEmpty() {
		return false
	}

	// Check patterns first
	if m.matchesPatterns(namespace) {
		return true
	}

	// Cannot evaluate selector terms without labels
	return false
}

// MatchesWithLabels checks if a namespace with known labels matches the filter.
// This is the primary matching method when namespace labels are available.
// Returns true if:
// - Namespace name matches any pattern, OR
// - Namespace labels match any selector term
func (m *NamespaceMatcher) MatchesWithLabels(namespace string, labels map[string]string) bool {
	if m.filter == nil || m.filter.IsEmpty() {
		return false
	}

	// Check patterns first
	if m.matchesPatterns(namespace) {
		return true
	}

	// Check selector terms
	return m.matchesSelectorTerms(labels)
}

// MatchesAny returns true if the filter is empty (matching all namespaces by convention).
// This is useful for allow-lists where an empty filter means "allow all".
func (m *NamespaceMatcher) MatchesAny() bool {
	return m.filter == nil || m.filter.IsEmpty()
}

// matchesPatterns checks if namespace matches any pattern.
func (m *NamespaceMatcher) matchesPatterns(namespace string) bool {
	if m.filter == nil {
		return false
	}

	for _, pattern := range m.filter.Patterns {
		if matched, _ := filepath.Match(pattern, namespace); matched {
			return true
		}
	}
	return false
}

// matchesSelectorTerms checks if labels match any selector term.
// Returns true if ANY term matches (OR semantics between terms).
// Within each term, ALL conditions must match (AND semantics).
func (m *NamespaceMatcher) matchesSelectorTerms(labels map[string]string) bool {
	if m.filter == nil || len(m.filter.SelectorTerms) == 0 {
		return false
	}

	if labels == nil {
		labels = map[string]string{}
	}

	// OR between terms: any term matching is sufficient
	for _, term := range m.filter.SelectorTerms {
		if m.termMatches(term, labels) {
			return true
		}
	}

	return false
}

// termMatches checks if a single selector term matches the labels.
// All conditions within the term must match (AND semantics).
func (m *NamespaceMatcher) termMatches(term v1alpha1.NamespaceSelectorTerm, labels map[string]string) bool {
	// Check matchLabels (all must match)
	for key, value := range term.MatchLabels {
		labelValue, exists := labels[key]
		if !exists || labelValue != value {
			return false
		}
	}

	// Check matchExpressions (all must match)
	for _, expr := range term.MatchExpressions {
		if !m.expressionMatches(expr, labels) {
			return false
		}
	}

	return true
}

// expressionMatches checks if a single expression matches the labels.
func (m *NamespaceMatcher) expressionMatches(expr v1alpha1.NamespaceSelectorRequirement, labels map[string]string) bool {
	value, exists := labels[expr.Key]

	switch expr.Operator {
	case v1alpha1.NamespaceSelectorOpIn:
		if !exists {
			return false
		}
		return contains(expr.Values, value)

	case v1alpha1.NamespaceSelectorOpNotIn:
		if !exists {
			return true // Key doesn't exist, so value is not in the set
		}
		return !contains(expr.Values, value)

	case v1alpha1.NamespaceSelectorOpExists:
		return exists

	case v1alpha1.NamespaceSelectorOpDoesNotExist:
		return !exists

	default:
		return false
	}
}

// contains checks if a slice contains a value.
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// NamespaceAllowDenyMatcher combines allow and deny filters for namespace access control.
// A namespace is allowed if:
// 1. Allow filter is empty (allow all by default), OR matches the allow filter
// 2. AND does NOT match the deny filter
type NamespaceAllowDenyMatcher struct {
	allow *NamespaceMatcher
	deny  *NamespaceMatcher
}

// NewNamespaceAllowDenyMatcher creates a matcher with allow and deny filters.
func NewNamespaceAllowDenyMatcher(allow, deny *v1alpha1.NamespaceFilter) *NamespaceAllowDenyMatcher {
	return &NamespaceAllowDenyMatcher{
		allow: NewNamespaceMatcher(allow),
		deny:  NewNamespaceMatcher(deny),
	}
}

// IsAllowed checks if a namespace is allowed based on allow/deny filters.
// Uses only namespace name for matching (no labels).
func (m *NamespaceAllowDenyMatcher) IsAllowed(namespace string) bool {
	// Check deny first (deny takes precedence if matched)
	if m.deny.Matches(namespace) {
		return false
	}

	// If allow filter is empty, allow all (that weren't denied)
	if m.allow.MatchesAny() {
		return true
	}

	// Otherwise, must match allow filter
	return m.allow.Matches(namespace)
}

// IsAllowedWithLabels checks if a namespace with labels is allowed.
func (m *NamespaceAllowDenyMatcher) IsAllowedWithLabels(namespace string, labels map[string]string) bool {
	// Check deny first (deny takes precedence if matched)
	if m.deny.MatchesWithLabels(namespace, labels) {
		return false
	}

	// If allow filter is empty, allow all (that weren't denied)
	if m.allow.MatchesAny() {
		return true
	}

	// Otherwise, must match allow filter
	return m.allow.MatchesWithLabels(namespace, labels)
}
