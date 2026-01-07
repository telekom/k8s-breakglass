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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestNamespaceMatcher_Matches(t *testing.T) {
	tests := []struct {
		name      string
		filter    *v1alpha1.NamespaceFilter
		namespace string
		want      bool
	}{
		{
			name:      "nil filter matches nothing",
			filter:    nil,
			namespace: "default",
			want:      false,
		},
		{
			name:      "empty filter matches nothing",
			filter:    &v1alpha1.NamespaceFilter{},
			namespace: "default",
			want:      false,
		},
		{
			name: "exact pattern match",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-system"},
			},
			namespace: "kube-system",
			want:      true,
		},
		{
			name: "glob pattern match",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			namespace: "app-frontend",
			want:      true,
		},
		{
			name: "glob pattern no match",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			namespace: "service-backend",
			want:      false,
		},
		{
			name: "multiple patterns - first matches",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*", "app-*"},
			},
			namespace: "kube-system",
			want:      true,
		},
		{
			name: "multiple patterns - second matches",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*", "app-*"},
			},
			namespace: "app-backend",
			want:      true,
		},
		{
			name: "selector terms ignored without labels",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			namespace: "production",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewNamespaceMatcher(tt.filter)
			got := m.Matches(tt.namespace)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceMatcher_MatchesWithLabels(t *testing.T) {
	tests := []struct {
		name      string
		filter    *v1alpha1.NamespaceFilter
		namespace string
		labels    map[string]string
		want      bool
	}{
		{
			name:      "nil filter matches nothing",
			filter:    nil,
			namespace: "default",
			labels:    map[string]string{"env": "prod"},
			want:      false,
		},
		{
			name: "pattern match takes precedence over labels",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*"},
			},
			namespace: "kube-system",
			labels:    nil,
			want:      true,
		},
		{
			name: "matchLabels - exact match",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      true,
		},
		{
			name: "matchLabels - missing label",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"team": "sre"},
			want:      false,
		},
		{
			name: "matchLabels - wrong value",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "staging"},
			want:      false,
		},
		{
			name: "matchLabels - multiple labels all match",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod", "team": "sre"}},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod", "team": "sre", "extra": "value"},
			want:      true,
		},
		{
			name: "matchLabels - multiple labels partial match fails",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod", "team": "sre"}},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      false,
		},
		{
			name: "matchExpressions - In operator",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "env", Operator: v1alpha1.NamespaceSelectorOpIn, Values: []string{"prod", "staging"}},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      true,
		},
		{
			name: "matchExpressions - In operator no match",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "env", Operator: v1alpha1.NamespaceSelectorOpIn, Values: []string{"prod", "staging"}},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "dev"},
			want:      false,
		},
		{
			name: "matchExpressions - NotIn operator",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "env", Operator: v1alpha1.NamespaceSelectorOpNotIn, Values: []string{"prod", "staging"}},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "dev"},
			want:      true,
		},
		{
			name: "matchExpressions - NotIn with missing key",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "env", Operator: v1alpha1.NamespaceSelectorOpNotIn, Values: []string{"prod"}},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{},
			want:      true,
		},
		{
			name: "matchExpressions - Exists operator",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "team", Operator: v1alpha1.NamespaceSelectorOpExists},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"team": "sre"},
			want:      true,
		},
		{
			name: "matchExpressions - Exists operator no match",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "team", Operator: v1alpha1.NamespaceSelectorOpExists},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      false,
		},
		{
			name: "matchExpressions - DoesNotExist operator",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "deprecated", Operator: v1alpha1.NamespaceSelectorOpDoesNotExist},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      true,
		},
		{
			name: "matchExpressions - DoesNotExist operator fails when key exists",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "deprecated", Operator: v1alpha1.NamespaceSelectorOpDoesNotExist},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"deprecated": "true"},
			want:      false,
		},
		{
			name: "multiple selector terms - OR semantics",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"team": "sre"}},
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      true,
		},
		{
			name: "combined matchLabels and matchExpressions - AND semantics within term",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchLabels: map[string]string{"env": "prod"},
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "team", Operator: v1alpha1.NamespaceSelectorOpExists},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod", "team": "sre"},
			want:      true,
		},
		{
			name: "combined matchLabels and matchExpressions - partial match fails",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchLabels: map[string]string{"env": "prod"},
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "team", Operator: v1alpha1.NamespaceSelectorOpExists},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    map[string]string{"env": "prod"},
			want:      false,
		},
		{
			name: "pattern OR selector match",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*"},
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			namespace: "production-ns",
			labels:    map[string]string{"env": "prod"},
			want:      true,
		},
		{
			name: "nil labels treated as empty map",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
							{Key: "team", Operator: v1alpha1.NamespaceSelectorOpDoesNotExist},
						},
					},
				},
			},
			namespace: "any-namespace",
			labels:    nil,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewNamespaceMatcher(tt.filter)
			got := m.MatchesWithLabels(tt.namespace, tt.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceAllowDenyMatcher(t *testing.T) {
	tests := []struct {
		name      string
		allow     *v1alpha1.NamespaceFilter
		deny      *v1alpha1.NamespaceFilter
		namespace string
		labels    map[string]string
		want      bool
	}{
		{
			name:      "nil allow/deny allows all",
			allow:     nil,
			deny:      nil,
			namespace: "any-namespace",
			labels:    nil,
			want:      true,
		},
		{
			name: "allow pattern matches",
			allow: &v1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			deny:      nil,
			namespace: "app-frontend",
			labels:    nil,
			want:      true,
		},
		{
			name: "allow pattern not matched",
			allow: &v1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			deny:      nil,
			namespace: "service-backend",
			labels:    nil,
			want:      false,
		},
		{
			name:  "deny overrides allow",
			allow: nil,
			deny: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*"},
			},
			namespace: "kube-system",
			labels:    nil,
			want:      false,
		},
		{
			name: "allowed but also denied - deny wins",
			allow: &v1alpha1.NamespaceFilter{
				Patterns: []string{"*"},
			},
			deny: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*"},
			},
			namespace: "kube-system",
			labels:    nil,
			want:      false,
		},
		{
			name: "label-based allow with pattern deny",
			allow: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			deny: &v1alpha1.NamespaceFilter{
				Patterns: []string{"kube-*"},
			},
			namespace: "production",
			labels:    map[string]string{"env": "prod"},
			want:      true,
		},
		{
			name:  "label-based deny blocks access",
			allow: nil,
			deny: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"security": "restricted"}},
				},
			},
			namespace: "secret-ns",
			labels:    map[string]string{"security": "restricted"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewNamespaceAllowDenyMatcher(tt.allow, tt.deny)
			got := m.IsAllowedWithLabels(tt.namespace, tt.labels)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceFilter_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		filter *v1alpha1.NamespaceFilter
		want   bool
	}{
		{
			name:   "nil filter",
			filter: nil,
			want:   true,
		},
		{
			name:   "empty filter",
			filter: &v1alpha1.NamespaceFilter{},
			want:   true,
		},
		{
			name: "filter with patterns",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			want: false,
		},
		{
			name: "filter with selector terms",
			filter: &v1alpha1.NamespaceFilter{
				SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.IsEmpty()
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMatchesWithLabels_UnknownOperator tests that unknown operators return false
func TestMatchesWithLabels_UnknownOperator(t *testing.T) {
	// Create a filter with an unknown operator (bypassing enum validation for test)
	filter := &v1alpha1.NamespaceFilter{
		SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
			{
				MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
					{Key: "env", Operator: v1alpha1.NamespaceSelectorOperator("Unknown"), Values: []string{"prod"}},
				},
			},
		},
	}

	m := NewNamespaceMatcher(filter)
	got := m.MatchesWithLabels("any-namespace", map[string]string{"env": "prod"})
	// Unknown operators should return false (fail closed)
	assert.False(t, got)
}

// TestMatchesWithLabels_InOperatorMissingKey tests In operator with missing key
func TestMatchesWithLabels_InOperatorMissingKey(t *testing.T) {
	filter := &v1alpha1.NamespaceFilter{
		SelectorTerms: []v1alpha1.NamespaceSelectorTerm{
			{
				MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{
					{Key: "env", Operator: v1alpha1.NamespaceSelectorOpIn, Values: []string{"prod", "staging"}},
				},
			},
		},
	}

	m := NewNamespaceMatcher(filter)
	got := m.MatchesWithLabels("any-namespace", map[string]string{"team": "sre"})
	// In operator with missing key should return false
	assert.False(t, got)
}

// TestContainsHelper tests the contains helper function directly
func TestContainsHelper(t *testing.T) {
	tests := []struct {
		name   string
		slice  []string
		value  string
		expect bool
	}{
		{
			name:   "empty slice",
			slice:  []string{},
			value:  "test",
			expect: false,
		},
		{
			name:   "nil slice",
			slice:  nil,
			value:  "test",
			expect: false,
		},
		{
			name:   "value found",
			slice:  []string{"a", "b", "c"},
			value:  "b",
			expect: true,
		},
		{
			name:   "value not found",
			slice:  []string{"a", "b", "c"},
			value:  "d",
			expect: false,
		},
		{
			name:   "empty string in slice",
			slice:  []string{"a", "", "c"},
			value:  "",
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contains(tt.slice, tt.value)
			assert.Equal(t, tt.expect, got)
		})
	}
}

// TestNewNamespaceAllowDenyMatcher_NilFilters tests the matcher with nil allow/deny
func TestNewNamespaceAllowDenyMatcher_NilFilters(t *testing.T) {
	m := NewNamespaceAllowDenyMatcher(nil, nil)
	// nil allow (match any) + nil deny = allow all
	assert.True(t, m.IsAllowed("any-namespace"))
	assert.True(t, m.IsAllowedWithLabels("any-namespace", nil))
}

// TestNamespaceMatcher_MatchesAny tests the MatchesAny helper
func TestNamespaceMatcher_MatchesAny(t *testing.T) {
	tests := []struct {
		name   string
		filter *v1alpha1.NamespaceFilter
		want   bool
	}{
		{
			name:   "nil filter matches any",
			filter: nil,
			want:   true,
		},
		{
			name:   "empty filter matches any",
			filter: &v1alpha1.NamespaceFilter{},
			want:   true,
		},
		{
			name: "filter with patterns does not match any",
			filter: &v1alpha1.NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewNamespaceMatcher(tt.filter)
			got := m.MatchesAny()
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestNamespaceMatcher_NilFilter tests behavior with nil filter in matcher
func TestNamespaceMatcher_NilFilter(t *testing.T) {
	m := NewNamespaceMatcher(nil)
	assert.False(t, m.Matches("any-namespace"))
	assert.False(t, m.MatchesWithLabels("any-namespace", map[string]string{"env": "prod"}))
	assert.True(t, m.MatchesAny())
}
