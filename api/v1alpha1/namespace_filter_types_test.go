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

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespaceFilter_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		filter *NamespaceFilter
		want   bool
	}{
		{
			name:   "nil filter is empty",
			filter: nil,
			want:   true,
		},
		{
			name:   "empty filter struct is empty",
			filter: &NamespaceFilter{},
			want:   true,
		},
		{
			name: "filter with patterns is not empty",
			filter: &NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			want: false,
		},
		{
			name: "filter with selector terms is not empty",
			filter: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			want: false,
		},
		{
			name: "filter with both patterns and selector terms is not empty",
			filter: &NamespaceFilter{
				Patterns: []string{"kube-*"},
				SelectorTerms: []NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			want: false,
		},
		{
			name: "filter with empty slices is empty",
			filter: &NamespaceFilter{
				Patterns:      []string{},
				SelectorTerms: []NamespaceSelectorTerm{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.IsEmpty()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceFilter_HasPatterns(t *testing.T) {
	tests := []struct {
		name   string
		filter *NamespaceFilter
		want   bool
	}{
		{
			name:   "nil filter has no patterns",
			filter: nil,
			want:   false,
		},
		{
			name:   "empty filter has no patterns",
			filter: &NamespaceFilter{},
			want:   false,
		},
		{
			name: "filter with patterns returns true",
			filter: &NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			want: true,
		},
		{
			name: "filter with empty patterns slice returns false",
			filter: &NamespaceFilter{
				Patterns: []string{},
			},
			want: false,
		},
		{
			name: "filter with only selector terms returns false",
			filter: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			want: false,
		},
		{
			name: "filter with multiple patterns returns true",
			filter: &NamespaceFilter{
				Patterns: []string{"app-*", "kube-*", "system-*"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.HasPatterns()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceFilter_HasSelectorTerms(t *testing.T) {
	tests := []struct {
		name   string
		filter *NamespaceFilter
		want   bool
	}{
		{
			name:   "nil filter has no selector terms",
			filter: nil,
			want:   false,
		},
		{
			name:   "empty filter has no selector terms",
			filter: &NamespaceFilter{},
			want:   false,
		},
		{
			name: "filter with selector terms returns true",
			filter: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			want: true,
		},
		{
			name: "filter with empty selector terms slice returns false",
			filter: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{},
			},
			want: false,
		},
		{
			name: "filter with only patterns returns false",
			filter: &NamespaceFilter{
				Patterns: []string{"app-*"},
			},
			want: false,
		},
		{
			name: "filter with match expressions returns true",
			filter: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{
					{
						MatchExpressions: []NamespaceSelectorRequirement{
							{Key: "env", Operator: NamespaceSelectorOpIn, Values: []string{"prod", "staging"}},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "filter with empty term still returns true",
			filter: &NamespaceFilter{
				SelectorTerms: []NamespaceSelectorTerm{
					{}, // Empty term
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.filter.HasSelectorTerms()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamespaceSelectorOperator_Constants(t *testing.T) {
	// Test that the operator constants are defined correctly
	assert.Equal(t, NamespaceSelectorOperator("In"), NamespaceSelectorOpIn)
	assert.Equal(t, NamespaceSelectorOperator("NotIn"), NamespaceSelectorOpNotIn)
	assert.Equal(t, NamespaceSelectorOperator("Exists"), NamespaceSelectorOpExists)
	assert.Equal(t, NamespaceSelectorOperator("DoesNotExist"), NamespaceSelectorOpDoesNotExist)
}

func TestNamespaceSelectorRequirement_Fields(t *testing.T) {
	req := NamespaceSelectorRequirement{
		Key:      "environment",
		Operator: NamespaceSelectorOpIn,
		Values:   []string{"prod", "staging"},
	}

	assert.Equal(t, "environment", req.Key)
	assert.Equal(t, NamespaceSelectorOpIn, req.Operator)
	assert.Equal(t, []string{"prod", "staging"}, req.Values)
}

func TestNamespaceSelectorTerm_Fields(t *testing.T) {
	term := NamespaceSelectorTerm{
		MatchLabels: map[string]string{
			"env":  "prod",
			"team": "sre",
		},
		MatchExpressions: []NamespaceSelectorRequirement{
			{Key: "tier", Operator: NamespaceSelectorOpExists},
		},
	}

	assert.Equal(t, "prod", term.MatchLabels["env"])
	assert.Equal(t, "sre", term.MatchLabels["team"])
	assert.Len(t, term.MatchExpressions, 1)
	assert.Equal(t, "tier", term.MatchExpressions[0].Key)
}
