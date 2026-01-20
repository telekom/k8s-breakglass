package breakglass

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIntersects tests the intersects helper function
func TestIntersects(t *testing.T) {
	tests := []struct {
		name     string
		amap     map[string]any
		b        []string
		expected bool
	}{
		{
			name:     "empty map returns false",
			amap:     map[string]any{},
			b:        []string{"a", "b"},
			expected: false,
		},
		{
			name:     "empty slice returns false",
			amap:     map[string]any{"a": nil, "b": nil},
			b:        []string{},
			expected: false,
		},
		{
			name:     "both empty returns false",
			amap:     map[string]any{},
			b:        []string{},
			expected: false,
		},
		{
			name:     "intersection exists at start",
			amap:     map[string]any{"a": nil, "b": nil, "c": nil},
			b:        []string{"a", "x", "y"},
			expected: true,
		},
		{
			name:     "intersection exists at end",
			amap:     map[string]any{"a": nil, "b": nil, "c": nil},
			b:        []string{"x", "y", "c"},
			expected: true,
		},
		{
			name:     "no intersection",
			amap:     map[string]any{"a": nil, "b": nil},
			b:        []string{"c", "d"},
			expected: false,
		},
		{
			name:     "single element intersection",
			amap:     map[string]any{"foo": nil},
			b:        []string{"foo"},
			expected: true,
		},
		{
			name:     "nil map returns false",
			amap:     nil,
			b:        []string{"a"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intersects(tt.amap, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMatchesGlobPattern tests the matchesGlobPattern function
func TestMatchesGlobPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		value    string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "cluster-a",
			value:    "cluster-a",
			expected: true,
		},
		{
			name:     "wildcard matches any suffix",
			pattern:  "cluster-*",
			value:    "cluster-prod",
			expected: true,
		},
		{
			name:     "wildcard matches empty suffix",
			pattern:  "cluster-*",
			value:    "cluster-",
			expected: true,
		},
		{
			name:     "star matches any string",
			pattern:  "*",
			value:    "anything",
			expected: true,
		},
		{
			name:     "star matches empty string",
			pattern:  "*",
			value:    "",
			expected: true,
		},
		{
			name:     "question mark matches single character",
			pattern:  "cluster-?",
			value:    "cluster-1",
			expected: true,
		},
		{
			name:     "question mark does not match multiple characters",
			pattern:  "cluster-?",
			value:    "cluster-12",
			expected: false,
		},
		{
			name:     "character class matches",
			pattern:  "cluster-[abc]",
			value:    "cluster-a",
			expected: true,
		},
		{
			name:     "character class no match",
			pattern:  "cluster-[abc]",
			value:    "cluster-d",
			expected: false,
		},
		{
			name:     "no match",
			pattern:  "cluster-a",
			value:    "cluster-b",
			expected: false,
		},
		{
			name:     "invalid pattern returns false",
			pattern:  "[",
			value:    "anything",
			expected: false,
		},
		{
			name:     "complex pattern",
			pattern:  "prod-*-[12]",
			value:    "prod-cluster-1",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesGlobPattern(tt.pattern, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestClusterMatchesPatterns tests the clusterMatchesPatterns function
func TestClusterMatchesPatterns(t *testing.T) {
	tests := []struct {
		name     string
		cluster  string
		patterns []string
		expected bool
	}{
		{
			name:     "exact match in patterns",
			cluster:  "cluster-prod",
			patterns: []string{"cluster-dev", "cluster-prod", "cluster-staging"},
			expected: true,
		},
		{
			name:     "glob match in patterns",
			cluster:  "cluster-prod",
			patterns: []string{"cluster-*"},
			expected: true,
		},
		{
			name:     "no match in patterns",
			cluster:  "cluster-prod",
			patterns: []string{"cluster-dev", "cluster-staging"},
			expected: false,
		},
		{
			name:     "empty patterns returns false",
			cluster:  "cluster-prod",
			patterns: []string{},
			expected: false,
		},
		{
			name:     "nil patterns returns false",
			cluster:  "cluster-prod",
			patterns: nil,
			expected: false,
		},
		{
			name:     "wildcard pattern matches all",
			cluster:  "anything",
			patterns: []string{"*"},
			expected: true,
		},
		{
			name:     "multiple patterns with one matching",
			cluster:  "eu-west-1",
			patterns: []string{"us-*", "eu-*", "ap-*"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clusterMatchesPatterns(tt.cluster, tt.patterns)
			assert.Equal(t, tt.expected, result)
		})
	}
}
