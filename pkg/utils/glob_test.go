package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		value       string
		wantMatch   bool
		wantErr     bool
		errContains string
	}{
		// Universal wildcard
		{name: "star matches anything", pattern: "*", value: "anything", wantMatch: true},
		{name: "star matches empty", pattern: "*", value: "", wantMatch: true},
		{name: "star matches special chars", pattern: "*", value: "test@example.com", wantMatch: true},

		// Exact match (no wildcards)
		{name: "exact match", pattern: "admin", value: "admin", wantMatch: true},
		{name: "exact mismatch", pattern: "admin", value: "user", wantMatch: false},
		{name: "exact case sensitive", pattern: "Admin", value: "admin", wantMatch: false},

		// Prefix patterns
		{name: "prefix with star", pattern: "platform-*", value: "platform-sre", wantMatch: true},
		{name: "prefix mismatch", pattern: "platform-*", value: "tenant-sre", wantMatch: false},

		// Suffix patterns
		{name: "suffix with star", pattern: "*-admin", value: "super-admin", wantMatch: true},
		{name: "suffix mismatch", pattern: "*-admin", value: "admin-super", wantMatch: false},

		// Middle patterns
		{name: "middle wildcard", pattern: "*.tst.*", value: "cluster.tst.eu", wantMatch: true},
		{name: "middle wildcard mismatch", pattern: "*.tst.*", value: "cluster.prd.eu", wantMatch: false},

		// Question mark wildcard
		{name: "question mark matches single char", pattern: "team-?", value: "team-a", wantMatch: true},
		{name: "question mark requires char", pattern: "team-?", value: "team-", wantMatch: false},
		{name: "question mark not multiple chars", pattern: "team-?", value: "team-ab", wantMatch: false},

		// Character classes
		{name: "char class matches", pattern: "team-[abc]", value: "team-a", wantMatch: true},
		{name: "char class mismatch", pattern: "team-[abc]", value: "team-d", wantMatch: false},

		// Invalid patterns
		{name: "invalid pattern bracket", pattern: "[invalid", value: "test", wantMatch: false, wantErr: true},

		// Edge cases
		{name: "empty pattern exact", pattern: "", value: "", wantMatch: true},
		{name: "empty pattern vs value", pattern: "", value: "test", wantMatch: false},
		{name: "special chars in value", pattern: "user@example.com", value: "user@example.com", wantMatch: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := GlobMatch(tc.pattern, tc.value)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantMatch, matched)
		})
	}
}

func TestGlobMatchAny(t *testing.T) {
	t.Run("matches first pattern", func(t *testing.T) {
		patterns := []string{"admin", "user", "guest"}
		assert.True(t, GlobMatchAny(patterns, "admin"))
	})

	t.Run("matches last pattern", func(t *testing.T) {
		patterns := []string{"admin", "user", "guest"}
		assert.True(t, GlobMatchAny(patterns, "guest"))
	})

	t.Run("matches wildcard pattern", func(t *testing.T) {
		patterns := []string{"platform-*", "tenant-*"}
		assert.True(t, GlobMatchAny(patterns, "platform-sre"))
	})

	t.Run("no match", func(t *testing.T) {
		patterns := []string{"admin", "user"}
		assert.False(t, GlobMatchAny(patterns, "guest"))
	})

	t.Run("empty patterns", func(t *testing.T) {
		patterns := []string{}
		assert.False(t, GlobMatchAny(patterns, "anything"))
	})

	t.Run("skips invalid patterns", func(t *testing.T) {
		patterns := []string{"[invalid", "valid"}
		assert.True(t, GlobMatchAny(patterns, "valid"))
	})
}

func TestGlobMatchGroups(t *testing.T) {
	t.Run("exact group match", func(t *testing.T) {
		allowed := []string{"admin", "superuser"}
		userGroups := []string{"guest", "admin"}
		assert.True(t, GlobMatchGroups(allowed, userGroups))
	})

	t.Run("wildcard group match", func(t *testing.T) {
		allowed := []string{"platform-*"}
		userGroups := []string{"tenant-team", "platform-sre"}
		assert.True(t, GlobMatchGroups(allowed, userGroups))
	})

	t.Run("no match", func(t *testing.T) {
		allowed := []string{"admin", "superuser"}
		userGroups := []string{"guest", "readonly"}
		assert.False(t, GlobMatchGroups(allowed, userGroups))
	})

	t.Run("empty allowed groups", func(t *testing.T) {
		allowed := []string{}
		userGroups := []string{"admin"}
		assert.False(t, GlobMatchGroups(allowed, userGroups))
	})

	t.Run("empty user groups", func(t *testing.T) {
		allowed := []string{"admin"}
		userGroups := []string{}
		assert.False(t, GlobMatchGroups(allowed, userGroups))
	})

	t.Run("star matches any group", func(t *testing.T) {
		allowed := []string{"*"}
		userGroups := []string{"any-group-at-all"}
		assert.True(t, GlobMatchGroups(allowed, userGroups))
	})
}
