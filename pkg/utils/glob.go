package utils

import (
	"path"
	"strings"
)

// GlobMatch checks if a value matches a glob pattern.
// Patterns support these wildcards (path.Match semantics):
//   - "*" matches any sequence of non-separator characters
//   - "?" matches any single non-separator character
//   - "[...]" matches character classes
//
// Special cases:
//   - Pattern "*" matches everything (short-circuit for common wildcard case)
//   - Pattern without wildcards uses exact string matching
//   - Invalid patterns return false and the error
//
// Examples:
//
//	GlobMatch("*", "anything")              → true, nil
//	GlobMatch("platform-*", "platform-sre") → true, nil
//	GlobMatch("*.tst.*", "cluster.tst.eu")  → true, nil
//	GlobMatch("admin", "admin")             → true, nil
//	GlobMatch("admin", "user")              → false, nil
//	GlobMatch("[invalid", "test")           → false, syntax error
func GlobMatch(pattern, value string) (bool, error) {
	// Short-circuit for universal wildcard
	if pattern == "*" {
		return true, nil
	}

	// If pattern contains wildcards, use path.Match (not filepath.Match) for
	// cross-platform consistency since these are logical identifiers, not file paths.
	if strings.ContainsAny(pattern, "*?[") {
		matched, err := path.Match(pattern, value)
		if err != nil {
			return false, err
		}
		return matched, nil
	}

	// No wildcards - exact match
	return pattern == value, nil
}

// GlobMatchAny checks if any pattern in the list matches the value.
// Returns true on first match, false if no patterns match.
// Patterns that fail to parse are skipped.
func GlobMatchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if matched, _ := GlobMatch(pattern, value); matched {
			return true
		}
	}
	return false
}

// GlobMatchGroups checks if any group in userGroups matches any pattern in allowedGroups.
// This is useful for authorization checks where a user has multiple groups and
// any group match should grant access.
func GlobMatchGroups(allowedGroups, userGroups []string) bool {
	for _, pattern := range allowedGroups {
		for _, group := range userGroups {
			if matched, _ := GlobMatch(pattern, group); matched {
				return true
			}
		}
	}
	return false
}
