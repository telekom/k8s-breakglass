package naming

import (
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
)

var (
	// invalidCharsRegex matches any character that is not alphanumeric, dash, or dot
	invalidCharsRegex = regexp.MustCompile(`[^a-z0-9\-.]`)
	// multiDashRegex matches consecutive dashes
	multiDashRegex = regexp.MustCompile(`-+`)
	// multiDotRegex matches consecutive dots
	multiDotRegex = regexp.MustCompile(`\.+`)
)

// ToRFC1123Subdomain converts a string to a Kubernetes RFC1123 subdomain compatible value.
// RFC1123 subdomains must:
//   - contain only lowercase alphanumeric characters, '-' or '.'
//   - start and end with an alphanumeric character
//   - be at most 253 characters long
//
// This function lowercases the string, replaces invalid characters with '-', collapses
// multiple separators, and ensures the result starts and ends with an alphanumeric character.
// If the input cannot produce a valid name, returns "x" as a fallback.
func ToRFC1123Subdomain(s string) string {
	if s == "" {
		return "x"
	}

	// Lowercase first
	s = strings.ToLower(s)

	// Replace invalid characters with '-'
	s = invalidCharsRegex.ReplaceAllString(s, "-")

	// Collapse multiple dashes and dots
	s = multiDashRegex.ReplaceAllString(s, "-")
	s = multiDotRegex.ReplaceAllString(s, ".")

	// Trim leading/trailing non-alphanumeric characters
	s = strings.Trim(s, "-.")

	// Ensure starts and ends with alphanumeric
	s = trimNonAlnum(s)

	if s == "" {
		return "x"
	}

	// Truncate to max subdomain length
	if len(s) > validation.DNS1123SubdomainMaxLength {
		s = s[:validation.DNS1123SubdomainMaxLength]
		s = trimNonAlnum(s)
		if s == "" {
			return "x"
		}
	}

	return s
}

// ToRFC1123Label converts an arbitrary string to a Kubernetes label-safe value.
// Label values must:
//   - contain only lowercase alphanumeric characters, '-', '_' or '.'
//   - start and end with an alphanumeric character
//   - be at most 63 characters long
//
// This function lowercases the string, replaces invalid characters with '-', collapses
// multiple separators, and ensures the result starts and ends with an alphanumeric character.
// If the input cannot produce a valid value, returns "x" as a fallback.
func ToRFC1123Label(s string) string {
	if s == "" {
		return "x"
	}

	// Lowercase first
	s = strings.ToLower(s)

	// Replace invalid characters with '-'
	// Note: Label values allow underscores, but we replace invalid chars with '-' for consistency
	s = invalidCharsRegex.ReplaceAllString(s, "-")

	// Collapse multiple separators
	s = multiDashRegex.ReplaceAllString(s, "-")
	s = multiDotRegex.ReplaceAllString(s, ".")

	// Trim leading/trailing non-alphanumeric characters
	s = strings.Trim(s, "-._")

	// Ensure starts and ends with alphanumeric
	s = trimNonAlnum(s)

	if s == "" {
		return "x"
	}

	// Truncate to max label value length
	if len(s) > validation.LabelValueMaxLength {
		s = s[:validation.LabelValueMaxLength]
		s = trimNonAlnum(s)
		if s == "" {
			return "x"
		}
	}

	return s
}

// isAlnum returns true if the rune is a lowercase alphanumeric character.
// Note: Input is expected to be already lowercased.
func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// trimNonAlnum removes leading and trailing non-alphanumeric characters from a string.
func trimNonAlnum(s string) string {
	for len(s) > 0 && !isAlnum(rune(s[0])) {
		s = s[1:]
	}
	for len(s) > 0 && !isAlnum(rune(s[len(s)-1])) {
		s = s[:len(s)-1]
	}
	return s
}
