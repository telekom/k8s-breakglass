package v1alpha1

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// FuzzValidateIdentifierFormat tests the identifier validation with fuzzed inputs
func FuzzValidateIdentifierFormat(f *testing.F) {
	// Add seed corpus with various edge cases
	seeds := []string{
		"",
		"admin",
		"admin-group",
		"admin_group",
		"admin.group",
		"admin@example.com",
		"user@domain.co.uk",
		"cluster-name-123",
		"a",
		"UPPERCASE",
		"MixedCase123",
		"with spaces",
		"with\ttabs",
		"with\nnewlines",
		"unicode:日本語",
		"emoji:🎉",
		"special<>chars",
		"quotes\"here",
		"null\x00byte",
		"path/like/value",
		"colon:value",
		string(make([]byte, 100)),  // Medium length
		string(make([]byte, 254)),  // Just over max
		string(make([]byte, 1000)), // Very long
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		path := field.NewPath("test")

		// validateIdentifierFormat should never panic
		errs := validateIdentifierFormat(value, path)

		// Basic invariants
		if len(value) > 253 && len(errs) == 0 {
			t.Errorf("expected error for value longer than 253 chars, got none")
		}

		// Empty values should be allowed
		if value == "" && len(errs) > 0 {
			t.Errorf("unexpected error for empty value: %v", errs)
		}
	})
}

// FuzzValidateURLFormat tests URL validation with fuzzed inputs
func FuzzValidateURLFormat(f *testing.F) {
	seeds := []string{
		"",
		"https://example.com",
		"http://localhost:8080",
		"https://keycloak.example.com/auth",
		"https://user:pass@host.com/path?query=1#frag",
		"ftp://example.com",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"file:///etc/passwd",
		"://missing-scheme",
		"https://",
		"http://",
		"not-a-url",
		"https://example.com:99999", // Invalid port
		"https://[::1]:8080",        // IPv6
		string(make([]byte, 10000)), // Very long
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, url string) {
		path := field.NewPath("test")

		// validateURLFormat should never panic
		_ = validateURLFormat(url, path)

		// Empty values should be allowed
		if url == "" {
			errs := validateURLFormat(url, path)
			if len(errs) > 0 {
				t.Errorf("unexpected error for empty URL: %v", errs)
			}
		}
	})
}

// FuzzValidateHTTPSURL tests HTTPS URL validation with fuzzed inputs
func FuzzValidateHTTPSURL(f *testing.F) {
	seeds := []string{
		"",
		"https://secure.example.com",
		"http://insecure.example.com",
		"HTTPS://UPPERCASE.COM",
		"hTTpS://mixed.case.com",
		"https://",
		"http://",
		"javascript:alert(1)",
		"ftp://example.com",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, url string) {
		path := field.NewPath("test")

		// validateHTTPSURL should never panic
		_ = validateHTTPSURL(url, path)
	})
}

// FuzzValidateStringListNoDuplicates tests duplicate detection with fuzzed inputs
func FuzzValidateStringListNoDuplicates(f *testing.F) {
	// Add seeds as comma-separated values that will be split
	seeds := []string{
		"",
		"single",
		"a,b,c",
		"dup,dup",
		"a,b,a",
		"case,CASE",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		path := field.NewPath("test")

		// Split input into a list
		var values []string
		if input != "" {
			for _, v := range splitByComma(input) {
				values = append(values, v)
			}
		}

		// validateStringListNoDuplicates should never panic
		_ = validateStringListNoDuplicates(values, path)
	})
}

// FuzzValidateEmailDomainList tests email domain validation with fuzzed inputs
func FuzzValidateEmailDomainList(f *testing.F) {
	seeds := []string{
		"",
		"example.com",
		"example.com,test.org",
		"invalid",
		"*.example.com",
		".com",
		"a.b.c.d.e.f",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		path := field.NewPath("test")

		var domains []string
		if input != "" {
			domains = splitByComma(input)
		}

		// validateEmailDomainList should never panic
		_ = validateEmailDomainList(domains, path)
	})
}

// splitByComma is a helper for fuzzing that splits a string by commas
func splitByComma(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	current := ""
	for _, ch := range s {
		if ch == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	result = append(result, current)
	return result
}
