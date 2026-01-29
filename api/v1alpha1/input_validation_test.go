package v1alpha1

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// TestValidateIdentifierFormat tests the identifier format validation
func TestValidateIdentifierFormat(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		shouldFail    bool
		expectedError string
	}{
		// Valid cases
		{name: "simple alphanumeric", value: "admin", shouldFail: false},
		{name: "with underscore", value: "admin_group", shouldFail: false},
		{name: "with dash", value: "admin-group", shouldFail: false},
		{name: "with dot", value: "admin.group", shouldFail: false},
		{name: "email format", value: "admin@example.com", shouldFail: false},
		{name: "k8s resource name", value: "escalation-config", shouldFail: false},
		{name: "with colon separator", value: "breakglass:platform:emergency", shouldFail: false},
		{name: "with colon and tenant", value: "breakglass:tenant:myapp:poweruser", shouldFail: false},

		// Invalid cases
		{name: "with space", value: "admin group", shouldFail: true},
		{name: "empty string", value: "", shouldFail: false}, // Empty is allowed by this function
		{name: "very long string", value: string(make([]byte, 300)), shouldFail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateIdentifierFormat(tc.value, field.NewPath("test"))
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for value %q, got none", tc.value)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for value %q: %v", tc.value, errs)
			}
		})
	}
}

// TestValidateURLFormat tests URL validation
func TestValidateURLFormat(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		shouldFail bool
	}{
		// Valid cases
		{name: "https URL", url: "https://auth.example.com", shouldFail: false},
		{name: "http URL", url: "http://localhost:8080", shouldFail: false},
		{name: "with path", url: "https://keycloak.example.com/auth", shouldFail: false},

		// Invalid cases
		{name: "no scheme", url: "example.com", shouldFail: true},
		{name: "invalid scheme", url: "ftp://example.com", shouldFail: true},
		{name: "no host", url: "https://", shouldFail: true},
		{name: "empty string", url: "", shouldFail: false}, // Empty is allowed
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateURLFormat(tc.url, field.NewPath("test"))
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for URL %q, got none", tc.url)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for URL %q: %v", tc.url, errs)
			}
		})
	}
}

// TestValidateHTTPSURL tests HTTPS URL validation
func TestValidateHTTPSURL(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		shouldFail bool
	}{
		{name: "https URL", url: "https://secure.example.com", shouldFail: false},
		{name: "http URL", url: "http://insecure.example.com", shouldFail: true},
		{name: "empty string", url: "", shouldFail: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateHTTPSURL(tc.url, field.NewPath("test"))
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for URL %q, got none", tc.url)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for URL %q: %v", tc.url, errs)
			}
		})
	}
}

// TestValidateEmailDomainList tests email domain list validation
func TestValidateEmailDomainList(t *testing.T) {
	tests := []struct {
		name       string
		domains    []string
		shouldFail bool
	}{
		// Valid cases
		{name: "single domain", domains: []string{"example.com"}, shouldFail: false},
		{name: "multiple domains", domains: []string{"example.com", "test.com"}, shouldFail: false},
		{name: "localhost", domains: []string{"localhost"}, shouldFail: false},
		{name: "empty list", domains: []string{}, shouldFail: false},

		// Invalid cases
		{name: "domain without dot", domains: []string{"example"}, shouldFail: true},
		{name: "duplicate domains", domains: []string{"example.com", "example.com"}, shouldFail: true},
		{name: "domain with invalid chars", domains: []string{"exam ple.com"}, shouldFail: true},
		{name: "empty domain in list", domains: []string{"", "example.com"}, shouldFail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateEmailDomainList(tc.domains, field.NewPath("domains"))
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for domains %v, got none", tc.domains)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for domains %v: %v", tc.domains, errs)
			}
		})
	}
}

// TestValidateStringListNoDuplicates tests duplicate detection
func TestValidateStringListNoDuplicates(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		shouldFail bool
	}{
		// Valid cases
		{name: "unique values", values: []string{"a", "b", "c"}, shouldFail: false},
		{name: "empty list", values: []string{}, shouldFail: false},
		{name: "single value", values: []string{"a"}, shouldFail: false},

		// Invalid cases
		{name: "duplicate values", values: []string{"a", "b", "a"}, shouldFail: true},
		{name: "all same", values: []string{"a", "a", "a"}, shouldFail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateStringListNoDuplicates(tc.values, field.NewPath("test"))
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for values %v, got none", tc.values)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for values %v: %v", tc.values, errs)
			}
		})
	}
}

// TestValidateStringListEntriesNotEmpty ensures blank values are rejected when present in lists
func TestValidateStringListEntriesNotEmpty(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		shouldFail bool
	}{
		{name: "all populated", values: []string{"a", "b"}, shouldFail: false},
		{name: "empty list", values: []string{}, shouldFail: false},
		{name: "with empty", values: []string{"a", ""}, shouldFail: true},
		{name: "with whitespace", values: []string{"  ", "b"}, shouldFail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateStringListEntriesNotEmpty(tc.values, field.NewPath("test"))
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for values %v, got none", tc.values)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for values %v: %v", tc.values, errs)
			}
		})
	}
}

// TestValidateNonEmptyStringList tests minimum items validation
func TestValidateNonEmptyStringList(t *testing.T) {
	tests := []struct {
		name       string
		values     []string
		minItems   int
		shouldFail bool
	}{
		// Valid cases
		{name: "sufficient items", values: []string{"a", "b"}, minItems: 1, shouldFail: false},
		{name: "exactly minimum", values: []string{"a"}, minItems: 1, shouldFail: false},

		// Invalid cases
		{name: "too few items", values: []string{}, minItems: 1, shouldFail: true},
		{name: "empty string in list", values: []string{"a", "", "c"}, minItems: 1, shouldFail: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateNonEmptyStringList(tc.values, field.NewPath("test"), tc.minItems)
			hasError := len(errs) > 0

			if tc.shouldFail && !hasError {
				t.Errorf("expected error for values %v (minItems=%d), got none", tc.values, tc.minItems)
			}
			if !tc.shouldFail && hasError {
				t.Errorf("unexpected error for values %v (minItems=%d): %v", tc.values, tc.minItems, errs)
			}
		})
	}
}
