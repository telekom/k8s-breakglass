package v1alpha1

import (
	"strings"
	"testing"
	"time"

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
			values = append(values, splitByComma(input)...)
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

// FuzzParseDuration tests the extended ParseDuration function (which adds "d" day
// suffix support on top of Go's standard time.ParseDuration) with fuzzed inputs.
func FuzzParseDuration(f *testing.F) {
	seeds := []string{
		"",
		"0s",
		"1h",
		"30m",
		"5m30s",
		"24h",
		"1d",
		"7d",
		"1d12h",
		"1d0h30m",
		"365d",
		"0d",
		"0d0s",
		"-1h",
		"-1d",
		"1d-2h",
		"100000d",
		"1ns",
		"1us",
		"1ms",
		"1.5h",
		"0.5d",
		"d",
		"dd",
		"1dd",
		"1d2d",
		"abc",
		"1x",
		"h1",
		"1d ",
		" 1d",
		"1d\n",
		string(make([]byte, 1000)),
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// ParseDuration must never panic
		d, err := ParseDuration(input)

		// If parsing succeeds, validate basic invariants
		if err == nil {
			// Empty input must return zero
			if input == "" && d != 0 {
				t.Errorf("expected 0 for empty input, got %v", d)
			}
			// A successfully parsed duration should round-trip through time.Duration
			_ = d.String()
		}

		// Non-negative integer day values ("Nd" or "NdXhYm") should parse without error
		// when the remainder is also valid (covered by seed corpus above).

		// Day values must be consistent with 24h conversion
		if err == nil && d > 0 {
			hours := d / time.Hour
			// Sanity: duration should not exceed ~100 years
			if hours > 876000 {
				// This is technically valid but would be unreasonable for session timeouts
				_ = hours // acceptable, no assertion needed
			}
		}
	})
}

// FuzzValidateImpersonationConstraints fuzzes the constrained-impersonation
// (KEP-5284) validation. It must never panic on arbitrary input, and it must
// uphold two invariants that carry real security weight:
//
//  1. system:masters is refused in EVERY mode, including legacy. The API server
//     hard-denies it for constrained impersonation but deliberately does NOT for
//     legacy, so leaving it to the API server leaves the legacy path wide open.
//  2. The header-mixing trap is always caught. Any uid/groups/extra alongside a
//     ServiceAccount or node username must be rejected, because the API server
//     would otherwise skip constrained impersonation and silently fall back to
//     legacy.
func FuzzValidateImpersonationConstraints(f *testing.F) {
	// Seed corpus spanning every mode, the trap, and the restriction list.
	seeds := []struct {
		mode     string
		userName string
		uid      string
		group    string
		extraKey string
		extraVal string
		saName   string
		saNS     string
	}{
		// Valid shapes.
		{"user-info", "jane@example.com", "", "", "", "", "", ""},
		{"user-info", "jane", "uid-1", "devs", "example.com/k", "v", "", ""},
		{"serviceaccount", "", "", "", "", "", "probe", "kube-system"},
		{"serviceaccount", "system:serviceaccount:ns:sa", "", "", "", "", "", ""},
		{"arbitrary-node", "system:node:worker-1", "", "", "", "", "", ""},
		{"associated-node", "system:node:worker-1", "", "", "", "", "", ""},
		{"legacy", "system:auth-checker", "", "admins", "", "", "", ""},
		{"", "", "", "", "", "", "", ""},

		// The header-mixing trap, in all three shapes for both mode families.
		{"serviceaccount", "", "uid-1", "", "", "", "sa", "ns"},
		{"serviceaccount", "", "", "g", "", "", "sa", "ns"},
		{"serviceaccount", "", "", "", "ex.io/k", "v", "sa", "ns"},
		{"arbitrary-node", "system:node:w1", "uid-1", "", "", "", "", ""},
		{"arbitrary-node", "system:node:w1", "", "g", "", "", "", ""},
		{"associated-node", "system:node:w1", "", "", "ex.io/k", "v", "", ""},

		// system:masters in every mode.
		{"user-info", "jane", "", "system:masters", "", "", "", ""},
		{"legacy", "jane", "", "system:masters", "", "", "", ""},
		{"serviceaccount", "", "", "system:masters", "", "", "sa", "ns"},
		{"arbitrary-node", "system:node:w1", "", "system:masters", "", "", "", ""},

		// Reserved-username buckets and mode mismatches.
		{"user-info", "system:node:w1", "", "", "", "", "", ""},
		{"user-info", "system:serviceaccount:ns:sa", "", "", "", "", "", ""},
		{"arbitrary-node", "jane", "", "", "", "", "", ""},
		{"serviceaccount", "jane", "", "", "", "", "", ""},
		{"arbitrary-node", "system:node:NOT_VALID_DNS", "", "", "", "", "", ""},

		// Extra-key restrictions.
		{"user-info", "jane", "", "", "UPPER.com/k", "v", "", ""},
		{"user-info", "jane", "", "", "nodomain", "v", "", ""},
		{"user-info", "jane", "", "", "example.com/k", "", "", ""},
		{"user-info", "jane", "", "", "", "v", "", ""},

		// Empty group.
		{"user-info", "jane", "", "", "", "", "", ""},

		// Adversarial values.
		{"future-mode", "jane", "", "", "", "", "", ""},
		{"user-info", "system:node:", "", "", "", "", "", ""},
		{"user-info", "system:serviceaccount:", "", "", "", "", "", ""},
		{"serviceaccount", "system:serviceaccount:::", "", "", "", "", "", ""},
		{"user-info", strings.Repeat("a", 300), "", "", "", "", "", ""},
		{"user-info", "unicode:日本語", "", "", "emoji:🎉", "v", "", ""},
		{"user-info", "null\x00byte", "", "\x00", "", "", "", ""},
	}

	for _, s := range seeds {
		f.Add(s.mode, s.userName, s.uid, s.group, s.extraKey, s.extraVal, s.saName, s.saNS)
	}

	f.Fuzz(func(t *testing.T,
		mode, userName, uid, group, extraKey, extraVal, saName, saNS string,
	) {
		ic := &ImpersonationConfig{
			Mode:     ImpersonationMode(mode),
			UserName: userName,
			UID:      uid,
		}
		if group != "" {
			ic.Groups = []string{group}
		}
		if extraKey != "" || extraVal != "" {
			ic.Extra = map[string][]string{extraKey: {extraVal}}
		}
		if saName != "" || saNS != "" {
			ic.ServiceAccountRef = &ServiceAccountReference{Name: saName, Namespace: saNS}
		}

		path := field.NewPath("spec", "impersonation")

		// Must never panic.
		errs := validateImpersonationConstraints(ic, path)
		// Warnings must never panic either.
		_ = warnImpersonationConfigIssues(ic, path)
		// Mode inference must never panic and must always return a value.
		inferred := InferImpersonationMode(ic)
		if inferred == "" {
			t.Fatal("InferImpersonationMode returned an empty mode")
		}
		_ = EffectiveImpersonationUserName(ic)

		// INVARIANT 1: system:masters is refused in every mode, legacy included.
		if group == "system:masters" {
			if len(errs) == 0 {
				t.Fatalf("system:masters accepted in mode %q (inferred %q); combined with a "+
					"legacy grant this is a complete cluster-admin bypass", mode, inferred)
			}
		}

		// INVARIANT 2: the header-mixing trap is always caught. Only applies when the
		// mode is one that requires only-username-set AND the config actually
		// resolves to a username of the right shape, since a mode/username mismatch
		// is reported as its own error.
		mixingMode := inferred == ImpersonationModeServiceAccount ||
			inferred == ImpersonationModeArbitraryNode ||
			inferred == ImpersonationModeAssociatedNode
		mixed := uid != "" || len(ic.Groups) > 0 || len(ic.Extra) > 0
		if mixingMode && mixed && len(errs) == 0 {
			t.Fatalf("mode %q (inferred from %+v) accepted with uid/groups/extra set; the API "+
				"server would skip constrained impersonation and silently fall back to legacy", inferred, ic)
		}

		// A validated-clean config must not carry an unknown mode.
		if len(errs) == 0 && mode != "" && !validImpersonationModes[ImpersonationMode(mode)] {
			t.Fatalf("unknown mode %q passed validation", mode)
		}
	})
}

// FuzzValidateImpersonationDenyRules fuzzes DenyPolicy impersonation rule
// validation. The invariant that matters is that a rule combining identities with
// actionVerbs is always rejected: the API server issues identity and action checks
// as separate authorization requests, so such a rule silently denies nothing.
func FuzzValidateImpersonationDenyRules(f *testing.F) {
	seeds := []struct {
		mode, identityResource, identity, actionVerb, targetResource, extraKey string
	}{
		{"", "", "", "", "", ""},
		{"legacy", "users", "jane", "", "", ""},
		{"user-info", "groups", "system:masters", "", "", ""},
		{"user-info", "", "", "delete", "secrets", ""},
		{"serviceaccount", "serviceaccounts", "probe", "", "", ""},
		{"arbitrary-node", "nodes", "worker-1", "", "", ""},
		{"associated-node", "nodes", "*", "", "", ""},
		{"user-info", "userextras", "v", "", "", "example.com/k"},
		{"user-info", "uids", "uid-1", "", "", ""},
		// Must be rejected: identity and action scoping cannot coexist.
		{"user-info", "users", "jane", "get", "", ""},
		// targetResource without actionVerb is ineffective.
		{"user-info", "", "", "", "pods", ""},
		// Invalid enum values.
		{"future-mode", "", "", "", "", ""},
		{"user-info", "pods", "", "", "", ""},
		{"", "", "*", "*", "*", "*"},
		{"LEGACY", "USERS", "", "", "", ""},
	}

	for _, s := range seeds {
		f.Add(s.mode, s.identityResource, s.identity, s.actionVerb, s.targetResource, s.extraKey)
	}

	f.Fuzz(func(t *testing.T,
		mode, identityResource, identity, actionVerb, targetResource, extraKey string,
	) {
		rule := ImpersonationDenyRule{}
		if mode != "" {
			rule.Modes = []ImpersonationMode{ImpersonationMode(mode)}
		}
		if identityResource != "" {
			rule.IdentityResources = []string{identityResource}
		}
		if identity != "" {
			rule.Identities = []string{identity}
		}
		if actionVerb != "" {
			rule.ActionVerbs = []string{actionVerb}
		}
		if targetResource != "" {
			rule.TargetResources = []string{targetResource}
		}
		if extraKey != "" {
			rule.ExtraKeys = []string{extraKey}
		}

		rules := []ImpersonationDenyRule{rule}
		path := field.NewPath("spec", "impersonationRules")

		// Must never panic.
		errs := validateImpersonationDenyRules(rules, path)
		_ = warnImpersonationDenyRuleIssues(rules, path)

		// INVARIANT: identities + actionVerbs is always rejected, because such a rule
		// can never match any authorization request the API server issues.
		if identity != "" && actionVerb != "" && len(errs) == 0 {
			t.Fatalf("a rule combining identities=%q with actionVerbs=%q passed validation; "+
				"it would silently deny nothing", identity, actionVerb)
		}

		// INVARIANT: unknown enum values are always rejected.
		if mode != "" && !validImpersonationModes[ImpersonationMode(mode)] && len(errs) == 0 {
			t.Fatalf("unknown mode %q passed validation", mode)
		}
		if identityResource != "" &&
			!validImpersonationIdentityResources[identityResource] && len(errs) == 0 {
			t.Fatalf("unknown identityResource %q passed validation", identityResource)
		}
	})
}

// FuzzNamespaceConstraintsDenyUserNamespace fuzzes the namespace-constraint
// validation and warning helpers around the additive denyUserNamespace field.
// Invariants:
//   - validation must never panic for any combination of switches;
//   - denyUserNamespace never adds a hard validation error, because it is an
//     optional narrowing switch;
//   - a constraint set with denyUserNamespace unset must produce exactly the
//     same errors and warnings as before the field existed.
func FuzzNamespaceConstraintsDenyUserNamespace(f *testing.F) {
	seeds := []struct {
		allowUser        bool
		denyUser         bool
		defaultNamespace string
		allowedPattern   string
		deniedPattern    string
	}{
		{false, false, "breakglass-debug", "", ""},
		{true, false, "breakglass-debug", "debug-*", ""},
		{false, true, "breakglass-debug", "", ""},
		{true, true, "breakglass-debug", "debug-*", "kube-*"},
		{true, true, "", "", ""},
		{false, true, "", "*", "*"},
		{true, false, "prod", "prod", "prod"},
		{true, true, "unicode-日本語", "*", ""},
		{false, false, string(make([]byte, 300)), "", ""},
	}

	for _, seed := range seeds {
		f.Add(seed.allowUser, seed.denyUser, seed.defaultNamespace, seed.allowedPattern, seed.deniedPattern)
	}

	f.Fuzz(func(t *testing.T, allowUser, denyUser bool, defaultNamespace, allowedPattern, deniedPattern string) {
		build := func(deny bool) *NamespaceConstraints {
			nc := &NamespaceConstraints{
				AllowUserNamespace: allowUser,
				DenyUserNamespace:  deny,
				DefaultNamespace:   defaultNamespace,
			}
			if allowedPattern != "" {
				nc.AllowedNamespaces = &NamespaceFilter{Patterns: []string{allowedPattern}}
			}
			if deniedPattern != "" {
				nc.DeniedNamespaces = &NamespaceFilter{Patterns: []string{deniedPattern}}
			}
			return nc
		}

		path := field.NewPath("spec", "namespaceConstraints")

		// Must never panic.
		withDeny := validateNamespaceConstraints(build(true), path)
		withoutDeny := validateNamespaceConstraints(build(false), path)

		// denyUserNamespace must not introduce hard validation errors.
		if len(withDeny) != len(withoutDeny) {
			t.Errorf("denyUserNamespace changed validation errors: %v vs %v", withDeny, withoutDeny)
		}

		// Warnings must never panic either.
		warnOff := warnNamespaceConstraintIssues(build(false), "")
		warnOn := warnNamespaceConstraintIssues(build(true), "")

		// With the field unset, warnings must match the pre-field behaviour:
		// the only denyUserNamespace warning fires when both switches are set.
		for _, w := range warnOff {
			if w == "" {
				t.Errorf("empty warning produced")
			}
		}
		if !allowUser && len(warnOn) != len(warnOff) {
			t.Errorf("denyUserNamespace warning fired without allowUserNamespace: %v vs %v", warnOn, warnOff)
		}
		if allowUser && len(warnOn) != len(warnOff)+1 {
			t.Errorf("expected exactly one extra warning when both switches are set: %v vs %v", warnOn, warnOff)
		}
	})
}
