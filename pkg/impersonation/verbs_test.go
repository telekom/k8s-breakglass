// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"testing"
)

func TestParseVerb(t *testing.T) {
	tests := []struct {
		name           string
		verb           string
		wantKind       VerbKind
		wantMode       Mode
		wantUnderlying string
	}{
		// Legacy
		{"legacy impersonate", "impersonate", VerbKindLegacyImpersonate, ModeLegacy, ""},

		// Identity verbs, all four constrained modes
		{"identity user-info", "impersonate:user-info", VerbKindIdentity, ModeUserInfo, ""},
		{"identity serviceaccount", "impersonate:serviceaccount", VerbKindIdentity, ModeServiceAccount, ""},
		{"identity arbitrary-node", "impersonate:arbitrary-node", VerbKindIdentity, ModeArbitraryNode, ""},
		{"identity associated-node", "impersonate:associated-node", VerbKindIdentity, ModeAssociatedNode, ""},

		// Action verbs
		{"action list", "impersonate-on:user-info:list", VerbKindAction, ModeUserInfo, "list"},
		{"action get", "impersonate-on:serviceaccount:get", VerbKindAction, ModeServiceAccount, "get"},
		{"action create", "impersonate-on:arbitrary-node:create", VerbKindAction, ModeArbitraryNode, "create"},
		{"action watch", "impersonate-on:associated-node:watch", VerbKindAction, ModeAssociatedNode, "watch"},
		{"action deletecollection", "impersonate-on:user-info:deletecollection", VerbKindAction, ModeUserInfo, "deletecollection"},
		// RBAC verbs: ["*"] does match these, but the apiserver builds the verb with
		// a concrete underlying verb, so "*" only arrives as an ordinary string.
		{"action star underlying", "impersonate-on:user-info:*", VerbKindAction, ModeUserInfo, "*"},

		// Ordinary verbs must not be misread as impersonation
		{"get", "get", VerbKindOther, "", ""},
		{"list", "list", VerbKindOther, "", ""},
		{"create", "create", VerbKindOther, "", ""},
		{"empty", "", VerbKindOther, "", ""},
		// Substring, not prefix: must not match.
		{"contains impersonate", "reimpersonate", VerbKindOther, "", ""},
		{"impersonation not impersonate", "impersonation", VerbKindOther, "", ""},

		// Malformed: unknown mode
		{"unknown identity mode", "impersonate:future-mode", VerbKindMalformed, "", ""},
		{"unknown action mode", "impersonate-on:future-mode:list", VerbKindMalformed, "", ""},
		// legacy has no identity or action verb of its own
		{"legacy as identity mode", "impersonate:legacy", VerbKindMalformed, "", ""},
		{"legacy as action mode", "impersonate-on:legacy:list", VerbKindMalformed, "", ""},
		// Malformed: structural
		{"identity empty mode", "impersonate:", VerbKindMalformed, "", ""},
		{"action no underlying", "impersonate-on:user-info", VerbKindMalformed, "", ""},
		{"action empty underlying", "impersonate-on:user-info:", VerbKindMalformed, "", ""},
		{"action empty everything", "impersonate-on:", VerbKindMalformed, "", ""},
		{"action extra colon", "impersonate-on:user-info:list:extra", VerbKindMalformed, "", ""},
		// Case sensitivity: modes are lowercase, anything else is unknown.
		{"uppercase mode", "impersonate:USER-INFO", VerbKindMalformed, "", ""},
		{"mixed case mode", "impersonate:User-Info", VerbKindMalformed, "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseVerb(tc.verb)

			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %v (%s), want %v (%s)",
					got.Kind, got.Kind, tc.wantKind, tc.wantKind)
			}
			if got.Mode != tc.wantMode {
				t.Errorf("Mode = %q, want %q", got.Mode, tc.wantMode)
			}
			if got.UnderlyingVerb != tc.wantUnderlying {
				t.Errorf("UnderlyingVerb = %q, want %q", got.UnderlyingVerb, tc.wantUnderlying)
			}
			if got.Raw != tc.verb {
				t.Errorf("Raw = %q, want %q", got.Raw, tc.verb)
			}
		})
	}
}

// TestParseVerb_UnknownVerbIsNeverOther is the security-critical property.
//
// A verb that uses an impersonation prefix must NEVER be classified as
// VerbKindOther, because VerbKindOther is what falls through to the generic
// authorization path. If a future apiserver adds a fifth mode, this build must
// report it as malformed — and therefore fail closed — rather than pass it through
// as an ordinary request that some other rule might allow.
func TestParseVerb_UnknownVerbIsNeverOther(t *testing.T) {
	unknownImpersonationVerbs := []string{
		"impersonate:some-future-mode",
		"impersonate:",
		"impersonate:x",
		"impersonate-on:some-future-mode:list",
		"impersonate-on:user-info",
		"impersonate-on:",
		"impersonate-on:x:y:z",
		"impersonate:USER-INFO",
	}

	for _, verb := range unknownImpersonationVerbs {
		t.Run(verb, func(t *testing.T) {
			got := ParseVerb(verb)

			if got.Kind == VerbKindOther {
				t.Fatalf("verb %q classified as VerbKindOther: it would fall through to the "+
					"generic authorization path and could be silently allowed", verb)
			}
			if !got.IsImpersonation() {
				t.Fatalf("verb %q reported IsImpersonation()=false; an authorizer would not "+
					"treat it as security-relevant", verb)
			}
		})
	}
}

func TestIdentityVerb(t *testing.T) {
	tests := []struct {
		mode Mode
		want string
	}{
		{ModeUserInfo, "impersonate:user-info"},
		{ModeServiceAccount, "impersonate:serviceaccount"},
		{ModeArbitraryNode, "impersonate:arbitrary-node"},
		{ModeAssociatedNode, "impersonate:associated-node"},
		// Legacy has no identity verb; it uses the plain verb.
		{ModeLegacy, "impersonate"},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			if got := IdentityVerb(tc.mode); got != tc.want {
				t.Errorf("IdentityVerb(%q) = %q, want %q", tc.mode, got, tc.want)
			}
		})
	}
}

func TestActionVerb(t *testing.T) {
	tests := []struct {
		mode       Mode
		underlying string
		want       string
	}{
		{ModeUserInfo, "list", "impersonate-on:user-info:list"},
		{ModeServiceAccount, "get", "impersonate-on:serviceaccount:get"},
		{ModeArbitraryNode, "patch", "impersonate-on:arbitrary-node:patch"},
		{ModeAssociatedNode, "update", "impersonate-on:associated-node:update"},
		// Legacy has no action verb at all.
		{ModeLegacy, "list", ""},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode)+"/"+tc.underlying, func(t *testing.T) {
			if got := ActionVerb(tc.mode, tc.underlying); got != tc.want {
				t.Errorf("ActionVerb(%q, %q) = %q, want %q", tc.mode, tc.underlying, got, tc.want)
			}
		})
	}
}

// TestVerbRoundTrip asserts that every verb the builders produce parses back to
// the same mode. This is what protects against a typo in a constant silently
// producing a verb the apiserver never issues.
func TestVerbRoundTrip(t *testing.T) {
	underlyingVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

	for _, mode := range ConstrainedModes {
		t.Run("identity/"+string(mode), func(t *testing.T) {
			parsed := ParseVerb(IdentityVerb(mode))
			if parsed.Kind != VerbKindIdentity {
				t.Fatalf("Kind = %s, want identity", parsed.Kind)
			}
			if parsed.Mode != mode {
				t.Errorf("Mode = %q, want %q", parsed.Mode, mode)
			}
		})

		for _, uv := range underlyingVerbs {
			t.Run("action/"+string(mode)+"/"+uv, func(t *testing.T) {
				parsed := ParseVerb(ActionVerb(mode, uv))
				if parsed.Kind != VerbKindAction {
					t.Fatalf("Kind = %s, want action", parsed.Kind)
				}
				if parsed.Mode != mode {
					t.Errorf("Mode = %q, want %q", parsed.Mode, mode)
				}
				if parsed.UnderlyingVerb != uv {
					t.Errorf("UnderlyingVerb = %q, want %q", parsed.UnderlyingVerb, uv)
				}
			})
		}
	}
}

func TestParseMode(t *testing.T) {
	for _, mode := range ModeEvaluationOrder {
		t.Run(string(mode), func(t *testing.T) {
			got, ok := ParseMode(string(mode))
			if !ok {
				t.Fatalf("ParseMode(%q) reported unknown", mode)
			}
			if got != mode {
				t.Errorf("ParseMode(%q) = %q", mode, got)
			}
		})
	}

	for _, s := range []string{"", "user_info", "userinfo", "node", "future", "LEGACY"} {
		t.Run("unknown/"+s, func(t *testing.T) {
			if _, ok := ParseMode(s); ok {
				t.Errorf("ParseMode(%q) reported known", s)
			}
		})
	}
}

func TestModePredicates(t *testing.T) {
	tests := []struct {
		mode            Mode
		wantConstrained bool
		wantNode        bool
	}{
		{ModeUserInfo, true, false},
		{ModeServiceAccount, true, false},
		{ModeArbitraryNode, true, true},
		{ModeAssociatedNode, true, true},
		{ModeLegacy, false, false},
		{Mode("bogus"), false, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			if got := tc.mode.IsConstrained(); got != tc.wantConstrained {
				t.Errorf("IsConstrained() = %v, want %v", got, tc.wantConstrained)
			}
			if got := tc.mode.IsNodeMode(); got != tc.wantNode {
				t.Errorf("IsNodeMode() = %v, want %v", got, tc.wantNode)
			}
		})
	}
}

func TestModeEvaluationOrder(t *testing.T) {
	// The order is what the apiserver uses and getting it wrong changes which mode
	// a given identity selects.
	want := []Mode{ModeAssociatedNode, ModeArbitraryNode, ModeServiceAccount, ModeUserInfo, ModeLegacy}

	if len(ModeEvaluationOrder) != len(want) {
		t.Fatalf("len = %d, want %d", len(ModeEvaluationOrder), len(want))
	}
	for i := range want {
		if ModeEvaluationOrder[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, ModeEvaluationOrder[i], want[i])
		}
	}
}

func TestIsIdentityResource(t *testing.T) {
	for _, r := range []string{"users", "groups", "uids", "userextras", "serviceaccounts", "nodes"} {
		if !IsIdentityResource(r) {
			t.Errorf("IsIdentityResource(%q) = false", r)
		}
	}
	for _, r := range []string{"", "pods", "secrets", "user", "group", "USERS"} {
		if IsIdentityResource(r) {
			t.Errorf("IsIdentityResource(%q) = true", r)
		}
	}
}

func TestVerbKindString(t *testing.T) {
	tests := map[VerbKind]string{
		VerbKindOther:             "other",
		VerbKindLegacyImpersonate: "legacy-impersonate",
		VerbKindIdentity:          "identity",
		VerbKindAction:            "action",
		VerbKindMalformed:         "malformed",
		VerbKind(99):              "unknown",
	}
	for kind, want := range tests {
		if got := kind.String(); got != want {
			t.Errorf("VerbKind(%d).String() = %q, want %q", kind, got, want)
		}
	}
}

func TestParsedVerbPredicates(t *testing.T) {
	tests := []struct {
		verb            string
		wantImper       bool
		wantConstrained bool
	}{
		{"get", false, false},
		{"impersonate", true, false},
		{"impersonate:user-info", true, true},
		{"impersonate-on:user-info:list", true, true},
		{"impersonate:bogus", true, false},
	}

	for _, tc := range tests {
		t.Run(tc.verb, func(t *testing.T) {
			p := ParseVerb(tc.verb)
			if got := p.IsImpersonation(); got != tc.wantImper {
				t.Errorf("IsImpersonation() = %v, want %v", got, tc.wantImper)
			}
			if got := p.IsConstrained(); got != tc.wantConstrained {
				t.Errorf("IsConstrained() = %v, want %v", got, tc.wantConstrained)
			}
			if p.Describe() == "" {
				t.Error("Describe() returned empty string")
			}
		})
	}
}

func TestAllIdentityVerbs(t *testing.T) {
	got := AllIdentityVerbs()
	want := map[string]bool{
		"impersonate:user-info":       true,
		"impersonate:serviceaccount":  true,
		"impersonate:arbitrary-node":  true,
		"impersonate:associated-node": true,
	}

	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %v", len(got), len(want), got)
	}
	for _, v := range got {
		if !want[v] {
			t.Errorf("unexpected verb %q", v)
		}
	}
	// Legacy must not appear: it is not a constrained identity verb.
	for _, v := range got {
		if v == VerbLegacyImpersonate {
			t.Error("AllIdentityVerbs included the legacy verb")
		}
	}
}

func TestAllActionVerbs(t *testing.T) {
	got := AllActionVerbs("get", "list")

	// 4 constrained modes x 2 verbs
	if len(got) != 8 {
		t.Fatalf("len = %d, want 8: %v", len(got), got)
	}
	for _, v := range got {
		parsed := ParseVerb(v)
		if parsed.Kind != VerbKindAction {
			t.Errorf("verb %q parsed as %s, want action", v, parsed.Kind)
		}
	}
}

func TestAPIGroupConstant(t *testing.T) {
	// Constrained identity checks use authentication.k8s.io; legacy uses the core
	// group. Confusing the two produces a rule that looks correct and does nothing.
	if APIGroupAuthentication != "authentication.k8s.io" {
		t.Errorf("APIGroupAuthentication = %q", APIGroupAuthentication)
	}
}
