// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"strings"
	"testing"
)

func TestIdentityOnlyUsernameSet(t *testing.T) {
	tests := []struct {
		name     string
		identity Identity
		want     bool
	}{
		{"username only", Identity{UserName: "jane"}, true},
		{"empty", Identity{}, true},
		{"with uid", Identity{UserName: "jane", UID: "abc"}, false},
		{"with groups", Identity{UserName: "jane", Groups: []string{"devs"}}, false},
		{"with extra", Identity{UserName: "jane", Extra: map[string][]string{"a.io/b": {"c"}}}, false},
		// An empty (non-nil) groups slice must still count as unset, matching the
		// apiserver's len()==0 check rather than a nil check.
		{"empty groups slice", Identity{UserName: "jane", Groups: []string{}}, true},
		{"empty extra map", Identity{UserName: "jane", Extra: map[string][]string{}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.identity.OnlyUsernameSet(); got != tc.want {
				t.Errorf("OnlyUsernameSet() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSelectMode covers the apiserver's mode selection across all five modes.
func TestSelectMode(t *testing.T) {
	tests := []struct {
		name              string
		identity          Identity
		requestorNodeName string
		want              Mode
	}{
		// associated-node: node username, only username set, requestor's node matches
		{
			name:              "associated node when requestor node matches",
			identity:          Identity{UserName: "system:node:worker-1"},
			requestorNodeName: "worker-1",
			want:              ModeAssociatedNode,
		},
		// arbitrary-node: node username, only username set, valid DNS subdomain,
		// requestor node absent or different
		{
			name:     "arbitrary node when requestor has no node",
			identity: Identity{UserName: "system:node:worker-1"},
			want:     ModeArbitraryNode,
		},
		{
			name:              "arbitrary node when requestor node differs",
			identity:          Identity{UserName: "system:node:worker-1"},
			requestorNodeName: "worker-2",
			want:              ModeArbitraryNode,
		},
		// A node username that is not a valid DNS subdomain matches no constrained
		// mode: user-info refuses node usernames, so it lands on legacy.
		{
			name:     "invalid node name falls to legacy",
			identity: Identity{UserName: "system:node:Not_A_Valid_Name"},
			want:     ModeLegacy,
		},
		// serviceaccount
		{
			name:     "serviceaccount",
			identity: Identity{UserName: "system:serviceaccount:kube-system:probe"},
			want:     ModeServiceAccount,
		},
		// user-info
		{
			name:     "plain user",
			identity: Identity{UserName: "jane.doe@example.com"},
			want:     ModeUserInfo,
		},
		{
			name:     "user with uid and groups",
			identity: Identity{UserName: "jane", UID: "u1", Groups: []string{"devs"}},
			want:     ModeUserInfo,
		},
		{
			name:     "synthetic probe user",
			identity: Identity{UserName: "system:auth-checker", Groups: []string{"admins"}},
			want:     ModeUserInfo,
		},

		// THE TRAP. Mixing uid/groups/extra with a node or SA username breaks
		// onlyUsernameSet, so the node/SA modes are skipped, user-info refuses these
		// reserved usernames, and the apiserver silently lands on legacy.
		{
			name:              "node username plus uid falls to legacy",
			identity:          Identity{UserName: "system:node:worker-1", UID: "u1"},
			requestorNodeName: "worker-1",
			want:              ModeLegacy,
		},
		{
			name:     "node username plus groups falls to legacy",
			identity: Identity{UserName: "system:node:worker-1", Groups: []string{"system:nodes"}},
			want:     ModeLegacy,
		},
		{
			name: "node username plus extra falls to legacy",
			identity: Identity{
				UserName: "system:node:worker-1",
				Extra:    map[string][]string{"example.io/k": {"v"}},
			},
			want: ModeLegacy,
		},
		{
			name:     "SA username plus uid falls to legacy",
			identity: Identity{UserName: "system:serviceaccount:ns:sa", UID: "u1"},
			want:     ModeLegacy,
		},
		{
			name:     "SA username plus groups falls to legacy",
			identity: Identity{UserName: "system:serviceaccount:ns:sa", Groups: []string{"g"}},
			want:     ModeLegacy,
		},

		// Empty username: nothing to impersonate.
		{"empty username", Identity{}, "", ModeLegacy},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.identity.SelectMode(tc.requestorNodeName); got != tc.want {
				t.Errorf("SelectMode(%q) = %q, want %q", tc.requestorNodeName, got, tc.want)
			}
		})
	}
}

func TestValidateIdentity_SystemMasters(t *testing.T) {
	// The apiserver hard-denies system:masters in constrained mode but deliberately
	// does NOT for legacy. Breakglass refuses it in every mode, because a legacy
	// grant plus system:masters is a complete cluster-admin bypass.
	for _, mode := range append(append([]Mode{}, ConstrainedModes...), ModeLegacy) {
		t.Run(string(mode), func(t *testing.T) {
			identity := Identity{UserName: "jane", Groups: []string{"devs", GroupSystemMasters}}
			violations := ValidateIdentity(identity, mode)

			found := false
			for _, v := range violations {
				if strings.Contains(v.Message, "system:masters") {
					found = true
					if !v.Fatal {
						t.Error("system:masters violation is not marked fatal")
					}
				}
			}
			if !found {
				t.Fatalf("system:masters not rejected in mode %q: %v", mode, violations)
			}
		})
	}
}

// TestValidateIdentity_HeaderMixingTrap is the guardrail for KEP-5284's central
// footgun.
func TestValidateIdentity_HeaderMixingTrap(t *testing.T) {
	mixingModes := []Mode{ModeServiceAccount, ModeArbitraryNode, ModeAssociatedNode}

	cases := []struct {
		name     string
		mutate   func(*Identity)
		offender string
	}{
		{"uid", func(i *Identity) { i.UID = "u1" }, "uid"},
		{"groups", func(i *Identity) { i.Groups = []string{"g"} }, "groups"},
		{"extra", func(i *Identity) { i.Extra = map[string][]string{"ex.io/k": {"v"}} }, "extra"},
	}

	for _, mode := range mixingModes {
		for _, tc := range cases {
			t.Run(string(mode)+"/"+tc.name, func(t *testing.T) {
				identity := Identity{UserName: usernameForMode(mode)}
				tc.mutate(&identity)

				violations := ValidateIdentity(identity, mode)
				if len(violations) == 0 {
					t.Fatalf("mode %q with %s set was accepted; the apiserver would silently "+
						"fall back to legacy impersonation", mode, tc.name)
				}

				fatal := false
				mentionsFallback := false
				for _, v := range violations {
					if v.Fatal {
						fatal = true
					}
					if strings.Contains(v.Message, "legacy") {
						mentionsFallback = true
					}
				}
				if !fatal {
					t.Error("no fatal violation reported")
				}
				if !mentionsFallback {
					t.Errorf("no violation explained the legacy fallback: %v", violations)
				}
			})
		}
	}
}

// TestValidateIdentity_ValidIdentities asserts the guardrails do not reject
// legitimate configurations.
func TestValidateIdentity_ValidIdentities(t *testing.T) {
	tests := []struct {
		name     string
		identity Identity
		mode     Mode
	}{
		{"user-info plain", Identity{UserName: "jane@example.com"}, ModeUserInfo},
		{
			"user-info with groups uid extra",
			Identity{
				UserName: "jane@example.com",
				UID:      "uid-1",
				Groups:   []string{"devs", "sre"},
				Extra:    map[string][]string{"identity.t-caas.telekom.com/issuer": {"https://idp"}},
			},
			ModeUserInfo,
		},
		{"serviceaccount", Identity{UserName: "system:serviceaccount:kube-system:probe"}, ModeServiceAccount},
		{"arbitrary-node", Identity{UserName: "system:node:worker-1.example.com"}, ModeArbitraryNode},
		{"associated-node", Identity{UserName: "system:node:worker-1"}, ModeAssociatedNode},
		{"legacy blanket", Identity{UserName: "system:auth-checker", Groups: []string{"a", "b"}}, ModeLegacy},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if violations := ValidateIdentity(tc.identity, tc.mode); len(violations) > 0 {
				t.Errorf("valid identity rejected: %v", violations)
			}
		})
	}
}

func TestValidateIdentity_NodeAndSAGroupsRejected(t *testing.T) {
	// The apiserver forces the groups for node and SA identities, so supplying them
	// is both useless and actively harmful (it trips onlyUsernameSet).
	tests := []struct {
		mode     Mode
		username string
	}{
		{ModeArbitraryNode, "system:node:worker-1"},
		{ModeAssociatedNode, "system:node:worker-1"},
		{ModeServiceAccount, "system:serviceaccount:ns:sa"},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			identity := Identity{UserName: tc.username, Groups: []string{"custom"}}
			violations := ValidateIdentity(identity, tc.mode)

			found := false
			for _, v := range violations {
				if strings.Contains(v.Message, "groups cannot be impersonated") {
					found = true
				}
			}
			if !found {
				t.Errorf("groups not rejected for mode %q: %v", tc.mode, violations)
			}
		})
	}
}

func TestValidateIdentity_UserInfoRefusesReservedUsernames(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     string
	}{
		{"node", "system:node:worker-1", "refuses node usernames"},
		{"serviceaccount", "system:serviceaccount:ns:sa", "refuses ServiceAccount usernames"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations := ValidateIdentity(Identity{UserName: tc.username}, ModeUserInfo)

			found := false
			for _, v := range violations {
				if strings.Contains(v.Message, tc.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("user-info did not reject %q: %v", tc.username, violations)
			}
		})
	}
}

func TestValidateIdentity_WrongUsernameForMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		username string
	}{
		{"node mode with plain user", ModeArbitraryNode, "jane"},
		{"node mode with SA", ModeAssociatedNode, "system:serviceaccount:ns:sa"},
		{"SA mode with plain user", ModeServiceAccount, "jane"},
		{"SA mode with node", ModeServiceAccount, "system:node:worker-1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations := ValidateIdentity(Identity{UserName: tc.username}, tc.mode)
			if len(violations) == 0 {
				t.Errorf("mode %q accepted username %q", tc.mode, tc.username)
			}
		})
	}
}

func TestValidateIdentity_EmptyGroupRejected(t *testing.T) {
	violations := ValidateIdentity(
		Identity{UserName: "jane", Groups: []string{"devs", ""}}, ModeUserInfo)

	found := false
	for _, v := range violations {
		if strings.Contains(v.Message, "must not be empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("empty group not rejected: %v", violations)
	}
}

func TestValidateExtra(t *testing.T) {
	tests := []struct {
		name    string
		extra   map[string][]string
		wantErr bool
	}{
		{"valid", map[string][]string{"example.com/key": {"v"}}, false},
		{"valid multiple values", map[string][]string{"example.com/key": {"a", "b"}}, false},
		{"nil", nil, false},
		{"empty key", map[string][]string{"": {"v"}}, true},
		{"uppercase key", map[string][]string{"Example.com/Key": {"v"}}, true},
		{"not domain prefixed", map[string][]string{"key": {"v"}}, true},
		{"empty values slice", map[string][]string{"example.com/key": {}}, true},
		{"nil values slice", map[string][]string{"example.com/key": nil}, true},
		{"empty string value", map[string][]string{"example.com/key": {""}}, true},
		{"empty value among valid", map[string][]string{"example.com/key": {"a", ""}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			violations := validateExtra(tc.extra)
			gotErr := len(violations) > 0
			if gotErr != tc.wantErr {
				t.Errorf("validateExtra(%v) violations = %v, wantErr = %v",
					tc.extra, violations, tc.wantErr)
			}
			for _, v := range violations {
				if !v.Fatal {
					t.Errorf("extra violation not fatal: %v", v)
				}
			}
		})
	}
}

// TestValidateIdentity_ExtraOnlyValidatedForConstrained asserts the apiserver's
// deliberate asymmetry: the constrained restrictions are NOT applied to legacy
// impersonation.
func TestValidateIdentity_ExtraOnlyValidatedForConstrained(t *testing.T) {
	badExtra := Identity{
		UserName: "jane",
		Extra:    map[string][]string{"NOT-lowercase": {""}},
	}

	if violations := ValidateIdentity(badExtra, ModeUserInfo); len(violations) == 0 {
		t.Error("constrained mode accepted invalid extra")
	}

	// Legacy: only the system:masters guardrail applies.
	if violations := ValidateIdentity(badExtra, ModeLegacy); len(violations) != 0 {
		t.Errorf("legacy mode applied constrained extra validation: %v", violations)
	}
}

func TestUsernameHelpers(t *testing.T) {
	if !IsNodeUsername("system:node:w1") {
		t.Error("IsNodeUsername false for node username")
	}
	if IsNodeUsername("system:nodes") {
		t.Error("IsNodeUsername true for system:nodes group name")
	}
	if !IsServiceAccountUsername("system:serviceaccount:ns:sa") {
		t.Error("IsServiceAccountUsername false for SA username")
	}
	if IsServiceAccountUsername("system:serviceaccounts") {
		t.Error("IsServiceAccountUsername true for group name")
	}

	name, ok := NodeNameFromUsername("system:node:worker-1")
	if !ok || name != "worker-1" {
		t.Errorf("NodeNameFromUsername = (%q, %v)", name, ok)
	}
	if _, ok := NodeNameFromUsername("jane"); ok {
		t.Error("NodeNameFromUsername reported ok for a plain username")
	}
}

func TestUnionSemanticsWarning(t *testing.T) {
	tests := []struct {
		identities, actions int
		wantWarning         bool
	}{
		{0, 0, false},
		{1, 1, false},
		{1, 5, false},
		{5, 1, false},
		{2, 2, true},
		{3, 4, true},
	}

	for _, tc := range tests {
		got := UnionSemanticsWarning(tc.identities, tc.actions)
		if (got != "") != tc.wantWarning {
			t.Errorf("UnionSemanticsWarning(%d, %d) = %q, wantWarning = %v",
				tc.identities, tc.actions, got, tc.wantWarning)
		}
		if tc.wantWarning && !strings.Contains(got, "cross product") {
			t.Errorf("warning did not mention cross product: %q", got)
		}
	}
}

func TestManyGroupsWarning(t *testing.T) {
	// The apiserver collapses to a wildcard check at 4 or more items.
	for _, n := range []int{0, 1, 2, 3} {
		if got := ManyGroupsWarning(n); got != "" {
			t.Errorf("ManyGroupsWarning(%d) = %q, want empty", n, got)
		}
	}
	for _, n := range []int{4, 5, 100} {
		got := ManyGroupsWarning(n)
		if got == "" {
			t.Errorf("ManyGroupsWarning(%d) = empty", n)
		}
		if !strings.Contains(got, "wildcard") {
			t.Errorf("warning did not mention wildcard: %q", got)
		}
	}
}

func TestViolationError(t *testing.T) {
	v := Violation{Field: "groups[0]", Message: "bad", Fatal: true}
	if got := v.Error(); got != "groups[0]: bad" {
		t.Errorf("Error() = %q", got)
	}
}

// usernameForMode returns a username that satisfies the given mode's username
// requirement, so trap tests isolate the mixing failure.
func usernameForMode(mode Mode) string {
	switch mode {
	case ModeServiceAccount:
		return "system:serviceaccount:ns:sa"
	case ModeArbitraryNode, ModeAssociatedNode:
		return "system:node:worker-1"
	case ModeUserInfo:
		return "jane"
	case ModeLegacy:
		return "jane"
	default:
		return "jane"
	}
}
