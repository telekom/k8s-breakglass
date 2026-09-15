// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
)

// identityAction builds an identity-check action for tests.
func identityAction(verb, resource, name string) ImpersonationAction {
	return ImpersonationAction{
		Verb:             impersonation.ParseVerb(verb),
		IdentityResource: resource,
		Identity:         name,
	}
}

// actionCheck builds an action-check action for tests.
func actionCheck(verb, targetResource, targetGroup string) ImpersonationAction {
	return ImpersonationAction{
		Verb:           impersonation.ParseVerb(verb),
		TargetResource: targetResource,
		TargetAPIGroup: targetGroup,
	}
}

// TestImpersonationRuleMatches_EmptyRuleDeniesEverything asserts the documented
// "no impersonation on this cluster at all" form.
func TestImpersonationRuleMatches_EmptyRuleDeniesEverything(t *testing.T) {
	empty := breakglassv1alpha1.ImpersonationDenyRule{}

	actions := []ImpersonationAction{
		identityAction("impersonate", "users", "jane"),
		identityAction("impersonate:user-info", "users", "jane"),
		identityAction("impersonate:serviceaccount", "serviceaccounts", "probe"),
		identityAction("impersonate:arbitrary-node", "nodes", "worker-1"),
		identityAction("impersonate:associated-node", "nodes", "*"),
		actionCheck("impersonate-on:user-info:list", "pods", ""),
		// Even a verb we cannot parse must be caught by a rule that constrains nothing.
		identityAction("impersonate:some-future-mode", "users", "jane"),
	}

	for _, act := range actions {
		t.Run(act.Verb.Raw, func(t *testing.T) {
			if !impersonationRuleMatches(empty, act) {
				t.Errorf("empty rule did not match %q", act.Verb.Raw)
			}
		})
	}
}

func TestImpersonationRuleMatches_ModeScoping(t *testing.T) {
	tests := []struct {
		name      string
		modes     []breakglassv1alpha1.ImpersonationMode
		verb      string
		wantMatch bool
	}{
		{"user-info rule vs user-info check", []breakglassv1alpha1.ImpersonationMode{"user-info"}, "impersonate:user-info", true},
		{"user-info rule vs serviceaccount check", []breakglassv1alpha1.ImpersonationMode{"user-info"}, "impersonate:serviceaccount", false},
		{"legacy rule vs legacy check", []breakglassv1alpha1.ImpersonationMode{"legacy"}, "impersonate", true},
		{"legacy rule vs constrained check", []breakglassv1alpha1.ImpersonationMode{"legacy"}, "impersonate:user-info", false},
		{"constrained rule vs legacy check", []breakglassv1alpha1.ImpersonationMode{"user-info"}, "impersonate", false},
		{
			"multi-mode rule including legacy",
			[]breakglassv1alpha1.ImpersonationMode{"user-info", "legacy"},
			"impersonate", true,
		},
		{"node modes", []breakglassv1alpha1.ImpersonationMode{"arbitrary-node", "associated-node"}, "impersonate:arbitrary-node", true},
		{"node modes vs user-info", []breakglassv1alpha1.ImpersonationMode{"arbitrary-node", "associated-node"}, "impersonate:user-info", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := breakglassv1alpha1.ImpersonationDenyRule{Modes: tc.modes}
			act := identityAction(tc.verb, "users", "jane")

			if got := impersonationRuleMatches(rule, act); got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

// TestImpersonationRuleMatches_LegacyFallbackEscapeHatch is the scenario the
// feature exists to close: denying only the constrained modes leaves legacy open.
func TestImpersonationRuleMatches_LegacyFallbackEscapeHatch(t *testing.T) {
	constrainedOnly := breakglassv1alpha1.ImpersonationDenyRule{
		Modes: []breakglassv1alpha1.ImpersonationMode{
			"user-info", "serviceaccount", "arbitrary-node", "associated-node",
		},
	}
	legacyCheck := identityAction("impersonate", "users", "jane")

	if impersonationRuleMatches(constrainedOnly, legacyCheck) {
		t.Fatal("a constrained-only rule matched the legacy check; the test's premise is wrong")
	}

	// Adding legacy closes the hatch.
	withLegacy := constrainedOnly
	withLegacy.Modes = append(append([]breakglassv1alpha1.ImpersonationMode{}, constrainedOnly.Modes...), "legacy")

	if !impersonationRuleMatches(withLegacy, legacyCheck) {
		t.Error("adding legacy to modes did not catch the legacy fallback check")
	}
}

func TestImpersonationRuleMatches_IdentityResourceScoping(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		IdentityResources: []string{"groups", "uids"},
	}

	tests := []struct {
		resource  string
		wantMatch bool
	}{
		{"groups", true},
		{"uids", true},
		{"users", false},
		{"nodes", false},
		{"serviceaccounts", false},
		{"userextras", false},
		// "*" is not a legal identityResources value, so it must not act as a wildcard.
		{"*", false},
	}

	for _, tc := range tests {
		t.Run(tc.resource, func(t *testing.T) {
			act := identityAction("impersonate:user-info", tc.resource, "x")
			if got := impersonationRuleMatches(rule, act); got != tc.wantMatch {
				t.Errorf("match for resource %q = %v, want %v", tc.resource, got, tc.wantMatch)
			}
		})
	}
}

func TestImpersonationRuleMatches_IdentityGlobs(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		IdentityResources: []string{"users"},
		Identities:        []string{"admin-*", "root"},
	}

	tests := []struct {
		identity  string
		wantMatch bool
	}{
		{"admin-jane", true},
		{"admin-", true},
		{"root", true},
		{"jane", false},
		{"superadmin-jane", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.identity, func(t *testing.T) {
			act := identityAction("impersonate:user-info", "users", tc.identity)
			if got := impersonationRuleMatches(rule, act); got != tc.wantMatch {
				t.Errorf("match for identity %q = %v, want %v", tc.identity, got, tc.wantMatch)
			}
		})
	}
}

// TestImpersonationRuleMatches_WildcardCollapseCannotBypass covers the apiserver's
// hardcoded behaviour of collapsing >= 4 per-item checks into a single "*" check.
//
// Without special handling, a policy listing specific usernames would be silently
// bypassed by requesting four identities at once.
func TestImpersonationRuleMatches_WildcardCollapseCannotBypass(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		IdentityResources: []string{"groups"},
		Identities:        []string{"cluster-admins"},
	}

	// The apiserver sends name="*" once the request names 4+ groups.
	collapsed := identityAction("impersonate:user-info", "groups", "*")

	if !impersonationRuleMatches(rule, collapsed) {
		t.Fatal("a wildcard-collapsed check bypassed a rule naming specific identities: " +
			"requesting 4+ groups at once would evade the policy entirely")
	}

	// A concrete non-matching identity must still not match.
	other := identityAction("impersonate:user-info", "groups", "devs")
	if impersonationRuleMatches(rule, other) {
		t.Error("rule matched an identity it does not name")
	}
}

func TestImpersonationRuleMatches_ActionVerbScoping(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		ActionVerbs: []string{"delete", "deletecollection"},
	}

	tests := []struct {
		name      string
		act       ImpersonationAction
		wantMatch bool
	}{
		{"delete matches", actionCheck("impersonate-on:user-info:delete", "pods", ""), true},
		{"deletecollection matches", actionCheck("impersonate-on:user-info:deletecollection", "pods", ""), true},
		{"list does not match", actionCheck("impersonate-on:user-info:list", "pods", ""), false},
		// An action-verb rule must not fire on an identity check.
		{"identity check does not match", identityAction("impersonate:user-info", "users", "jane"), false},
		{"legacy check does not match", identityAction("impersonate", "users", "jane"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := impersonationRuleMatches(rule, tc.act); got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

func TestImpersonationRuleMatches_ActionVerbWildcard(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{ActionVerbs: []string{"*"}}

	for _, verb := range []string{"get", "list", "create", "delete", "patch"} {
		act := actionCheck("impersonate-on:user-info:"+verb, "pods", "")
		if !impersonationRuleMatches(rule, act) {
			t.Errorf("wildcard actionVerbs did not match %q", verb)
		}
	}
}

func TestImpersonationRuleMatches_TargetScoping(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		ActionVerbs:     []string{"get", "list"},
		TargetResources: []string{"secrets"},
		TargetAPIGroups: []string{""},
	}

	tests := []struct {
		name      string
		act       ImpersonationAction
		wantMatch bool
	}{
		{"core secrets get", actionCheck("impersonate-on:user-info:get", "secrets", ""), true},
		{"core secrets list", actionCheck("impersonate-on:user-info:list", "secrets", ""), true},
		{"core pods get", actionCheck("impersonate-on:user-info:get", "pods", ""), false},
		{"other group secrets", actionCheck("impersonate-on:user-info:get", "secrets", "apps"), false},
		{"core secrets delete", actionCheck("impersonate-on:user-info:delete", "secrets", ""), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := impersonationRuleMatches(rule, tc.act); got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

func TestImpersonationRuleMatches_ExtraKeys(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		IdentityResources: []string{"userextras"},
		ExtraKeys:         []string{"example.com/*"},
	}

	tests := []struct {
		extraKey  string
		wantMatch bool
	}{
		{"example.com/scopes", true},
		{"example.com/", true},
		{"other.com/scopes", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.extraKey, func(t *testing.T) {
			act := identityAction("impersonate:user-info", "userextras", "value")
			act.ExtraKey = tc.extraKey
			if got := impersonationRuleMatches(rule, act); got != tc.wantMatch {
				t.Errorf("match for extraKey %q = %v, want %v", tc.extraKey, got, tc.wantMatch)
			}
		})
	}
}

func TestImpersonationRuleMatches_ServiceAccountNamespaces(t *testing.T) {
	rule := breakglassv1alpha1.ImpersonationDenyRule{
		IdentityResources: []string{"serviceaccounts"},
		Namespaces: &breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"kube-*"},
		},
	}

	tests := []struct {
		namespace string
		wantMatch bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"default", false},
		{"my-kube-system", false},
	}

	for _, tc := range tests {
		t.Run(tc.namespace, func(t *testing.T) {
			act := identityAction("impersonate:serviceaccount", "serviceaccounts", "sa")
			act.IdentityNamespace = tc.namespace
			if got := impersonationRuleMatches(rule, act); got != tc.wantMatch {
				t.Errorf("match for namespace %q = %v, want %v", tc.namespace, got, tc.wantMatch)
			}
		})
	}
}

// TestImpersonationRuleMatches_MalformedVerbOnlyMatchesBroadRules asserts we do
// not evaluate attributes parsed out of a verb we already know is bogus.
func TestImpersonationRuleMatches_MalformedVerbOnlyMatchesBroadRules(t *testing.T) {
	malformed := identityAction("impersonate:some-future-mode", "users", "jane")

	if !impersonationRuleMatches(breakglassv1alpha1.ImpersonationDenyRule{}, malformed) {
		t.Error("empty rule did not match a malformed verb")
	}

	narrow := []breakglassv1alpha1.ImpersonationDenyRule{
		{Modes: []breakglassv1alpha1.ImpersonationMode{"user-info"}},
		{IdentityResources: []string{"users"}},
		{Identities: []string{"jane"}},
		{ActionVerbs: []string{"list"}},
	}
	for i, rule := range narrow {
		if impersonationRuleMatches(rule, malformed) {
			t.Errorf("narrow rule %d matched a malformed verb; its attributes are not trustworthy", i)
		}
	}
}

func TestDefaultImpersonationDenyReason(t *testing.T) {
	tests := []struct {
		name     string
		act      ImpersonationAction
		wantSubs []string
	}{
		{
			"legacy",
			identityAction("impersonate", "users", "jane"),
			[]string{"legacy", "unconstrained", "users", "jane"},
		},
		{
			"identity",
			identityAction("impersonate:user-info", "groups", "cluster-admins"),
			[]string{"constrained", "user-info", "groups", "cluster-admins"},
		},
		{
			"action",
			actionCheck("impersonate-on:user-info:delete", "secrets", ""),
			[]string{"delete", "user-info", "secrets"},
		},
		{
			"malformed",
			identityAction("impersonate:future", "users", "jane"),
			[]string{"unrecognised", "impersonate:future"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := defaultImpersonationDenyReason(tc.act)
			for _, sub := range tc.wantSubs {
				if !strings.Contains(got, sub) {
					t.Errorf("reason %q does not contain %q", got, sub)
				}
			}
		})
	}
}

func TestDefaultImpersonationDenyReason_EmptyFieldsRenderReadably(t *testing.T) {
	act := identityAction("impersonate:user-info", "", "")
	got := defaultImpersonationDenyReason(act)

	if strings.Contains(got, `""`) && !strings.Contains(got, "(any)") {
		t.Errorf("reason %q renders empty fields as bare quotes rather than (any)", got)
	}
}

func TestModeMatches(t *testing.T) {
	// An empty mode list matches every mode, which is what makes a bare rule
	// deny-all.
	for _, mode := range impersonation.ModeEvaluationOrder {
		if !modeMatches(nil, mode) {
			t.Errorf("empty mode list did not match %q", mode)
		}
	}

	if !modeMatches([]breakglassv1alpha1.ImpersonationMode{"legacy"}, impersonation.ModeLegacy) {
		t.Error("legacy did not match")
	}
	if modeMatches([]breakglassv1alpha1.ImpersonationMode{"legacy"}, impersonation.ModeUserInfo) {
		t.Error("legacy rule matched user-info")
	}
}

func TestContainsExact(t *testing.T) {
	// containsExact must NOT treat "*" as a wildcard, because it guards enum fields
	// where "*" is not a legal value.
	if !containsExact([]string{"a", "b"}, "a") {
		t.Error("containsExact missed a present value")
	}
	if containsExact([]string{"*"}, "a") {
		t.Error("containsExact treated * as a wildcard")
	}
	if containsExact(nil, "a") {
		t.Error("containsExact matched against a nil slice")
	}
}

func TestIsUnconstrainedRule(t *testing.T) {
	if !isUnconstrainedRule(breakglassv1alpha1.ImpersonationDenyRule{}) {
		t.Error("empty rule not reported as unconstrained")
	}
	// Reason is metadata, not a constraint, so it must not make a rule narrow.
	if !isUnconstrainedRule(breakglassv1alpha1.ImpersonationDenyRule{Reason: "nope"}) {
		t.Error("a rule with only a reason was reported as constrained")
	}

	narrow := []breakglassv1alpha1.ImpersonationDenyRule{
		{Modes: []breakglassv1alpha1.ImpersonationMode{"user-info"}},
		{IdentityResources: []string{"users"}},
		{Identities: []string{"jane"}},
		{ExtraKeys: []string{"k"}},
		{ActionVerbs: []string{"get"}},
		{TargetResources: []string{"pods"}},
		{TargetAPIGroups: []string{""}},
		{Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"x"}}},
	}
	for i, rule := range narrow {
		if isUnconstrainedRule(rule) {
			t.Errorf("narrow rule %d reported as unconstrained", i)
		}
	}
}
