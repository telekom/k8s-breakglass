// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestInferImpersonationMode(t *testing.T) {
	tests := []struct {
		name string
		ic   *ImpersonationConfig
		want ImpersonationMode
	}{
		{"nil", nil, ImpersonationModeLegacy},
		{"empty", &ImpersonationConfig{}, ImpersonationModeLegacy},
		{
			"explicit mode wins",
			&ImpersonationConfig{Mode: ImpersonationModeUserInfo, UserName: "jane"},
			ImpersonationModeUserInfo,
		},
		{
			"explicit legacy wins over serviceAccountRef",
			&ImpersonationConfig{
				Mode:              ImpersonationModeLegacy,
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
			},
			ImpersonationModeLegacy,
		},
		// Backwards compatibility: an existing template that only sets
		// serviceAccountRef infers serviceaccount mode, which its only-username-set
		// shape already satisfies. Nothing about it needs to change.
		{
			"serviceAccountRef infers serviceaccount",
			&ImpersonationConfig{ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"}},
			ImpersonationModeServiceAccount,
		},
		{
			"node username infers arbitrary-node",
			&ImpersonationConfig{UserName: "system:node:worker-1"},
			ImpersonationModeArbitraryNode,
		},
		{
			"plain username infers user-info",
			&ImpersonationConfig{UserName: "jane@example.com"},
			ImpersonationModeUserInfo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := InferImpersonationMode(tc.ic); got != tc.want {
				t.Errorf("InferImpersonationMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectiveImpersonationUserName(t *testing.T) {
	tests := []struct {
		name string
		ic   *ImpersonationConfig
		want string
	}{
		{"nil", nil, ""},
		{"empty", &ImpersonationConfig{}, ""},
		{"userName", &ImpersonationConfig{UserName: "jane"}, "jane"},
		{
			"serviceAccountRef expands",
			&ImpersonationConfig{ServiceAccountRef: &ServiceAccountReference{Name: "probe", Namespace: "kube-system"}},
			"system:serviceaccount:kube-system:probe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveImpersonationUserName(tc.ic); got != tc.want {
				t.Errorf("EffectiveImpersonationUserName() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestValidateImpersonationConstraints_BackwardsCompatible is the compatibility
// contract at the API level: every ImpersonationConfig that was valid before this
// feature existed must remain valid, with zero values reproducing today's behaviour.
func TestValidateImpersonationConstraints_BackwardsCompatible(t *testing.T) {
	preExisting := []*ImpersonationConfig{
		// The only shape the type supported before: a bare serviceAccountRef.
		{ServiceAccountRef: &ServiceAccountReference{Name: "debug-deployer", Namespace: "breakglass-debug"}},
		{ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "default"}},
		// An empty config was and remains legal.
		{},
		nil,
	}

	for i, ic := range preExisting {
		errs := validateImpersonationConstraints(ic, field.NewPath("spec", "impersonation"))
		if len(errs) > 0 {
			t.Errorf("pre-existing config %d rejected by new validation: %v", i, errs)
		}
	}
}

func TestValidateImpersonationConstraints_ValidConfigs(t *testing.T) {
	tests := []struct {
		name string
		ic   *ImpersonationConfig
	}{
		{"user-info plain", &ImpersonationConfig{Mode: ImpersonationModeUserInfo, UserName: "jane@example.com"}},
		{
			"user-info full",
			&ImpersonationConfig{
				Mode:     ImpersonationModeUserInfo,
				UserName: "jane@example.com",
				UID:      "uid-1",
				Groups:   []string{"devs", "sre"},
				Extra:    map[string][]string{"example.com/scopes": {"read"}},
			},
		},
		{
			"serviceaccount via ref",
			&ImpersonationConfig{
				Mode:              ImpersonationModeServiceAccount,
				ServiceAccountRef: &ServiceAccountReference{Name: "probe", Namespace: "kube-system"},
			},
		},
		{
			"serviceaccount via username",
			&ImpersonationConfig{
				Mode:     ImpersonationModeServiceAccount,
				UserName: "system:serviceaccount:kube-system:probe",
			},
		},
		{"arbitrary-node", &ImpersonationConfig{Mode: ImpersonationModeArbitraryNode, UserName: "system:node:worker-1"}},
		{
			"arbitrary-node fqdn",
			&ImpersonationConfig{Mode: ImpersonationModeArbitraryNode, UserName: "system:node:worker-1.example.com"},
		},
		// associated-node is deliberately absent: it is rejected at admission. See
		// TestValidateImpersonationConstraints_AssociatedNodeRejected.
		{
			"legacy tolerates anything short of system:masters",
			&ImpersonationConfig{
				Mode:     ImpersonationModeLegacy,
				UserName: "system:node:whatever",
				UID:      "u",
				Groups:   []string{"g"},
				Extra:    map[string][]string{"NOT-lowercase": {""}},
			},
		},
		{
			"allowlist and action verbs",
			&ImpersonationConfig{
				Mode:              ImpersonationModeUserInfo,
				UserName:          "jane",
				AllowedIdentities: []string{"jane"},
				ActionVerbs:       []string{"get", "list"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateImpersonationConstraints(tc.ic, field.NewPath("spec", "impersonation"))
			if len(errs) > 0 {
				t.Errorf("valid config rejected: %v", errs)
			}
		})
	}
}

// TestValidateImpersonationConstraints_HeaderMixingTrapRejected is the admission
// guardrail for the KEP's central footgun.
func TestValidateImpersonationConstraints_HeaderMixingTrapRejected(t *testing.T) {
	mixingModes := []struct {
		mode     ImpersonationMode
		username string
	}{
		{ImpersonationModeServiceAccount, "system:serviceaccount:ns:sa"},
		{ImpersonationModeArbitraryNode, "system:node:worker-1"},
		// associated-node omitted: rejected outright before the mixing check runs.
	}

	offenders := []struct {
		name   string
		mutate func(*ImpersonationConfig)
	}{
		{"uid", func(ic *ImpersonationConfig) { ic.UID = "uid-1" }},
		{"groups", func(ic *ImpersonationConfig) { ic.Groups = []string{"custom"} }},
		{"extra", func(ic *ImpersonationConfig) { ic.Extra = map[string][]string{"ex.io/k": {"v"}} }},
	}

	for _, mm := range mixingModes {
		for _, off := range offenders {
			t.Run(string(mm.mode)+"/"+off.name, func(t *testing.T) {
				ic := &ImpersonationConfig{Mode: mm.mode, UserName: mm.username}
				off.mutate(ic)

				errs := validateImpersonationConstraints(ic, field.NewPath("spec", "impersonation"))
				if len(errs) == 0 {
					t.Fatalf("mode %q with %s set was accepted; the API server would silently "+
						"fall back to legacy unconstrained impersonation", mm.mode, off.name)
				}

				// The error must explain the silent-fallback consequence, otherwise the
				// operator has no way to understand why the object was rejected.
				explained := false
				for _, e := range errs {
					if strings.Contains(e.Detail, "legacy") {
						explained = true
					}
				}
				if !explained {
					t.Errorf("no error explained the legacy fallback: %v", errs)
				}
			})
		}
	}
}

func TestValidateImpersonationConstraints_SystemMastersRejectedInEveryMode(t *testing.T) {
	// The API server hard-denies system:masters in constrained mode but NOT for
	// legacy. Breakglass refuses it everywhere.
	// associated-node is excluded because it is rejected for being that mode at all,
	// before the system:masters check is reached. It is therefore still refused — just
	// for a different, stricter reason. See
	// TestValidateImpersonationConstraints_AssociatedNodeRejected.
	modes := []ImpersonationMode{
		ImpersonationModeUserInfo, ImpersonationModeServiceAccount,
		ImpersonationModeArbitraryNode,
		ImpersonationModeLegacy,
	}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			ic := &ImpersonationConfig{
				Mode:     mode,
				UserName: "jane",
				Groups:   []string{"system:masters"},
			}
			errs := validateImpersonationConstraints(ic, field.NewPath("spec", "impersonation"))

			found := false
			for _, e := range errs {
				if strings.Contains(e.Detail, "system:masters") {
					found = true
				}
			}
			if !found {
				t.Errorf("system:masters accepted in mode %q: %v", mode, errs)
			}
		})
	}
}

func TestValidateImpersonationConstraints_InvalidConfigs(t *testing.T) {
	tests := []struct {
		name    string
		ic      *ImpersonationConfig
		wantSub string
	}{
		{
			"unknown mode",
			&ImpersonationConfig{Mode: ImpersonationMode("future-mode"), UserName: "jane"},
			"",
		},
		{
			"userName and serviceAccountRef both set",
			&ImpersonationConfig{
				Mode:              ImpersonationModeServiceAccount,
				UserName:          "system:serviceaccount:ns:sa",
				ServiceAccountRef: &ServiceAccountReference{Name: "sa", Namespace: "ns"},
			},
			"mutually exclusive",
		},
		{
			"user-info with node username",
			&ImpersonationConfig{Mode: ImpersonationModeUserInfo, UserName: "system:node:worker-1"},
			"refuses node usernames",
		},
		{
			"user-info with SA username",
			&ImpersonationConfig{Mode: ImpersonationModeUserInfo, UserName: "system:serviceaccount:ns:sa"},
			"refuses ServiceAccount usernames",
		},
		{
			"user-info without username",
			&ImpersonationConfig{Mode: ImpersonationModeUserInfo},
			"requires a userName",
		},
		{
			"serviceaccount mode with plain username",
			&ImpersonationConfig{Mode: ImpersonationModeServiceAccount, UserName: "jane"},
			"requires a serviceAccountRef",
		},
		{
			"node mode with plain username",
			&ImpersonationConfig{Mode: ImpersonationModeArbitraryNode, UserName: "jane"},
			"requires a system:node:<name> username",
		},
		{
			// arbitrary-node is only selected when the node name is a valid DNS
			// subdomain; otherwise the API server falls back to legacy.
			"node mode with invalid DNS node name",
			&ImpersonationConfig{Mode: ImpersonationModeArbitraryNode, UserName: "system:node:NOT_VALID"},
			"valid DNS subdomain",
		},
		{
			"empty group",
			&ImpersonationConfig{Mode: ImpersonationModeUserInfo, UserName: "jane", Groups: []string{""}},
			"must not be empty",
		},
		{
			"extra key not lowercase",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				Extra: map[string][]string{"Example.com/Key": {"v"}},
			},
			"lowercase",
		},
		{
			"extra key not domain prefixed",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				Extra: map[string][]string{"key": {"v"}},
			},
			"domain-prefixed path",
		},
		{
			"extra empty values",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				Extra: map[string][]string{"example.com/key": {}},
			},
			"must not be empty",
		},
		{
			"extra empty string value",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				Extra: map[string][]string{"example.com/key": {""}},
			},
			"must not be empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateImpersonationConstraints(tc.ic, field.NewPath("spec", "impersonation"))
			if len(errs) == 0 {
				t.Fatalf("invalid config accepted")
			}
			if tc.wantSub == "" {
				return
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e.Detail, tc.wantSub) || strings.Contains(e.Error(), tc.wantSub) {
					found = true
				}
			}
			if !found {
				t.Errorf("errors %v do not mention %q", errs, tc.wantSub)
			}
		})
	}
}

func TestWarnImpersonationConfigIssues(t *testing.T) {
	tests := []struct {
		name       string
		ic         *ImpersonationConfig
		wantSub    string
		wantNoWarn bool
	}{
		{"nil", nil, "", true},
		{
			"legacy warns about no constraint",
			&ImpersonationConfig{Mode: ImpersonationModeLegacy, UserName: "jane"},
			"no constraint is applied", false,
		},
		{
			// The apiserver collapses to a wildcard check at 4+ items.
			"four groups warns about wildcard collapse",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				Groups: []string{"a", "b", "c", "d"},
			},
			"wildcard", false,
		},
		{
			"three groups does not warn",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				Groups: []string{"a", "b", "c"},
			},
			"", true,
		},
		{
			"union semantics cross product",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				AllowedIdentities: []string{"a", "b"},
				ActionVerbs:       []string{"get", "list"},
			},
			"cross product", false,
		},
		{
			// Kubernetes has no prefix wildcard for impersonate-on verbs.
			"partial action verb wildcard never matches",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				ActionVerbs: []string{"get*"},
			},
			"never match", false,
		},
		{
			"bare star action verb does not warn",
			&ImpersonationConfig{
				Mode: ImpersonationModeUserInfo, UserName: "jane",
				ActionVerbs: []string{"*"},
			},
			"", true,
		},
		{
			// associated-node is a hard admission ERROR, not a warning, so warning on
			// it too would be noise the operator can never act on differently.
			"associated-node does not warn because it is rejected outright",
			&ImpersonationConfig{Mode: ImpersonationModeAssociatedNode, UserName: "system:node:w1"},
			"", true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warnings := warnImpersonationConfigIssues(tc.ic, field.NewPath("spec", "impersonation"))

			if tc.wantNoWarn {
				if len(warnings) > 0 {
					t.Errorf("unexpected warnings: %v", warnings)
				}
				return
			}

			joined := strings.Join(warnings, " | ")
			if !strings.Contains(joined, tc.wantSub) {
				t.Errorf("warnings %q do not mention %q", joined, tc.wantSub)
			}
		})
	}
}

func TestValidateImpersonationDenyRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []ImpersonationDenyRule
		wantSub string
	}{
		{"empty list", nil, ""},
		{"bare rule is valid (deny all)", []ImpersonationDenyRule{{}}, ""},
		{
			"valid identity rule",
			[]ImpersonationDenyRule{{
				Modes:             []ImpersonationMode{ImpersonationModeUserInfo, ImpersonationModeLegacy},
				IdentityResources: []string{"groups"},
				Identities:        []string{"cluster-admins"},
			}},
			"",
		},
		{
			"valid action rule",
			[]ImpersonationDenyRule{{
				ActionVerbs:     []string{"delete"},
				TargetResources: []string{"secrets"},
				TargetAPIGroups: []string{""},
			}},
			"",
		},
		{
			"unknown mode",
			[]ImpersonationDenyRule{{Modes: []ImpersonationMode{"future"}}},
			"future",
		},
		{
			"unknown identity resource",
			[]ImpersonationDenyRule{{IdentityResources: []string{"pods"}}},
			"must be one of",
		},
		{
			// The API server issues identity and action checks as separate requests,
			// so a rule requiring both could never fire.
			"identities and actionVerbs combined",
			[]ImpersonationDenyRule{{
				Identities:  []string{"jane"},
				ActionVerbs: []string{"get"},
			}},
			"separate authorization requests",
		},
		{
			"targetResources without actionVerbs",
			[]ImpersonationDenyRule{{TargetResources: []string{"pods"}}},
			"only applies to action checks",
		},
		{
			"targetAPIGroups without actionVerbs",
			[]ImpersonationDenyRule{{TargetAPIGroups: []string{"apps"}}},
			"only applies to action checks",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateImpersonationDenyRules(tc.rules, field.NewPath("spec", "impersonationRules"))

			if tc.wantSub == "" {
				if len(errs) > 0 {
					t.Errorf("valid rules rejected: %v", errs)
				}
				return
			}

			if len(errs) == 0 {
				t.Fatal("invalid rules accepted")
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e.Error(), tc.wantSub) {
					found = true
				}
			}
			if !found {
				t.Errorf("errors %v do not mention %q", errs, tc.wantSub)
			}
		})
	}
}

// TestWarnImpersonationDenyRuleIssues_LegacyEscapeHatch is the highest-value
// warning: a rule denying only the constrained modes is defeated by the API
// server's legacy fallback.
func TestWarnImpersonationDenyRuleIssues_LegacyEscapeHatch(t *testing.T) {
	constrainedOnly := []ImpersonationDenyRule{{
		Modes: []ImpersonationMode{ImpersonationModeUserInfo, ImpersonationModeServiceAccount},
	}}

	warnings := warnImpersonationDenyRuleIssues(constrainedOnly, field.NewPath("spec", "impersonationRules"))
	joined := strings.Join(warnings, " | ")

	if !strings.Contains(joined, "legacy") {
		t.Errorf("no warning about the legacy fallback escape hatch: %q", joined)
	}

	// Including legacy silences the warning.
	withLegacy := []ImpersonationDenyRule{{
		Modes: []ImpersonationMode{ImpersonationModeUserInfo, ImpersonationModeLegacy},
	}}
	warnings = warnImpersonationDenyRuleIssues(withLegacy, field.NewPath("spec", "impersonationRules"))
	for _, w := range warnings {
		if strings.Contains(w, "close the fallback") {
			t.Errorf("still warned about the fallback despite legacy being listed: %q", w)
		}
	}

	// A rule with no modes at all matches every mode including legacy, so it must
	// not warn either.
	warnings = warnImpersonationDenyRuleIssues([]ImpersonationDenyRule{{}}, field.NewPath("x"))
	if len(warnings) > 0 {
		t.Errorf("a deny-all rule produced warnings: %v", warnings)
	}
}

func TestWarnImpersonationDenyRuleIssues_IneffectiveFields(t *testing.T) {
	tests := []struct {
		name    string
		rule    ImpersonationDenyRule
		wantSub string
	}{
		{
			"extraKeys without userextras",
			ImpersonationDenyRule{
				Modes:             []ImpersonationMode{ImpersonationModeLegacy},
				IdentityResources: []string{"users"},
				ExtraKeys:         []string{"k"},
			},
			"no effect",
		},
		{
			"namespaces without serviceaccounts",
			ImpersonationDenyRule{
				Modes:             []ImpersonationMode{ImpersonationModeLegacy},
				IdentityResources: []string{"users"},
				Namespaces:        &NamespaceFilter{Patterns: []string{"kube-*"}},
			},
			"no effect",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warnings := warnImpersonationDenyRuleIssues(
				[]ImpersonationDenyRule{tc.rule}, field.NewPath("spec", "impersonationRules"))
			joined := strings.Join(warnings, " | ")
			if !strings.Contains(joined, tc.wantSub) {
				t.Errorf("warnings %q do not mention %q", joined, tc.wantSub)
			}
		})
	}
}

// TestConstrainedImpersonationConfigAccessors covers the nil-receiver defaults.
// These matter for backwards compatibility: a ClusterConfig onboarded before the
// field existed has a nil block and must get the safe defaults.
func TestConstrainedImpersonationConfigAccessors(t *testing.T) {
	var nilCfg *ConstrainedImpersonationConfig

	if got := nilCfg.EffectiveSupport(); got != ConstrainedImpersonationAuto {
		t.Errorf("nil EffectiveSupport() = %q, want Auto", got)
	}
	if got := nilCfg.EffectiveLegacyFallback(); got != LegacyImpersonationFallbackAllow {
		t.Errorf("nil EffectiveLegacyFallback() = %q, want Allow: existing deployments depend "+
			"on the legacy fallback", got)
	}
	// This default is the security-critical one: an old ClusterConfig must still
	// deny impersonation verbs the webhook cannot parse.
	if !nilCfg.ShouldDenyUnrecognisedVerbs() {
		t.Error("nil ShouldDenyUnrecognisedVerbs() = false; a ClusterConfig predating this " +
			"field would silently grant constrained impersonation")
	}
	if got := nilCfg.EffectiveProbeMode(); got != ImpersonationModeUserInfo {
		t.Errorf("nil EffectiveProbeMode() = %q, want user-info", got)
	}

	// An empty (non-nil) block must behave identically.
	empty := &ConstrainedImpersonationConfig{}
	if empty.EffectiveSupport() != ConstrainedImpersonationAuto ||
		empty.EffectiveLegacyFallback() != LegacyImpersonationFallbackAllow ||
		!empty.ShouldDenyUnrecognisedVerbs() ||
		empty.EffectiveProbeMode() != ImpersonationModeUserInfo {
		t.Error("an empty config block does not reproduce the nil defaults")
	}

	// Explicit values are honoured.
	no := false
	explicit := &ConstrainedImpersonationConfig{
		Support:               ConstrainedImpersonationDisabled,
		LegacyFallback:        LegacyImpersonationFallbackForbidden,
		DenyUnrecognisedVerbs: &no,
		ProbeMode:             ImpersonationModeLegacy,
	}
	if explicit.EffectiveSupport() != ConstrainedImpersonationDisabled {
		t.Error("explicit Support not honoured")
	}
	if explicit.EffectiveLegacyFallback() != LegacyImpersonationFallbackForbidden {
		t.Error("explicit LegacyFallback not honoured")
	}
	if explicit.ShouldDenyUnrecognisedVerbs() {
		t.Error("explicit DenyUnrecognisedVerbs=false not honoured")
	}
	if explicit.EffectiveProbeMode() != ImpersonationModeLegacy {
		t.Error("explicit ProbeMode not honoured")
	}
}
