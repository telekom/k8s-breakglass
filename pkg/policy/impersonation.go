// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// ImpersonationAction describes an impersonation authorization check for
// DenyPolicy evaluation. It is derived from the SubjectAccessReview the API
// server sent to the breakglass authorization webhook.
type ImpersonationAction struct {
	// Verb is the classified impersonation verb.
	Verb impersonation.ParsedVerb

	// IdentityResource is the identity resource kind for identity checks
	// (users, groups, uids, userextras, serviceaccounts, nodes). Empty for action
	// checks.
	IdentityResource string

	// Identity is the impersonation target for identity checks: the username,
	// group name, UID, node name, ServiceAccount name or extra value.
	Identity string

	// IdentityNamespace is the namespace for serviceaccounts identity checks.
	IdentityNamespace string

	// ExtraKey is the extra key for userextras identity checks, carried in the
	// SAR's subresource.
	ExtraKey string

	// TargetResource and TargetAPIGroup describe what is being acted on for action
	// checks. These come from the TARGET request's own attributes, not the
	// impersonation target's.
	TargetResource string
	TargetAPIGroup string

	// NamespaceLabels are the labels of IdentityNamespace, when available, for
	// NamespaceFilter selector-term evaluation.
	NamespaceLabels map[string]string

	// ClusterID, Tenant and Session scope the action for DenyPolicy.appliesTo.
	ClusterID string
	Tenant    string
	Session   string
}

// MatchImpersonation reports whether any DenyPolicy denies the given
// impersonation check, returning the policy name and a user-facing reason.
func (e *Evaluator) MatchImpersonation(ctx context.Context, act ImpersonationAction) (bool, string, string, error) {
	policies, err := e.listPolicies(ctx)
	if err != nil {
		return false, "", "", err
	}
	sortPoliciesByPrecedence(policies)

	scopeAct := Action{ClusterID: act.ClusterID, Tenant: act.Tenant, Session: act.Session}

	for _, pol := range policies {
		if !scopeMatches(pol.Spec.AppliesTo, scopeAct) {
			continue
		}
		for i, rule := range pol.Spec.ImpersonationRules {
			if impersonationRuleMatches(rule, act) {
				reason := rule.Reason
				if reason == "" {
					reason = defaultImpersonationDenyReason(act)
				}
				if e.log != nil {
					e.log.Infow("Impersonation denied by DenyPolicy",
						"policy", pol.Name,
						"ruleIndex", i,
						"verb", act.Verb.Raw,
						"verbKind", act.Verb.Kind.String(),
						"mode", string(act.Verb.Mode),
						"identityResource", act.IdentityResource,
						"identity", act.Identity,
						"cluster", act.ClusterID)
				}
				return true, pol.Name, reason, nil
			}
		}
	}

	return false, "", "", nil
}

// impersonationRuleMatches evaluates one ImpersonationDenyRule against a check.
//
// An empty rule matches everything, which is the documented way to write "no
// impersonation on this cluster at all".
func impersonationRuleMatches(r breakglassv1alpha1.ImpersonationDenyRule, act ImpersonationAction) bool {
	// Malformed impersonation verbs carry no trustworthy mode or target, so only a
	// rule that constrains nothing can meaningfully match them. Anything narrower
	// would be evaluating fields parsed out of a verb we already know is bogus.
	if act.Verb.Kind == impersonation.VerbKindMalformed {
		return isUnconstrainedRule(r)
	}

	if !modeMatches(r.Modes, act.Verb.Mode) {
		return false
	}

	isAction := act.Verb.Kind == impersonation.VerbKindAction

	// A rule naming action verbs only applies to action checks, and vice versa for
	// identity-specific fields. The API server issues these as separate
	// authorization requests, so a rule cannot straddle both.
	if len(r.ActionVerbs) > 0 {
		if !isAction {
			return false
		}
		if !contains(r.ActionVerbs, act.Verb.UnderlyingVerb) {
			return false
		}
		if len(r.TargetResources) > 0 && !contains(r.TargetResources, act.TargetResource) {
			return false
		}
		if len(r.TargetAPIGroups) > 0 && !contains(r.TargetAPIGroups, act.TargetAPIGroup) {
			return false
		}
		return true
	}

	// Identity-scoping fields only apply to identity checks.
	hasIdentityScope := len(r.IdentityResources) > 0 ||
		len(r.Identities) > 0 ||
		len(r.ExtraKeys) > 0 ||
		!r.Namespaces.IsEmpty()

	if hasIdentityScope && isAction {
		return false
	}

	if len(r.IdentityResources) > 0 && !containsExact(r.IdentityResources, act.IdentityResource) {
		return false
	}

	if len(r.Identities) > 0 {
		// The API server collapses per-item checks into a single "*" check once a
		// request names four or more items. A literal "*" identity must therefore
		// match any rule that names identities at all, otherwise a policy listing
		// specific usernames would be silently bypassed by requesting many at once.
		if act.Identity != "*" && !matchAny(r.Identities, act.Identity) {
			return false
		}
	}

	if len(r.ExtraKeys) > 0 && !matchAny(r.ExtraKeys, act.ExtraKey) {
		return false
	}

	if !r.Namespaces.IsEmpty() {
		nsMatcher := utils.NewNamespaceMatcher(r.Namespaces)
		if act.NamespaceLabels != nil {
			if !nsMatcher.MatchesWithLabels(act.IdentityNamespace, act.NamespaceLabels) {
				return false
			}
		} else {
			if r.Namespaces.HasSelectorTerms() && !r.Namespaces.HasPatterns() {
				return false
			}
			if !nsMatcher.Matches(act.IdentityNamespace) {
				return false
			}
		}
	}

	return true
}

// isUnconstrainedRule reports whether a rule constrains nothing beyond, possibly,
// the mode — i.e. whether it is broad enough to apply to a check whose attributes
// could not be parsed.
func isUnconstrainedRule(r breakglassv1alpha1.ImpersonationDenyRule) bool {
	return len(r.IdentityResources) == 0 &&
		len(r.Identities) == 0 &&
		len(r.ExtraKeys) == 0 &&
		len(r.ActionVerbs) == 0 &&
		len(r.TargetResources) == 0 &&
		len(r.TargetAPIGroups) == 0 &&
		r.Namespaces.IsEmpty() &&
		len(r.Modes) == 0
}

// modeMatches reports whether the rule's mode list covers mode. An empty list
// matches every mode.
func modeMatches(modes []breakglassv1alpha1.ImpersonationMode, mode impersonation.Mode) bool {
	if len(modes) == 0 {
		return true
	}
	for _, m := range modes {
		if string(m) == string(mode) {
			return true
		}
	}
	return false
}

// containsExact is contains without the "*" wildcard, for enum-valued fields
// where "*" is not a legal value.
func containsExact(sl []string, v string) bool {
	for _, s := range sl {
		if s == v {
			return true
		}
	}
	return false
}

func defaultImpersonationDenyReason(act ImpersonationAction) string {
	switch act.Verb.Kind {
	case impersonation.VerbKindLegacyImpersonate:
		return fmt.Sprintf("Denied by DenyPolicy: legacy (unconstrained) impersonation of %s %q",
			orAny(act.IdentityResource), orAny(act.Identity))
	case impersonation.VerbKindIdentity:
		return fmt.Sprintf(
			"Denied by DenyPolicy: constrained impersonation (mode %s) of %s %q",
			act.Verb.Mode, orAny(act.IdentityResource), orAny(act.Identity))
	case impersonation.VerbKindAction:
		target := act.TargetResource
		if act.TargetAPIGroup != "" {
			target = act.TargetAPIGroup + "/" + target
		}
		return fmt.Sprintf(
			"Denied by DenyPolicy: %q under constrained impersonation (mode %s) on %s",
			act.Verb.UnderlyingVerb, act.Verb.Mode, orAny(target))
	case impersonation.VerbKindMalformed:
		return fmt.Sprintf("Denied by DenyPolicy: unrecognised impersonation verb %q", act.Verb.Raw)
	case impersonation.VerbKindOther:
		return fmt.Sprintf("Denied by DenyPolicy: %q", act.Verb.Raw)
	default:
		return fmt.Sprintf("Denied by DenyPolicy: %q", act.Verb.Raw)
	}
}

func orAny(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(any)"
	}
	return s
}
