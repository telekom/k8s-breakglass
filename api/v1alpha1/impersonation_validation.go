// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Constrained-impersonation constants duplicated here so that api/v1alpha1 stays
// free of dependencies on pkg/. pkg/impersonation holds the canonical
// definitions and pkg/impersonation/apiconsistency_test.go asserts these agree.
const (
	impGroupSystemMasters   = "system:masters"
	impUsernameNodePrefix   = "system:node:"
	impUsernameSAPrefix     = "system:serviceaccount:"
	impManyChecksInLoop     = 4
	impIdentityResourceList = "users, groups, uids, userextras, serviceaccounts, nodes"
)

// validImpersonationModes is the set of modes accepted by the CRD enum.
var validImpersonationModes = map[ImpersonationMode]bool{
	ImpersonationModeUserInfo:       true,
	ImpersonationModeServiceAccount: true,
	ImpersonationModeArbitraryNode:  true,
	ImpersonationModeAssociatedNode: true,
	ImpersonationModeLegacy:         true,
}

// validImpersonationIdentityResources is the set of identity resource kinds the
// API server evaluates constrained identity checks against.
var validImpersonationIdentityResources = map[string]bool{
	"users":           true,
	"groups":          true,
	"uids":            true,
	"userextras":      true,
	"serviceaccounts": true,
	"nodes":           true,
}

// InferImpersonationMode returns the mode an ImpersonationConfig describes when
// spec.mode is not set explicitly. A ServiceAccount target implies serviceaccount
// mode, a system:node: username implies arbitrary-node, and anything else with a
// username implies user-info.
//
// An empty config infers legacy, which is what pre-existing DebugSessionTemplates
// that only set serviceAccountRef relied on before the mode field existed — those
// keep working unchanged because serviceAccountRef alone infers serviceaccount
// mode and satisfies the only-username-set requirement by construction.
func InferImpersonationMode(ic *ImpersonationConfig) ImpersonationMode {
	if ic == nil {
		return ImpersonationModeLegacy
	}
	if ic.Mode != "" {
		return ic.Mode
	}
	if ic.ServiceAccountRef != nil {
		return ImpersonationModeServiceAccount
	}
	if strings.HasPrefix(ic.UserName, impUsernameNodePrefix) {
		return ImpersonationModeArbitraryNode
	}
	if ic.UserName != "" {
		return ImpersonationModeUserInfo
	}
	return ImpersonationModeLegacy
}

// EffectiveImpersonationUserName renders the username the config impersonates,
// expanding a serviceAccountRef into its system:serviceaccount:<ns>:<name> form.
func EffectiveImpersonationUserName(ic *ImpersonationConfig) string {
	if ic == nil {
		return ""
	}
	if ic.ServiceAccountRef != nil {
		return fmt.Sprintf("%s%s:%s", impUsernameSAPrefix,
			ic.ServiceAccountRef.Namespace, ic.ServiceAccountRef.Name)
	}
	return ic.UserName
}

// validateImpersonationConstraints validates the constrained-impersonation fields
// of an ImpersonationConfig. It enforces every restriction the API server applies
// in constrained mode plus the breakglass guardrails, so that a configuration
// which would silently degrade to legacy impersonation is rejected at admission
// rather than discovered in an audit log months later.
func validateImpersonationConstraints(ic *ImpersonationConfig, fieldPath *field.Path) field.ErrorList {
	if ic == nil {
		return nil
	}

	var errs field.ErrorList

	if ic.Mode != "" && !validImpersonationModes[ic.Mode] {
		errs = append(errs, field.NotSupported(fieldPath.Child("mode"), ic.Mode,
			[]string{"user-info", "serviceaccount", "arbitrary-node", "associated-node", "legacy"}))
		return errs
	}

	// associated-node is a valid KEP-5284 mode, and the authorization webhook still
	// recognises and can deny its verbs, but breakglass cannot CONFIGURE it. Rejecting
	// it here converts a mid-incident runtime failure into a `kubectl apply` error.
	//
	// Why it cannot work, rather than merely being unimplemented: the mode is only
	// selected when the impersonated node name equals the REQUESTOR's own node, taken
	// from its authentication.kubernetes.io/node-name extra. Satisfying that would mean
	// injecting the controller pod's own node via the downward API — and the node the
	// controller happens to be scheduled on is arbitrary with respect to the spoke
	// cluster, the session and the target workload. Breakglass authorizes humans via
	// OIDC, not node-bound ServiceAccounts, so a controller impersonating its own node
	// grants something semantically meaningless. Wiring it would turn a loud failure
	// into a silent fake success, which is strictly worse.
	if ic.Mode == ImpersonationModeAssociatedNode {
		errs = append(errs, field.Invalid(fieldPath.Child("mode"), ic.Mode,
			"mode associated-node is not supported by breakglass. The API server only selects it "+
				"when the impersonated node matches the REQUESTOR's own node (via its "+
				"authentication.kubernetes.io/node-name extra), so it requires a node-bound "+
				"ServiceAccount token. Breakglass authorizes human users via OIDC and has no "+
				"node-bound identity, so this mode would fail at deploy time or silently fall back "+
				"to legacy (unconstrained) impersonation. Use arbitrary-node to impersonate a "+
				"specific node, serviceaccount for a ServiceAccount, or user-info for a user."))
		return errs
	}

	mode := InferImpersonationMode(ic)

	if ic.ServiceAccountRef != nil && ic.UserName != "" {
		errs = append(errs, field.Invalid(fieldPath.Child("userName"), ic.UserName,
			"userName and serviceAccountRef are mutually exclusive"))
	}

	// system:masters is refused in every mode. The API server hard-denies it for
	// constrained impersonation but deliberately does NOT for legacy, so relying on
	// the API server alone leaves the legacy path wide open.
	for i, g := range ic.Groups {
		if g == impGroupSystemMasters {
			errs = append(errs, field.Invalid(fieldPath.Child("groups").Index(i), g,
				"impersonating the system:masters group is not allowed"))
		}
	}

	if mode == ImpersonationModeLegacy {
		// The constrained restrictions do not apply to legacy impersonation, and
		// legacy carries no uid/groups/extra semantics worth validating beyond the
		// system:masters guardrail above.
		return errs
	}

	errs = append(errs, validateImpersonationExtra(ic.Extra, fieldPath.Child("extra"))...)

	for i, g := range ic.Groups {
		if g == "" {
			errs = append(errs, field.Invalid(fieldPath.Child("groups").Index(i), g,
				"impersonated group must not be empty"))
		}
	}

	username := EffectiveImpersonationUserName(ic)

	switch mode {
	case ImpersonationModeArbitraryNode, ImpersonationModeAssociatedNode:
		errs = append(errs, validateNodeImpersonation(ic, mode, username, fieldPath)...)

	case ImpersonationModeServiceAccount:
		if !strings.HasPrefix(username, impUsernameSAPrefix) {
			errs = append(errs, field.Invalid(fieldPath.Child("userName"), username,
				"mode serviceaccount requires a serviceAccountRef or a "+
					impUsernameSAPrefix+"<namespace>:<name> username"))
		}
		if len(ic.Groups) > 0 {
			errs = append(errs, field.Invalid(fieldPath.Child("groups"), ic.Groups,
				"groups cannot be impersonated for a ServiceAccount identity; "+
					"the API server computes them from the namespace"))
		}

	case ImpersonationModeUserInfo:
		if strings.HasPrefix(username, impUsernameNodePrefix) {
			errs = append(errs, field.Invalid(fieldPath.Child("userName"), username,
				"mode user-info refuses node usernames; use arbitrary-node or associated-node"))
		}
		if strings.HasPrefix(username, impUsernameSAPrefix) {
			errs = append(errs, field.Invalid(fieldPath.Child("userName"), username,
				"mode user-info refuses ServiceAccount usernames; use mode serviceaccount"))
		}
		if username == "" {
			errs = append(errs, field.Required(fieldPath.Child("userName"),
				"mode user-info requires a userName"))
		}

	case ImpersonationModeLegacy:
		// Handled by the early return above.
	}

	// The header-mixing trap: node and serviceaccount modes require that only the
	// username be set. Anything else and the API server skips constrained
	// impersonation entirely, falls through user-info (which refuses these
	// usernames) and lands on legacy — succeeding with no constraint applied.
	if mode == ImpersonationModeServiceAccount ||
		mode == ImpersonationModeArbitraryNode ||
		mode == ImpersonationModeAssociatedNode {
		errs = append(errs, validateOnlyUsernameSet(ic, mode, fieldPath)...)
	}

	return errs
}

func validateNodeImpersonation(
	ic *ImpersonationConfig,
	mode ImpersonationMode,
	username string,
	fieldPath *field.Path,
) field.ErrorList {
	var errs field.ErrorList

	if !strings.HasPrefix(username, impUsernameNodePrefix) {
		errs = append(errs, field.Invalid(fieldPath.Child("userName"), username,
			fmt.Sprintf("mode %s requires a %s<name> username", mode, impUsernameNodePrefix)))
		return errs
	}

	nodeName := strings.TrimPrefix(username, impUsernameNodePrefix)
	// arbitrary-node mode is only selected when the node name is a valid DNS
	// subdomain; otherwise the API server falls through to legacy.
	if msgs := validation.IsDNS1123Subdomain(nodeName); len(msgs) > 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("userName"), username,
			"node name must be a valid DNS subdomain for node impersonation modes to be "+
				"selected, otherwise the API server falls back to legacy impersonation: "+
				strings.Join(msgs, "; ")))
	}

	if len(ic.Groups) > 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("groups"), ic.Groups,
			"groups cannot be impersonated for a node identity; "+
				"the API server forces groups=[system:nodes]"))
	}

	return errs
}

// validateOnlyUsernameSet enforces the API server's onlyUsernameSet() precondition.
func validateOnlyUsernameSet(
	ic *ImpersonationConfig,
	mode ImpersonationMode,
	fieldPath *field.Path,
) field.ErrorList {
	var errs field.ErrorList

	msg := fmt.Sprintf(
		"mode %s requires that ONLY the username is set; setting this field makes the API server "+
			"skip constrained impersonation and silently fall back to legacy (unconstrained) "+
			"impersonation", mode)

	if ic.UID != "" {
		errs = append(errs, field.Invalid(fieldPath.Child("uid"), ic.UID, msg))
	}
	if len(ic.Groups) > 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("groups"), ic.Groups, msg))
	}
	if len(ic.Extra) > 0 {
		errs = append(errs, field.Invalid(fieldPath.Child("extra"), keysOf(ic.Extra), msg))
	}

	return errs
}

// validateImpersonationExtra mirrors the API server's validateExtra.
func validateImpersonationExtra(extra map[string][]string, fieldPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	for k, vals := range extra {
		keyPath := fieldPath.Key(k)

		if k == "" {
			errs = append(errs, field.Required(fieldPath, "extra key must not be empty"))
			continue
		}
		if k != strings.ToLower(k) {
			errs = append(errs, field.Invalid(keyPath, k, "extra key must be lowercase"))
		}
		if msgs := validation.IsDomainPrefixedPath(fieldPath, k); len(msgs) > 0 {
			errs = append(errs, field.Invalid(keyPath, k,
				"extra key must be a valid domain-prefixed path: "+msgs.ToAggregate().Error()))
		}
		if len(vals) == 0 {
			errs = append(errs, field.Required(keyPath, "extra values must not be empty"))
			continue
		}
		for i, v := range vals {
			if v == "" {
				errs = append(errs, field.Invalid(keyPath.Index(i), v,
					"extra value must not be empty"))
			}
		}
	}

	return errs
}

// warnImpersonationConfigIssues returns admission warnings for configurations that
// are legal but surprising.
func warnImpersonationConfigIssues(ic *ImpersonationConfig, fieldPath *field.Path) []string {
	if ic == nil {
		return nil
	}

	var warnings []string
	mode := InferImpersonationMode(ic)

	if mode == ImpersonationModeLegacy && (ic.ServiceAccountRef != nil || ic.UserName != "") {
		warnings = append(warnings, fmt.Sprintf(
			"%s: mode is legacy, so no constraint is applied — the API server does not enforce the "+
				"system:masters, group or extra restrictions on legacy impersonation. Set an explicit "+
				"constrained mode once every target spoke runs Kubernetes 1.35+ with the "+
				"ConstrainedImpersonation gate enabled.", fieldPath))
	}

	if len(ic.Groups) >= impManyChecksInLoop {
		warnings = append(warnings, fmt.Sprintf(
			"%s.groups: %d groups reaches the API server's hardcoded threshold of %d, above which it "+
				"performs a single wildcard (\"*\") authorization check instead of one per group; RBAC "+
				"grants naming individual groups will not be consulted.",
			fieldPath, len(ic.Groups), impManyChecksInLoop))
	}

	// Union, not correlation: the effective grant is the cross product.
	identityCount := len(ic.AllowedIdentities)
	actionCount := len(ic.ActionVerbs)
	if identityCount > 1 && actionCount > 1 {
		warnings = append(warnings, fmt.Sprintf(
			"%s: %d allowedIdentities combined with %d actionVerbs grants the %d-way cross product — "+
				"Kubernetes unions rather than correlates impersonation grants, so every identity "+
				"becomes usable for every action. Split into separate configurations if that is not "+
				"intended.", fieldPath, identityCount, actionCount, identityCount*actionCount))
	}

	for _, v := range ic.ActionVerbs {
		if v != "*" && strings.Contains(v, "*") {
			warnings = append(warnings, fmt.Sprintf(
				"%s.actionVerbs: %q contains a wildcard, but Kubernetes has no prefix wildcard for "+
					"impersonate-on verbs — only a bare \"*\" works. This entry will never match.",
				fieldPath, v))
		}
	}

	// No associated-node warning here on purpose: validateImpersonationConstraints
	// REJECTS that mode outright, so a warning could never be the outcome. See the
	// rejection there for why the mode is unsupportable in the OIDC model.

	return warnings
}

// validateImpersonationDenyRules validates DenyPolicy impersonation rules.
func validateImpersonationDenyRules(rules []ImpersonationDenyRule, fieldPath *field.Path) field.ErrorList {
	var errs field.ErrorList

	for i, r := range rules {
		rulePath := fieldPath.Index(i)

		for j, m := range r.Modes {
			if !validImpersonationModes[m] {
				errs = append(errs, field.NotSupported(rulePath.Child("modes").Index(j), m,
					[]string{"user-info", "serviceaccount", "arbitrary-node", "associated-node", "legacy"}))
			}
		}

		for j, res := range r.IdentityResources {
			if !validImpersonationIdentityResources[res] {
				errs = append(errs, field.Invalid(
					rulePath.Child("identityResources").Index(j), res,
					"must be one of "+impIdentityResourceList))
			}
		}

		// The API server issues identity and action checks as two separate
		// authorization requests. A rule requiring an identity match AND an action
		// verb match can therefore never fire, so accepting it would silently
		// produce a policy that denies nothing.
		if len(r.Identities) > 0 && len(r.ActionVerbs) > 0 {
			errs = append(errs, field.Invalid(rulePath, "identities+actionVerbs",
				"identities and actionVerbs cannot be combined: the API server evaluates identity "+
					"and action checks as separate authorization requests, so this rule would never "+
					"match. Split it into one identity rule and one action rule."))
		}

		if len(r.TargetResources) > 0 && len(r.ActionVerbs) == 0 {
			errs = append(errs, field.Invalid(rulePath.Child("targetResources"), r.TargetResources,
				"targetResources only applies to action checks; set actionVerbs as well"))
		}
		if len(r.TargetAPIGroups) > 0 && len(r.ActionVerbs) == 0 {
			errs = append(errs, field.Invalid(rulePath.Child("targetAPIGroups"), r.TargetAPIGroups,
				"targetAPIGroups only applies to action checks; set actionVerbs as well"))
		}
	}

	return errs
}

// warnImpersonationDenyRuleIssues returns warnings for impersonation deny rules
// that are unlikely to have the effect the author intended.
func warnImpersonationDenyRuleIssues(rules []ImpersonationDenyRule, fieldPath *field.Path) []string {
	var warnings []string

	for i, r := range rules {
		rulePath := fieldPath.Index(i)

		// The legacy fallback is the escape hatch. A rule that denies only the
		// constrained modes accomplishes nothing on a cluster that still carries a
		// blanket `impersonate` grant, because the API server falls back to it when
		// every constrained mode denies.
		if len(r.Modes) > 0 && !containsMode(r.Modes, ImpersonationModeLegacy) {
			warnings = append(warnings, fmt.Sprintf(
				"%s.modes: this rule denies only constrained impersonation modes. The API server falls "+
					"back to legacy (unconstrained) impersonation whenever every constrained mode "+
					"denies, so any blanket `impersonate` grant on the spoke defeats this rule. Add "+
					"\"legacy\" to the modes list to close the fallback.", rulePath))
		}

		if len(r.ExtraKeys) > 0 && len(r.IdentityResources) > 0 &&
			!containsString(r.IdentityResources, "userextras") {
			warnings = append(warnings, fmt.Sprintf(
				"%s.extraKeys: extraKeys only applies to userextras identity checks, which are not in "+
					"this rule's identityResources; the field will have no effect.", rulePath))
		}

		if len(r.Namespaces.patternsOrNil()) > 0 && len(r.IdentityResources) > 0 &&
			!containsString(r.IdentityResources, "serviceaccounts") {
			warnings = append(warnings, fmt.Sprintf(
				"%s.namespaces: serviceaccounts is the only namespaced identity kind, and it is not in "+
					"this rule's identityResources; the namespace filter will have no effect.", rulePath))
		}
	}

	return warnings
}

func containsMode(modes []ImpersonationMode, want ImpersonationMode) bool {
	for _, m := range modes {
		if m == want {
			return true
		}
	}
	return false
}

func containsString(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// patternsOrNil safely reads the patterns of a possibly-nil NamespaceFilter.
func (f *NamespaceFilter) patternsOrNil() []string {
	if f == nil {
		return nil
	}
	return f.Patterns
}
