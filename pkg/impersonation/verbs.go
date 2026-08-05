// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"fmt"
	"strings"
)

// Mode is a constrained-impersonation mode as derived by the kube-apiserver from
// the value of the Impersonate-User header. Modes are NOT selected by a new
// header: KEP-5284 deliberately keeps client-side semantics unchanged.
type Mode string

const (
	// ModeAssociatedNode impersonates the node the requesting ServiceAccount is
	// itself running on. Selected when the impersonated username is
	// "system:node:<name>", only the username is set, and the requestor is a
	// ServiceAccount whose "authentication.kubernetes.io/node-name" extra
	// matches <name>.
	ModeAssociatedNode Mode = "associated-node"

	// ModeArbitraryNode impersonates any node. Selected when the impersonated
	// username is "system:node:<name>", only the username is set, and <name> is
	// a valid DNS subdomain.
	ModeArbitraryNode Mode = "arbitrary-node"

	// ModeServiceAccount impersonates a ServiceAccount. Selected when the
	// impersonated username is "system:serviceaccount:<ns>:<name>" and only the
	// username is set.
	ModeServiceAccount Mode = "serviceaccount"

	// ModeUserInfo impersonates a regular user identity. Selected when the
	// impersonated username is neither a node nor a ServiceAccount username.
	// This is the only mode that supports UID, groups and extras.
	ModeUserInfo Mode = "user-info"

	// ModeLegacy is the classic blanket `impersonate` verb in the core API group.
	// The apiserver falls back to it when every constrained mode denies. Legacy
	// grants therefore WIN BY FALLBACK and silently defeat any constraint.
	ModeLegacy Mode = "legacy"
)

// ModeEvaluationOrder is the order in which the kube-apiserver tries modes.
// The first mode whose selection preconditions hold is the one evaluated; if it
// denies, the apiserver falls through to ModeLegacy.
var ModeEvaluationOrder = []Mode{
	ModeAssociatedNode,
	ModeArbitraryNode,
	ModeServiceAccount,
	ModeUserInfo,
	ModeLegacy,
}

// ConstrainedModes lists the modes that use the constrained verbs. ModeLegacy is
// excluded because it uses the plain `impersonate` verb in the core API group.
var ConstrainedModes = []Mode{
	ModeAssociatedNode,
	ModeArbitraryNode,
	ModeServiceAccount,
	ModeUserInfo,
}

// IsConstrained reports whether m is a constrained mode (i.e. not legacy).
func (m Mode) IsConstrained() bool {
	switch m {
	case ModeAssociatedNode, ModeArbitraryNode, ModeServiceAccount, ModeUserInfo:
		return true
	case ModeLegacy:
		return false
	default:
		return false
	}
}

// IsNodeMode reports whether m impersonates a node identity. Node modes force
// Groups=[system:nodes] server-side; groups cannot be impersonated alongside.
func (m Mode) IsNodeMode() bool {
	return m == ModeAssociatedNode || m == ModeArbitraryNode
}

// ParseMode converts a string to a Mode, reporting whether it is a known mode.
func ParseMode(s string) (Mode, bool) {
	switch Mode(s) {
	case ModeAssociatedNode:
		return ModeAssociatedNode, true
	case ModeArbitraryNode:
		return ModeArbitraryNode, true
	case ModeServiceAccount:
		return ModeServiceAccount, true
	case ModeUserInfo:
		return ModeUserInfo, true
	case ModeLegacy:
		return ModeLegacy, true
	default:
		return "", false
	}
}

const (
	// VerbLegacyImpersonate is the classic blanket impersonation verb, evaluated
	// against the CORE ("") API group.
	VerbLegacyImpersonate = "impersonate"

	// IdentityVerbPrefix prefixes the identity verbs, e.g. "impersonate:user-info".
	IdentityVerbPrefix = "impersonate:"

	// ActionVerbPrefix prefixes the action verbs, e.g. "impersonate-on:user-info:list".
	ActionVerbPrefix = "impersonate-on:"

	// APIGroupAuthentication is the API group constrained identity checks are
	// evaluated against. Legacy impersonation uses the core ("") group instead —
	// mixing the two up is the single easiest way to write an ineffective rule.
	APIGroupAuthentication = "authentication.k8s.io"
)

// Identity resource kinds used by the apiserver's identity checks. All are
// evaluated in the authentication.k8s.io API group.
const (
	ResourceUsers           = "users"
	ResourceGroups          = "groups"
	ResourceUIDs            = "uids"
	ResourceUserExtras      = "userextras"
	ResourceServiceAccounts = "serviceaccounts"
	ResourceNodes           = "nodes"
)

// IdentityResources lists every resource kind a constrained identity check can
// target.
var IdentityResources = []string{
	ResourceUsers,
	ResourceGroups,
	ResourceUIDs,
	ResourceUserExtras,
	ResourceServiceAccounts,
	ResourceNodes,
}

// IsIdentityResource reports whether resource is one of the constrained-impersonation
// identity resource kinds.
func IsIdentityResource(resource string) bool {
	for _, r := range IdentityResources {
		if r == resource {
			return true
		}
	}
	return false
}

// IdentityVerb returns the identity verb for a mode, e.g.
// IdentityVerb(ModeUserInfo) == "impersonate:user-info".
//
// ModeLegacy has no identity verb and yields VerbLegacyImpersonate.
func IdentityVerb(m Mode) string {
	if m == ModeLegacy {
		return VerbLegacyImpersonate
	}
	return IdentityVerbPrefix + string(m)
}

// ActionVerb returns the action verb for a mode and the verb of the underlying
// request, e.g. ActionVerb(ModeUserInfo, "list") == "impersonate-on:user-info:list".
//
// ModeLegacy has no action verb and yields the empty string.
func ActionVerb(m Mode, underlying string) string {
	if m == ModeLegacy {
		return ""
	}
	return ActionVerbPrefix + string(m) + ":" + underlying
}

// VerbKind classifies an SAR verb with respect to impersonation.
type VerbKind int

const (
	// VerbKindOther is any verb unrelated to impersonation (get, list, create, …).
	VerbKindOther VerbKind = iota

	// VerbKindLegacyImpersonate is the plain `impersonate` verb.
	VerbKindLegacyImpersonate

	// VerbKindIdentity is an `impersonate:<mode>` verb.
	VerbKindIdentity

	// VerbKindAction is an `impersonate-on:<mode>:<verb>` verb.
	VerbKindAction

	// VerbKindMalformed is a verb that uses an impersonation prefix but does not
	// parse: an unknown mode, a missing underlying verb, or extra separators.
	//
	// This case matters for security: a malformed verb must never be treated as
	// VerbKindOther and passed through to a permissive allow path, because future
	// apiserver versions may add modes this build does not know about.
	VerbKindMalformed
)

// String renders the verb kind for logs, metrics and audit records.
func (k VerbKind) String() string {
	switch k {
	case VerbKindLegacyImpersonate:
		return "legacy-impersonate"
	case VerbKindIdentity:
		return "identity"
	case VerbKindAction:
		return "action"
	case VerbKindMalformed:
		return "malformed"
	case VerbKindOther:
		return "other"
	default:
		return "unknown"
	}
}

// ParsedVerb is the result of classifying an SAR verb.
type ParsedVerb struct {
	// Kind classifies the verb.
	Kind VerbKind

	// Mode is the impersonation mode, set for VerbKindIdentity and
	// VerbKindAction. For VerbKindLegacyImpersonate it is ModeLegacy.
	Mode Mode

	// UnderlyingVerb is the verb of the request being performed under
	// impersonation. Only set for VerbKindAction.
	UnderlyingVerb string

	// Raw is the verb string exactly as it arrived.
	Raw string
}

// IsImpersonation reports whether the parsed verb concerns impersonation at all,
// including the malformed case. Authorizers should treat every verb for which
// this returns true as security-relevant.
func (p ParsedVerb) IsImpersonation() bool {
	return p.Kind != VerbKindOther
}

// IsConstrained reports whether the parsed verb is one of the constrained
// impersonation verbs (identity or action).
func (p ParsedVerb) IsConstrained() bool {
	return p.Kind == VerbKindIdentity || p.Kind == VerbKindAction
}

// Describe renders a short human-readable description for deny reasons and audit
// details.
func (p ParsedVerb) Describe() string {
	switch p.Kind {
	case VerbKindLegacyImpersonate:
		return "legacy (unconstrained) impersonation"
	case VerbKindIdentity:
		return fmt.Sprintf("constrained impersonation identity grant for mode %q", p.Mode)
	case VerbKindAction:
		return fmt.Sprintf("constrained impersonation of verb %q in mode %q", p.UnderlyingVerb, p.Mode)
	case VerbKindMalformed:
		return fmt.Sprintf("unrecognised impersonation verb %q", p.Raw)
	case VerbKindOther:
		return fmt.Sprintf("verb %q", p.Raw)
	default:
		return fmt.Sprintf("verb %q", p.Raw)
	}
}

// ParseVerb classifies an SAR verb.
//
// The apiserver builds action verbs as `"impersonate-on:" + mode + ":" + verb`,
// so the underlying verb is everything after the second colon. Because verbs
// themselves never contain colons in practice, but a hostile or buggy caller
// could send one, anything with additional separators is reported as malformed
// rather than silently reinterpreted.
func ParseVerb(verb string) ParsedVerb {
	p := ParsedVerb{Raw: verb}

	switch {
	case verb == VerbLegacyImpersonate:
		p.Kind = VerbKindLegacyImpersonate
		p.Mode = ModeLegacy
		return p

	case strings.HasPrefix(verb, ActionVerbPrefix):
		rest := strings.TrimPrefix(verb, ActionVerbPrefix)
		modeStr, underlying, found := strings.Cut(rest, ":")
		if !found || underlying == "" {
			p.Kind = VerbKindMalformed
			return p
		}
		mode, ok := ParseMode(modeStr)
		// Legacy has no action verbs; treating "impersonate-on:legacy:x" as valid
		// would invent a verb the apiserver never issues.
		if !ok || !mode.IsConstrained() {
			p.Kind = VerbKindMalformed
			return p
		}
		if strings.Contains(underlying, ":") {
			p.Kind = VerbKindMalformed
			return p
		}
		p.Kind = VerbKindAction
		p.Mode = mode
		p.UnderlyingVerb = underlying
		return p

	case strings.HasPrefix(verb, IdentityVerbPrefix):
		modeStr := strings.TrimPrefix(verb, IdentityVerbPrefix)
		mode, ok := ParseMode(modeStr)
		if !ok || !mode.IsConstrained() {
			p.Kind = VerbKindMalformed
			return p
		}
		p.Kind = VerbKindIdentity
		p.Mode = mode
		return p

	default:
		p.Kind = VerbKindOther
		return p
	}
}

// AllIdentityVerbs returns the identity verbs for every constrained mode. Useful
// for building allow/deny lists and for documentation.
func AllIdentityVerbs() []string {
	out := make([]string, 0, len(ConstrainedModes))
	for _, m := range ConstrainedModes {
		out = append(out, IdentityVerb(m))
	}
	return out
}

// AllActionVerbs returns the action verbs for every constrained mode combined
// with each of the supplied underlying verbs.
func AllActionVerbs(underlying ...string) []string {
	out := make([]string, 0, len(ConstrainedModes)*len(underlying))
	for _, m := range ConstrainedModes {
		for _, v := range underlying {
			out = append(out, ActionVerb(m, v))
		}
	}
	return out
}
