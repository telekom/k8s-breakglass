// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	// GroupSystemMasters is the cluster-admin escape-hatch group. Constrained
	// impersonation hard-denies it; legacy impersonation does NOT, which is
	// exactly why a legacy fallback grant is dangerous.
	GroupSystemMasters = "system:masters"

	// GroupSystemNodes is force-set by the apiserver when impersonating a node.
	GroupSystemNodes = "system:nodes"

	// GroupSystemAuthenticated is auto-added by the apiserver to every
	// impersonated identity that is not system:anonymous.
	GroupSystemAuthenticated = "system:authenticated"

	// UsernameNodePrefix prefixes node usernames.
	UsernameNodePrefix = "system:node:"

	// UsernameServiceAccountPrefix prefixes ServiceAccount usernames.
	UsernameServiceAccountPrefix = "system:serviceaccount:"

	// NodeNameExtraKey is the requestor extra key the apiserver compares against
	// the impersonated node name in associated-node mode.
	NodeNameExtraKey = "authentication.kubernetes.io/node-name"

	// ManyAuthorizationChecksInLoop is the apiserver's hardcoded threshold above
	// which it collapses per-item identity checks into a single "*" wildcard
	// check. At or above this many groups, a grant for the literal group name is
	// not consulted — only a wildcard grant is. Not configurable.
	ManyAuthorizationChecksInLoop = 4
)

// IsNodeUsername reports whether username is a node username.
func IsNodeUsername(username string) bool {
	return strings.HasPrefix(username, UsernameNodePrefix)
}

// IsServiceAccountUsername reports whether username is a ServiceAccount username.
func IsServiceAccountUsername(username string) bool {
	return strings.HasPrefix(username, UsernameServiceAccountPrefix)
}

// NodeNameFromUsername extracts <name> from "system:node:<name>".
func NodeNameFromUsername(username string) (string, bool) {
	if !IsNodeUsername(username) {
		return "", false
	}
	return strings.TrimPrefix(username, UsernameNodePrefix), true
}

// Identity describes an impersonation target as it would be sent on the wire via
// the four Impersonate-* headers (equivalently, rest.ImpersonationConfig).
type Identity struct {
	UserName string
	UID      string
	Groups   []string
	Extra    map[string][]string
}

// OnlyUsernameSet mirrors the apiserver's unexported onlyUsernameSet() predicate:
// UID, Groups and Extra must all be empty.
//
// This predicate is the KEP's central footgun. Sending Impersonate-Uid,
// Impersonate-Group or Impersonate-Extra-* alongside a node or ServiceAccount
// username makes the apiserver SKIP the node/serviceaccount constrained modes,
// fall through to user-info (which refuses node and SA usernames), and then land
// on legacy impersonation. The request may still succeed — via the blanket legacy
// grant — with no constraint applied and nothing in the audit log to say so.
func (i Identity) OnlyUsernameSet() bool {
	return i.UID == "" && len(i.Groups) == 0 && len(i.Extra) == 0
}

// SelectMode returns the mode the kube-apiserver would select for this identity,
// following the documented evaluation order.
//
// requestorNodeName is the value of the requestor's
// "authentication.kubernetes.io/node-name" extra, or "" when the requestor is not
// a node-bound ServiceAccount. It is only consulted for associated-node mode.
func (i Identity) SelectMode(requestorNodeName string) Mode {
	if nodeName, ok := NodeNameFromUsername(i.UserName); ok && i.OnlyUsernameSet() {
		if requestorNodeName != "" && requestorNodeName == nodeName {
			return ModeAssociatedNode
		}
		if len(validation.IsDNS1123Subdomain(nodeName)) == 0 {
			return ModeArbitraryNode
		}
		// A node username that is not a valid DNS subdomain matches no
		// constrained mode: user-info refuses node usernames, so legacy.
		return ModeLegacy
	}

	if IsServiceAccountUsername(i.UserName) && i.OnlyUsernameSet() {
		return ModeServiceAccount
	}

	// user-info refuses the reserved node and ServiceAccount username buckets.
	if IsNodeUsername(i.UserName) || IsServiceAccountUsername(i.UserName) {
		return ModeLegacy
	}

	if i.UserName != "" {
		return ModeUserInfo
	}

	return ModeLegacy
}

// Violation is a single constrained-impersonation restriction that an identity or
// a configuration breaks.
type Violation struct {
	// Field names the offending input, in a form suitable for appending to a
	// field.Path (e.g. "groups[0]", "extra[foo]", "userName").
	Field string

	// Message explains the violation.
	Message string

	// Fatal marks violations that make constrained impersonation impossible or
	// unsafe, as opposed to warnings about surprising-but-legal configuration.
	Fatal bool
}

func (v Violation) Error() string {
	return fmt.Sprintf("%s: %s", v.Field, v.Message)
}

// ValidateIdentity applies every constrained-impersonation restriction the
// apiserver enforces, plus the breakglass guardrails from the KEP's knob list.
//
// mode is the constrained mode the identity is intended for. Pass ModeLegacy to
// skip the constrained-only restrictions (the apiserver deliberately does not
// apply them to legacy impersonation) while still reporting the system:masters
// guardrail, which breakglass refuses in every mode.
func ValidateIdentity(i Identity, mode Mode) []Violation {
	var out []Violation

	// system:masters is hard-denied by the apiserver in constrained mode. We also
	// refuse it for legacy, because a legacy grant plus system:masters is a
	// complete cluster-admin bypass of every breakglass control.
	for idx, g := range i.Groups {
		if g == GroupSystemMasters {
			out = append(out, Violation{
				Field:   fmt.Sprintf("groups[%d]", idx),
				Message: "impersonating the system:masters group is not allowed",
				Fatal:   true,
			})
		}
	}

	if !mode.IsConstrained() {
		return out
	}

	for idx, g := range i.Groups {
		if g == "" {
			out = append(out, Violation{
				Field:   fmt.Sprintf("groups[%d]", idx),
				Message: "impersonated group must not be empty",
				Fatal:   true,
			})
		}
	}

	out = append(out, validateExtra(i.Extra)...)

	switch {
	case mode.IsNodeMode():
		if !IsNodeUsername(i.UserName) {
			out = append(out, Violation{
				Field:   "userName",
				Message: fmt.Sprintf("mode %q requires a %s<name> username", mode, UsernameNodePrefix),
				Fatal:   true,
			})
		}
		// The apiserver forces Groups=[system:nodes]; anything supplied here both
		// has no effect and, worse, trips OnlyUsernameSet and disables the mode.
		if len(i.Groups) > 0 {
			out = append(out, Violation{
				Field:   "groups",
				Message: "groups cannot be impersonated for a node identity; the apiserver forces groups=[" + GroupSystemNodes + "]",
				Fatal:   true,
			})
		}

	case mode == ModeServiceAccount:
		if !IsServiceAccountUsername(i.UserName) {
			out = append(out, Violation{
				Field:   "userName",
				Message: fmt.Sprintf("mode %q requires a %s<namespace>:<name> username", mode, UsernameServiceAccountPrefix),
				Fatal:   true,
			})
		}
		if len(i.Groups) > 0 {
			out = append(out, Violation{
				Field:   "groups",
				Message: "groups cannot be impersonated for a ServiceAccount identity; the apiserver computes them from the namespace",
				Fatal:   true,
			})
		}

	case mode == ModeUserInfo:
		if IsNodeUsername(i.UserName) {
			out = append(out, Violation{
				Field:   "userName",
				Message: "mode \"user-info\" refuses node usernames; use arbitrary-node or associated-node",
				Fatal:   true,
			})
		}
		if IsServiceAccountUsername(i.UserName) {
			out = append(out, Violation{
				Field:   "userName",
				Message: "mode \"user-info\" refuses ServiceAccount usernames; use serviceaccount mode",
				Fatal:   true,
			})
		}
	}

	// The header-mixing trap. Node and ServiceAccount modes require that only the
	// username be set; if UID, groups or extras accompany them the apiserver
	// silently downgrades to legacy impersonation.
	if mode.IsNodeMode() || mode == ModeServiceAccount {
		if !i.OnlyUsernameSet() {
			out = append(out, mixingViolation(i, mode))
		}
	}

	return out
}

// mixingViolation builds the violation for the header-mixing trap, naming the
// specific field that breaks OnlyUsernameSet so the operator can fix it.
func mixingViolation(i Identity, mode Mode) Violation {
	var offenders []string
	if i.UID != "" {
		offenders = append(offenders, "uid")
	}
	if len(i.Groups) > 0 {
		offenders = append(offenders, "groups")
	}
	if len(i.Extra) > 0 {
		offenders = append(offenders, "extra")
	}
	offendingField := "uid"
	if len(offenders) > 0 {
		offendingField = offenders[0]
	}
	return Violation{
		Field: offendingField,
		Message: fmt.Sprintf(
			"mode %q requires that ONLY the username is set, but %s is also set; "+
				"the apiserver would skip constrained impersonation entirely and silently fall back to "+
				"legacy (unconstrained) impersonation",
			mode, strings.Join(offenders, "+")),
		Fatal: true,
	}
}

// validateExtra mirrors the apiserver's validateExtra: keys must be non-empty,
// lowercase, valid domain-prefixed paths; value slices must be non-empty and
// contain no empty strings.
func validateExtra(extra map[string][]string) []Violation {
	var out []Violation
	for k, vals := range extra {
		path := fmt.Sprintf("extra[%s]", k)
		switch {
		case k == "":
			out = append(out, Violation{Field: "extra", Message: "extra key must not be empty", Fatal: true})
			continue
		case k != strings.ToLower(k):
			out = append(out, Violation{Field: path, Message: "extra key must be lowercase", Fatal: true})
		}
		if errs := validation.IsDomainPrefixedPath(field.NewPath("extra"), k); len(errs) > 0 {
			out = append(out, Violation{
				Field:   path,
				Message: "extra key must be a valid domain-prefixed path: " + errs.ToAggregate().Error(),
				Fatal:   true,
			})
		}
		if len(vals) == 0 {
			out = append(out, Violation{Field: path, Message: "extra values must not be empty", Fatal: true})
			continue
		}
		for idx, v := range vals {
			if v == "" {
				out = append(out, Violation{
					Field:   fmt.Sprintf("extra[%s][%d]", k, idx),
					Message: "extra value must not be empty",
					Fatal:   true,
				})
			}
		}
	}
	return out
}

// UnionSemanticsWarning returns a warning when a configuration grants more than
// one identity together with more than one action, because RBAC unions rather
// than correlates them: the effective grant is the full cross product. There is
// no way to express "user A only for pods AND user B only for secrets" in one
// rule set.
func UnionSemanticsWarning(identityCount, actionCount int) string {
	if identityCount <= 1 || actionCount <= 1 {
		return ""
	}
	return fmt.Sprintf(
		"this configuration grants %d impersonation identities and %d actions; "+
			"Kubernetes unions rather than correlates them, so the effective grant is the "+
			"%d-way cross product. Split into separate configurations if the identities must "+
			"not be usable for every action",
		identityCount, actionCount, identityCount*actionCount)
}

// ManyGroupsWarning returns a warning when a group allowlist is large enough that
// the apiserver collapses per-group identity checks into a single "*" wildcard
// check, meaning grants naming individual groups stop being consulted.
func ManyGroupsWarning(groupCount int) string {
	if groupCount < ManyAuthorizationChecksInLoop {
		return ""
	}
	return fmt.Sprintf(
		"%d impersonated groups reaches the apiserver's hardcoded threshold of %d, above which it "+
			"performs a single wildcard (\"*\") authorization check instead of one check per group; "+
			"grants that name individual groups will not be consulted",
		groupCount, ManyAuthorizationChecksInLoop)
}
