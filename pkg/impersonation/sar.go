// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
)

// Request is the impersonation-relevant view of a SubjectAccessReview that the
// kube-apiserver sent to an authorization webhook.
type Request struct {
	// Verb is the classified verb.
	Verb ParsedVerb

	// Target describes what is being impersonated, for identity checks. For
	// action checks it is zero-valued, because an action check carries the TARGET
	// request's own resource attributes rather than the impersonation target.
	Target IdentityTarget

	// Requestor is the identity performing the impersonation, taken from
	// sar.Spec.User / Groups / UID / Extra.
	Requestor Requestor
}

// IdentityTarget is the resource an identity check names.
type IdentityTarget struct {
	// Resource is one of the constrained identity resources
	// (users, groups, uids, userextras, serviceaccounts, nodes).
	Resource string

	// Subresource carries the extra key for userextras checks.
	Subresource string

	// Name is the impersonated username / group name / UID / node name / SA name.
	// It is "*" when the apiserver collapsed many checks into a wildcard check,
	// and "*" for associated-node identity checks (which take no resourceNames).
	Name string

	// Namespace is set for ServiceAccount identity checks.
	Namespace string

	// Wildcard reports whether Name is the literal "*" collapse marker.
	Wildcard bool
}

// Requestor is the identity that issued the impersonating request.
type Requestor struct {
	User   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

// NodeName returns the requestor's associated node name from its
// "authentication.kubernetes.io/node-name" extra, if present. This is what the
// apiserver compares against the impersonated node name to select
// associated-node mode.
func (r Requestor) NodeName() string {
	vals := r.Extra[NodeNameExtraKey]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// ClassifySAR extracts the impersonation view of a SubjectAccessReview.
//
// It reads Spec.UID as well as Spec.User, Groups and Extra: the requestor UID is
// part of the impersonating identity and belongs in audit records, and omitting it
// is how a webhook ends up unable to distinguish two principals with the same
// username.
//
// The second return value reports whether the SAR concerns impersonation at all.
func ClassifySAR(sar *authorizationv1.SubjectAccessReview) (Request, bool) {
	if sar == nil {
		return Request{}, false
	}

	req := Request{
		Requestor: Requestor{
			User:   sar.Spec.User,
			UID:    sar.Spec.UID,
			Groups: sar.Spec.Groups,
			Extra:  extraToMap(sar.Spec.Extra),
		},
	}

	ra := sar.Spec.ResourceAttributes
	if ra == nil {
		// Impersonation is always a resource check; a non-resource SAR is never
		// an impersonation check.
		if nra := sar.Spec.NonResourceAttributes; nra != nil {
			req.Verb = ParseVerb(nra.Verb)
			// Defensive: the apiserver does not issue non-resource impersonation
			// checks. If one appears, surface it rather than swallowing it.
			return req, req.Verb.IsImpersonation()
		}
		return req, false
	}

	req.Verb = ParseVerb(ra.Verb)
	if !req.Verb.IsImpersonation() {
		return req, false
	}

	if req.Verb.Kind == VerbKindIdentity || req.Verb.Kind == VerbKindLegacyImpersonate {
		req.Target = IdentityTarget{
			Resource:    ra.Resource,
			Subresource: ra.Subresource,
			Name:        ra.Name,
			Namespace:   ra.Namespace,
			Wildcard:    ra.Name == "*",
		}
	}

	return req, true
}

func extraToMap(in map[string]authorizationv1.ExtraValue) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = []string(v)
	}
	return out
}

// ExpectedAPIGroup returns the API group the apiserver evaluates this check
// against: authentication.k8s.io for constrained identity checks, the core group
// for legacy impersonation. Action checks are evaluated against the TARGET
// request's own API group, so no expectation can be stated and "" / false is
// returned.
func (r Request) ExpectedAPIGroup() (string, bool) {
	switch r.Verb.Kind {
	case VerbKindIdentity:
		return APIGroupAuthentication, true
	case VerbKindLegacyImpersonate:
		return "", true
	case VerbKindAction, VerbKindMalformed, VerbKindOther:
		return "", false
	default:
		return "", false
	}
}

// Decision is an authorizer's explicit decision about an impersonation check.
type Decision struct {
	// Allowed reports the outcome.
	Allowed bool

	// Reason is the human-readable justification, surfaced in the SAR response.
	Reason string

	// Constraint records the identity verb in play, matching the apiserver's
	// audit field authenticationMetadata.impersonationConstraint. Empty for
	// legacy impersonation, exactly as the apiserver omits the field there.
	Constraint string

	// Source is a short machine-readable label for metrics
	// (e.g. "unrecognised-verb", "system-masters", "no-grant").
	Source string
}

// DenyUnrecognisedVerb builds the decision for an impersonation verb this build
// does not understand.
//
// This is the case that makes a permissive webhook dangerous. If breakglass
// returned "no opinion" or, worse, allowed by default, then on any cluster with
// the ConstrainedImpersonation gate enabled the apiserver would accept an
// impersonation it believes breakglass vetted. Failing closed is the only safe
// answer, and a future apiserver adding a fifth mode must produce a loud denial
// rather than a silent grant.
func DenyUnrecognisedVerb(p ParsedVerb) Decision {
	return Decision{
		Allowed: false,
		Reason: fmt.Sprintf(
			"Denied: %s. Breakglass does not recognise this impersonation verb and fails closed "+
				"rather than risk silently granting constrained impersonation. If your cluster runs a "+
				"newer Kubernetes with additional impersonation modes, upgrade breakglass.",
			p.Describe()),
		Source: "unrecognised-impersonation-verb",
	}
}
