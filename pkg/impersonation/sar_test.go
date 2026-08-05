// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package impersonation

import (
	"reflect"
	"strings"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestClassifySAR_NonImpersonation(t *testing.T) {
	// Ordinary requests must be reported as not-impersonation, so the webhook's
	// existing path is untouched for the overwhelming majority of traffic.
	tests := []struct {
		name string
		sar  *authorizationv1.SubjectAccessReview
	}{
		{"nil", nil},
		{"empty spec", &authorizationv1.SubjectAccessReview{}},
		{
			"get pods",
			&authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "jane",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb: "get", Resource: "pods", Namespace: "default",
					},
				},
			},
		},
		{
			"nonresource healthz",
			&authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "jane",
					NonResourceAttributes: &authorizationv1.NonResourceAttributes{
						Path: "/healthz", Verb: "get",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, isImpersonation := ClassifySAR(tc.sar)
			if isImpersonation {
				t.Error("ordinary request classified as impersonation")
			}
		})
	}
}

// TestClassifySAR_ReadsUID asserts the SAR's UID is captured. Without it a webhook
// cannot distinguish two principals sharing a username, and the audit record is
// incomplete.
func TestClassifySAR_ReadsUID(t *testing.T) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "system:serviceaccount:breakglass:manager",
			UID:    "9f0c1d2e-3a4b-5c6d-7e8f-901234567890",
			Groups: []string{"system:serviceaccounts", "system:authenticated"},
			Extra: map[string]authorizationv1.ExtraValue{
				"authentication.kubernetes.io/node-name": {"worker-1"},
				"identity.t-caas.telekom.com/issuer":     {"https://idp.example.com"},
			},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "impersonate:user-info",
				Group:    "authentication.k8s.io",
				Resource: "users",
				Name:     "jane@example.com",
			},
		},
	}

	req, isImpersonation := ClassifySAR(sar)
	if !isImpersonation {
		t.Fatal("impersonation SAR not classified as impersonation")
	}

	if req.Requestor.UID != "9f0c1d2e-3a4b-5c6d-7e8f-901234567890" {
		t.Errorf("Requestor.UID = %q; Spec.UID was not read", req.Requestor.UID)
	}
	if req.Requestor.User != "system:serviceaccount:breakglass:manager" {
		t.Errorf("Requestor.User = %q", req.Requestor.User)
	}
	if !reflect.DeepEqual(req.Requestor.Groups, []string{"system:serviceaccounts", "system:authenticated"}) {
		t.Errorf("Requestor.Groups = %v", req.Requestor.Groups)
	}
	if got := req.Requestor.NodeName(); got != "worker-1" {
		t.Errorf("Requestor.NodeName() = %q, want worker-1", got)
	}
}

func TestRequestorNodeName(t *testing.T) {
	tests := []struct {
		name  string
		extra map[string][]string
		want  string
	}{
		{"present", map[string][]string{NodeNameExtraKey: {"worker-1"}}, "worker-1"},
		{"absent", map[string][]string{"other": {"x"}}, ""},
		{"nil", nil, ""},
		{"empty slice", map[string][]string{NodeNameExtraKey: {}}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Requestor{Extra: tc.extra}
			if got := r.NodeName(); got != tc.want {
				t.Errorf("NodeName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifySAR_IdentityChecks(t *testing.T) {
	// The identity-check attribute table from the KEP.
	tests := []struct {
		name          string
		verb          string
		group         string
		resource      string
		subresource   string
		objName       string
		namespace     string
		wantKind      VerbKind
		wantMode      Mode
		wantResource  string
		wantName      string
		wantNamespace string
		wantExtraKey  string
		wantWildcard  bool
	}{
		{
			name: "generic user", verb: "impersonate:user-info",
			group: "authentication.k8s.io", resource: "users", objName: "jane@example.com",
			wantKind: VerbKindIdentity, wantMode: ModeUserInfo,
			wantResource: "users", wantName: "jane@example.com",
		},
		{
			name: "serviceaccount is namespaced", verb: "impersonate:serviceaccount",
			group: "authentication.k8s.io", resource: "serviceaccounts",
			objName: "probe", namespace: "kube-system",
			wantKind: VerbKindIdentity, wantMode: ModeServiceAccount,
			wantResource: "serviceaccounts", wantName: "probe", wantNamespace: "kube-system",
		},
		{
			name: "arbitrary node names the node", verb: "impersonate:arbitrary-node",
			group: "authentication.k8s.io", resource: "nodes", objName: "worker-1",
			wantKind: VerbKindIdentity, wantMode: ModeArbitraryNode,
			wantResource: "nodes", wantName: "worker-1",
		},
		{
			// associated-node identity rules take NO resourceNames, so the apiserver
			// checks against "*".
			name: "associated node uses wildcard name", verb: "impersonate:associated-node",
			group: "authentication.k8s.io", resource: "nodes", objName: "*",
			wantKind: VerbKindIdentity, wantMode: ModeAssociatedNode,
			wantResource: "nodes", wantName: "*", wantWildcard: true,
		},
		{
			name: "uid", verb: "impersonate:user-info",
			group: "authentication.k8s.io", resource: "uids", objName: "uid-1",
			wantKind: VerbKindIdentity, wantMode: ModeUserInfo,
			wantResource: "uids", wantName: "uid-1",
		},
		{
			name: "group", verb: "impersonate:user-info",
			group: "authentication.k8s.io", resource: "groups", objName: "sre",
			wantKind: VerbKindIdentity, wantMode: ModeUserInfo,
			wantResource: "groups", wantName: "sre",
		},
		{
			// At >= 4 groups the apiserver collapses to a single wildcard check.
			name: "group wildcard collapse", verb: "impersonate:user-info",
			group: "authentication.k8s.io", resource: "groups", objName: "*",
			wantKind: VerbKindIdentity, wantMode: ModeUserInfo,
			wantResource: "groups", wantName: "*", wantWildcard: true,
		},
		{
			// userextras carry the extra key in the subresource.
			name: "userextras", verb: "impersonate:user-info",
			group: "authentication.k8s.io", resource: "userextras",
			subresource: "example.com/key", objName: "value",
			wantKind: VerbKindIdentity, wantMode: ModeUserInfo,
			wantResource: "userextras", wantName: "value", wantExtraKey: "example.com/key",
		},
		{
			// Legacy uses the CORE api group, not authentication.k8s.io.
			name: "legacy user", verb: "impersonate",
			group: "", resource: "users", objName: "jane",
			wantKind: VerbKindLegacyImpersonate, wantMode: ModeLegacy,
			wantResource: "users", wantName: "jane",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sar := &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "requestor",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:        tc.verb,
						Group:       tc.group,
						Resource:    tc.resource,
						Subresource: tc.subresource,
						Name:        tc.objName,
						Namespace:   tc.namespace,
					},
				},
			}

			req, isImpersonation := ClassifySAR(sar)
			if !isImpersonation {
				t.Fatal("not classified as impersonation")
			}

			if req.Verb.Kind != tc.wantKind {
				t.Errorf("Kind = %s, want %s", req.Verb.Kind, tc.wantKind)
			}
			if req.Verb.Mode != tc.wantMode {
				t.Errorf("Mode = %q, want %q", req.Verb.Mode, tc.wantMode)
			}
			if req.Target.Resource != tc.wantResource {
				t.Errorf("Target.Resource = %q, want %q", req.Target.Resource, tc.wantResource)
			}
			if req.Target.Name != tc.wantName {
				t.Errorf("Target.Name = %q, want %q", req.Target.Name, tc.wantName)
			}
			if req.Target.Namespace != tc.wantNamespace {
				t.Errorf("Target.Namespace = %q, want %q", req.Target.Namespace, tc.wantNamespace)
			}
			if req.Target.Subresource != tc.wantExtraKey {
				t.Errorf("Target.Subresource = %q, want %q", req.Target.Subresource, tc.wantExtraKey)
			}
			if req.Target.Wildcard != tc.wantWildcard {
				t.Errorf("Target.Wildcard = %v, want %v", req.Target.Wildcard, tc.wantWildcard)
			}
		})
	}
}

// TestClassifySAR_ActionChecksCarryTargetAttributes documents that action checks
// carry the TARGET request's own attributes, not the impersonation target's — so
// Target must be left zero-valued to avoid misinterpreting them.
func TestClassifySAR_ActionChecksCarryTargetAttributes(t *testing.T) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "requestor",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:      "impersonate-on:user-info:list",
				Group:     "", // core: the target request's group
				Resource:  "pods",
				Namespace: "default",
			},
		},
	}

	req, isImpersonation := ClassifySAR(sar)
	if !isImpersonation {
		t.Fatal("not classified as impersonation")
	}

	if req.Verb.Kind != VerbKindAction {
		t.Fatalf("Kind = %s, want action", req.Verb.Kind)
	}
	if req.Verb.UnderlyingVerb != "list" {
		t.Errorf("UnderlyingVerb = %q, want list", req.Verb.UnderlyingVerb)
	}

	// "pods" is what is being listed, NOT an impersonation identity kind. Populating
	// Target.Resource with it would make an identity-scoped deny rule match an
	// action check.
	if req.Target.Resource != "" {
		t.Errorf("Target.Resource = %q, want empty for an action check: %q is the target "+
			"request's resource, not an impersonation identity kind",
			req.Target.Resource, req.Target.Resource)
	}
	if req.Target.Name != "" {
		t.Errorf("Target.Name = %q, want empty for an action check", req.Target.Name)
	}
}

func TestClassifySAR_MalformedVerbIsSurfaced(t *testing.T) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "requestor",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     "impersonate:some-future-mode",
				Group:    "authentication.k8s.io",
				Resource: "users",
				Name:     "jane",
			},
		},
	}

	req, isImpersonation := ClassifySAR(sar)
	if !isImpersonation {
		t.Fatal("a malformed impersonation verb was not surfaced as impersonation; " +
			"it would fall through to the generic path and could be silently allowed")
	}
	if req.Verb.Kind != VerbKindMalformed {
		t.Errorf("Kind = %s, want malformed", req.Verb.Kind)
	}
}

func TestExpectedAPIGroup(t *testing.T) {
	tests := []struct {
		verb      string
		wantGroup string
		wantOK    bool
	}{
		// Constrained identity checks use authentication.k8s.io.
		{"impersonate:user-info", "authentication.k8s.io", true},
		{"impersonate:serviceaccount", "authentication.k8s.io", true},
		// Legacy uses the core group.
		{"impersonate", "", true},
		// Action checks are evaluated against the target request's group, so no
		// expectation can be stated.
		{"impersonate-on:user-info:list", "", false},
		{"impersonate:bogus", "", false},
		{"get", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.verb, func(t *testing.T) {
			req := Request{Verb: ParseVerb(tc.verb)}
			gotGroup, gotOK := req.ExpectedAPIGroup()
			if gotGroup != tc.wantGroup || gotOK != tc.wantOK {
				t.Errorf("ExpectedAPIGroup() = (%q, %v), want (%q, %v)",
					gotGroup, gotOK, tc.wantGroup, tc.wantOK)
			}
		})
	}
}

func TestDenyUnrecognisedVerb(t *testing.T) {
	decision := DenyUnrecognisedVerb(ParseVerb("impersonate:some-future-mode"))

	if decision.Allowed {
		t.Fatal("DenyUnrecognisedVerb returned Allowed=true")
	}
	if decision.Source != "unrecognised-impersonation-verb" {
		t.Errorf("Source = %q", decision.Source)
	}
	// The reason must name the offending verb so an operator can act on it.
	if !strings.Contains(decision.Reason, "impersonate:some-future-mode") {
		t.Errorf("Reason %q does not name the verb", decision.Reason)
	}
	// And it must explain the remedy.
	if !strings.Contains(decision.Reason, "upgrade breakglass") {
		t.Errorf("Reason %q does not suggest a remedy", decision.Reason)
	}
}

func TestClassifySAR_ExtraConversion(t *testing.T) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "requestor",
			Extra: map[string]authorizationv1.ExtraValue{
				"a.io/k": {"v1", "v2"},
			},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb: "impersonate", Resource: "users", Name: "jane",
			},
		},
	}

	req, _ := ClassifySAR(sar)
	want := map[string][]string{"a.io/k": {"v1", "v2"}}
	if !reflect.DeepEqual(req.Requestor.Extra, want) {
		t.Errorf("Requestor.Extra = %v, want %v", req.Requestor.Extra, want)
	}

	// No extras at all must yield nil rather than an empty map, so callers can
	// distinguish "absent".
	sar.Spec.Extra = nil
	req, _ = ClassifySAR(sar)
	if req.Requestor.Extra != nil {
		t.Errorf("Requestor.Extra = %v, want nil", req.Requestor.Extra)
	}
}
