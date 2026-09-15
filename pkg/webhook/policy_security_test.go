// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type policyMemberResolver struct {
	members []string
	err     error
}

type countingPolicyMemberResolver struct {
	members []string
	err     error
	calls   *int
}

func (r countingPolicyMemberResolver) Members(_ context.Context, _ string) ([]string, error) {
	(*r.calls)++
	return r.members, r.err
}

func (r policyMemberResolver) Members(_ context.Context, group string) ([]string, error) {
	if group != "security-team" {
		return nil, errors.New("unexpected group")
	}
	return r.members, r.err
}

func TestOverrideOwnerAndGroupApproval(t *testing.T) {
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc", Namespace: "ns", UID: "current"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
				Enabled:         true,
				RequireApproval: true,
				ExemptFactors:   []string{"hostPID"},
				MaxAllowedScore: ptr.To(100),
				Approvers:       &breakglassv1alpha1.PodSecurityApprovers{Groups: []string{"security-team"}},
			},
		},
	}
	manager := &escalation.EscalationManager{Client: fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc).Build()}
	controller := &WebhookController{escalManager: manager}
	base := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: breakglassv1alpha1.GroupVersion.String(),
				Kind:       "BreakglassEscalation",
				Name:       "esc",
				UID:        "current",
				Controller: ptr.To(true),
			}},
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State:                     breakglassv1alpha1.SessionStateApproved,
			Approvers:                 []string{"security@example.com"},
			ApproverIdentityProviders: []string{"idp-a"},
		},
	}
	for _, tc := range []struct {
		name     string
		mutate   func(*breakglassv1alpha1.BreakglassSession)
		resolver policyMemberResolver
		want     bool
	}{
		{name: "member", resolver: policyMemberResolver{members: []string{"security@example.com"}}, want: true},
		{name: "nonmember", resolver: policyMemberResolver{members: []string{"other@example.com"}}},
		{name: "lookup failure", resolver: policyMemberResolver{err: errors.New("unavailable")}},
		{name: "recreated escalation", mutate: func(s *breakglassv1alpha1.BreakglassSession) { s.OwnerReferences[0].UID = "old" }, resolver: policyMemberResolver{members: []string{"security@example.com"}}},
		{name: "wrong API", mutate: func(s *breakglassv1alpha1.BreakglassSession) { s.OwnerReferences[0].APIVersion = "other/v1" }, resolver: policyMemberResolver{members: []string{"security@example.com"}}},
		{name: "noncontroller owner", mutate: func(s *breakglassv1alpha1.BreakglassSession) { s.OwnerReferences[0].Controller = ptr.To(false) }, resolver: policyMemberResolver{members: []string{"security@example.com"}}},
		{name: "unapproved session", mutate: func(s *breakglassv1alpha1.BreakglassSession) { s.Status.State = breakglassv1alpha1.SessionStatePending }, resolver: policyMemberResolver{members: []string{"security@example.com"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := base.DeepCopy()
			if tc.mutate != nil {
				tc.mutate(session)
			}
			controller.approverResolverFetchFn = func(_ context.Context, provider string) (breakglass.GroupMemberResolver, error) {
				if provider != "idp-a" {
					return nil, errors.New("unexpected provider")
				}
				return tc.resolver, nil
			}
			got := controller.getPodSecurityOverridesFromSessions(context.Background(), []breakglassv1alpha1.BreakglassSession{*session}, nil)
			if (got != nil) != tc.want {
				t.Fatalf("override available=%v want=%v", got != nil, tc.want)
			}
			denyPolicy := &breakglassv1alpha1.DenyPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-hostpid"}, Spec: breakglassv1alpha1.DenyPolicySpec{PodSecurityRules: &breakglassv1alpha1.PodSecurityRules{BlockFactors: []string{"hostPID"}}}}
			evaluator := policy.NewEvaluator(fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(denyPolicy).Build(), zap.NewNop().Sugar())
			denied, _, err := evaluator.Match(context.Background(), policy.Action{Resource: "pods", Subresource: "exec", Pod: &corev1.Pod{Spec: corev1.PodSpec{HostPID: true}}, PodSecurityOverrides: got, PodSecurityOverrideApproved: got != nil})
			if err != nil || denied == tc.want {
				t.Fatalf("selected override evaluation denied=%v want=%v err=%v", denied, !tc.want, err)
			}
		})
	}
}

func TestOverrideGroupApprovalRequiresUnambiguousProvider(t *testing.T) {
	manager := &escalation.EscalationManager{}
	manager.SetResolver(policyMemberResolver{members: []string{"security@example.com"}})
	controller := &WebhookController{escalManager: manager}
	session := breakglassv1alpha1.BreakglassSession{Status: breakglassv1alpha1.BreakglassSessionStatus{Approvers: []string{"security@example.com"}}}
	overrides := &breakglassv1alpha1.PodSecurityOverrides{RequireApproval: true, Approvers: &breakglassv1alpha1.PodSecurityApprovers{Groups: []string{"security-team"}}}
	if controller.podSecurityOverrideApprovalGranted(context.Background(), session, overrides, "idp-a", "idp-b") {
		t.Fatal("ambiguous approver provider must not use default resolver membership")
	}
	if controller.podSecurityOverrideApprovalGranted(context.Background(), session, overrides, "idp-a") {
		t.Fatal("missing provider lookup must not use default resolver membership")
	}
}

func TestOverrideApprovalUsesEachRecordedProvider(t *testing.T) {
	controller := &WebhookController{}
	controller.approverResolverFetchFn = func(_ context.Context, provider string) (breakglass.GroupMemberResolver, error) {
		switch provider {
		case "idp-a":
			return policyMemberResolver{members: []string{"other@example.com"}}, nil
		case "idp-b":
			return policyMemberResolver{members: []string{"shared@example.com"}}, nil
		default:
			return nil, errors.New("provider unavailable")
		}
	}
	groupPolicy := &breakglassv1alpha1.PodSecurityOverrides{RequireApproval: true, Approvers: &breakglassv1alpha1.PodSecurityApprovers{Groups: []string{"security-team"}}}
	userPolicy := &breakglassv1alpha1.PodSecurityOverrides{RequireApproval: true, Approvers: &breakglassv1alpha1.PodSecurityApprovers{Users: []string{"shared@example.com"}}}
	for _, tc := range []struct {
		name                          string
		approvers, providers, allowed []string
		overrides                     *breakglassv1alpha1.PodSecurityOverrides
		want                          bool
	}{
		{name: "same email wrong provider cannot borrow membership", approvers: []string{"shared@example.com"}, providers: []string{"idp-a"}, allowed: []string{"idp-a", "idp-b"}, overrides: groupPolicy},
		{name: "actual provider membership", approvers: []string{"shared@example.com"}, providers: []string{"idp-b"}, allowed: []string{"idp-a", "idp-b"}, overrides: groupPolicy, want: true},
		{name: "aligned duplicate identity", approvers: []string{"shared@example.com", "shared@example.com"}, providers: []string{"idp-a", "idp-b"}, allowed: []string{"idp-a", "idp-b"}, overrides: groupPolicy, want: true},
		{name: "disallowed provider group", approvers: []string{"shared@example.com"}, providers: []string{"idp-b"}, allowed: []string{"idp-a"}, overrides: groupPolicy},
		{name: "disallowed provider direct user", approvers: []string{"shared@example.com"}, providers: []string{"idp-b"}, allowed: []string{"idp-a"}, overrides: userPolicy},
		{name: "allowed provider direct user", approvers: []string{"shared@example.com"}, providers: []string{"idp-b"}, allowed: []string{"idp-b"}, overrides: userPolicy, want: true},
		{name: "mixed case allowed provider direct user", approvers: []string{"Shared@Example.COM"}, providers: []string{"idp-b"}, allowed: []string{"idp-b"}, overrides: userPolicy, want: true},
		{name: "mixed case disallowed provider direct user", approvers: []string{"Shared@Example.COM"}, providers: []string{"idp-a"}, allowed: []string{"idp-b"}, overrides: userPolicy},
		{name: "missing legacy group provenance", approvers: []string{"shared@example.com"}, overrides: groupPolicy},
		{name: "legacy cannot infer single provider", approvers: []string{"shared@example.com"}, allowed: []string{"idp-b"}, overrides: groupPolicy},
		{name: "legacy direct user with restriction", approvers: []string{"shared@example.com"}, allowed: []string{"idp-b"}, overrides: userPolicy},
		{name: "unrestricted explicit identifier legacy compatibility", approvers: []string{"shared@example.com"}, overrides: userPolicy, want: true},
		{name: "short provenance list", approvers: []string{"other@example.com", "shared@example.com"}, providers: []string{"idp-b"}, overrides: groupPolicy},
		{name: "extra provenance cannot create approval", approvers: []string{"shared@example.com"}, providers: []string{"idp-a", "idp-b"}, overrides: groupPolicy},
		{name: "provider lookup failure", approvers: []string{"shared@example.com"}, providers: []string{"missing"}, overrides: groupPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := breakglassv1alpha1.BreakglassSession{Status: breakglassv1alpha1.BreakglassSessionStatus{Approvers: tc.approvers, ApproverIdentityProviders: tc.providers}}
			// Neither the requester nor last approver can supply missing array provenance.
			session.Spec.IdentityProviderName = "idp-b"
			session.Status.Approver = "shared@example.com"
			session.Status.ApproverIdentityProvider = "idp-b"
			got := controller.podSecurityOverrideApprovalGranted(context.Background(), session, tc.overrides, tc.allowed...)
			if got != tc.want {
				t.Fatalf("approval=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestOverrideApprovalCachesMembersPerProviderAndGroupPerDecision(t *testing.T) {
	calls := 0
	resolver := countingPolicyMemberResolver{members: []string{"other@example.com"}, calls: &calls}
	controller := &WebhookController{approverResolverFetchFn: func(_ context.Context, provider string) (breakglass.GroupMemberResolver, error) {
		if provider != "idp-a" {
			return nil, errors.New("unexpected provider")
		}
		return resolver, nil
	}}
	session := breakglassv1alpha1.BreakglassSession{Status: breakglassv1alpha1.BreakglassSessionStatus{
		Approvers: []string{"first@example.com", "second@example.com"}, ApproverIdentityProviders: []string{"idp-a", "idp-a"},
	}}
	overrides := &breakglassv1alpha1.PodSecurityOverrides{RequireApproval: true, Approvers: &breakglassv1alpha1.PodSecurityApprovers{Groups: []string{"security-team"}}}
	if controller.podSecurityOverrideApprovalGranted(context.Background(), session, overrides, "idp-a") {
		t.Fatal("unexpected approval")
	}
	if calls != 1 {
		t.Fatalf("Members calls=%d, want 1", calls)
	}
	if controller.podSecurityOverrideApprovalGranted(context.Background(), session, overrides, "idp-a") {
		t.Fatal("unexpected approval")
	}
	if calls != 2 {
		t.Fatalf("new decision calls=%d, want 2", calls)
	}

	calls = 0
	resolver.err = errors.New("unavailable")
	if controller.podSecurityOverrideApprovalGranted(context.Background(), session, overrides, "idp-a") {
		t.Fatal("unexpected approval")
	}
	if calls != 1 {
		t.Fatalf("failed Members calls=%d, want 1", calls)
	}
}
