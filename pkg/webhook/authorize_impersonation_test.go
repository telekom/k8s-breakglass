// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
	"github.com/telekom/k8s-breakglass/pkg/policy"
)

// impersonationTestFixture wires a WebhookController with the given DenyPolicies so
// impersonation evaluation can be driven directly.
type impersonationTestFixture struct {
	wc *WebhookController
	c  *gin.Context
	w  *httptest.ResponseRecorder
	s  *authorizeState
}

func newImpersonationFixture(
	t *testing.T,
	clusterCfg *breakglassv1alpha1.ClusterConfig,
	policies ...*breakglassv1alpha1.DenyPolicy,
) *impersonationTestFixture {
	t.Helper()

	gin.SetMode(gin.TestMode)
	logger := zaptest.NewLogger(t).Sugar()

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for _, p := range policies {
		builder = builder.WithObjects(p)
	}
	cli := builder.Build()

	cfg := config.Config{}
	cfg.Frontend.BaseURL = "https://breakglass.example.com"

	wc := NewWebhookController(
		logger, cfg,
		&breakglass.SessionManager{Client: cli},
		&escalation.EscalationManager{Client: cli},
		nil,
		policy.NewEvaluator(cli, logger),
	)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/authorize/test-cluster", nil)

	s := &authorizeState{
		startTime:   time.Now(),
		clusterName: "test-cluster",
		ctx:         context.Background(),
		reqLog:      logger,
		phases:      NewSARPhaseTracker("test-cluster", logger),
		clusterCfg:  clusterCfg,
	}

	return &impersonationTestFixture{wc: wc, c: c, w: w, s: s}
}

// withSAR sets the SubjectAccessReview under test.
func (f *impersonationTestFixture) withSAR(verb, group, resource, subresource, name, namespace string) *impersonationTestFixture {
	f.s.sar = authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "system:serviceaccount:breakglass:manager",
			UID:    "requestor-uid-1",
			Groups: []string{"system:serviceaccounts", "system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:        verb,
				Group:       group,
				Resource:    resource,
				Subresource: subresource,
				Name:        name,
				Namespace:   namespace,
			},
		},
	}
	return f
}

// response decodes the SAR response the handler wrote.
func (f *impersonationTestFixture) response(t *testing.T) SubjectAccessReviewResponse {
	t.Helper()
	var resp SubjectAccessReviewResponse
	require.NoError(t, json.Unmarshal(f.w.Body.Bytes(), &resp), "response body: %s", f.w.Body.String())
	return resp
}

// TestEvaluateImpersonation_OrdinaryRequestsUntouched is the no-regression guard.
//
// A false deny here would lock people out of production clusters during an
// emergency, which is the exact opposite of what breakglass is for. Ordinary
// requests must pass straight through with nothing written to the response.
func TestEvaluateImpersonation_OrdinaryRequestsUntouched(t *testing.T) {
	ordinary := []struct {
		name                  string
		verb, group, resource string
	}{
		{"get pods", "get", "", "pods"},
		{"list secrets", "list", "", "secrets"},
		{"create deployments", "create", "apps", "deployments"},
		{"delete nodes", "delete", "", "nodes"},
		// Resources that share a NAME with impersonation identity kinds but are not
		// impersonation checks, because the verb is ordinary.
		{"get users resource", "get", "", "users"},
		{"list groups resource", "list", "", "groups"},
		// A verb that merely contains the substring must not be caught.
		{"reimpersonate verb", "reimpersonate", "", "users"},
	}

	// A deny-all impersonation policy must not affect any of these.
	denyAll := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-all-impersonation"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{}},
		},
	}

	for _, tc := range ordinary {
		t.Run(tc.name, func(t *testing.T) {
			f := newImpersonationFixture(t, nil, denyAll).
				withSAR(tc.verb, tc.group, tc.resource, "", "", "default")

			handled := f.wc.evaluateImpersonation(f.c, f.s)

			assert.False(t, handled,
				"an ordinary request was short-circuited by impersonation evaluation")
			assert.Nil(t, f.s.impersonation,
				"impersonation state was populated for an ordinary request")
			assert.Empty(t, f.w.Body.String(),
				"a response was written for an ordinary request")
		})
	}
}

// TestEvaluateImpersonation_UnrecognisedVerbDenied is THE security test.
//
// A webhook authorizer that allows verbs it does not recognise silently grants
// constrained impersonation on any cluster with the gate enabled — beta and on by
// default since 1.36. This must fail closed.
func TestEvaluateImpersonation_UnrecognisedVerbDenied(t *testing.T) {
	unrecognised := []string{
		// A mode a future apiserver might add.
		"impersonate:some-future-mode",
		"impersonate-on:some-future-mode:list",
		// Structurally malformed.
		"impersonate:",
		"impersonate-on:user-info",
		"impersonate-on:user-info:",
		"impersonate-on:",
		"impersonate-on:user-info:list:extra",
		// Legacy is not a constrained mode, so these verbs are never issued.
		"impersonate:legacy",
		"impersonate-on:legacy:list",
		// Case sensitivity.
		"impersonate:USER-INFO",
	}

	for _, verb := range unrecognised {
		t.Run(verb, func(t *testing.T) {
			f := newImpersonationFixture(t, nil).
				withSAR(verb, "authentication.k8s.io", "users", "", "jane@example.com", "")

			handled := f.wc.evaluateImpersonation(f.c, f.s)

			require.True(t, handled,
				"verb %q was NOT handled; it would fall through to the generic path and could "+
					"be silently allowed, granting constrained impersonation", verb)

			resp := f.response(t)
			assert.False(t, resp.Status.Allowed,
				"verb %q was ALLOWED: this is the silent-grant vulnerability", verb)
			assert.Contains(t, resp.Status.Reason, "does not recognise",
				"the denial does not explain itself")
			assert.Contains(t, resp.Status.Reason, verb,
				"the denial does not name the offending verb")
		})
	}
}

// TestEvaluateImpersonation_UnrecognisedVerbOptOut covers the escape hatch for
// debugging a newer apiserver against an older breakglass.
func TestEvaluateImpersonation_UnrecognisedVerbOptOut(t *testing.T) {
	no := false
	cc := &breakglassv1alpha1.ClusterConfig{
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ConstrainedImpersonation: &breakglassv1alpha1.ConstrainedImpersonationConfig{
				DenyUnrecognisedVerbs: &no,
			},
		},
	}

	f := newImpersonationFixture(t, cc).
		withSAR("impersonate:some-future-mode", "authentication.k8s.io", "users", "", "jane", "")

	handled := f.wc.evaluateImpersonation(f.c, f.s)

	assert.False(t, handled, "opt-out did not let the verb through")
	assert.Empty(t, f.w.Body.String())
}

// TestEvaluateImpersonation_UnrecognisedVerbDeniedByDefaultForOldClusterConfig is
// the backwards-compatibility half of the security property: a ClusterConfig
// onboarded before this field existed must still be protected.
func TestEvaluateImpersonation_UnrecognisedVerbDeniedByDefaultForOldClusterConfig(t *testing.T) {
	oldConfigs := []*breakglassv1alpha1.ClusterConfig{
		// No ClusterConfig resolved at all.
		nil,
		// A ClusterConfig with no constrainedImpersonation block, i.e. every cluster
		// onboarded before this change.
		{Spec: breakglassv1alpha1.ClusterConfigSpec{ClusterID: "old-spoke"}},
		// An empty block.
		{Spec: breakglassv1alpha1.ClusterConfigSpec{
			ConstrainedImpersonation: &breakglassv1alpha1.ConstrainedImpersonationConfig{},
		}},
	}

	for i, cc := range oldConfigs {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			f := newImpersonationFixture(t, cc).
				withSAR("impersonate:future", "authentication.k8s.io", "users", "", "jane", "")

			require.True(t, f.wc.evaluateImpersonation(f.c, f.s),
				"a ClusterConfig predating this feature did not deny an unknown impersonation verb")
			assert.False(t, f.response(t).Status.Allowed)
		})
	}
}

// TestEvaluateImpersonation_SystemMastersAlwaysDenied covers the guardrail that
// closes the legacy path's gap.
func TestEvaluateImpersonation_SystemMastersAlwaysDenied(t *testing.T) {
	// Every verb family, including legacy — which the apiserver does NOT protect.
	verbs := []string{
		"impersonate",
		"impersonate:user-info",
		"impersonate:serviceaccount",
	}

	for _, verb := range verbs {
		t.Run(verb, func(t *testing.T) {
			f := newImpersonationFixture(t, nil).
				withSAR(verb, "authentication.k8s.io", "groups", "", "system:masters", "")

			require.True(t, f.wc.evaluateImpersonation(f.c, f.s),
				"system:masters impersonation via %q was not denied", verb)

			resp := f.response(t)
			assert.False(t, resp.Status.Allowed)
			assert.Contains(t, resp.Status.Reason, "system:masters")
		})
	}
}

// TestEvaluateImpersonation_SystemMastersWildcardCollapseDenied is the regression
// test for the guardrail's evasion path.
//
// The named system:masters check above is not enough on its own. The API server
// collapses per-group identity checks into a SINGLE check with Name="*" once a
// request impersonates four or more groups
// (impersonation.ManyAuthorizationChecksInLoop). A request for system:masters plus
// three filler groups therefore never presents Name=="system:masters" — it presents
// "*" — so a guardrail that only compares the literal name is bypassed by adding
// padding groups.
//
// Both shapes are asserted deliberately: the 3-group shape proves the per-group
// checks still arrive by name (and are denied by name), and the 4-group shape proves
// the collapsed wildcard is denied too.
func TestEvaluateImpersonation_SystemMastersWildcardCollapseDenied(t *testing.T) {
	// Pin the assumption this test is built on. If upstream ever changes the
	// threshold, the shapes below stop modelling the apiserver and this fails loudly
	// rather than silently testing nothing.
	require.Equal(t, 4, impersonation.ManyAuthorizationChecksInLoop,
		"the apiserver's wildcard-collapse threshold changed; the group shapes below must follow")

	// Verbs that carry an identity target. Legacy is included because it is the
	// exposure the guardrail exists to close: the apiserver does not hard-deny
	// system:masters for legacy impersonation.
	verbs := []string{"impersonate", "impersonate:user-info"}

	t.Run("below the collapse threshold each group arrives by name", func(t *testing.T) {
		// 3 groups: no collapse, so the apiserver issues one check per group and the
		// system:masters one is caught by name.
		for _, verb := range verbs {
			t.Run(verb, func(t *testing.T) {
				f := newImpersonationFixture(t, nil).
					withSAR(verb, "authentication.k8s.io", "groups", "", "system:masters", "")

				require.True(t, f.wc.evaluateImpersonation(f.c, f.s),
					"the named system:masters check was not denied for %q", verb)

				resp := f.response(t)
				assert.False(t, resp.Status.Allowed)
				assert.Contains(t, resp.Status.Reason, "system:masters")
			})
		}
	})

	t.Run("at or above the collapse threshold the wildcard check is denied", func(t *testing.T) {
		// 4+ groups including system:masters: the apiserver collapses to Name="*",
		// which cannot be proven not to include system:masters.
		for _, verb := range verbs {
			t.Run(verb, func(t *testing.T) {
				f := newImpersonationFixture(t, nil).
					withSAR(verb, "authentication.k8s.io", "groups", "", "*", "")

				require.True(t, f.wc.evaluateImpersonation(f.c, f.s),
					"a collapsed wildcard group check evaded the system:masters guardrail for %q; "+
						"impersonating system:masters plus three filler groups is a cluster-admin bypass",
					verb)

				resp := f.response(t)
				assert.False(t, resp.Status.Allowed)
				assert.Contains(t, resp.Status.Reason, "wildcard",
					"the denial should explain why a wildcard group check is refused")
			})
		}
	})

	// The guardrail must stay narrow: a wildcard on a resource OTHER than groups is
	// not a system:masters risk and must not be swept up by this denial.
	t.Run("a wildcard on a non-group identity resource is not denied here", func(t *testing.T) {
		f := newImpersonationFixture(t, nil).
			withSAR("impersonate:associated-node", "authentication.k8s.io", "nodes", "", "*", "")

		assert.False(t, f.wc.evaluateImpersonation(f.c, f.s),
			"the system:masters guardrail denied a nodes wildcard; associated-node identity "+
				"checks legitimately use Name=\"*\" and must fall through to the normal path")
	})
}

// TestEvaluateImpersonation_LegacyFallbackPolicy covers the three fallback policies.
func TestEvaluateImpersonation_LegacyFallbackPolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      breakglassv1alpha1.LegacyImpersonationFallbackPolicy
		wantHandled bool
		wantWarned  bool
	}{
		// Allow is the default so that existing deployments, whose blanket
		// `impersonate` grants depend on the fallback, keep working.
		{"allow", breakglassv1alpha1.LegacyImpersonationFallbackAllow, false, false},
		{"warn", breakglassv1alpha1.LegacyImpersonationFallbackWarn, false, true},
		{"forbidden", breakglassv1alpha1.LegacyImpersonationFallbackForbidden, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cc := &breakglassv1alpha1.ClusterConfig{
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					ConstrainedImpersonation: &breakglassv1alpha1.ConstrainedImpersonationConfig{
						LegacyFallback: tc.policy,
					},
				},
			}

			f := newImpersonationFixture(t, cc).
				withSAR("impersonate", "", "users", "", "jane@example.com", "")

			handled := f.wc.evaluateImpersonation(f.c, f.s)

			assert.Equal(t, tc.wantHandled, handled)
			assert.Equal(t, tc.wantWarned, f.s.impersonationWarnedLegacy)

			if tc.wantHandled {
				resp := f.response(t)
				assert.False(t, resp.Status.Allowed)
				assert.Contains(t, resp.Status.Reason, "forbidden")
			}
		})
	}
}

// TestEvaluateImpersonation_LegacyFallbackDefaultsToAllow is a compatibility test:
// an absent config must not start denying legacy impersonation.
func TestEvaluateImpersonation_LegacyFallbackDefaultsToAllow(t *testing.T) {
	for _, cc := range []*breakglassv1alpha1.ClusterConfig{
		nil,
		{Spec: breakglassv1alpha1.ClusterConfigSpec{ClusterID: "old"}},
	} {
		f := newImpersonationFixture(t, cc).
			withSAR("impersonate", "", "users", "", "jane", "")

		handled := f.wc.evaluateImpersonation(f.c, f.s)

		assert.False(t, handled,
			"legacy impersonation was denied without an explicit Forbidden policy; "+
				"this would break every existing deployment")
		assert.Empty(t, f.w.Body.String())
	}
}

// TestEvaluateImpersonation_DenyPolicyIdentityRules covers DenyPolicy matching of
// the new verbs end to end through the webhook.
func TestEvaluateImpersonation_DenyPolicyIdentityRules(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-admin-impersonation"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				// Includes legacy, closing the fallback escape hatch.
				Modes: []breakglassv1alpha1.ImpersonationMode{
					breakglassv1alpha1.ImpersonationModeUserInfo,
					breakglassv1alpha1.ImpersonationModeLegacy,
				},
				IdentityResources: []string{"users"},
				Identities:        []string{"admin-*"},
				Reason:            "impersonating admin accounts is not permitted",
			}},
		},
	}

	tests := []struct {
		name       string
		verb       string
		group      string
		resource   string
		identity   string
		wantDenied bool
	}{
		{"constrained admin denied", "impersonate:user-info", "authentication.k8s.io", "users", "admin-jane", true},
		{"legacy admin denied", "impersonate", "", "users", "admin-jane", true},
		{"non-admin allowed through", "impersonate:user-info", "authentication.k8s.io", "users", "jane", false},
		{"groups resource not in rule", "impersonate:user-info", "authentication.k8s.io", "groups", "admin-jane", false},
		{"serviceaccount mode not in rule", "impersonate:serviceaccount", "authentication.k8s.io", "serviceaccounts", "admin-jane", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newImpersonationFixture(t, nil, pol).
				withSAR(tc.verb, tc.group, tc.resource, "", tc.identity, "")

			handled := f.wc.evaluateImpersonation(f.c, f.s)

			if !tc.wantDenied {
				assert.False(t, handled, "request was denied unexpectedly")
				return
			}

			require.True(t, handled, "request was not denied")
			resp := f.response(t)
			assert.False(t, resp.Status.Allowed)
			assert.Contains(t, resp.Status.Reason, "impersonating admin accounts is not permitted")
		})
	}
}

// TestEvaluateImpersonation_DenyPolicyActionRules covers the action-verb family.
func TestEvaluateImpersonation_DenyPolicyActionRules(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-secret-writes-under-impersonation"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				ActionVerbs:     []string{"create", "update", "patch", "delete"},
				TargetResources: []string{"secrets"},
				TargetAPIGroups: []string{""},
				Reason:          "writing secrets under impersonation is not permitted",
			}},
		},
	}

	tests := []struct {
		name       string
		verb       string
		group      string
		resource   string
		wantDenied bool
	}{
		{"delete secrets denied", "impersonate-on:user-info:delete", "", "secrets", true},
		{"create secrets denied", "impersonate-on:serviceaccount:create", "", "secrets", true},
		{"get secrets allowed", "impersonate-on:user-info:get", "", "secrets", false},
		{"delete pods allowed", "impersonate-on:user-info:delete", "", "pods", false},
		{"delete secrets other group allowed", "impersonate-on:user-info:delete", "apps", "secrets", false},
		// An action rule must not fire on an identity check.
		{"identity check unaffected", "impersonate:user-info", "authentication.k8s.io", "users", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newImpersonationFixture(t, nil, pol).
				withSAR(tc.verb, tc.group, tc.resource, "", "", "default")

			handled := f.wc.evaluateImpersonation(f.c, f.s)

			if !tc.wantDenied {
				assert.False(t, handled, "request was denied unexpectedly")
				return
			}

			require.True(t, handled, "request was not denied")
			resp := f.response(t)
			assert.False(t, resp.Status.Allowed)
			assert.Contains(t, resp.Status.Reason, "writing secrets under impersonation")
		})
	}
}

// TestEvaluateImpersonation_DenyPolicyWildcardCollapse covers the apiserver's
// hardcoded behaviour of collapsing >= 4 identity checks into one "*" check.
func TestEvaluateImpersonation_DenyPolicyWildcardCollapse(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-cluster-admin-group"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				IdentityResources: []string{"groups"},
				Identities:        []string{"cluster-admins"},
			}},
		},
	}

	// The apiserver sends name="*" once a request names 4+ groups.
	f := newImpersonationFixture(t, nil, pol).
		withSAR("impersonate:user-info", "authentication.k8s.io", "groups", "", "*", "")

	require.True(t, f.wc.evaluateImpersonation(f.c, f.s),
		"a wildcard-collapsed group check bypassed the policy; requesting 4+ groups at once "+
			"would evade it entirely")
	assert.False(t, f.response(t).Status.Allowed)
}

// TestEvaluateImpersonation_DenyAllRule covers the "no impersonation here" form.
func TestEvaluateImpersonation_DenyAllRule(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-impersonation-at-all"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{}},
		},
	}

	verbs := []struct {
		verb, group, resource, name string
	}{
		{"impersonate", "", "users", "jane"},
		{"impersonate:user-info", "authentication.k8s.io", "users", "jane"},
		{"impersonate:serviceaccount", "authentication.k8s.io", "serviceaccounts", "probe"},
		{"impersonate:arbitrary-node", "authentication.k8s.io", "nodes", "worker-1"},
		{"impersonate:associated-node", "authentication.k8s.io", "nodes", "*"},
		{"impersonate-on:user-info:list", "", "pods", ""},
	}

	for _, v := range verbs {
		t.Run(v.verb, func(t *testing.T) {
			f := newImpersonationFixture(t, nil, pol).
				withSAR(v.verb, v.group, v.resource, "", v.name, "default")

			require.True(t, f.wc.evaluateImpersonation(f.c, f.s),
				"deny-all rule did not catch %q", v.verb)
			assert.False(t, f.response(t).Status.Allowed)
		})
	}
}

// TestEvaluateImpersonation_ScopedDenyPolicyDoesNotLeak asserts appliesTo scoping
// is honoured, so a policy for one cluster cannot deny on another.
func TestEvaluateImpersonation_ScopedDenyPolicyDoesNotLeak(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "other-cluster-only"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			AppliesTo: &breakglassv1alpha1.DenyPolicyScope{
				Clusters: []string{"some-other-cluster"},
			},
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{}},
		},
	}

	f := newImpersonationFixture(t, nil, pol).
		withSAR("impersonate:user-info", "authentication.k8s.io", "users", "", "jane", "")

	assert.False(t, f.wc.evaluateImpersonation(f.c, f.s),
		"a policy scoped to another cluster denied on this one")
}

// TestEvaluateImpersonation_PopulatesStateForAudit asserts the impersonation
// context is captured, including the requestor UID that the webhook previously
// never read.
func TestEvaluateImpersonation_PopulatesStateForAudit(t *testing.T) {
	f := newImpersonationFixture(t, nil).
		withSAR("impersonate:user-info", "authentication.k8s.io", "users", "", "jane@example.com", "")

	f.wc.evaluateImpersonation(f.c, f.s)

	require.NotNil(t, f.s.impersonation, "impersonation state was not populated")
	assert.Equal(t, "impersonate:user-info", f.s.impersonation.Verb.Raw)
	assert.Equal(t, "user-info", string(f.s.impersonation.Verb.Mode))
	assert.Equal(t, "users", f.s.impersonation.Target.Resource)
	assert.Equal(t, "jane@example.com", f.s.impersonation.Target.Name)
	assert.Equal(t, "requestor-uid-1", f.s.impersonation.Requestor.UID,
		"Spec.UID was not read into the impersonation context")
}

// TestEvaluateImpersonation_UserExtrasSubresourceIsExtraKey asserts the extra key
// is read from the subresource, which is where the apiserver puts it.
func TestEvaluateImpersonation_UserExtrasSubresourceIsExtraKey(t *testing.T) {
	pol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "no-scope-extras"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				IdentityResources: []string{"userextras"},
				ExtraKeys:         []string{"example.com/*"},
			}},
		},
	}

	f := newImpersonationFixture(t, nil, pol).
		withSAR("impersonate:user-info", "authentication.k8s.io", "userextras",
			"example.com/scopes", "admin", "")

	require.True(t, f.wc.evaluateImpersonation(f.c, f.s))
	assert.Equal(t, "example.com/scopes", f.s.impersonation.Target.Subresource)
}

// TestNoteImpersonationOutcome_DoesNotPanicWithoutImpersonation asserts the
// post-decision hook is inert for ordinary requests.
func TestNoteImpersonationOutcome_DoesNotPanicWithoutImpersonation(t *testing.T) {
	f := newImpersonationFixture(t, nil).withSAR("get", "", "pods", "", "", "default")
	f.s.allowed = true
	f.s.allowSource = "rbac"

	f.wc.noteImpersonationOutcome(f.s) // must be a no-op
}

func TestNoteImpersonationOutcome_RecordsAllowedImpersonation(t *testing.T) {
	f := newImpersonationFixture(t, nil).
		withSAR("impersonate:user-info", "authentication.k8s.io", "users", "", "jane", "")

	// Classify, then simulate the RBAC path allowing it.
	f.wc.evaluateImpersonation(f.c, f.s)
	require.NotNil(t, f.s.impersonation)
	f.s.allowed = true
	f.s.allowSource = "rbac"
	f.s.reason = "Allowed by RBAC"

	f.wc.noteImpersonationOutcome(f.s) // must not panic and must not alter the decision

	assert.True(t, f.s.allowed, "noteImpersonationOutcome changed the decision")
}

// TestConstrainedImpersonationConfig_NilClusterConfig asserts the accessor is
// nil-safe, since the webhook can run without a resolved ClusterConfig.
func TestConstrainedImpersonationConfig_NilClusterConfig(t *testing.T) {
	f := newImpersonationFixture(t, nil)

	cfg := f.wc.constrainedImpersonationConfig(f.s)

	assert.Nil(t, cfg)
	// The nil-receiver defaults must still be the safe ones.
	assert.True(t, cfg.ShouldDenyUnrecognisedVerbs())
	assert.Equal(t, breakglassv1alpha1.LegacyImpersonationFallbackAllow, cfg.EffectiveLegacyFallback())
}
