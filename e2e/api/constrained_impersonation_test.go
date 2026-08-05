/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/impersonation"
)

// sarWebhookResponse mirrors the webhook's response shape.
type sarWebhookResponse struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	} `json:"status"`
}

// constrainedImpersonationGateEnabled reports whether the e2e cluster was created
// with the ConstrainedImpersonation gate on. The kind setup script exports this, so
// the same test file covers both halves of the version matrix.
func constrainedImpersonationGateEnabled() bool {
	// Default true: the gate is beta and on by default from Kubernetes 1.36, which
	// is the version the e2e node image pins.
	return os.Getenv("CONSTRAINED_IMPERSONATION") != "false"
}

// postSARToWebhook sends a SubjectAccessReview to the breakglass authorization
// webhook and returns the decoded decision.
//
// This exercises the real HTTP path the kube-apiserver uses, so a regression in
// verb handling shows up here exactly as it would in production.
func postSARToWebhook(
	t *testing.T,
	ctx context.Context,
	clusterName string,
	sar *authorizationv1.SubjectAccessReview,
) sarWebhookResponse {
	t.Helper()

	body, err := json.Marshal(sar)
	require.NoError(t, err, "failed to marshal SubjectAccessReview")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		helpers.GetWebhookAuthorizePath(clusterName), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := helpers.WebhookHTTPClient().Do(req)
	require.NoError(t, err, "the breakglass webhook must be reachable in the E2E environment")
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"the webhook must answer 200 even for denials; body: %s", string(raw))

	var decoded sarWebhookResponse
	require.NoError(t, json.Unmarshal(raw, &decoded), "response body: %s", string(raw))

	t.Logf("SAR verb=%q -> allowed=%v reason=%q",
		sar.Spec.ResourceAttributes.Verb, decoded.Status.Allowed, decoded.Status.Reason)

	return decoded
}

// impersonationSAR builds a SubjectAccessReview of the shape the kube-apiserver
// issues for an impersonation authorization check.
func impersonationSAR(verb, group, resource, subresource, name, namespace string) *authorizationv1.SubjectAccessReview {
	return &authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   helpers.TestUsers.Requester.Email,
			UID:    "e2e-requestor-uid",
			Groups: []string{"system:authenticated"},
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
}

// TestConstrainedImpersonation_UnrecognisedVerbsAreDenied is the end-to-end proof
// that the security gap is closed.
//
// Before this feature, the webhook had no notion of the constrained impersonation
// verbs. Since Kubernetes 1.36 the apiserver asks about them by default, and an
// authorizer that allows verbs it does not recognise silently grants constrained
// impersonation. This test drives the real webhook over HTTP and asserts it denies.
//
// It runs regardless of the gate: the webhook's answer must not depend on whether
// the cluster it is protecting has the feature enabled, because the webhook may
// authorize several spokes at different versions.
func TestConstrainedImpersonation_UnrecognisedVerbsAreDenied(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()

	unrecognised := []string{
		// A mode a future apiserver might introduce.
		"impersonate:some-future-mode",
		"impersonate-on:some-future-mode:list",
		// Structurally malformed.
		"impersonate:",
		"impersonate-on:user-info",
		"impersonate-on:user-info:",
		// legacy has no constrained verb form.
		"impersonate:legacy",
		"impersonate-on:legacy:list",
	}

	for _, verb := range unrecognised {
		t.Run(verb, func(t *testing.T) {
			sar := impersonationSAR(verb, impersonation.APIGroupAuthentication,
				"users", "", "someone@example.com", "")

			decision := postSARToWebhook(t, ctx, clusterName, sar)

			require.False(t, decision.Status.Allowed,
				"the webhook ALLOWED unrecognised impersonation verb %q. On a cluster with the "+
					"ConstrainedImpersonation gate enabled the apiserver would treat this as "+
					"vetted, silently granting constrained impersonation.", verb)
			assert.Contains(t, decision.Status.Reason, "does not recognise",
				"the denial should explain why it happened")
		})
	}
}

// TestConstrainedImpersonation_SystemMastersDenied proves the guardrail holds over
// the real HTTP path, for both the constrained and the legacy verb.
//
// The legacy case matters most: the apiserver hard-denies system:masters for
// constrained impersonation but deliberately does NOT for legacy, so this is a gap
// only breakglass can close.
func TestConstrainedImpersonation_SystemMastersDenied(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()

	verbs := []struct {
		name  string
		verb  string
		group string
	}{
		{"constrained", impersonation.IdentityVerb(impersonation.ModeUserInfo), impersonation.APIGroupAuthentication},
		// Legacy uses the CORE api group, not authentication.k8s.io.
		{"legacy", impersonation.VerbLegacyImpersonate, ""},
	}

	for _, tc := range verbs {
		t.Run(tc.name, func(t *testing.T) {
			sar := impersonationSAR(tc.verb, tc.group, "groups", "",
				impersonation.GroupSystemMasters, "")

			decision := postSARToWebhook(t, ctx, clusterName, sar)

			require.False(t, decision.Status.Allowed,
				"the webhook allowed impersonation of %s via %q",
				impersonation.GroupSystemMasters, tc.verb)
			assert.Contains(t, decision.Status.Reason, "system:masters")
		})
	}
}

// TestConstrainedImpersonation_DenyPolicyGrantAndDeny proves the allow/deny pair
// the task calls for: an impersonation check is denied when a DenyPolicy targets it
// and permitted through when none does.
func TestConstrainedImpersonation_DenyPolicyGrantAndDeny(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	clusterName := helpers.GetTestClusterName()

	const deniedIdentity = "e2e-forbidden-impersonation-target@example.com"
	const allowedIdentity = "e2e-ordinary-impersonation-target@example.com"

	// Baseline: with no policy in place the webhook must NOT deny for policy
	// reasons. It may still deny for lack of a grant, but the reason must not name a
	// policy — otherwise the second half of this test proves nothing.
	baseline := postSARToWebhook(t, ctx, clusterName,
		impersonationSAR(impersonation.IdentityVerb(impersonation.ModeUserInfo),
			impersonation.APIGroupAuthentication, "users", "", deniedIdentity, ""))
	assert.NotContains(t, baseline.Status.Reason, "DenyPolicy",
		"a DenyPolicy denial was reported before any policy was created")

	// Now install a policy that denies exactly this identity, in every mode
	// including legacy so the fallback cannot be used to route around it.
	policy := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-constrained-impersonation-deny"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				Modes: []breakglassv1alpha1.ImpersonationMode{
					breakglassv1alpha1.ImpersonationModeUserInfo,
					breakglassv1alpha1.ImpersonationModeLegacy,
				},
				IdentityResources: []string{"users"},
				Identities:        []string{deniedIdentity},
				Reason:            "e2e: impersonating this identity is forbidden",
			}},
		},
	}
	helpers.CreateAndCleanup(t, ctx, cli, policy)

	// The evaluator reads through the controller-runtime cache, so allow the
	// informer a moment to observe the new policy.
	require.Eventually(t, func() bool {
		d := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.IdentityVerb(impersonation.ModeUserInfo),
				impersonation.APIGroupAuthentication, "users", "", deniedIdentity, ""))
		return !d.Status.Allowed &&
			bytes.Contains([]byte(d.Status.Reason), []byte("forbidden"))
	}, 60*time.Second, 2*time.Second,
		"the DenyPolicy never took effect for the targeted identity")

	t.Run("LegacyVerbAlsoDenied", func(t *testing.T) {
		// The rule lists legacy, so the apiserver's fallback to unconstrained
		// impersonation must not be a way around it.
		decision := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.VerbLegacyImpersonate, "", "users", "", deniedIdentity, ""))

		require.False(t, decision.Status.Allowed,
			"the legacy fallback verb bypassed a policy that explicitly lists legacy mode")
	})

	t.Run("UntargetedIdentityNotDeniedByPolicy", func(t *testing.T) {
		// A different identity must not be caught. This is what proves the rule is
		// scoped rather than denying everything.
		decision := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.IdentityVerb(impersonation.ModeUserInfo),
				impersonation.APIGroupAuthentication, "users", "", allowedIdentity, ""))

		assert.NotContains(t, decision.Status.Reason, "forbidden",
			"the policy denied an identity it does not name")
	})
}

// TestConstrainedImpersonation_ActionVerbDenyPolicy covers the action-verb family
// over the real HTTP path.
func TestConstrainedImpersonation_ActionVerbDenyPolicy(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	clusterName := helpers.GetTestClusterName()

	policy := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-impersonation-no-secret-writes"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				ActionVerbs:     []string{"create", "update", "patch", "delete"},
				TargetResources: []string{"secrets"},
				TargetAPIGroups: []string{""},
				Reason:          "e2e: writing secrets under impersonation is forbidden",
			}},
		},
	}
	helpers.CreateAndCleanup(t, ctx, cli, policy)

	// Action checks carry the TARGET request's own attributes, so the SAR names the
	// resource being written rather than an impersonation identity.
	deleteSecrets := impersonationSAR(
		impersonation.ActionVerb(impersonation.ModeUserInfo, "delete"), "", "secrets", "", "", "default")

	require.Eventually(t, func() bool {
		d := postSARToWebhook(t, ctx, clusterName, deleteSecrets)
		return !d.Status.Allowed && bytes.Contains([]byte(d.Status.Reason), []byte("forbidden"))
	}, 60*time.Second, 2*time.Second,
		"the action-verb DenyPolicy never took effect")

	t.Run("ReadIsNotDenied", func(t *testing.T) {
		// The rule lists only write verbs.
		decision := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.ActionVerb(impersonation.ModeUserInfo, "get"),
				"", "secrets", "", "", "default"))

		assert.NotContains(t, decision.Status.Reason, "forbidden",
			"a read action was denied by a write-only rule")
	})

	t.Run("OtherResourceIsNotDenied", func(t *testing.T) {
		decision := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.ActionVerb(impersonation.ModeUserInfo, "delete"),
				"", "pods", "", "", "default"))

		assert.NotContains(t, decision.Status.Reason, "forbidden",
			"a rule scoped to secrets denied an action on pods")
	})
}

// TestConstrainedImpersonation_OrdinaryRequestsUnaffected is the no-regression test.
//
// A false deny in the authorization webhook locks people out of production during
// an emergency, which is the opposite of this tool's purpose. Ordinary verbs must
// behave exactly as before, even with a deny-all impersonation policy installed.
func TestConstrainedImpersonation_OrdinaryRequestsUnaffected(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	clusterName := helpers.GetTestClusterName()

	// The broadest possible impersonation policy: an empty rule denies ALL
	// impersonation, in every mode.
	policy := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-impersonation-deny-all"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			ImpersonationRules: []breakglassv1alpha1.ImpersonationDenyRule{{
				Reason: "e2e: no impersonation at all",
			}},
		},
	}
	helpers.CreateAndCleanup(t, ctx, cli, policy)

	// Confirm the policy is actually live, so the assertions below are meaningful.
	require.Eventually(t, func() bool {
		d := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.IdentityVerb(impersonation.ModeUserInfo),
				impersonation.APIGroupAuthentication, "users", "", "anyone@example.com", ""))
		return !d.Status.Allowed &&
			bytes.Contains([]byte(d.Status.Reason), []byte("no impersonation at all"))
	}, 60*time.Second, 2*time.Second, "the deny-all impersonation policy never took effect")

	ordinary := []struct {
		name                  string
		verb, group, resource string
	}{
		{"get pods", "get", "", "pods"},
		{"list deployments", "list", "apps", "deployments"},
		// Resources whose names collide with impersonation identity kinds. These must
		// not be caught, because the verb is ordinary.
		{"get users resource", "get", "", "users"},
		{"list groups resource", "list", "", "groups"},
		{"get nodes", "get", "", "nodes"},
		{"list serviceaccounts", "list", "", "serviceaccounts"},
	}

	for _, tc := range ordinary {
		t.Run(tc.name, func(t *testing.T) {
			decision := postSARToWebhook(t, ctx, clusterName,
				impersonationSAR(tc.verb, tc.group, tc.resource, "", "", "default"))

			// The request may legitimately be denied for lack of a grant, but never
			// because of the impersonation policy.
			assert.NotContains(t, decision.Status.Reason, "no impersonation at all",
				"an ordinary %s %s request was caught by the impersonation deny-all policy",
				tc.verb, tc.resource)
			assert.NotContains(t, decision.Status.Reason, "does not recognise",
				"an ordinary request was treated as an unrecognised impersonation verb")
		})
	}
}

// TestConstrainedImpersonation_GateMatrix asserts the per-spoke compatibility
// contract against the live cluster, in whichever gate state it was created.
//
// Run it twice to cover the matrix:
//
//	CONSTRAINED_IMPERSONATION=true  make e2e && go test ./e2e/api -run ConstrainedImpersonation
//	CONSTRAINED_IMPERSONATION=false make e2e && go test ./e2e/api -run ConstrainedImpersonation
func TestConstrainedImpersonation_GateMatrix(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	gateEnabled := constrainedImpersonationGateEnabled()
	t.Logf("ConstrainedImpersonation gate enabled on this cluster: %v", gateEnabled)

	// Log the server version for the record, so a matrix run is self-documenting.
	cfg := helpers.GetConfig(t)
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	require.NoError(t, err)
	if version, verr := dc.ServerVersion(); verr == nil {
		t.Logf("spoke server version: %s (major=%s minor=%s), VersionHint=%v",
			version.GitVersion, version.Major, version.Minor,
			impersonation.VersionHint(version.Major, version.Minor))
	}

	clusterName := helpers.GetTestClusterName()

	// INVARIANT, independent of the gate: the webhook denies verbs it cannot parse.
	// Its answer must not depend on the gate state of the cluster it protects,
	// because one breakglass instance authorizes many spokes at many versions.
	decision := postSARToWebhook(t, ctx, clusterName,
		impersonationSAR("impersonate:some-future-mode",
			impersonation.APIGroupAuthentication, "users", "", "jane@example.com", ""))
	require.False(t, decision.Status.Allowed,
		"unrecognised impersonation verbs must be denied regardless of the gate state")

	// INVARIANT, independent of the gate: legacy impersonation is still evaluated.
	// With the gate off this is the ONLY impersonation path, and breaking it would
	// stop breakglass authorizing anyone on a pre-1.35 spoke.
	legacy := postSARToWebhook(t, ctx, clusterName,
		impersonationSAR(impersonation.VerbLegacyImpersonate, "", "users", "", "jane@example.com", ""))
	assert.NotContains(t, legacy.Status.Reason, "does not recognise",
		"the legacy `impersonate` verb was treated as unrecognised; with the gate off this "+
			"is the only impersonation path and breakglass would authorize nobody")
}

// TestConstrainedImpersonation_LegacyFallbackForbidden proves the strictest
// per-spoke setting is enforced: on a spoke configured to forbid the fallback, the
// legacy verb is denied outright.
func TestConstrainedImpersonation_LegacyFallbackForbidden(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("webhook tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	cc := &breakglassv1alpha1.ClusterConfig{}
	key := types.NamespacedName{Name: clusterName, Namespace: namespace}
	if err := cli.Get(ctx, key, cc); err != nil {
		t.Skipf("cannot read ClusterConfig %s: %v", key, err)
	}

	original := cc.Spec.ConstrainedImpersonation
	t.Cleanup(func() {
		restoreCtx, cancelRestore := context.WithTimeout(context.Background(), time.Minute)
		defer cancelRestore()

		latest := &breakglassv1alpha1.ClusterConfig{}
		if err := cli.Get(restoreCtx, key, latest); err != nil {
			t.Logf("failed to reload ClusterConfig for cleanup: %v", err)
			return
		}
		latest.Spec.ConstrainedImpersonation = original
		if err := cli.Update(restoreCtx, latest); err != nil {
			t.Logf("failed to restore ClusterConfig: %v", err)
		}
	})

	cc.Spec.ConstrainedImpersonation = &breakglassv1alpha1.ConstrainedImpersonationConfig{
		Support:        breakglassv1alpha1.ConstrainedImpersonationAuto,
		LegacyFallback: breakglassv1alpha1.LegacyImpersonationFallbackForbidden,
	}
	require.NoError(t, cli.Update(ctx, cc),
		"failed to set legacyFallback=Forbidden on the ClusterConfig")

	require.Eventually(t, func() bool {
		d := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.VerbLegacyImpersonate, "", "users", "", "jane@example.com", ""))
		return !d.Status.Allowed &&
			bytes.Contains([]byte(d.Status.Reason), []byte("forbidden"))
	}, 60*time.Second, 2*time.Second,
		"legacyFallback=Forbidden did not cause the legacy `impersonate` verb to be denied")

	t.Run("ConstrainedVerbStillEvaluated", func(t *testing.T) {
		// Forbidding the fallback must not break the constrained path; otherwise the
		// setting would be unusable.
		decision := postSARToWebhook(t, ctx, clusterName,
			impersonationSAR(impersonation.IdentityVerb(impersonation.ModeUserInfo),
				impersonation.APIGroupAuthentication, "users", "", "jane@example.com", ""))

		assert.NotContains(t, decision.Status.Reason, "legacy (unconstrained) impersonation is forbidden",
			"the constrained verb was rejected by the legacy-fallback rule")
	})
}

// TestConstrainedImpersonation_MetricsExposed asserts the new metrics appear once
// impersonation SARs have been processed, so the migration is observable.
func TestConstrainedImpersonation_MetricsExposed(t *testing.T) {
	if !helpers.IsWebhookTestEnabled() || !helpers.IsMetricsTestEnabled() {
		t.Skip("webhook or metrics tests disabled")
	}
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	clusterName := helpers.GetTestClusterName()

	// Generate traffic on both the identity and the unrecognised-verb paths.
	postSARToWebhook(t, ctx, clusterName,
		impersonationSAR(impersonation.IdentityVerb(impersonation.ModeUserInfo),
			impersonation.APIGroupAuthentication, "users", "", "metrics@example.com", ""))
	postSARToWebhook(t, ctx, clusterName,
		impersonationSAR("impersonate:some-future-mode",
			impersonation.APIGroupAuthentication, "users", "", "metrics@example.com", ""))

	wantMetrics := []string{
		"breakglass_impersonation_sar_requests_total",
		"breakglass_impersonation_sar_decisions_total",
		// The security-critical series to alert on.
		"breakglass_impersonation_unrecognised_verbs_total",
	}

	require.Eventually(t, func() bool {
		body, err := helpers.FetchMetrics(ctx)
		if err != nil {
			t.Logf("failed to fetch metrics: %v", err)
			return false
		}
		for _, name := range wantMetrics {
			if !bytes.Contains([]byte(body), []byte(name)) {
				t.Logf("metric %q not present yet", name)
				return false
			}
		}
		return true
	}, 60*time.Second, 5*time.Second,
		"the constrained-impersonation metrics were never exposed: %v", wantMetrics)
}

// verify the impersonation constants used above match the spec's verb spellings.
// A typo would make every assertion in this file vacuous, since the webhook would
// classify the verb as an ordinary one.
func TestConstrainedImpersonation_VerbSpellings(t *testing.T) {
	assert.Equal(t, "impersonate", impersonation.VerbLegacyImpersonate)
	assert.Equal(t, "impersonate:user-info", impersonation.IdentityVerb(impersonation.ModeUserInfo))
	assert.Equal(t, "impersonate:serviceaccount", impersonation.IdentityVerb(impersonation.ModeServiceAccount))
	assert.Equal(t, "impersonate:arbitrary-node", impersonation.IdentityVerb(impersonation.ModeArbitraryNode))
	assert.Equal(t, "impersonate:associated-node", impersonation.IdentityVerb(impersonation.ModeAssociatedNode))
	assert.Equal(t, "impersonate-on:user-info:list",
		impersonation.ActionVerb(impersonation.ModeUserInfo, "list"))
	assert.Equal(t, "authentication.k8s.io", impersonation.APIGroupAuthentication)
	assert.Equal(t, fmt.Sprintf("%s%s", "system:", "masters"), impersonation.GroupSystemMasters)
}
