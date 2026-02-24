/*
Copyright 2024.

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
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDenyPolicyNamespaceSelectorTerms tests DenyPolicy namespace matching using label selectors.
func TestDenyPolicyNamespaceSelectorTerms(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	// For multi-cluster tests, namespaces must be created on the SPOKE cluster (where SAR is evaluated)
	// The default client connects to the hub cluster
	spokeCli := helpers.GetSpokeAClient(t)
	if spokeCli == nil {
		// Fall back to hub client for single-cluster tests
		spokeCli = cli
	}
	spokeCleanup := helpers.NewCleanup(t, spokeCli)

	// Create test namespaces with labels on the SPOKE cluster
	prodNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-ns-selector-prod",
			Labels: map[string]string{
				"env":  "production",
				"tier": "critical",
			},
		},
	}
	spokeCleanup.Add(prodNS)
	err := spokeCli.Create(ctx, prodNS)
	if err != nil {
		t.Logf("Namespace %s may already exist: %v", prodNS.Name, err)
	}

	stagingNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-ns-selector-staging",
			Labels: map[string]string{
				"env":  "staging",
				"tier": "non-critical",
			},
		},
	}
	spokeCleanup.Add(stagingNS)
	err = spokeCli.Create(ctx, stagingNS)
	if err != nil {
		t.Logf("Namespace %s may already exist: %v", stagingNS.Name, err)
	}

	// Create DenyPolicy with namespace selector terms on HUB cluster (where breakglass controller runs)
	// Note: Use "services" instead of "configmaps" to avoid conflict with e2e-dp007-high-precedence
	// policy which blocks all configmap operations with higher precedence
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-ns-selector-policy", "").
		AppliesToClusters(clusterName).
		WithRule(breakglassv1alpha1.DenyRule{
			APIGroups: []string{""},
			Resources: []string{"services"},
			Verbs:     []string{"delete"},
			Namespaces: &breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{
						MatchLabels: map[string]string{
							"env": "production",
						},
					},
				},
			},
		}).
		Build()
	cleanup.Add(denyPolicy)
	err = cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with namespace selector")

	// Create escalation that references this deny policy
	// Use breakglass-emergency-admin which has RBAC permissions for all resources.
	// Without RBAC permissions, the session SAR check fails before policy evaluation.
	testGroup := helpers.TestGroupEmergencyAdmin
	escalation := helpers.NewEscalationBuilder("e2e-ns-selector-escalation", namespace).
		WithEscalatedGroup(testGroup).
		WithAllowedClusters(clusterName).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   testGroup,
		Reason:  "Test namespace selector policy",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)
	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session")
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	t.Run("PolicyBlocksMatchingNamespace", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{testGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: prodNS.Name,
					Verb:      "delete",
					Group:     "",
					Resource:  "services",
				},
			},
		}
		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed,
			"Service deletion in production namespace should be denied by label selector policy")
		assert.Contains(t, strings.ToLower(resp.Status.Reason), "denied",
			"Denial reason should mention deny policy")
		assert.Contains(t, strings.ToLower(resp.Status.Reason), "policy",
			"Denial reason should mention the policy that blocked")
	})

	t.Run("PolicyDoesNotBlockNonMatchingNamespace", func(t *testing.T) {
		// This test verifies that DenyPolicy with namespace selector ONLY blocks
		// matching namespaces. Non-matching namespaces should be ALLOWED because
		// the group (breakglass-emergency-admin) has full RBAC permissions.
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{testGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: stagingNS.Name,
					Verb:      "delete",
					Group:     "",
					Resource:  "services",
				},
			},
		}
		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		// With breakglass-emergency-admin which has full permissions, the request should be allowed
		// because the staging namespace does NOT have env=production label.
		assert.True(t, resp.Status.Allowed,
			"Staging namespace should NOT be blocked by the production-only DenyPolicy")
		assert.NotContains(t, strings.ToLower(resp.Status.Reason), "e2e-ns-selector-policy",
			"Staging namespace should NOT be blocked by the production-only DenyPolicy")
	})
}

// TestDenyPolicyMixedNamespaceFilters tests DenyPolicy with both patterns and selectors combined.
func TestDenyPolicyMixedNamespaceFilters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	// For multi-cluster tests, namespaces must be created on the SPOKE cluster (where SAR is evaluated)
	spokeCli := helpers.GetSpokeAClient(t)
	if spokeCli == nil {
		spokeCli = cli
	}
	spokeCleanup := helpers.NewCleanup(t, spokeCli)

	// Create test namespace with labels that WILL match the selector (restricted=true)
	// on the SPOKE cluster
	mixedNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-mixed-ns-filter",
			Labels: map[string]string{
				"env":        "test",
				"restricted": "true",
			},
		},
	}
	spokeCleanup.Add(mixedNS)
	err := spokeCli.Create(ctx, mixedNS)
	if err != nil {
		t.Logf("Namespace %s may already exist: %v", mixedNS.Name, err)
	}

	// Create a namespace that will NOT match any filter (for testing allowed case)
	// on the SPOKE cluster
	allowedNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-mixed-ns-allowed",
			Labels: map[string]string{
				"env":        "dev",
				"restricted": "false",
			},
		},
	}
	spokeCleanup.Add(allowedNS)
	err = spokeCli.Create(ctx, allowedNS)
	if err != nil {
		t.Logf("Namespace %s may already exist: %v", allowedNS.Name, err)
	}

	// Create DenyPolicy with both patterns AND selector terms (OR logic) on HUB cluster
	// Note: Use "endpoints" instead of "secrets" to avoid conflict with pre-deployed
	// e2e-deny-secrets-all-test policy which blocks all secret operations in default/kube-system
	// Use a unique pattern (e2e-mixed-ns-blocked) that won't match pre-deployed policies
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-mixed-ns-filter-policy", "").
		AppliesToClusters(clusterName).
		WithRule(breakglassv1alpha1.DenyRule{
			APIGroups: []string{""},
			Resources: []string{"endpoints"},
			Verbs:     []string{"delete"},
			Namespaces: &breakglassv1alpha1.NamespaceFilter{
				Patterns: []string{"e2e-mixed-ns-blocked-*"},
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{
						MatchLabels: map[string]string{
							"restricted": "true",
						},
					},
				},
			},
		}).
		Build()
	cleanup.Add(denyPolicy)
	err = cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with mixed namespace filter")

	// Create escalation
	// Use breakglass-emergency-admin which has RBAC permissions for all resources.
	// Without RBAC permissions, the session SAR check fails before policy evaluation.
	testGroup := helpers.TestGroupEmergencyAdmin
	escalation := helpers.NewEscalationBuilder("e2e-mixed-ns-filter-escalation", namespace).
		WithEscalatedGroup(testGroup).
		WithAllowedClusters(clusterName).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err)

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   testGroup,
		Reason:  "Test mixed namespace filter",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)
	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Create a namespace that matches the pattern for testing on the SPOKE cluster
	blockedPatternNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-mixed-ns-blocked-pattern",
			Labels: map[string]string{
				"env": "blocked",
			},
		},
	}
	spokeCleanup.Add(blockedPatternNS)
	err = spokeCli.Create(ctx, blockedPatternNS)
	if err != nil {
		t.Logf("Namespace %s may already exist: %v", blockedPatternNS.Name, err)
	}

	t.Run("BlockedByPattern", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{testGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: blockedPatternNS.Name,
					Verb:      "delete",
					Group:     "",
					Resource:  "endpoints",
				},
			},
		}
		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed,
			"Endpoint deletion in pattern-matched namespace should be denied")
		assert.Contains(t, strings.ToLower(resp.Status.Reason), "policy",
			"Denial should mention the policy")
	})

	t.Run("BlockedByLabelSelector", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{testGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: mixedNS.Name,
					Verb:      "delete",
					Group:     "",
					Resource:  "endpoints",
				},
			},
		}
		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed,
			"Endpoint deletion in restricted namespace should be denied by label selector")
		assert.Contains(t, strings.ToLower(resp.Status.Reason), "policy",
			"Denial should mention the policy")
	})

	t.Run("PolicyDoesNotBlockUnmatchedNamespace", func(t *testing.T) {
		// This test verifies that DenyPolicy only blocks namespaces that match
		// either the pattern OR the label selector. Unmatched namespaces should
		// be ALLOWED because the group (breakglass-emergency-admin) has full RBAC permissions.
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.Requester.Email,
				Groups: []string{testGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: allowedNS.Name,
					Verb:      "delete",
					Group:     "",
					Resource:  "endpoints",
				},
			},
		}
		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		// With breakglass-emergency-admin which has full permissions, the request should be allowed
		assert.True(t, resp.Status.Allowed,
			"Unmatched namespace should be allowed for group with full permissions")
		assert.NotContains(t, strings.ToLower(resp.Status.Reason), "e2e-mixed-ns-filter-policy",
			"Unmatched namespace should NOT be blocked by the mixed DenyPolicy")
	})
}

// TestDenyPolicyMatchExpressions tests DenyPolicy with matchExpressions in label selectors.
func TestDenyPolicyMatchExpressions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// Create DenyPolicy with matchExpressions
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-match-expressions-policy", "").
		WithRule(breakglassv1alpha1.DenyRule{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"delete"},
			Namespaces: &breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{
						MatchExpressions: []breakglassv1alpha1.NamespaceSelectorRequirement{
							{
								Key:      "env",
								Operator: breakglassv1alpha1.NamespaceSelectorOpIn,
								Values:   []string{"production", "staging"},
							},
							{
								Key:      "tier",
								Operator: breakglassv1alpha1.NamespaceSelectorOpNotIn,
								Values:   []string{"dev"},
							},
						},
					},
				},
			},
		}).
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with matchExpressions")
	t.Log("DenyPolicy with matchExpressions created successfully")

	// Verify the policy was created correctly
	var fetched breakglassv1alpha1.DenyPolicy
	err = cli.Get(ctx, types.NamespacedName{Name: denyPolicy.Name}, &fetched)
	require.NoError(t, err)
	require.Len(t, fetched.Spec.Rules, 1)
	require.NotNil(t, fetched.Spec.Rules[0].Namespaces)
	require.Len(t, fetched.Spec.Rules[0].Namespaces.SelectorTerms, 1)
	require.Len(t, fetched.Spec.Rules[0].Namespaces.SelectorTerms[0].MatchExpressions, 2)
}

// TestAuditConfigNamespaceSelectors tests AuditConfig namespace label selectors.
func TestAuditConfigNamespaceSelectors(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// Create AuditConfig with namespace selectors
	auditConfig := &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-ns-selector-audit",
			Labels: map[string]string{
				"e2e-test": "true",
			},
		},
		Spec: breakglassv1alpha1.AuditConfigSpec{
			Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{
				{
					Name: "test-log",
					Type: breakglassv1alpha1.AuditSinkTypeLog,
				},
			},
			Filtering: &breakglassv1alpha1.AuditFilterConfig{
				IncludeNamespaces: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
						{
							MatchLabels: map[string]string{
								"audit": "enabled",
							},
						},
					},
				},
			},
		},
	}
	cleanup.Add(auditConfig)
	err := cli.Create(ctx, auditConfig)
	require.NoError(t, err, "Failed to create AuditConfig with namespace selector")
	t.Log("AuditConfig with namespace selector created successfully")

	// Verify the config was created correctly
	var fetched breakglassv1alpha1.AuditConfig
	err = cli.Get(ctx, types.NamespacedName{Name: auditConfig.Name}, &fetched)
	require.NoError(t, err)
	require.NotNil(t, fetched.Spec.Filtering)
	require.NotNil(t, fetched.Spec.Filtering.IncludeNamespaces)
	require.Len(t, fetched.Spec.Filtering.IncludeNamespaces.SelectorTerms, 1)
}
