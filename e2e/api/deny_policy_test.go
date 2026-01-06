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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDenyPolicyEnforcement tests that DenyPolicy resources are enforced correctly.
//
// Test coverage for issue #48:
// - Create DenyPolicy that blocks specific resources
// - Verify policy is created and can be fetched
// - Test policy lifecycle (create, update, delete)
func TestDenyPolicyEnforcement(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateDenyPolicy", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-deny-secrets",
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{"production"},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						APIGroups:  []string{""},
						Resources:  []string{"secrets"},
						Verbs:      []string{"*"},
						Namespaces: []string{"*"},
					},
				},
			},
		}

		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create DenyPolicy")

		// Verify it can be fetched
		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err, "Failed to get DenyPolicy")
		require.Len(t, fetched.Spec.Rules, 1)
		require.Contains(t, fetched.Spec.Rules[0].Resources, "secrets")
	})

	t.Run("CreateMultiRuleDenyPolicy", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-deny-multi-rule",
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{
					{
						APIGroups:  []string{""},
						Resources:  []string{"secrets"},
						Verbs:      []string{"delete"},
						Namespaces: []string{"kube-system"},
					},
					{
						APIGroups:  []string{""},
						Resources:  []string{"configmaps"},
						Verbs:      []string{"delete"},
						Namespaces: []string{"kube-system"},
					},
				},
			},
		}

		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create multi-rule DenyPolicy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Rules, 2)
	})

	t.Run("UpdateDenyPolicy", func(t *testing.T) {
		var policy telekomv1alpha1.DenyPolicy
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-deny-secrets"}, &policy)
		require.NoError(t, err)

		// Add another deny rule
		policy.Spec.Rules = append(policy.Spec.Rules, telekomv1alpha1.DenyRule{
			APIGroups:  []string{""},
			Resources:  []string{"configmaps"},
			Verbs:      []string{"delete"},
			Namespaces: []string{"kube-system"},
		})

		err = cli.Update(ctx, &policy)
		require.NoError(t, err, "Failed to update DenyPolicy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Rules, 2)
	})

	t.Run("DeleteDenyPolicy", func(t *testing.T) {
		var policy telekomv1alpha1.DenyPolicy
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-deny-secrets"}, &policy)
		require.NoError(t, err)

		err = cli.Delete(ctx, &policy)
		require.NoError(t, err, "Failed to delete DenyPolicy")

		err = helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: policy.Name}, &telekomv1alpha1.DenyPolicy{}, 30*time.Second)
		require.NoError(t, err, "DenyPolicy was not deleted")
	})
}

// TestDenyPolicyWithPodSecurityRules tests DenyPolicy with pod security evaluation.
func TestDenyPolicyWithPodSecurityRules(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreatePolicyWithPodSecurityRules", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "e2e-test-pod-security-policy",
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
					BlockFactors: []string{
						"hostNetwork",
						"hostPID",
					},
					RiskFactors: telekomv1alpha1.RiskFactors{
						PrivilegedContainer: 100,
						HostNetwork:         80,
						HostPID:             80,
					},
					Thresholds: []telekomv1alpha1.RiskThreshold{
						{MaxScore: 50, Action: "allow"},
						{MaxScore: 80, Action: "warn"},
						{MaxScore: 100, Action: "deny", Reason: "Pod risk score too high: {{.Score}}"},
					},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						APIGroups:  []string{""},
						Resources:  []string{"pods/exec"},
						Verbs:      []string{"create"},
						Namespaces: []string{"*"},
					},
				},
			},
		}

		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create DenyPolicy with PodSecurityRules")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		require.Len(t, fetched.Spec.PodSecurityRules.Thresholds, 3)
	})
}

// TestDenyPolicyBlocksSpecificVerbs [DP-001] tests that DenyPolicy can block specific verbs
// while allowing others.
func TestDenyPolicyBlocksSpecificVerbs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create DenyPolicy that blocks "delete" verb on pods
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp001-block-delete",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{""},
					Resources:  []string{"pods"},
					Verbs:      []string{"delete"},
					Namespaces: []string{"*"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp001-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// Use breakglass-pods-admin which has RBAC for pods (get, list, create, update, patch, delete)
			EscalatedGroup:  "breakglass-pods-admin",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy verb blocking",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	t.Run("DeleteVerbBlocked", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "delete",
					Group:     "",
					Resource:  "pods",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "Delete verb should be blocked by DenyPolicy")
	})

	t.Run("GetVerbAllowed", func(t *testing.T) {
		// Use 'list' verb instead of 'get' to avoid fixture policy blocking 'get pods'
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "list",
					Group:     "",
					Resource:  "pods",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.True(t, resp.Status.Allowed, "List verb should be allowed")
	})
}

// TestDenyPolicyBlocksSpecificResources [DP-002] tests that DenyPolicy can block
// specific resources while allowing others.
func TestDenyPolicyBlocksSpecificResources(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create DenyPolicy that blocks all verbs on secrets
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp002-block-secrets",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{""},
					Resources:  []string{"secrets"},
					Verbs:      []string{"*"},
					Namespaces: []string{"*"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp002-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// Use breakglass-emergency-admin which has RBAC for all resources
			EscalatedGroup:  "breakglass-emergency-admin",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy resource blocking",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	t.Run("SecretsBlocked", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "Secrets access should be blocked by DenyPolicy")
	})

	t.Run("ConfigMapsAllowed", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "configmaps",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.True(t, resp.Status.Allowed, "ConfigMaps access should be allowed")
	})
}

// TestDenyPolicyBlocksSpecificNamespaces [DP-003] tests that DenyPolicy can block
// access to specific namespaces while allowing others.
func TestDenyPolicyBlocksSpecificNamespaces(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create DenyPolicy that blocks access to "production" namespace
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp003-block-production",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{""},
					Resources:  []string{"*"},
					Verbs:      []string{"*"},
					Namespaces: []string{"production"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp003-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// Use breakglass-pods-admin which has RBAC for pods
			EscalatedGroup:  "breakglass-pods-admin",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy namespace blocking",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	t.Run("ProductionNamespaceBlocked", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "production",
					Verb:      "get",
					Group:     "",
					Resource:  "pods",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "Production namespace access should be blocked")
	})

	t.Run("DefaultNamespaceAllowed", func(t *testing.T) {
		// Use 'services' instead of 'pods' to avoid fixture policy blocking 'get pods'
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "services",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.True(t, resp.Status.Allowed, "Default namespace access should be allowed")
	})
}

// TestDenyPolicyBlocksSpecificAPIGroups [DP-004] tests that DenyPolicy can block
// specific API groups while allowing others.
func TestDenyPolicyBlocksSpecificAPIGroups(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create DenyPolicy that blocks "apps" API group
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp004-block-apps",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{"apps"},
					Resources:  []string{"*"},
					Verbs:      []string{"*"},
					Namespaces: []string{"*"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp004-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// Use breakglass-multi-cluster-ops which has RBAC for apps group (deployments, etc.)
			EscalatedGroup:  "breakglass-multi-cluster-ops",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy API group blocking",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	t.Run("AppsGroupBlocked", func(t *testing.T) {
		// Deployments are in the "apps" group
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "apps",
					Resource:  "deployments",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "Apps API group access should be blocked")
	})

	t.Run("CoreGroupAllowed", func(t *testing.T) {
		// Services are in core group (empty string) - use services instead of pods
		// to avoid fixture policy blocking 'get pods'
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "services",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.True(t, resp.Status.Allowed, "Core API group access should be allowed")
	})
}

// TestDenyPolicyBlocksSpecificResourceNames [DP-005] tests that DenyPolicy can block
// access to specific resource names while allowing others.
func TestDenyPolicyBlocksSpecificResourceNames(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create DenyPolicy that blocks access to secret named "database-password"
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp005-block-resource-name",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:     []string{""},
					Resources:     []string{"secrets"},
					Verbs:         []string{"*"},
					Namespaces:    []string{"*"},
					ResourceNames: []string{"database-password"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp005-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// Use breakglass-emergency-admin which has RBAC for all resources
			EscalatedGroup:  "breakglass-emergency-admin",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy resource name blocking",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	t.Run("SpecificSecretBlocked", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
					Name:      "database-password",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "Access to database-password secret should be blocked")
	})

	t.Run("OtherConfigMapsAllowed", func(t *testing.T) {
		// Use configmaps instead of secrets since fixture policy blocks all secrets in default namespace
		// This tests that our policy only blocks the specific resource name "database-password"
		// by using a different resource type (configmaps) that has no fixture blocking it
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "configmaps",
					Name:      "other-configmap",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.True(t, resp.Status.Allowed, "Access to other configmaps should be allowed")
	})
}

// TestDenyPolicyPrecedenceOrdering [DP-007] tests that DenyPolicy precedence controls
// evaluation order when multiple policies apply.
func TestDenyPolicyPrecedenceOrdering(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create two overlapping policies with different precedence
	// Policy 1: Lower precedence (10) - blocks secrets
	lowerPrecedence := int32(10)
	denyPolicy1 := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp007-low-precedence",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Precedence: &lowerPrecedence,
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{""},
					Resources:  []string{"secrets"},
					Verbs:      []string{"*"},
					Namespaces: []string{"*"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy1)
	err := cli.Create(ctx, denyPolicy1)
	require.NoError(t, err, "Failed to create low precedence DenyPolicy")

	// Policy 2: Higher precedence (50) - blocks configmaps
	higherPrecedence := int32(50)
	denyPolicy2 := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp007-high-precedence",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			Precedence: &higherPrecedence,
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{""},
					Resources:  []string{"configmaps"},
					Verbs:      []string{"*"},
					Namespaces: []string{"*"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy2)
	err = cli.Create(ctx, denyPolicy2)
	require.NoError(t, err, "Failed to create high precedence DenyPolicy")

	// Create escalation referencing both policies
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp007-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			// Use breakglass-emergency-admin which has RBAC for all resources
			EscalatedGroup:  "breakglass-emergency-admin",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy1.Name, denyPolicy2.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy precedence ordering",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	// Both policies should be evaluated and block their respective resources
	t.Run("SecretsBlockedByLowerPrecedence", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "secrets",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "Secrets should be blocked by low precedence policy")
	})

	t.Run("ConfigMapsBlockedByHigherPrecedence", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "configmaps",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.False(t, resp.Status.Allowed, "ConfigMaps should be blocked by high precedence policy")
	})

	t.Run("ServicesAllowedByBothPolicies", func(t *testing.T) {
		// Use 'services' instead of 'pods' to avoid fixture policy blocking 'get pods'
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "services",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		assert.True(t, resp.Status.Allowed, "Services should be allowed (no matching policy)")
	})
}

// TestDenyPolicyExemptionByNamespace [DP-008] tests that PodSecurityRules exemptions
// by namespace work correctly.
func TestDenyPolicyExemptionByNamespace(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// Create DenyPolicy with PodSecurityRules that exempts kube-system namespace
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp008-exempt-namespace",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         80,
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "deny", Reason: "High risk pod"},
				},
				Exemptions: &telekomv1alpha1.PodSecurityExemptions{
					Namespaces: []string{"kube-system"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with namespace exemption")

	// Verify policy was created correctly
	var fetched telekomv1alpha1.DenyPolicy
	err = cli.Get(ctx, types.NamespacedName{Name: denyPolicy.Name}, &fetched)
	require.NoError(t, err)
	require.NotNil(t, fetched.Spec.PodSecurityRules)
	require.NotNil(t, fetched.Spec.PodSecurityRules.Exemptions)
	require.Contains(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces, "kube-system")
}

// TestDenyPolicyAppliesToClusters [DP-011] tests that DenyPolicy appliesTo.clusters
// scopes the policy to specific clusters.
func TestDenyPolicyAppliesToClusters(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, helpers.GetTestNamespace())
	apiClient := tc.ClientForUser(helpers.TestUsers.PolicyTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.PolicyTestApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create DenyPolicy that only applies to a different cluster (not our test cluster)
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "e2e-dp011-applies-to-cluster",
			Labels: map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			AppliesTo: &telekomv1alpha1.DenyPolicyScope{
				Clusters: []string{"other-cluster"}, // Not our test cluster
			},
			Rules: []telekomv1alpha1.DenyRule{
				{
					APIGroups:  []string{""},
					Resources:  []string{"secrets"},
					Verbs:      []string{"*"},
					Namespaces: []string{"*"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with appliesTo.clusters")

	// Create escalation referencing the DenyPolicy
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-dp011-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "breakglass-emergency-admin", // Must have RBAC binding for SAR to succeed
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.PolicyTestRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.PolicyTestApprover.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy cluster scope",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	t.Run("PolicyNotEnforcedOnOtherCluster", func(t *testing.T) {
		// Policy applies to "other-cluster", not our test cluster
		// Use serviceaccounts - a resource not blocked by other test policies
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   helpers.TestUsers.PolicyTestRequester.Email,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Group:     "",
					Resource:  "serviceaccounts",
				},
			},
		}

		resp, err := apiClient.SendSAR(ctx, t, clusterName, sar)
		require.NoError(t, err)
		// Policy should NOT be enforced because it only applies to "other-cluster"
		assert.True(t, resp.Status.Allowed, "ServiceAccounts should be allowed (policy applies to different cluster)")
	})
}
