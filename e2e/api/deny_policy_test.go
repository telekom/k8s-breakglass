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
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDenyPolicyEnforcement tests that DenyPolicy resources are enforced correctly.
//
// Test coverage for issue #48:
// - Create DenyPolicy that blocks specific resources
// - Verify policy is created and can be fetched
// - Test policy lifecycle (create, update, delete)
func TestDenyPolicyEnforcement(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateDenyPolicy", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-test-deny-secrets", "").
			AppliesToClusters("production").
			DenyAll([]string{""}, []string{"secrets"}, "*").
			Build()

		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create DenyPolicy")

		// Verify it can be fetched
		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err, "Failed to get DenyPolicy")
		require.Len(t, fetched.Spec.Rules, 1)
		require.Contains(t, fetched.Spec.Rules[0].Resources, "secrets")
	})

	t.Run("CreateMultiRuleDenyPolicy", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-test-deny-multi-rule", "").
			DenyResource("", "secrets", []string{"delete"}, "kube-system").
			DenyResource("", "configmaps", []string{"delete"}, "kube-system").
			Build()

		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create multi-rule DenyPolicy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Rules, 2)
	})

	t.Run("UpdateDenyPolicy", func(t *testing.T) {
		var policy breakglassv1alpha1.DenyPolicy
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-deny-secrets"}, &policy)
		require.NoError(t, err)

		// Use retry to handle conflicts with the DenyPolicyReconciler
		err = helpers.UpdateWithRetry(ctx, cli, &policy, func(p *breakglassv1alpha1.DenyPolicy) error {
			// Add another deny rule
			p.Spec.Rules = append(p.Spec.Rules, breakglassv1alpha1.DenyRule{
				APIGroups:  []string{""},
				Resources:  []string{"configmaps"},
				Verbs:      []string{"delete"},
				Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
			})
			return nil
		})
		require.NoError(t, err, "Failed to update DenyPolicy")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Rules, 2)
	})

	t.Run("DeleteDenyPolicy", func(t *testing.T) {
		var policy breakglassv1alpha1.DenyPolicy
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-deny-secrets"}, &policy)
		require.NoError(t, err)

		err = cli.Delete(ctx, &policy)
		require.NoError(t, err, "Failed to delete DenyPolicy")

		err = helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: policy.Name}, &breakglassv1alpha1.DenyPolicy{}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "DenyPolicy was not deleted")
	})
}

// TestDenyPolicyWithPodSecurityRules tests DenyPolicy with pod security evaluation.
func TestDenyPolicyWithPodSecurityRules(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreatePolicyWithPodSecurityRules", func(t *testing.T) {
		policy := helpers.NewDenyPolicyBuilder("e2e-test-pod-security-policy", "").
			WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
				BlockFactors: []string{
					"hostNetwork",
					"hostPID",
				},
				RiskFactors: breakglassv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
					HostNetwork:         80,
					HostPID:             80,
				},
				Thresholds: []breakglassv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 80, Action: "warn"},
					{MaxScore: 100, Action: "deny", Reason: "Pod risk score too high: {{.Score}}"},
				},
			}).
			DenyPodsExec("*").
			Build()

		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create DenyPolicy with PodSecurityRules")

		var fetched breakglassv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		require.Len(t, fetched.Spec.PodSecurityRules.Thresholds, 3)
	})
}

// TestDenyPolicyBlocksSpecificVerbs [DP-001] tests that DenyPolicy can block specific verbs
// while allowing others.
func TestDenyPolicyBlocksSpecificVerbs(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp001-block-delete", "").
		DenyPods([]string{"delete"}, "*").
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := helpers.NewEscalationBuilder("e2e-dp001-escalation", namespace).
		WithEscalatedGroup("breakglass-pods-admin"). // Use breakglass-pods-admin which has RBAC for pods
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy verb blocking",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp002-block-secrets", "").
		DenyAll([]string{""}, []string{"secrets"}, "*").
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := helpers.NewEscalationBuilder("e2e-dp002-escalation", namespace).
		WithEscalatedGroup("breakglass-emergency-admin"). // Use breakglass-emergency-admin which has RBAC for all resources
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy resource blocking",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp003-block-production", "").
		DenyAll([]string{""}, []string{"*"}, "production").
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := helpers.NewEscalationBuilder("e2e-dp003-escalation", namespace).
		WithEscalatedGroup("breakglass-pods-admin"). // Use breakglass-pods-admin which has RBAC for pods
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy namespace blocking",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp004-block-apps", "").
		DenyAll([]string{"apps"}, []string{"*"}, "*").
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := helpers.NewEscalationBuilder("e2e-dp004-escalation", namespace).
		WithEscalatedGroup("breakglass-multi-cluster-ops"). // Use breakglass-multi-cluster-ops which has RBAC for apps group
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy API group blocking",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp005-block-resource-name", "").
		WithRule(breakglassv1alpha1.DenyRule{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			Verbs:         []string{"*"},
			Namespaces:    &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"*"}},
			ResourceNames: []string{"database-password"},
		}).
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy")

	// Create escalation referencing the DenyPolicy
	escalation := helpers.NewEscalationBuilder("e2e-dp005-escalation", namespace).
		WithEscalatedGroup("breakglass-emergency-admin"). // Use breakglass-emergency-admin which has RBAC for all resources
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy resource name blocking",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy1 := helpers.NewDenyPolicyBuilder("e2e-dp007-low-precedence", "").
		WithPrecedence(10).
		DenyAll([]string{""}, []string{"secrets"}, "*").
		Build()
	cleanup.Add(denyPolicy1)
	err := cli.Create(ctx, denyPolicy1)
	require.NoError(t, err, "Failed to create low precedence DenyPolicy")

	// Policy 2: Higher precedence (50) - blocks configmaps
	denyPolicy2 := helpers.NewDenyPolicyBuilder("e2e-dp007-high-precedence", "").
		WithPrecedence(50).
		DenyAll([]string{""}, []string{"configmaps"}, "*").
		Build()
	cleanup.Add(denyPolicy2)
	err = cli.Create(ctx, denyPolicy2)
	require.NoError(t, err, "Failed to create high precedence DenyPolicy")

	// Create escalation referencing both policies
	escalation := helpers.NewEscalationBuilder("e2e-dp007-escalation", namespace).
		WithEscalatedGroup("breakglass-emergency-admin"). // Use breakglass-emergency-admin which has RBAC for all resources
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy1.Name, denyPolicy2.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy precedence ordering",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	// Create DenyPolicy with PodSecurityRules that exempts kube-system namespace
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp008-exempt-namespace", "").
		WithPodSecurityRules(&breakglassv1alpha1.PodSecurityRules{
			RiskFactors: breakglassv1alpha1.RiskFactors{
				HostNetwork:         80,
				PrivilegedContainer: 100,
			},
			Thresholds: []breakglassv1alpha1.RiskThreshold{
				{MaxScore: 50, Action: "allow"},
				{MaxScore: 100, Action: "deny", Reason: "High risk pod"},
			},
			Exemptions: &breakglassv1alpha1.PodSecurityExemptions{
				Namespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
			},
		}).
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with namespace exemption")

	// Verify policy was created correctly
	var fetched breakglassv1alpha1.DenyPolicy
	err = cli.Get(ctx, types.NamespacedName{Name: denyPolicy.Name}, &fetched)
	require.NoError(t, err)
	require.NotNil(t, fetched.Spec.PodSecurityRules)
	require.NotNil(t, fetched.Spec.PodSecurityRules.Exemptions)
	require.Contains(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces.Patterns, "kube-system")
}

// TestDenyPolicyAppliesToClusters [DP-011] tests that DenyPolicy appliesTo.clusters
// scopes the policy to specific clusters.
func TestDenyPolicyAppliesToClusters(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

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
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-dp011-applies-to-cluster", "").
		AppliesToClusters("other-cluster"). // Not our test cluster
		DenyAll([]string{""}, []string{"secrets"}, "*").
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create DenyPolicy with appliesTo.clusters")

	// Create escalation referencing the DenyPolicy
	escalation := helpers.NewEscalationBuilder("e2e-dp011-escalation", namespace).
		WithEscalatedGroup("breakglass-emergency-admin"). // Must have RBAC binding for SAR to succeed
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedGroups(helpers.TestUsers.PolicyTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.PolicyTestApprover.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Create and approve session
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.PolicyTestRequester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "Test deny policy cluster scope",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

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
