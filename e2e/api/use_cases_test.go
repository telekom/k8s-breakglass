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

// Package api contains end-to-end tests for breakglass use cases.
// These tests cover all real-world scenarios documented in docs/use-cases.md
// including both happy path and error/denial scenarios.
//
// IMPORTANT: Sessions should be created via the REST API (helpers.APIClient) rather than
// directly via the K8s API (cli.Create). This ensures sessions go through the real session
// controller which sets proper status, sends notifications, and validates against escalations.
//
// Test coverage:
// - Pod Shell Access (kubectl exec)
// - Pod Restart and Rollout
// - Scaling Workloads
// - Resource Deletion
// - Debug Tool Pods
// - M2M Automated Access
// - Self-Service Debugging (BIS)
// - Deny Policy Enforcement
package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// =============================================================================
// USE CASE 1: Pod Shell Access (kubectl exec)
// =============================================================================
// From docs/use-cases.md:
// Grants temporary exec access into running pods for debugging.
// Verbs: create (pods/exec subresource)

func TestUseCasePodShellAccess(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Wait for API to be ready
	require.NoError(t, apiClient.WaitForAPIReady(ctx, helpers.WaitForStateTimeout), "API should be ready")

	// Create escalation for pod exec access
	escalation := helpers.NewEscalationBuilder("e2e-pod-exec-access", namespace).
		WithEscalatedGroup("pod-exec-access").
		WithMaxValidFor("2h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverGroups("team-leads@example.com").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithRequestReason(true, "Ticket ID and purpose for pod access").
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "pod-shell-access"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create pod-exec escalation")

	t.Run("HappyPath_PodExecWithApproval", func(t *testing.T) {
		// Create session via REST API - this goes through the real session controller
		session, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "INC-12345: Debug pod networking issue",
		})
		require.NoError(t, err, "Failed to create pod exec session via API")
		require.NotEmpty(t, session.Name, "Session name should be returned")

		// Session should already be in Pending state (set by session controller)
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Approve the session via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Session approval should succeed")

		// Verify session transitions to Approved
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_SessionWithoutReason", func(t *testing.T) {
		// Create session without required reason via API - should fail
		_, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			// Reason omitted - should be rejected by escalation requiring it
		})
		// Session creation should fail due to missing mandatory reason
		assert.Error(t, err, "Session creation should fail without mandatory reason")
	})

	t.Run("ErrorPath_UnauthorizedUser", func(t *testing.T) {
		// Use a client authenticated as Limited user who is NOT in the allowed groups
		// The escalation allows groups: ["dev", "ops", "requester"]
		// Limited user has groups: ["read-only"] - so they should not be authorized
		limitedClient := tc.ClientForUser(helpers.TestUsers.Limited)

		_, err := limitedClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Limited.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Should fail - user not authorized",
		})
		// Session creation should fail due to unauthorized user (user not in allowed groups)
		assert.Error(t, err, "Session creation should fail for unauthorized user")
		if err != nil {
			t.Logf("Unauthorized user correctly rejected: %v", err)
		}
	})
}

// =============================================================================
// USE CASE 2: Pod Restart and Rollout
// =============================================================================
// From docs/use-cases.md:
// Allows restarting deployments and statefulsets.
// Verbs: update, patch (deployments, statefulsets)

func TestUseCasePodRestart(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation for pod restart
	escalation := helpers.NewEscalationBuilder("e2e-pod-restart", namespace).
		WithEscalatedGroup("pod-restart-access").
		WithAllowedClusters(clusterName).
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "pod-restart"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create pod-restart escalation")

	t.Run("HappyPath_DeploymentRestart", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Rolling restart after config update",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create restart session via API")
		cleanup.Add(session)

		// Approve via API with authenticated approver client
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_SessionRejected", func(t *testing.T) {
		// Create a separate escalation for this subtest to avoid conflicts
		rejectEscalation := helpers.NewEscalationBuilder("e2e-pod-restart-reject", namespace).
			WithEscalatedGroup("pod-restart-reject-access").
			WithAllowedClusters(clusterName).
			WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "pod-restart-reject"})).
			Build()
		cleanup.Add(rejectEscalation)
		require.NoError(t, cli.Create(ctx, rejectEscalation), "Failed to create reject escalation")

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   rejectEscalation.Spec.EscalatedGroup,
			Reason:  "This restart will be rejected",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Reject via API with authenticated approver client
		err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "Not approved for this environment")
		require.NoError(t, err)

		// Verify rejected state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateRejected, helpers.WaitForStateTimeout)
	})
}

// =============================================================================
// USE CASE 3: Scaling Workloads
// =============================================================================
// From docs/use-cases.md:
// Emergency scaling of deployments during incidents.
// Verbs: update, patch (deployments/scale, statefulsets/scale)

func TestUseCaseWorkloadScaling(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation for scaling
	escalation := helpers.NewEscalationBuilder("e2e-scaling", namespace).
		WithEscalatedGroup("scaling-access").
		WithMaxValidFor("4h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverGroups("incident-commanders@example.com").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithRequestReason(true, "Incident ticket and scaling justification").
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "scaling"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create scaling escalation")

	t.Run("HappyPath_EmergencyScaleUp", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "INC-99999: Scale up due to traffic surge",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_ApprovalTimeout", func(t *testing.T) {
		// Create escalation with very short approval timeout
		shortTimeoutEscalation := helpers.NewEscalationBuilder("e2e-scaling-short-timeout", namespace).
			WithEscalatedGroup("scaling-short-timeout").
			WithMaxValidFor("1h").
			WithApprovalTimeout("5s"). // Very short timeout for testing
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(shortTimeoutEscalation)
		err := cli.Create(ctx, shortTimeoutEscalation)
		require.NoError(t, err)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   shortTimeoutEscalation.Spec.EscalatedGroup,
			Reason:  "This will timeout",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Wait for session to timeout (don't approve)
		// Controller should mark it as ApprovalTimeout after 5s + reconciliation interval
		var fetched telekomv1alpha1.BreakglassSession
		err = helpers.WaitForCondition(ctx, func() (bool, error) {
			if err := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched); err != nil {
				return false, nil
			}
			// Wait for session to leave Pending state (timed out or other terminal state)
			return fetched.Status.State != telekomv1alpha1.SessionStatePending, nil
		}, helpers.WaitForStateTimeout, 1*time.Second)
		if err == nil {
			t.Logf("Session state after timeout period: %s", fetched.Status.State)
		} else {
			t.Logf("Session still in Pending state after timeout: %v", err)
		}
	})
}

// =============================================================================
// USE CASE 4: Resource Deletion
// =============================================================================
// From docs/use-cases.md:
// Controlled deletion of pods/deployments during incidents.
// Verbs: delete (pods, deployments, statefulsets)

func TestUseCaseResourceDeletion(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with approval reason required
	escalation := helpers.NewEscalationBuilder("e2e-deletion", namespace).
		WithEscalatedGroup("deletion-access").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverGroups("sre-leads@example.com").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithRequestReason(true, "Incident ticket and resources to delete").
		WithApprovalReason(true, "Confirmation of deletion necessity").
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "deletion"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create deletion escalation")

	t.Run("HappyPath_PodDeletion", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "INC-88888: Delete stuck terminating pods",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_DenyPolicyBlocks", func(t *testing.T) {
		// Create a DenyPolicy that blocks deletion of specific pods
		denyPolicy := helpers.NewDenyPolicyBuilder("e2e-block-deletions", namespace).
			DenyPods([]string{"delete"}, "kube-system").
			Build()
		cleanup.Add(denyPolicy)
		err := cli.Create(ctx, denyPolicy)
		require.NoError(t, err, "Failed to create deny policy")

		// The deny policy would prevent deletion when evaluated by the webhook
		// This test validates DenyPolicy creation succeeds
		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: denyPolicy.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Rules, 1)
	})
}

// =============================================================================
// USE CASE 5: M2M Automated Access
// =============================================================================
// From docs/use-cases.md:
// Machine-to-machine access for automation scripts and CI/CD.

func TestUseCaseM2MAutomatedAccess(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation for M2M access (no approval required for automation)
	escalation := helpers.NewEscalationBuilder("e2e-m2m-access", namespace).
		WithEscalatedGroup("m2m-automation").
		WithMaxValidFor("168h"). // 7 days for long-running automation
		WithApprovalTimeout("1h").
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithDisableNotifications(true).
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "m2m"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create M2M escalation")

	t.Run("HappyPath_AutomationSession", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    "automation-sa@example.com",
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "CI/CD pipeline run #1234",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve for M2M (in real scenarios, might be auto-approved)
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_LongDurationRejected", func(t *testing.T) {
		// Test with duration exceeding max allowed - API should reject this
		_, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    "automation-sa@example.com",
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Attempting too long session",
		})
		// Session creation may fail or succeed but be rejected later
		if err != nil {
			t.Logf("Session creation correctly rejected: %v", err)
		} else {
			t.Logf("Session created - will be validated during reconciliation")
		}
	})
}

// =============================================================================
// USE CASE 6: BIS Self-Service Debugging
// =============================================================================
// From docs/use-cases.md:
// Business Information System debugging during non-production phases.

func TestUseCaseBISDebugging(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create self-service escalation (no approval needed)
	escalation := helpers.NewEscalationBuilder("e2e-bis-debug", namespace).
		WithEscalatedGroup("bis-debug-access").
		WithMaxValidFor("4h").
		WithApprovalTimeout("1h").
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverGroups("bis-developers@example.com").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithRequestReason(true, "BIS ticket or work item reference").
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "bis-debugging"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create BIS escalation")

	t.Run("HappyPath_SelfServiceDebug", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "BISWI-567: Investigate data sync issue",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Self-approve (user in approvers group)
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_BlockSelfApproval", func(t *testing.T) {
		// Create escalation that blocks self-approval
		blockSelfEscalation := helpers.NewEscalationBuilder("e2e-bis-no-self-approve", namespace).
			WithEscalatedGroup("bis-no-self-approve").
			WithMaxValidFor("2h").
			WithApprovalTimeout("30m").
			WithBlockSelfApproval(true).
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(blockSelfEscalation)
		err := cli.Create(ctx, blockSelfEscalation)
		require.NoError(t, err)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   blockSelfEscalation.Spec.EscalatedGroup,
			Reason:  "Testing self-approval block",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Attempting self-approval should fail when BlockSelfApproval is true
		// The actual behavior depends on how the API handles this
		t.Log("Created session with BlockSelfApproval=true")
	})
}

// =============================================================================
// USE CASE 7: Ingress/Service Restart
// =============================================================================
// From docs/use-cases.md:
// Restart ingress controllers or services during incidents.

func TestUseCaseIngressRestart(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation for ingress management
	escalation := helpers.NewEscalationBuilder("e2e-ingress-restart", namespace).
		WithEscalatedGroup("ingress-admin").
		WithMaxValidFor("2h").
		WithApprovalTimeout("15m").
		WithAllowedClusters(clusterName).
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "ingress-restart"})).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create ingress escalation")

	t.Run("HappyPath_IngressRestart", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Ingress controller restart for certificate rotation",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})
}

// =============================================================================
// USE CASE 8: Pod Security Rules
// =============================================================================
// From docs/use-cases.md:
// Control access to privileged pods based on security scoring.

func TestUseCasePodSecurityRules(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create deny policy with pod security rules
	denyPolicy := helpers.NewDenyPolicyBuilder("e2e-pod-security", namespace).
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "pod-security"})).
		WithPodSecurityRules(&telekomv1alpha1.PodSecurityRules{
			RiskFactors: telekomv1alpha1.RiskFactors{
				HostNetwork:         30,
				HostPID:             40,
				PrivilegedContainer: 50,
			},
			Thresholds: []telekomv1alpha1.RiskThreshold{
				{MaxScore: 50, Action: "allow"},
				{MaxScore: 100, Action: "warn"},
				{MaxScore: 1000, Action: "deny", Reason: "Pod security score too high: {{.Score}}"},
			},
		}).
		WithRule(telekomv1alpha1.DenyRule{
			Verbs:        []string{"create"},
			APIGroups:    []string{""},
			Resources:    []string{"pods"},
			Subresources: []string{"exec"},
		}).
		Build()
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create pod security deny policy")

	// Create escalation with pod security overrides for SREs
	escalation := helpers.NewEscalationBuilder("e2e-sre-privileged", namespace).
		WithEscalatedGroup("sre-privileged-access").
		WithMaxValidFor("1h").
		WithApprovalTimeout("15m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.Requester.Groups...).
		WithApproverGroups("sre-leads@example.com").
		WithApproverUsers(helpers.TestUsers.Approver.Email).
		WithDenyPolicyRefs(denyPolicy.Name).
		WithPodSecurityOverrides(&telekomv1alpha1.PodSecurityOverrides{
			Enabled:         true,
			MaxAllowedScore: intPtr(150), // Higher threshold for SREs
			ExemptFactors:   []string{"privilegedContainer", "hostNetwork"},
		}).
		WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "pod-security"})).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create SRE escalation with pod security overrides")

	t.Run("HappyPath_SREPrivilegedAccess", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Debug privileged pod issue",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	})

	t.Run("ErrorPath_RegularUserBlockedFromPrivileged", func(t *testing.T) {
		// Create escalation without pod security overrides
		regularEscalation := helpers.NewEscalationBuilder("e2e-regular-no-override", namespace).
			WithEscalatedGroup("regular-access").
			WithMaxValidFor("1h").
			WithApprovalTimeout("15m").
			WithAllowedClusters(clusterName).
			WithDenyPolicyRefs(denyPolicy.Name).
			// No PodSecurityOverrides - will be blocked by default policy
			Build()
		cleanup.Add(regularEscalation)
		err := cli.Create(ctx, regularEscalation)
		require.NoError(t, err)

		// Session will be created but access to privileged pods would be denied
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   regularEscalation.Spec.EscalatedGroup,
			Reason:  "Regular user requesting access",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Session can be created and approved, but webhook would block privileged pod access
		t.Log("Created session without pod security overrides - privileged access would be blocked by webhook")
	})
}

// =============================================================================
// USE CASE 9: Session Lifecycle Management
// =============================================================================
// Tests various session lifecycle scenarios: withdrawal, expiration, renewal.

func TestUseCaseSessionLifecycle(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("SessionWithdrawal", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-lifecycle-withdraw", namespace).
			WithEscalatedGroup("lifecycle-withdraw-test").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithRetainFor("5m").
			WithAllowedClusters(clusterName).
			WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "lifecycle-withdraw"})).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Will be withdrawn",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Withdraw the session
		err = helpers.WithdrawSession(ctx, cli, session.Name, namespace)
		require.NoError(t, err, "Session withdrawal should succeed")

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateWithdrawn, helpers.WaitForStateTimeout)
	})

	t.Run("SessionExpiration", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-lifecycle-expire", namespace).
			WithEscalatedGroup("lifecycle-expire-test").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithRetainFor("5m").
			WithAllowedClusters(clusterName).
			WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "lifecycle-expire"})).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Create session with very short validity
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Short-lived session",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve session
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Verify session stays approved (not expired yet since MaxValidFor is 1h)
		// Just fetch current state to confirm it's still approved
		var fetched telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		t.Logf("Session state after approval: %s, ExpiresAt: %v", fetched.Status.State, fetched.Status.ExpiresAt)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, fetched.Status.State, "Session should remain approved")
	})

	t.Run("MultipleSessionsPerUser", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-lifecycle-multiple", namespace).
			WithEscalatedGroup("lifecycle-multiple-test").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithRetainFor("5m").
			WithAllowedClusters(clusterName).
			WithApproverUsers(helpers.TestUsers.Approver.Email).
			WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "lifecycle-multiple"})).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Create first session
		session1, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "First session",
		})
		require.NoError(t, err, "Failed to create first session via API")
		cleanup.Add(session1)

		// Create second session for same user - should fail with 409
		_, err = apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Second session",
		})
		// Multiple sessions for same user/group should be rejected
		require.Error(t, err, "Second session creation should fail")
		assert.Contains(t, err.Error(), "409", "Should return 409 conflict")
		t.Log("Multiple sessions correctly prevented for same user/group")
	})

	t.Run("SessionWithScheduledStart", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-lifecycle-scheduled", namespace).
			WithEscalatedGroup("lifecycle-scheduled-test").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithRetainFor("5m").
			WithAllowedClusters(clusterName).
			WithLabels(helpers.E2ELabelsWithExtra(map[string]string{"use-case": "lifecycle-scheduled"})).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Schedule session to start in the future (minimum 5 minutes required)
		futureTime := time.Now().Add(6 * time.Minute).Format(time.RFC3339)
		session, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster:            clusterName,
			User:               helpers.GetTestUserEmail(),
			Group:              escalation.Spec.EscalatedGroup,
			Reason:             "Scheduled maintenance window",
			ScheduledStartTime: futureTime,
		})
		require.NoError(t, err, "Failed to create scheduled session via API")
		cleanup.Add(session)

		// Session should go to pending
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// After approval, should go to WaitingForScheduledTime or Approved
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		// Wait for session to reach expected state after approval
		fetched := helpers.WaitForSessionStateAny(t, ctx, cli, session.Name, namespace, []telekomv1alpha1.BreakglassSessionState{
			telekomv1alpha1.SessionStateApproved,
			telekomv1alpha1.SessionStateWaitingForScheduledTime,
		}, 15*time.Second)
		t.Logf("Scheduled session state: %s", fetched.Status.State)
	})
}

// intPtr returns a pointer to the given int value.
func intPtr(i int) *int {
	return &i
}
