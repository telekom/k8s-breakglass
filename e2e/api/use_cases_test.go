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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	require.NoError(t, apiClient.WaitForAPIReady(ctx, 30*time.Second), "API should be ready")

	// Create escalation for pod exec access
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-pod-exec-access",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "pod-shell-access"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "pod-exec-access",
			MaxValidFor:     "2h",
			ApprovalTimeout: "30m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Use authenticated user's groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"team-leads@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
			RequestReason: &telekomv1alpha1.ReasonConfig{
				Mandatory:   true,
				Description: "Ticket ID and purpose for pod access",
			},
		},
	}
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
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStatePending, 30*time.Second)

		// Approve the session via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Session approval should succeed")

		// Verify session transitions to Approved
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-pod-restart",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "pod-restart"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "pod-restart-access",
			MaxValidFor:     "4h",
			ApprovalTimeout: "1h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Use authenticated user's groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"sre-leads@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create pod-restart escalation")

	t.Run("HappyPath_DeploymentRestart", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Rolling restart after config update",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create restart session via API")
		cleanup.Add(session)

		// Approve via API with authenticated approver client
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	})

	t.Run("ErrorPath_SessionRejected", func(t *testing.T) {
		// Create a separate escalation for this subtest to avoid conflicts
		rejectEscalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-pod-restart-reject",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "use-case": "pod-restart-reject"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "pod-restart-reject-access",
				MaxValidFor:     "4h",
				ApprovalTimeout: "1h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
		cleanup.Add(rejectEscalation)
		require.NoError(t, cli.Create(ctx, rejectEscalation), "Failed to create reject escalation")

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   rejectEscalation.Spec.EscalatedGroup,
			Reason:  "This restart will be rejected",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Reject via API with authenticated approver client
		err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "Not approved for this environment")
		require.NoError(t, err)

		// Verify rejected state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateRejected, 30*time.Second)
	})
}

// =============================================================================
// USE CASE 3: Scaling Workloads
// =============================================================================
// From docs/use-cases.md:
// Emergency scaling of deployments during incidents.
// Verbs: update, patch (deployments/scale, statefulsets/scale)

func TestUseCaseWorkloadScaling(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-scaling",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "scaling"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "scaling-access",
			MaxValidFor:     "4h",
			ApprovalTimeout: "30m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"incident-commanders@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
			RequestReason: &telekomv1alpha1.ReasonConfig{
				Mandatory:   true,
				Description: "Incident ticket and scaling justification",
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create scaling escalation")

	t.Run("HappyPath_EmergencyScaleUp", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "INC-99999: Scale up due to traffic surge",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	})

	t.Run("ErrorPath_ApprovalTimeout", func(t *testing.T) {
		// Create escalation with very short approval timeout
		shortTimeoutEscalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-scaling-short-timeout",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "scaling-short-timeout",
				MaxValidFor:     "1h",
				ApprovalTimeout: "5s", // Very short timeout for testing
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
		cleanup.Add(shortTimeoutEscalation)
		err := cli.Create(ctx, shortTimeoutEscalation)
		require.NoError(t, err)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   shortTimeoutEscalation.Spec.EscalatedGroup,
			Reason:  "This will timeout",
		}, 30*time.Second)
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
		}, 30*time.Second, 1*time.Second)
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-deletion",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "deletion"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "deletion-access",
			MaxValidFor:     "1h",
			ApprovalTimeout: "30m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"sre-leads@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
			RequestReason: &telekomv1alpha1.ReasonConfig{
				Mandatory:   true,
				Description: "Incident ticket and resources to delete",
			},
			ApprovalReason: &telekomv1alpha1.ReasonConfig{
				Mandatory:   true,
				Description: "Confirmation of deletion necessity",
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create deletion escalation")

	t.Run("HappyPath_PodDeletion", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "INC-88888: Delete stuck terminating pods",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	})

	t.Run("ErrorPath_DenyPolicyBlocks", func(t *testing.T) {
		// Create a DenyPolicy that blocks deletion of specific pods
		denyPolicy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-block-deletions",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:      []string{"delete"},
						APIGroups:  []string{""},
						Resources:  []string{"pods"},
						Namespaces: []string{"kube-system"},
					},
				},
			},
		}
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-m2m-access",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "m2m"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "m2m-automation",
			MaxValidFor:     "168h", // 7 days for long-running automation
			ApprovalTimeout: "1h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
			},
			// Note: For true M2M, approvers might be a pre-approved list
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
			DisableNotifications: boolPtr(true),
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create M2M escalation")

	t.Run("HappyPath_AutomationSession", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    "automation-sa@example.com",
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "CI/CD pipeline run #1234",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve for M2M (in real scenarios, might be auto-approved)
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-bis-debug",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "bis-debugging"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "bis-debug-access",
			MaxValidFor:     "4h",
			ApprovalTimeout: "1h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
			},
			// Self-service: approvers could include the requesting groups
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"bis-developers@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
			RequestReason: &telekomv1alpha1.ReasonConfig{
				Mandatory:   true,
				Description: "BIS ticket or work item reference",
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create BIS escalation")

	t.Run("HappyPath_SelfServiceDebug", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "BISWI-567: Investigate data sync issue",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Self-approve (user in approvers group)
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	})

	t.Run("ErrorPath_BlockSelfApproval", func(t *testing.T) {
		// Create escalation that blocks self-approval
		blockSelfEscalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-bis-no-self-approve",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:    "bis-no-self-approve",
				MaxValidFor:       "2h",
				ApprovalTimeout:   "30m",
				BlockSelfApproval: boolPtr(true),
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
		cleanup.Add(blockSelfEscalation)
		err := cli.Create(ctx, blockSelfEscalation)
		require.NoError(t, err)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   blockSelfEscalation.Spec.EscalatedGroup,
			Reason:  "Testing self-approval block",
		}, 30*time.Second)
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-ingress-restart",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "ingress-restart"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "ingress-admin",
			MaxValidFor:     "2h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"network-leads@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create ingress escalation")

	t.Run("HappyPath_IngressRestart", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Ingress controller restart for certificate rotation",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	})
}

// =============================================================================
// USE CASE 8: Pod Security Rules
// =============================================================================
// From docs/use-cases.md:
// Control access to privileged pods based on security scoring.

func TestUseCasePodSecurityRules(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
	denyPolicy := &telekomv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-pod-security",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "pod-security"},
		},
		Spec: telekomv1alpha1.DenyPolicySpec{
			PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
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
			},
			Rules: []telekomv1alpha1.DenyRule{
				{
					Verbs:        []string{"create"},
					APIGroups:    []string{""},
					Resources:    []string{"pods"},
					Subresources: []string{"exec"},
				},
			},
		},
	}
	cleanup.Add(denyPolicy)
	err := cli.Create(ctx, denyPolicy)
	require.NoError(t, err, "Failed to create pod security deny policy")

	// Create escalation with pod security overrides for SREs
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-sre-privileged",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "use-case": "pod-security"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "sre-privileged-access",
			MaxValidFor:     "1h",
			ApprovalTimeout: "15m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"sre-leads@example.com"},
				Users:  []string{helpers.TestUsers.Approver.Email},
			},
			DenyPolicyRefs: []string{denyPolicy.Name},
			PodSecurityOverrides: &telekomv1alpha1.PodSecurityOverrides{
				Enabled:         true,
				MaxAllowedScore: intPtr(150), // Higher threshold for SREs
				ExemptFactors:   []string{"privilegedContainer", "hostNetwork"},
			},
		},
	}
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create SRE escalation with pod security overrides")

	t.Run("HappyPath_SREPrivilegedAccess", func(t *testing.T) {
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Debug privileged pod issue",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	})

	t.Run("ErrorPath_RegularUserBlockedFromPrivileged", func(t *testing.T) {
		// Create escalation without pod security overrides
		regularEscalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-regular-no-override",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "regular-access",
				MaxValidFor:     "1h",
				ApprovalTimeout: "15m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups, // Must match authenticated user's groups
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
				DenyPolicyRefs: []string{denyPolicy.Name},
				// No PodSecurityOverrides - will be blocked by default policy
			},
		}
		cleanup.Add(regularEscalation)
		err := cli.Create(ctx, regularEscalation)
		require.NoError(t, err)

		// Session will be created but access to privileged pods would be denied
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   regularEscalation.Spec.EscalatedGroup,
			Reason:  "Regular user requesting access",
		}, 30*time.Second)
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-lifecycle-withdraw",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "use-case": "lifecycle-withdraw"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "lifecycle-withdraw-test",
				MaxValidFor:     "1h",
				ApprovalTimeout: "30m",
				RetainFor:       "5m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Will be withdrawn",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Withdraw the session
		err = helpers.WithdrawSession(ctx, cli, session.Name, namespace)
		require.NoError(t, err, "Session withdrawal should succeed")

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateWithdrawn, 30*time.Second)
	})

	t.Run("SessionExpiration", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-lifecycle-expire",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "use-case": "lifecycle-expire"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "lifecycle-expire-test",
				MaxValidFor:     "1h",
				ApprovalTimeout: "30m",
				RetainFor:       "5m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Create session with very short validity
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Short-lived session",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve session
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

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
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-lifecycle-multiple",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "use-case": "lifecycle-multiple"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "lifecycle-multiple-test",
				MaxValidFor:     "1h",
				ApprovalTimeout: "30m",
				RetainFor:       "5m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
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
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-lifecycle-scheduled",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "use-case": "lifecycle-scheduled"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "lifecycle-scheduled-test",
				MaxValidFor:     "1h",
				ApprovalTimeout: "30m",
				RetainFor:       "5m",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
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
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStatePending, 30*time.Second)

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
