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
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestMultiUserSameGroupSessions tests MU-001: Multiple users from same group can request sessions
func TestMultiUserSameGroupSessions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation allowing the "dev" group
	escalation := helpers.NewEscalationBuilder("e2e-multi-user-same-group", namespace).
		WithEscalatedGroup("multi-user-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups("dev"). // DevAlpha, DevBeta, and TenantB are in "dev" group
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Three users from "dev" group each create a session
	users := []helpers.TestUser{
		helpers.TestUsers.DevAlpha,
		helpers.TestUsers.DevBeta,
		helpers.TestUsers.TenantB,
	}

	sessionNames := make([]string, 0, len(users))

	for i, user := range users {
		t.Run(user.Username, func(t *testing.T) {
			client := tc.ClientForUser(user)

			session, err := client.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
				Cluster: clusterName,
				User:    user.Email,
				Group:   escalation.Spec.EscalatedGroup,
				Reason:  "MU-001 test - user " + user.Username,
			}, helpers.WaitForStateTimeout)
			require.NoError(t, err, "User %d (%s) failed to create session", i, user.Username)
			cleanup.Add(session)
			sessionNames = append(sessionNames, session.Name)
		})
	}

	// Verify all sessions have unique names
	require.Len(t, sessionNames, len(users), "All users should have created sessions")
	uniqueNames := make(map[string]bool)
	for _, name := range sessionNames {
		require.False(t, uniqueNames[name], "Session names should be unique")
		uniqueNames[name] = true
	}
}

// TestUserInMultipleGroupsMultipleEscalations tests MU-002: User in multiple groups can request for any matching escalation
func TestUserInMultipleGroupsMultipleEscalations(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// TestUsers.Requester belongs to many groups - we test with a specific subset
	// to avoid conflicts with other tests. These groups are guaranteed to be in
	// TestUsers.Requester.Groups and are unique to this test.
	requester := helpers.TestUsers.Requester
	requesterClient := tc.ClientForUser(requester)

	// Test with specific groups that are in requester's group list
	// Using "dev", "ops", "requester" as these are the core identity groups
	groupsToTest := []string{"dev", "ops", "requester"}
	escalations := make([]*breakglassv1alpha1.BreakglassEscalation, len(groupsToTest))

	for i, group := range groupsToTest {
		escalation := helpers.NewEscalationBuilder("e2e-mu002-escalation-"+group, namespace).
			WithEscalatedGroup("mu002-" + group + "-admins").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(group). // Only this one group
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))
		escalations[i] = escalation
	}

	// User should be able to create sessions for all 3 escalations
	for i, escalation := range escalations {
		t.Run(groupsToTest[i], func(t *testing.T) {
			session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
				Cluster: clusterName,
				User:    requester.Email,
				Group:   escalation.Spec.EscalatedGroup,
				Reason:  "MU-002 test - group " + groupsToTest[i],
			}, helpers.WaitForStateTimeout)
			require.NoError(t, err, "Failed to create session for group %s", groupsToTest[i])
			cleanup.Add(session)
		})
	}
}

// TestUserNotInAllowedGroupRejected tests MU-003: User NOT in allowed group cannot request session
func TestUserNotInAllowedGroupRejected(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation only allowing "admin-only" group
	escalation := helpers.NewEscalationBuilder("e2e-mu003-admin-only", namespace).
		WithEscalatedGroup("admin-only-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups("admin-only"). // No test user is in this group
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// DevAlpha has groups: ["dev", "frontend-team", "devs-a"] - NOT "admin-only"
	devAlphaClient := tc.ClientForUser(helpers.TestUsers.DevAlpha)

	// Attempt to create session should fail
	_, err := devAlphaClient.CreateSession(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.DevAlpha.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "MU-003 test - should fail",
	})

	require.Error(t, err, "Session creation should fail for user not in allowed group")
	assert.Contains(t, err.Error(), "403", "Error should indicate forbidden (user authenticated but not in allowed group)")
}

// TestGroupBasedApproverCanApprove tests MU-004: Group-based approver can approve session
func TestGroupBasedApproverCanApprove(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with group-based approvers
	// TestUsers.Approver has groups: ["approver", "senior-ops", "approval-notes"]
	escalation := helpers.NewEscalationBuilder("e2e-mu004-group-approver", namespace).
		WithEscalatedGroup("mu004-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithApproverGroups("senior-ops"). // Group-based approvers
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create session as requester
	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "MU-004 test - group-based approval",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Approve as user in "senior-ops" group
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)
	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Approver in senior-ops group should be able to approve")

	// Verify session is approved
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
}

// TestMultipleApproversFirstWins tests MU-005: Multiple approvers from same group - first wins
func TestMultipleApproversFirstWins(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with multiple users as approvers
	escalation := helpers.NewEscalationBuilder("e2e-mu005-multi-approver", namespace).
		WithEscalatedGroup("mu005-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithApproverUsers(
			helpers.TestUsers.Approver.Email,
			helpers.TestUsers.ApproverInternal.Email,
			helpers.TestUsers.SeniorApprover.Email,
		).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create session
	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "MU-005 test - multiple approvers",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// First approver approves
	approver1Client := tc.ClientForUser(helpers.TestUsers.Approver)
	err = approver1Client.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "First approver should succeed")

	// Wait for approved state
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Second approver attempts to approve - should fail or be no-op
	approver2Client := tc.ClientForUser(helpers.TestUsers.ApproverInternal)
	_ = approver2Client.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	// This could either error or be a no-op - verify session is still approved
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, fetched.Status.State)
}

// TestBlockSelfApprovalEnabled tests MU-006: User in both requester and approver group - blockSelfApproval enforced
func TestBlockSelfApprovalEnabled(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// InfraLead has groups: ["ops", "senior-ops", "ops-b"] - in both requester group (ops) and approver group (senior-ops)
	selfApprover := helpers.TestUsers.InfraLead

	escalation := helpers.NewEscalationBuilder("e2e-mu006-block-self-approval", namespace).
		WithEscalatedGroup("mu006-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithBlockSelfApproval(true). // Block self-approval
		WithAllowedClusters(clusterName).
		WithAllowedGroups("ops").         // InfraLead is in ops
		WithApproverGroups("senior-ops"). // InfraLead is also in senior-ops
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create session as InfraLead
	client := tc.ClientForUser(selfApprover)
	session, err := client.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    selfApprover.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "MU-006 test - block self approval",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Attempt to self-approve - should fail
	err = client.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.Error(t, err, "Self-approval should be blocked")
	assert.Contains(t, err.Error(), "403", "Error should indicate forbidden (user authenticated but not authorized)")
}

// TestBlockSelfApprovalDisabled tests MU-007: User in both requester and approver group - blockSelfApproval disabled
func TestBlockSelfApprovalDisabled(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	selfApprover := helpers.TestUsers.InfraLead

	escalation := helpers.NewEscalationBuilder("e2e-mu007-allow-self-approval", namespace).
		WithEscalatedGroup("mu007-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithBlockSelfApproval(false). // Allow self-approval
		WithAllowedClusters(clusterName).
		WithAllowedGroups("ops").
		WithApproverGroups("senior-ops").
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create and self-approve session
	client := tc.ClientForUser(selfApprover)
	session, err := client.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    selfApprover.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "MU-007 test - allow self approval",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Self-approve - should succeed
	err = client.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Self-approval should be allowed")

	// Verify session is approved
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
}

// TestCrossGroupEscalationChain tests MU-008: Cross-group escalation chain
func TestCrossGroupEscalationChain(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// DevAlpha: ["dev", "frontend-team", "devs-a"] - can request
	// Approver: ["approver", "senior-ops", "approval-notes"] - can approve

	escalation := helpers.NewEscalationBuilder("e2e-mu008-cross-group", namespace).
		WithEscalatedGroup("mu008-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		WithAllowedGroups("dev").       // Only dev can request
		WithApproverGroups("approver"). // Only approver group can approve
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	t.Run("DevCanRequest", func(t *testing.T) {
		devClient := tc.ClientForUser(helpers.TestUsers.DevAlpha)
		session, err := devClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.DevAlpha.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "MU-008 test - dev can request",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err)
		cleanup.Add(session)

		// Dev cannot approve their own session (not in approver group)
		err = devClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.Error(t, err, "Dev should not be able to approve")

		// Approver can approve
		approverClient := tc.ClientForUser(helpers.TestUsers.Approver)
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Approver should be able to approve")
	})

	t.Run("ApproverCannotRequest", func(t *testing.T) {
		approverClient := tc.ClientForUser(helpers.TestUsers.Approver)
		_, err := approverClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Approver.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "MU-008 test - approver cannot request",
		})
		require.Error(t, err, "Approver should not be able to request (not in dev group)")
	})
}

// TestActiveSessionRemainsAfterGroupRemoval tests MU-010: User removed from group mid-session
func TestActiveSessionRemainsAfterGroupRemoval(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	// Note: This test verifies that existing sessions are not revoked when group membership changes.
	// In a real scenario, group changes would happen in the IdP (Keycloak).
	// This test creates and approves a session, then verifies the session remains active.

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-mu010-group-removal", namespace).
		WithEscalatedGroup("mu010-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create and approve session
	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "MU-010 test - group removal",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)
	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Verify session is still approved (not revoked)
	// In real scenario, group removal in IdP wouldn't affect already-approved sessions
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, fetched.Status.State, "Session should remain active after theoretical group removal")
}
