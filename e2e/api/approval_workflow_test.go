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

// TestApprovalSingleApprover tests AW-001: Single approver can approve session
func TestApprovalSingleApprover(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-aw001-single-approver", namespace).
		WithEscalatedGroup("aw001-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-001 test - single approver",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Verify approver recorded
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, helpers.TestUsers.Approver.Email, fetched.Status.Approver)
}

// TestApprovalAnyFromList tests AW-002: Any approver from list can approve
func TestApprovalAnyFromList(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with multiple allowed approvers
	escalation := helpers.NewEscalationBuilder("e2e-aw002-any-approver", namespace).
		WithEscalatedGroup("aw002-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithApproverUsers(
			helpers.TestUsers.Approver.Email,
			helpers.TestUsers.SeniorApprover.Email,
			helpers.TestUsers.ApproverInternal.Email,
		).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	seniorApproverClient := tc.ClientForUser(helpers.TestUsers.SeniorApprover)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-002 test - any approver",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Use a different approver than the first one
	require.NoError(t, seniorApproverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, helpers.TestUsers.SeniorApprover.Email, fetched.Status.Approver)
}

// TestApprovalUnauthorizedRejected tests AW-003: Unauthorized approver rejected
func TestApprovalUnauthorizedRejected(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Escalation only allows a specific approver
	escalation := helpers.NewEscalationBuilder("e2e-aw003-unauthorized", namespace).
		WithEscalatedGroup("aw003-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		Build() // Only TestUsers.Approver.Email can approve (default)
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	// Use OpsGamma who is NOT in the allowed approvers list
	unauthorizedClient := tc.ClientForUser(helpers.TestUsers.OpsGamma)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-003 test - unauthorized approver",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Attempt to approve with unauthorized user - should fail
	err = unauthorizedClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	assert.Error(t, err, "Unauthorized user should not be able to approve")
}

// TestApprovalByGroup tests AW-004: Approval based on group membership
func TestApprovalByGroup(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with group-based approvers
	escalation := helpers.NewEscalationBuilder("e2e-aw004-group-approver", namespace).
		WithEscalatedGroup("aw004-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithApproverGroups("approver"). // Anyone in the "approver" group can approve
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver) // In "approver" group

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-004 test - group-based approver",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
}

// TestRejectionWithReason tests AW-006: Rejection with reason is recorded
func TestRejectionWithReason(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-aw006-rejection-reason", namespace).
		WithEscalatedGroup("aw006-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-006 test - rejection with reason",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	rejectionReason := "Access not needed for this maintenance window"
	require.NoError(t, approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, rejectionReason))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateRejected, helpers.WaitForStateTimeout)

	// Verify rejection details
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, helpers.TestUsers.Approver.Email, fetched.Status.Approver)
	assert.False(t, fetched.Status.RejectedAt.IsZero())
}

// TestApprovalTimeoutNoAutoApprove tests AW-009: Timeout doesn't auto-approve
func TestApprovalTimeoutNoAutoApprove(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-aw009-timeout-no-approve", namespace).
		WithEscalatedGroup("aw009-test-group").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("20s"). // Very short
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-009 test - timeout no auto-approve",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Wait for timeout
	t.Log("Waiting for approval timeout...")
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateTimeout, helpers.WaitForConditionTimeout)

	// Verify state is timeout, not approved
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, breakglassv1alpha1.SessionStateTimeout, fetched.Status.State)
	assert.True(t, fetched.Status.ApprovedAt.IsZero(), "ApprovedAt should not be set for timeout")
}
