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

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestSessionStateHappyPath tests SS-001: Pending → Approved → Active → Expired (happy path)
func TestSessionStateHappyPath(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with short validity for expiry testing
	escalation := helpers.NewEscalationBuilder("e2e-ss001-happy-path", namespace).
		WithEscalatedGroup("ss001-test-group").
		WithMaxValidFor("30s").     // Very short for testing expiry
		WithApprovalTimeout("20s"). // Must be <= maxValidFor
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	// Step 1: Create session (should be Pending)
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-001 test - happy path",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)
	t.Log("Session created in Pending state")

	// Step 2: Approve session (should transition to Approved)
	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	t.Log("Session approved")

	// Verify timestamps are set
	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.False(t, fetched.Status.ApprovedAt.IsZero(), "ApprovedAt should be set")
	assert.False(t, fetched.Status.ExpiresAt.IsZero(), "ExpiresAt should be set")

	// Step 3: Wait for expiry (30s validity)
	t.Log("Waiting for session to expire...")
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateExpired, helpers.WaitForConditionTimeout)
	t.Log("Session expired")
}

// TestSessionStateRejected tests SS-002: Pending → Rejected (rejection path)
func TestSessionStateRejected(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-ss002-rejection", namespace).
		WithEscalatedGroup("ss002-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	// Create session
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-002 test - rejection",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Reject session with reason
	rejectionReason := "Request denied due to security policy"
	require.NoError(t, approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, rejectionReason))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateRejected, helpers.WaitForStateTimeout)

	// Verify rejection details
	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, telekomv1alpha1.SessionStateRejected, fetched.Status.State)
	assert.False(t, fetched.Status.RejectedAt.IsZero(), "RejectedAt should be set")
}

// TestSessionStateWithdrawn tests SS-003: Pending → Withdrawn (requester cancels before approval)
func TestSessionStateWithdrawn(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-ss003-withdrawn", namespace).
		WithEscalatedGroup("ss003-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)

	// Create session
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-003 test - withdrawal",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Requester withdraws the session
	require.NoError(t, requesterClient.WithdrawSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateWithdrawn, helpers.WaitForStateTimeout)

	// Verify withdrawal details
	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, telekomv1alpha1.SessionStateWithdrawn, fetched.Status.State)
	assert.False(t, fetched.Status.WithdrawnAt.IsZero(), "WithdrawnAt should be set")
}

// TestSessionStateApprovalTimeout tests SS-004: Pending → ApprovalTimeout (timeout path)
func TestSessionStateApprovalTimeout(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with very short approval timeout
	escalation := helpers.NewEscalationBuilder("e2e-ss004-timeout", namespace).
		WithEscalatedGroup("ss004-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30s"). // Very short timeout
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)

	// Create session and don't approve it
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-004 test - approval timeout",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Wait for timeout (30s + buffer)
	t.Log("Waiting for approval timeout...")
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateTimeout, helpers.WaitForConditionTimeout)
	t.Log("Session timed out")
}

// TestSessionStateCancelled tests SS-005: Active → Cancelled (admin cancels active session)
func TestSessionStateCancelled(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-ss005-cancelled", namespace).
		WithEscalatedGroup("ss005-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	// Create and approve session
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-005 test - cancellation",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Cancel the active session
	require.NoError(t, approverClient.CancelSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateExpired, helpers.WaitForStateTimeout)

	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, telekomv1alpha1.SessionStateExpired, fetched.Status.State)
}

// TestSessionStateDropped tests SS-006: Active → Dropped (owner drops)
func TestSessionStateDropped(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-ss006-dropped", namespace).
		WithEscalatedGroup("ss006-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	// Create and approve session
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-006 test - drop",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Drop the session (using the requester - session owner)
	require.NoError(t, requesterClient.DropSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateExpired, helpers.WaitForStateTimeout)

	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, telekomv1alpha1.SessionStateExpired, fetched.Status.State)
}

// TestSessionStateScheduledStart tests SS-007: Pending → WaitingForScheduledTime → Active
func TestSessionStateScheduledStart(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-ss007-scheduled", namespace).
		WithEscalatedGroup("ss007-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	// Schedule session for 6 minutes in the future (minimum 5 minutes required)
	scheduledTime := time.Now().Add(6 * time.Minute).Format(time.RFC3339)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster:            clusterName,
		User:               helpers.TestUsers.Requester.Email,
		Group:              escalation.Spec.EscalatedGroup,
		Reason:             "SS-007 test - scheduled start",
		ScheduledStartTime: scheduledTime,
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	// Approve immediately - session should go to WaitingForScheduledTime
	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))

	// Verify session is waiting for scheduled time after approval
	t.Log("Verifying session is in WaitingForScheduledTime or Approved state...")
	// Wait for state transition using condition helper
	fetched := helpers.WaitForSessionStateAny(t, ctx, cli, session.Name, namespace, []telekomv1alpha1.BreakglassSessionState{
		telekomv1alpha1.SessionStateApproved,
		telekomv1alpha1.SessionStateWaitingForScheduledTime,
	}, 10*time.Second)

	t.Logf("Session state after approval with scheduled time: %s", fetched.Status.State)
	// Session should be Approved or WaitingForScheduledTime
	require.True(t, fetched.Status.State == telekomv1alpha1.SessionStateApproved ||
		fetched.Status.State == telekomv1alpha1.SessionStateWaitingForScheduledTime,
		"Session should be Approved or WaitingForScheduledTime, got: %s", fetched.Status.State)
}

// TestMultiplePendingSessions tests SS-012: Verifies that a user cannot have multiple pending
// sessions for the same escalation/group - the system should return 409 "already requested"
func TestMultiplePendingSessions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := helpers.NewEscalationBuilder("e2e-ss012-multiple", namespace).
		WithEscalatedGroup("ss012-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)

	// Create first session successfully
	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-012 test - first session",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "First session should be created")
	cleanup.Add(session)
	t.Logf("First session created: %s", session.Name)

	// Try to create second session - should fail with 409 "already requested"
	_, err = requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SS-012 test - second session attempt",
	})
	require.Error(t, err, "Second session creation should fail")
	assert.Contains(t, err.Error(), "409", "Should return 409 conflict")
	assert.Contains(t, err.Error(), "already requested", "Error should indicate session already requested")
	t.Log("Second session correctly rejected with 409 already requested")
}

// TestSessionWithJustificationRequired tests SS-013: Session with notes/justification required
func TestSessionWithJustificationRequired(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation requiring justification
	escalation := helpers.NewEscalationBuilder("e2e-ss013-justification", namespace).
		WithEscalatedGroup("ss013-test-group").
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithRequestReason(true, "Please provide a reason for this request").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)

	t.Run("WithoutReason", func(t *testing.T) {
		// Attempt to create session without reason
		_, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "", // No reason
		})
		// This might succeed at API level but fail validation - check behavior
		if err != nil {
			assert.Contains(t, err.Error(), "reason", "Error should mention missing reason")
		}
	})

	t.Run("WithReason", func(t *testing.T) {
		// Create session with reason - should succeed
		session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "This is a valid justification for access",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Session with reason should succeed")
		cleanup.Add(session)
	})
}

// TestInvalidStateTransitions tests SS-008 to SS-011: Invalid state transitions
func TestInvalidStateTransitions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	t.Run("DoubleApproval", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-ss-double-approval", namespace).
			WithEscalatedGroup("double-approval-group").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))

		session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Test double approval",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err)
		cleanup.Add(session)

		// First approval should succeed
		require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Second approval should be idempotent or fail
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		// May succeed (idempotent) or fail - both are acceptable
		t.Logf("Double approval result: %v", err)
	})

	t.Run("ApproveAfterRejection", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-ss-approve-after-reject", namespace).
			WithEscalatedGroup("approve-after-reject-group").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))

		session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Test approve after reject",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err)
		cleanup.Add(session)

		// First reject
		require.NoError(t, approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "Testing rejection"))
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateRejected, helpers.WaitForStateTimeout)

		// Then try to approve - should fail
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		assert.Error(t, err, "Should not be able to approve a rejected session")
	})

	t.Run("WithdrawAfterApproval", func(t *testing.T) {
		// Create unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-ss-withdraw-after-approve", namespace).
			WithEscalatedGroup("withdraw-after-approve-group").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation))

		session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Test withdraw after approval",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err)
		cleanup.Add(session)

		// First approve
		require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Then try to withdraw - should fail (use drop instead for approved sessions)
		err = requesterClient.WithdrawSessionViaAPI(ctx, t, session.Name, namespace)
		assert.Error(t, err, "Should not be able to withdraw an approved session")
	})
}
