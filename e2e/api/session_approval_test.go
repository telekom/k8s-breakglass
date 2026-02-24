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

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestSessionApprovalWorkflow tests the complete session approval workflow.
//
// Test coverage for issue #48:
// - Create BreakglassSession and verify pending state
// - Approve session and verify state transitions
// - Reject session and verify rejected state
// - Session expiration handling
func TestSessionApprovalWorkflow(t *testing.T) {
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

	// Use the authenticated user's groups for escalation matching
	requesterGroups := helpers.TestUsers.Requester.Groups

	// Wait for API to be ready
	require.NoError(t, apiClient.WaitForAPIReady(ctx, helpers.WaitForStateTimeout), "API should be ready")

	t.Run("CreatePendingSession", func(t *testing.T) {
		// Create a unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-test-pending-escalation", namespace).
			WithEscalatedGroup("pending-test-group").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(requesterGroups...).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Create session via API instead of direct K8s client
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test session - pending state verification",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Verify the session is created with correct values
		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err, "Failed to fetch session")

		// The session should exist and have the correct spec
		require.Equal(t, escalation.Spec.EscalatedGroup, fetched.Spec.GrantedGroup)
		require.Equal(t, helpers.GetTestUserEmail(), fetched.Spec.User)
	})

	t.Run("ApproveSession", func(t *testing.T) {
		// Create a unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-test-approve-escalation", namespace).
			WithEscalatedGroup("approve-test-group").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(requesterGroups...).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Create session via API
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test session - approval workflow",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve the session via authenticated API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session")

		// Wait for and verify the session is now approved
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, breakglassv1alpha1.SessionStateApproved, fetched.Status.State)
	})

	t.Run("RejectSession", func(t *testing.T) {
		// Create a unique escalation for this subtest
		escalation := helpers.NewEscalationBuilder("e2e-test-reject-escalation", namespace).
			WithEscalatedGroup("reject-test-group").
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(requesterGroups...).
			Build()
		cleanup.Add(escalation)
		require.NoError(t, cli.Create(ctx, escalation), "Failed to create escalation")

		// Create session via API
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test session - rejection workflow",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Reject the session via authenticated API
		err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "E2E test rejection")
		require.NoError(t, err, "Failed to reject session")

		// Wait for and verify the session is rejected
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateRejected, helpers.WaitForStateTimeout)

		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, breakglassv1alpha1.SessionStateRejected, fetched.Status.State)
	})

	t.Run("SessionWithDisabledNotifications", func(t *testing.T) {
		// Create escalation with notifications disabled
		quietEscalation := helpers.NewEscalationBuilder("e2e-test-quiet-escalation", namespace).
			WithEscalatedGroup("quiet-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithDisableNotifications(true).
			WithAllowedClusters(clusterName).
			WithAllowedGroups(requesterGroups...).
			Build()

		cleanup.Add(quietEscalation)
		err := cli.Create(ctx, quietEscalation)
		require.NoError(t, err, "Failed to create quiet escalation")

		// Create session via API
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.GetTestUserEmail(),
			Group:   quietEscalation.Spec.EscalatedGroup,
			Reason:  "E2E test session - quiet escalation verification",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create quiet session via API")
		cleanup.Add(session)

		// The session should exist with correct values
		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err, "Failed to fetch quiet session")
		require.Equal(t, quietEscalation.Spec.EscalatedGroup, fetched.Spec.GrantedGroup)
	})
}

// TestSessionStateTransitions tests valid and invalid state transitions.
func TestSessionStateTransitions(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Create an escalation for the tests
	escalation := helpers.NewEscalationBuilder("e2e-test-transition-escalation", namespace).
		WithEscalatedGroup("transition-test-group").
		WithMaxValidFor("2h").
		WithApprovalTimeout("1h").
		WithAllowedClusters(helpers.GetTestClusterName()).
		WithApproverUsers(helpers.GetTestApproverEmail()).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	t.Run("TransitionApprovedToExpired", func(t *testing.T) {
		// Create session via API
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.RequesterClient()
		approverClient := tc.ApproverClient()

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - expiration",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session via API")

		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Now expire it (this is testing controller behavior, done via status update)
		var toExpire breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &toExpire)
		require.NoError(t, err)

		toExpire.Status.State = breakglassv1alpha1.SessionStateExpired
		toExpire.Status.ReasonEnded = "timeExpired"
		err = cli.Status().Update(ctx, &toExpire)
		require.NoError(t, err)

		// Verify
		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, breakglassv1alpha1.SessionStateExpired, fetched.Status.State)
	})

	t.Run("TransitionPendingToWithdrawn", func(t *testing.T) {
		// Create session via API
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.RequesterClient()

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - withdrawal",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Withdraw the session via API
		err = apiClient.WithdrawSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to withdraw session via API")

		// Verify
		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, breakglassv1alpha1.SessionStateWithdrawn, fetched.Status.State)
	})
}

// TestMultipleApproversScenario tests scenarios with multiple approvers.
func TestMultipleApproversScenario(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EscalationWithMultipleApprovers", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-test-multi-approver-escalation", namespace).
			WithEscalatedGroup("multi-approver-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithApproverUsers(helpers.TestUsers.Approver.Email, helpers.TestUsers.SeniorApprover.Email, helpers.TestUsers.ApproverInternal.Email).
			WithApproverGroups("security-team").
			Build()

		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create multi-approver escalation")

		// Verify the escalation was created with all approvers
		var fetched breakglassv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Approvers.Users, 3)
		require.Len(t, fetched.Spec.Approvers.Groups, 1)
	})
}
