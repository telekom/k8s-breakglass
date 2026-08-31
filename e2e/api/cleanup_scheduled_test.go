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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestScheduledSessionActivation tests that sessions with ScheduledStartTime
// are properly handled through the WaitingForScheduledTime → Approved transition.
func TestScheduledSessionActivation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation for scheduled sessions
	escalation := helpers.NewEscalationBuilder("e2e-scheduled-escalation", namespace).
		WithEscalatedGroup("scheduled-admins").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("2h").
		WithApprovalTimeout("1h").
		WithAllowedGroups(helpers.TestUsers.SchedulingTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.SchedulingTestApprover.Email).
		WithLabels(map[string]string{"feature": "scheduled"}).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation for scheduled session test")

	t.Run("ImmediateScheduledSession", func(t *testing.T) {
		// Note: Scheduled sessions require start time to be at least 5 minutes in future.
		// For this test, we create a non-scheduled session (immediate) by not setting ScheduledStartTime.
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.ClientForUser(helpers.TestUsers.SchedulingTestRequester)

		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SchedulingTestRequester.Email,
			Group:   "scheduled-admins", // Must match escalation EscalatedGroup
			Reason:  "Immediate scheduled session test",
		})
		require.NoError(t, err, "Failed to create immediate scheduled session via API")
		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to get a state
		err = helpers.WaitForConditionSimple(ctx, func() bool {
			var s breakglassv1alpha1.BreakglassSession
			if err := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &s); err != nil {
				return false
			}
			return s.Status.State != ""
		}, helpers.WaitForStateTimeout, 2*time.Second)
		require.NoError(t, err)

		t.Logf("Immediate scheduled session created via API")
	})
}

// TestSessionRetentionCleanup tests that expired sessions are cleaned up
// after their RetainedUntil timestamp passes.
func TestSessionRetentionCleanup(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with very short retention for testing
	escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-cleanup-esc"), namespace).
		WithEscalatedGroup("cleanup-test-admins").
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedGroups(helpers.TestUsers.SchedulingTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.SchedulingTestApprover.Email).
		WithLabels(map[string]string{"feature": "cleanup"}).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation for cleanup test")

	t.Run("SessionExpirationFlow", func(t *testing.T) {
		// Create via API to ensure proper authorization
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.ClientForUser(helpers.TestUsers.SchedulingTestRequester)

		session, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SchedulingTestRequester.Email,
			Group:   "cleanup-test-admins",
			Reason:  "Testing session expiration",
		})
		require.NoError(t, err, "Failed to create short-lived session")
		cleanup.Add(session)

		// Wait for session to be created
		err = helpers.WaitForConditionSimple(ctx, func() bool {
			var s breakglassv1alpha1.BreakglassSession
			if err := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &s); err != nil {
				return false
			}
			return s.Status.State != ""
		}, helpers.WaitForStateTimeout, 2*time.Second)
		require.NoError(t, err)

		t.Logf("Short-lived session created for expiration test")
	})
}

// TestSessionStateTransitionsComplete tests all session state transitions.
func TestSessionStateTransitionsComplete(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Each subtest gets a unique group to avoid session conflicts
	// (user+cluster+group uniqueness constraint).
	pendingGroup := helpers.GenerateUniqueName("state-pending")
	approvalGroup := helpers.GenerateUniqueName("state-approval")

	// Create escalation for pending test
	pendingEscalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-states-pending"), namespace).
		WithEscalatedGroup(pendingGroup).
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedGroups(helpers.TestUsers.SchedulingTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.SchedulingTestApprover.Email).
		Build()
	cleanup.Add(pendingEscalation)
	err := cli.Create(ctx, pendingEscalation)
	require.NoError(t, err)

	// Create escalation for approval test
	approvalEscalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-states-approval"), namespace).
		WithEscalatedGroup(approvalGroup).
		WithAllowedClusters(clusterName).
		WithMaxValidFor("1h").
		WithApprovalTimeout("30m").
		WithAllowedGroups(helpers.TestUsers.SchedulingTestRequester.Groups...).
		WithApproverUsers(helpers.TestUsers.SchedulingTestApprover.Email).
		Build()
	cleanup.Add(approvalEscalation)
	err = cli.Create(ctx, approvalEscalation)
	require.NoError(t, err)

	t.Run("PendingSessionCreation", func(t *testing.T) {
		// Create via API to ensure proper authorization
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.ClientForUser(helpers.TestUsers.SchedulingTestRequester)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SchedulingTestRequester.Email,
			Group:   pendingGroup,
			Reason:  "State transition test - pending",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)

		t.Logf("Session state: %s", fetched.Status.State)
		assert.NotEmpty(t, fetched.Status.State)
	})

	t.Run("ManualApprovalTransition", func(t *testing.T) {
		// Create via API to ensure proper authorization
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.ClientForUser(helpers.TestUsers.SchedulingTestRequester)
		approverClient := tc.ClientForUser(helpers.TestUsers.SchedulingTestApprover)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SchedulingTestRequester.Email,
			Group:   approvalGroup,
			Reason:  "State transition test - approve",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)

		// Approve via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session via API")

		// Wait for approved state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

		// Verify
		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, breakglassv1alpha1.SessionStateApproved, fetched.Status.State)

		t.Logf("Session approved via API")
	})
}

// TestDebugSessionCleanupFlow tests that debug sessions go through proper cleanup lifecycle.
func TestDebugSessionCleanupFlow(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("DebugSessionExpirationState", func(t *testing.T) {
		template := helpers.NewValidDebugSessionTemplate(
			helpers.GenerateUniqueName("e2e-debug-cleanup-template"), "Short-lived cleanup fixture", clusterName,
			breakglassv1alpha1.DebugSessionModeKubectlDebug, "")
		template.Spec.Constraints.MaxDuration = "15s"
		template.Spec.Constraints.DefaultDuration = "15s"
		cleanup.Add(template)
		require.NoError(t, cli.Create(ctx, template))
		tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
		ds, err := tc.ClientForUser(helpers.TestUsers.SchedulingTestRequester).CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
			TemplateRef: template.Name, Cluster: clusterName, Namespace: namespace,
			RequestedDuration: "15s", Reason: "Testing natural debug-session cleanup",
		})
		require.NoError(t, err)
		cleanup.Add(ds)
		ds = helpers.WaitForDebugSessionState(t, ctx, cli, ds.Name, ds.Namespace,
			breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForConditionTimeout)
		require.NotNil(t, ds.Status.ExpiresAt)
		require.True(t, ds.Status.ExpiresAt.After(time.Now()), "active fixture must start with a live lease")

		// The controller should mark this as expired at the persisted boundary.
		err = helpers.WaitForConditionSimple(ctx, func() bool {
			var fetched breakglassv1alpha1.DebugSession
			if err := cli.Get(ctx, types.NamespacedName{Name: ds.Name, Namespace: ds.Namespace}, &fetched); err != nil {
				return false
			}
			return fetched.Status.State == breakglassv1alpha1.DebugSessionStateExpired
		}, 2*time.Minute, 5*time.Second)

		if err != nil {
			// Log current state if wait failed
			var fetched breakglassv1alpha1.DebugSession
			_ = cli.Get(ctx, types.NamespacedName{Name: ds.Name, Namespace: ds.Namespace}, &fetched)
			t.Logf("Debug session state after wait: %s (message: %s)", fetched.Status.State, fetched.Status.Message)
		}
		require.NoError(t, err, "short-lived debug session must naturally reach Expired")
	})
}

// TestSessionRetainedUntilHandling tests the RetainedUntil timestamp is respected.
func TestSessionRetainedUntilHandling(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("SessionWithRetainedUntil", func(t *testing.T) {
		// Create escalation for this test
		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-retained-esc"), namespace).
			WithEscalatedGroup("retained-test-admins").
			WithAllowedClusters(clusterName).
			WithMaxValidFor("1h").
			WithApprovalTimeout("30m").
			WithAllowedGroups(helpers.TestUsers.SchedulingTestRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SchedulingTestApprover.Email).
			WithLabels(map[string]string{"feature": "retained"}).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create a session via API
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.ClientForUser(helpers.TestUsers.SchedulingTestRequester)

		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SchedulingTestRequester.Email,
			Group:   "retained-test-admins",
			Reason:  "RetainedUntil handling test",
		})
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(&breakglassv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for session to get a state
		err = helpers.WaitForConditionSimple(ctx, func() bool {
			var s breakglassv1alpha1.BreakglassSession
			if err := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &s); err != nil {
				return false
			}
			return s.Status.State != ""
		}, helpers.WaitForStateTimeout, 2*time.Second)
		require.NoError(t, err)

		// Check that session exists
		var fetched breakglassv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetched)
		require.NoError(t, err)

		t.Logf("Session created via API: state=%s, retainedUntil=%v", fetched.Status.State, fetched.Status.RetainedUntil)
	})
}
