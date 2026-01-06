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

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestApprovalSingleApprover tests AW-001: Single approver can approve session
func TestApprovalSingleApprover(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-aw001-single-approver",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "aw001-test-group",
			MaxValidFor:     "1h",
			ApprovalTimeout: "30m",
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
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-001 test - single approver",
	}, 30*time.Second)
	require.NoError(t, err)
	cleanup.Add(session)

	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	// Verify approver recorded
	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, helpers.TestUsers.Approver.Email, fetched.Status.Approver)
}

// TestApprovalAnyFromList tests AW-002: Any approver from list can approve
func TestApprovalAnyFromList(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with multiple allowed approvers
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-aw002-any-approver",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "aw002-test-group",
			MaxValidFor:     "1h",
			ApprovalTimeout: "30m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{
					helpers.TestUsers.Approver.Email,
					helpers.TestUsers.SeniorApprover.Email,
					helpers.TestUsers.ApproverInternal.Email,
				},
			},
		},
	}
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	seniorApproverClient := tc.ClientForUser(helpers.TestUsers.SeniorApprover)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-002 test - any approver",
	}, 30*time.Second)
	require.NoError(t, err)
	cleanup.Add(session)

	// Use a different approver than the first one
	require.NoError(t, seniorApproverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, helpers.TestUsers.SeniorApprover.Email, fetched.Status.Approver)
}

// TestApprovalUnauthorizedRejected tests AW-003: Unauthorized approver rejected
func TestApprovalUnauthorizedRejected(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Escalation only allows a specific approver
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-aw003-unauthorized",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "aw003-test-group",
			MaxValidFor:     "1h",
			ApprovalTimeout: "30m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email}, // Only this specific approver
			},
		},
	}
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
	}, 30*time.Second)
	require.NoError(t, err)
	cleanup.Add(session)

	// Attempt to approve with unauthorized user - should fail
	err = unauthorizedClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	assert.Error(t, err, "Unauthorized user should not be able to approve")
}

// TestApprovalByGroup tests AW-004: Approval based on group membership
func TestApprovalByGroup(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Create escalation with group-based approvers
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-aw004-group-approver",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "aw004-test-group",
			MaxValidFor:     "1h",
			ApprovalTimeout: "30m",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Groups: []string{"approver"}, // Anyone in the "approver" group can approve
			},
		},
	}
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver) // In "approver" group

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-004 test - group-based approver",
	}, 30*time.Second)
	require.NoError(t, err)
	cleanup.Add(session)

	require.NoError(t, approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
}

// TestRejectionWithReason tests AW-006: Rejection with reason is recorded
func TestRejectionWithReason(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-aw006-rejection-reason",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "aw006-test-group",
			MaxValidFor:     "1h",
			ApprovalTimeout: "30m",
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
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)
	approverClient := tc.ClientForUser(helpers.TestUsers.Approver)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-006 test - rejection with reason",
	}, 30*time.Second)
	require.NoError(t, err)
	cleanup.Add(session)

	rejectionReason := "Access not needed for this maintenance window"
	require.NoError(t, approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, rejectionReason))
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateRejected, 30*time.Second)

	// Verify rejection details
	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, helpers.TestUsers.Approver.Email, fetched.Status.Approver)
	assert.False(t, fetched.Status.RejectedAt.IsZero())
}

// TestApprovalTimeoutNoAutoApprove tests AW-009: Timeout doesn't auto-approve
func TestApprovalTimeoutNoAutoApprove(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-aw009-timeout-no-approve",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "aw009-test-group",
			MaxValidFor:     "1h",
			ApprovalTimeout: "20s", // Very short
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
	require.NoError(t, cli.Create(ctx, escalation))

	requesterClient := tc.ClientForUser(helpers.TestUsers.Requester)

	session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    helpers.TestUsers.Requester.Email,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "AW-009 test - timeout no auto-approve",
	}, 30*time.Second)
	require.NoError(t, err)
	cleanup.Add(session)

	// Wait for timeout
	t.Log("Waiting for approval timeout...")
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateTimeout, 60*time.Second)

	// Verify state is timeout, not approved
	var fetched telekomv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched))
	assert.Equal(t, telekomv1alpha1.SessionStateTimeout, fetched.Status.State)
	assert.True(t, fetched.Status.ApprovedAt.IsZero(), "ApprovedAt should not be set for timeout")
}
