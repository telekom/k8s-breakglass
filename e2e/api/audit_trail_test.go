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

// =============================================================================
// AUDIT TRAIL VERIFICATION E2E TESTS
// From E2E_COVERAGE_ANALYSIS.md - Medium gap (complete audit trail)
// =============================================================================

// TestCompleteAuditTrailSessionLifecycle verifies that complete audit trail is maintained
// throughout the session lifecycle (create → approve → SAR access → reject/withdraw).
func TestCompleteAuditTrailSessionLifecycle(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Helper to create unique escalation for each sub-test to avoid 409 conflicts
	createEscalation := func(t *testing.T, suffix string) (*telekomv1alpha1.BreakglassEscalation, string) {
		testGroup := helpers.GenerateUniqueName("audit-" + suffix)
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-audit-esc-" + suffix),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "audit-trail"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: testGroup,
				MaxValidFor:    "1h",
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
		return escalation, testGroup
	}

	t.Run("SessionCreationRecordsAuditEvent", func(t *testing.T) {
		_, testGroup := createEscalation(t, "create")
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()

		// Create session
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   testGroup,
			Reason:  "Audit trail test - creation",
		})
		require.NoError(t, err)
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, 30*time.Second)

		// Verify session has creation metadata
		var fetchedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetchedSession)
		require.NoError(t, err)

		// Audit trail - creation event should have:
		// - CreationTimestamp
		// - User (the requester)
		// - RequestReason
		assert.NotZero(t, fetchedSession.CreationTimestamp, "Should have creation timestamp")
		assert.Equal(t, helpers.TestUsers.Requester.Email, fetchedSession.Spec.User, "Should record requester")
		assert.Contains(t, fetchedSession.Spec.RequestReason, "Audit trail test", "Should record reason")
		t.Logf("AUDIT-001: Session creation recorded - User: %s, Reason: %s, Created: %v",
			fetchedSession.Spec.User, fetchedSession.Spec.RequestReason, fetchedSession.CreationTimestamp)
	})

	t.Run("SessionApprovalRecordsApprover", func(t *testing.T) {
		_, testGroup := createEscalation(t, "approval")
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()
		approverClient := tc.ApproverClient()

		// Create session
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   testGroup,
			Reason:  "Audit trail test - approval",
		})
		require.NoError(t, err)
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, 30*time.Second)

		// Approve session
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStateApproved, 30*time.Second)

		// Verify approval is recorded
		var fetchedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetchedSession)
		require.NoError(t, err)

		// Audit trail - approval event should have:
		// - Approver user
		// - ExpiresAt timestamp
		assert.NotEmpty(t, fetchedSession.Status.Approver, "Should record approver")
		assert.False(t, fetchedSession.Status.ExpiresAt.IsZero(), "Should have expiration time")
		t.Logf("AUDIT-002: Session approval recorded - Approver: %s, ExpiresAt: %v",
			fetchedSession.Status.Approver, fetchedSession.Status.ExpiresAt)
	})
}

// TestAuditEventActorIdentity verifies that actor identities (requester, approver)
// are properly captured in audit events.
func TestAuditEventActorIdentity(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Helper to create unique escalation for each sub-test to avoid 409 conflicts
	createEscalation := func(t *testing.T, suffix string) (*telekomv1alpha1.BreakglassEscalation, string) {
		testGroup := helpers.GenerateUniqueName("actor-" + suffix)
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-actor-esc-" + suffix),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "feature": "audit-trail"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: testGroup,
				MaxValidFor:    "1h",
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
		return escalation, testGroup
	}

	t.Run("RequesterIdentityCaptured", func(t *testing.T) {
		_, testGroup := createEscalation(t, "req")
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()

		expectedRequester := helpers.TestUsers.Requester.Email

		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    expectedRequester,
			Group:   testGroup,
			Reason:  "Actor identity test",
		})
		require.NoError(t, err)
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, 30*time.Second)

		var fetchedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, expectedRequester, fetchedSession.Spec.User,
			"Requester identity should match authenticated user")
		t.Logf("AUDIT-003: Requester identity captured: %s", fetchedSession.Spec.User)
	})

	t.Run("ApproverIdentityCaptured", func(t *testing.T) {
		_, testGroup := createEscalation(t, "appr")
		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()
		approverClient := tc.ApproverClient()

		expectedApprover := helpers.TestUsers.Approver.Email

		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   testGroup,
			Reason:  "Approver identity test",
		})
		require.NoError(t, err)
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, 30*time.Second)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err)

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStateApproved, 30*time.Second)

		var fetchedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetchedSession)
		require.NoError(t, err)

		assert.Equal(t, expectedApprover, fetchedSession.Status.Approver,
			"Approver identity should match authenticated approver")
		t.Logf("AUDIT-004: Approver identity captured: %s", fetchedSession.Status.Approver)
	})
}

// TestAuditTimestampAccuracy verifies that audit timestamps are accurate.
func TestAuditTimestampAccuracy(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	testGroup := helpers.GenerateUniqueName("timestamp-grp")
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-timestamp-esc"),
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true", "feature": "audit-trail"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup: testGroup,
			MaxValidFor:    "1h",
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

	t.Run("CreationTimestampIsRecent", func(t *testing.T) {
		beforeCreate := time.Now()

		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()

		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.Requester.Email,
			Group:   testGroup,
			Reason:  "Timestamp test",
		})
		require.NoError(t, err)
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		afterCreate := time.Now()

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, 30*time.Second)

		var fetchedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetchedSession)
		require.NoError(t, err)

		creationTime := fetchedSession.CreationTimestamp.Time

		// Allow for some clock skew (up to 1 minute)
		assert.True(t, creationTime.After(beforeCreate.Add(-time.Minute)),
			"Creation timestamp should not be too far in the past")
		assert.True(t, creationTime.Before(afterCreate.Add(time.Minute)),
			"Creation timestamp should not be in the future")

		t.Logf("AUDIT-005: Creation timestamp accurate - Before: %v, Created: %v, After: %v",
			beforeCreate, creationTime, afterCreate)
	})
}
