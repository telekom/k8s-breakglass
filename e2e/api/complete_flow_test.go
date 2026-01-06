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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestCompleteBreakglassFlow tests the COMPLETE authorization flow:
// 1. First request is DENIED (no active session)
// 2. Create and approve a BreakglassSession
// 3. Same request is now ALLOWED
// 4. Expire the session
// 5. Request is DENIED again
//
// This is the critical end-to-end test for issue #48.
func TestCompleteBreakglassFlow(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
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
	// Use the actual authenticated user's email and one of their groups
	// RequesterClient authenticates as TestUsers.Requester
	testUser := helpers.TestUsers.Requester.Email
	testGroup := "complete-flow-test-admins"
	// The requester has groups: ["dev", "ops", "requester"] - use "dev" for Allowed.Groups
	requesterGroups := helpers.TestUsers.Requester.Groups

	// Create a BreakglassEscalation first
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-complete-flow-esc"),
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  testGroup,
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   requesterGroups, // Use the authenticated user's actual groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")
	t.Logf("Created escalation: %s", escalation.Name)

	// Debug: Log ClusterConfig status and verify secret configuration
	helpers.LogClusterConfigStatus(t, ctx, cli)
	if err := helpers.VerifyClusterConfigSecret(t, ctx, cli, clusterName); err != nil {
		t.Fatalf("ClusterConfig secret verification failed: %v", err)
	}

	// Shared session name across sub-tests
	var sessionName string

	t.Run("Step1_RequestDeniedWithoutSession", func(t *testing.T) {
		// Without an active session, the user should be denied
		// Use 'get configmaps' which is NOT blocked by any deny policy
		sar := helpers.BuildResourceSAR(testUser, []string{testGroup}, "get", "configmaps", "default")
		sarResp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Webhook must be reachable - check port-forward and API server")

		// The user has no active session, so should be denied
		t.Logf("Step 1: SAR response - allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		assert.False(t, sarResp.Status.Allowed, "Request should be DENIED without an active session")
	})

	t.Run("Step2_CreateAndApproveSession", func(t *testing.T) {
		// Create a session for the user via API
		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    testUser,
			Group:   testGroup,
			Reason:  "Complete flow E2E test",
		}, 30*time.Second)
		require.NoError(t, err, "Failed to create session via API")
		cleanup.Add(session)
		sessionName = session.Name
		t.Logf("Step 2a: Created session via API: %s", session.Name)

		// Approve the session using the authenticated API client
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
		require.NoError(t, err, "Failed to approve session")

		// Wait for session to be approved
		helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

		// Verify session is approved
		var approved telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &approved)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateApproved, approved.Status.State)
		t.Logf("Step 2b: Approved session by %s, expires at %s", approved.Status.Approver, approved.Status.ExpiresAt)
	})

	t.Run("Step3_RequestAllowedWithApprovedSession", func(t *testing.T) {
		// Now with an active approved session, the user should be allowed
		// Use 'get configmaps' which is NOT blocked by any deny policy
		sar := helpers.BuildResourceSAR(testUser, []string{testGroup}, "get", "configmaps", "default")
		sarResp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Webhook must be reachable - check port-forward and API server")

		t.Logf("Step 3: SAR response - allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		assert.True(t, sarResp.Status.Allowed, "Request should be ALLOWED with an active approved session")
	})

	t.Run("Step4_ExpireSession", func(t *testing.T) {
		// Expire the session
		require.NotEmpty(t, sessionName, "Session name should be set from Step2")
		var toExpire telekomv1alpha1.BreakglassSession
		err := cli.Get(ctx, types.NamespacedName{Name: sessionName, Namespace: namespace}, &toExpire)
		require.NoError(t, err)

		toExpire.Status.State = telekomv1alpha1.SessionStateExpired
		toExpire.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Minute))
		err = cli.Status().Update(ctx, &toExpire)
		require.NoError(t, err, "Failed to expire session")
		t.Logf("Step 4: Expired session")
	})

	t.Run("Step5_RequestDeniedAfterExpiry", func(t *testing.T) {
		// After expiry, the user should be denied again
		// Use 'get configmaps' which is NOT blocked by any deny policy
		sar := helpers.BuildResourceSAR(testUser, []string{testGroup}, "get", "configmaps", "default")
		sarResp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Webhook must be reachable - check port-forward and API server")

		t.Logf("Step 5: SAR response - allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		assert.False(t, sarResp.Status.Allowed, "Request should be DENIED after session expired")
	})
}

// TestCompleteFlowWithDenyPolicy tests the complete flow with deny policies:
// 1. Create a DenyPolicy blocking a specific action
// 2. Request is DENIED by policy even with an active session
// 3. Delete the policy
// 4. Request is now ALLOWED
func TestCompleteFlowWithDenyPolicy(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
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
	// Use the actual authenticated user's email and groups
	testUser := helpers.TestUsers.Requester.Email
	testGroup := "breakglass-emergency-admin" // Must have RBAC binding for SAR to succeed
	requesterGroups := helpers.TestUsers.Requester.Groups

	// Create escalation
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-deny-policy-esc"),
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  testGroup,
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   requesterGroups, // Use the authenticated user's actual groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create and approve session via API
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    testUser,
		Group:   testGroup,
		Reason:  "Deny policy flow test",
	}, 30*time.Second)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session")

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Logf("Created and approved session for user %s", testUser)

	t.Run("Step1_RequestAllowedWithoutPolicy", func(t *testing.T) {
		// Use delete configmaps - not blocked by any default deny policy
		sar := helpers.BuildResourceSAR(testUser, []string{testGroup}, "delete", "configmaps", "default")
		sarResp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Webhook must be reachable - check port-forward and API server")
		t.Logf("Step 1: delete configmaps - allowed=%v", sarResp.Status.Allowed)
		assert.True(t, sarResp.Status.Allowed, "Request should be ALLOWED without deny policy")
	})

	t.Run("Step2_CreateDenyPolicy", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-block-configmap-deletion",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				AppliesTo: &telekomv1alpha1.DenyPolicyScope{
					Clusters: []string{clusterName},
				},
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"delete"},
						Resources: []string{"configmaps"},
						APIGroups: []string{""},
					},
				},
			},
		}
		cleanup.Add(policy)
		require.NoError(t, cli.Create(ctx, policy))
		t.Logf("Step 2: Created deny policy blocking configmap deletion")
		// Policy propagation happens via controller watch - verify in next test step
	})

	t.Run("Step3_RequestDeniedByPolicy", func(t *testing.T) {
		// Wait for the deny policy to take effect by polling until denied
		var sarResp *authorizationv1.SubjectAccessReview
		err := helpers.WaitForCondition(ctx, func() (bool, error) {
			sar := helpers.BuildResourceSAR(testUser, []string{testGroup}, "delete", "configmaps", "default")
			resp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
			if err != nil {
				return false, err // Fail immediately if webhook not reachable
			}
			sarResp = resp
			return !resp.Status.Allowed, nil // Wait until denied
		}, 15*time.Second, 500*time.Millisecond)
		require.NoError(t, err, "Webhook must be reachable and policy must take effect")
		t.Logf("Step 3: delete configmaps - allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
		assert.False(t, sarResp.Status.Allowed, "Request should be DENIED by deny policy")
	})

	t.Run("Step4_DeletePolicyAndRequestAllowed", func(t *testing.T) {
		// Delete the policy
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-block-configmap-deletion",
				Namespace: namespace,
			},
		}
		require.NoError(t, cli.Delete(ctx, policy))
		t.Logf("Step 4a: Deleted deny policy")

		// Wait for policy deletion to take effect by polling until allowed
		var sarResp *authorizationv1.SubjectAccessReview
		err := helpers.WaitForCondition(ctx, func() (bool, error) {
			sar := helpers.BuildResourceSAR(testUser, []string{testGroup}, "delete", "configmaps", "default")
			resp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
			if err != nil {
				return false, err // Fail immediately if webhook not reachable
			}
			sarResp = resp
			return resp.Status.Allowed, nil // Wait until allowed
		}, 15*time.Second, 500*time.Millisecond)
		require.NoError(t, err, "Webhook must be reachable and policy deletion must take effect")
		t.Logf("Step 4b: delete configmaps - allowed=%v", sarResp.Status.Allowed)
		assert.True(t, sarResp.Status.Allowed, "Request should be ALLOWED after policy deletion")
	})
}

// TestCompleteFlowMultipleUsers tests concurrent access by multiple users
func TestCompleteFlowMultipleUsers(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
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

	// Use real test users from Keycloak
	// Requester (has session) and DevAlpha (no session) - both have "dev" group
	// Use a group with RBAC bindings for the SAR check to succeed
	testGroup := "breakglass-read-only" // Has RBAC binding for get/list on pods, services, configmaps
	// Combine groups from both users to ensure escalation allows both
	// Deduplicate to avoid validation error
	allowedGroupsSet := make(map[string]struct{})
	for _, g := range helpers.TestUsers.Requester.Groups {
		allowedGroupsSet[g] = struct{}{}
	}
	for _, g := range helpers.TestUsers.DevAlpha.Groups {
		allowedGroupsSet[g] = struct{}{}
	}
	allowedGroups := make([]string, 0, len(allowedGroupsSet))
	for g := range allowedGroupsSet {
		allowedGroups = append(allowedGroups, g)
	}

	// Two users with different session states
	users := []struct {
		email       string
		group       string
		hasSession  bool
		sessionName string
	}{
		{email: helpers.TestUsers.Requester.Email, group: testGroup, hasSession: true, sessionName: ""},
		{email: helpers.TestUsers.DevAlpha.Email, group: testGroup, hasSession: false, sessionName: ""},
	}

	// Create escalation for both
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("e2e-multi-user-esc"),
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  testGroup,
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   allowedGroups, // Allow both users' groups
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.Approver.Email},
			},
		},
	}
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation))

	// Create session only for user with session
	for i, u := range users {
		if u.hasSession {
			session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
				Cluster: clusterName,
				User:    u.email,
				Group:   u.group,
				Reason:  "Multi-user flow test",
			}, 30*time.Second)
			require.NoError(t, err, "Failed to create session via API")
			cleanup.Add(session)
			users[i].sessionName = session.Name

			// Approve the session using authenticated API client
			err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
			require.NoError(t, err, "Failed to approve session")

			helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)
			t.Logf("Created and approved session for %s", u.email)
		}
	}

	t.Run("UserWithSessionAllowed", func(t *testing.T) {
		// Use 'get configmaps' which is NOT blocked by any deny policy
		sar := helpers.BuildResourceSAR(users[0].email, []string{users[0].group}, "get", "configmaps", "default")
		sarResp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Webhook must be reachable - check port-forward and API server")
		t.Logf("User with session: allowed=%v", sarResp.Status.Allowed)
		assert.True(t, sarResp.Status.Allowed, "User WITH session should be ALLOWED")
	})

	t.Run("UserWithoutSessionDenied", func(t *testing.T) {
		// Use 'get configmaps' which is NOT blocked by any deny policy
		sar := helpers.BuildResourceSAR(users[1].email, []string{users[1].group}, "get", "configmaps", "default")
		sarResp, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Webhook must be reachable - check port-forward and API server")
		t.Logf("User without session: allowed=%v", sarResp.Status.Allowed)
		assert.False(t, sarResp.Status.Allowed, "User WITHOUT session should be DENIED")
	})
}
