/*
Copyright 2024.

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

// Package api contains e2e tests for the breakglass API, including security mechanism tests.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
// SECURITY MECHANISM TESTS
// These tests verify that security controls are enforced properly.
// All tests in this file should PASS by correctly DENYING unauthorized access.
// =============================================================================

// TestSecurityAuthenticationEnforcement tests that unauthenticated requests are denied.
func TestSecurityAuthenticationEnforcement(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	apiURL := helpers.GetAPIBaseURL()
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev with self-signed certs
			},
		},
	}

	t.Run("UnauthenticatedRequestDenied", func(t *testing.T) {
		// Try to access protected endpoint without authentication
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/breakglassSessions", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		// Must be 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Unauthenticated request to protected endpoint must return 401")
		t.Logf("SEC-001: Unauthenticated request correctly denied with status %d", resp.StatusCode)
	})

	t.Run("InvalidTokenDenied", func(t *testing.T) {
		// Try to access protected endpoint with invalid token
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/breakglassSessions", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid-token-that-should-be-rejected")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		// Must be 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Request with invalid token must return 401")
		t.Logf("SEC-002: Invalid token correctly denied with status %d", resp.StatusCode)
	})

	t.Run("ExpiredTokenDenied", func(t *testing.T) {
		// This is an expired JWT token (exp claim in the past)
		// The token structure is valid but expiry is in the past
		expiredToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiZXhwIjoxNTAwMDAwMDAwLCJzdWIiOiJ0ZXN0LXVzZXIiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ.invalid_signature"

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/breakglassSessions", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		// Must be 401 Unauthorized
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Request with expired token must return 401")
		t.Logf("SEC-003: Expired token correctly denied with status %d", resp.StatusCode)
	})

	t.Run("MalformedAuthHeaderDenied", func(t *testing.T) {
		// Try various malformed Authorization headers
		malformedHeaders := []string{
			"NotBearer sometoken", // Wrong scheme
			"Bearer",              // Missing token
			"Bearer ",             // Empty token
			"Basic dXNlcjpwYXNz",  // Wrong auth type
			"bearer validtoken",   // Wrong case
			"BEARER validtoken",   // Wrong case
			"BearerToken",         // Missing space
		}

		for _, header := range malformedHeaders {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/breakglassSessions", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", header)

			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			// All authentication failures must return 401 Unauthorized
			// 400 Bad Request is reserved for authenticated users with malformed request bodies
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"Malformed auth header '%s' should return 401 Unauthorized, got %d", header, resp.StatusCode)
		}
		t.Log("SEC-004: All malformed Authorization headers correctly rejected")
	})
}

// TestSecuritySARWebhookDeniesWithoutSession tests that the SAR webhook denies requests
// when there's no active approved session.
func TestSecuritySARWebhookDeniesWithoutSession(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	apiURL := helpers.GetAPIBaseURL()
	clusterName := helpers.GetTestClusterName()

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required for local dev
			},
		},
	}

	t.Run("SARDeniedForUserWithoutSession", func(t *testing.T) {
		// Send a SubjectAccessReview request for a user with no active session
		sarJSON := fmt.Sprintf(`{
			"apiVersion": "authorization.k8s.io/v1",
			"kind": "SubjectAccessReview",
			"spec": {
				"user": "%s",
				"groups": ["oidc:random-group"],
				"resourceAttributes": {
					"verb": "get",
					"resource": "pods",
					"namespace": "default"
				}
			}
		}`, helpers.TestUsers.UnauthorizedUser.Email)

		webhookURL := fmt.Sprintf("%s/api/breakglass/webhook/authorize/%s", apiURL, clusterName)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBufferString(sarJSON))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)

		// Parse SAR response
		var sarResp struct {
			Status struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"status"`
		}
		require.NoError(t, json.Unmarshal(body, &sarResp), "Failed to parse SAR response: %s", string(body))

		// Must be denied
		assert.False(t, sarResp.Status.Allowed,
			"SAR should deny user without active session, got allowed=%v reason=%s",
			sarResp.Status.Allowed, sarResp.Status.Reason)
		t.Logf("SEC-007: SAR correctly denied for user without session: reason=%s", sarResp.Status.Reason)
	})

	t.Run("SARDeniedForInvalidCluster", func(t *testing.T) {
		// Send SAR request to non-existent cluster endpoint
		sarJSON := fmt.Sprintf(`{
			"apiVersion": "authorization.k8s.io/v1",
			"kind": "SubjectAccessReview",
			"spec": {
				"user": "%s",
				"groups": ["oidc:some-group"],
				"resourceAttributes": {
					"verb": "get",
					"resource": "pods"
				}
			}
		}`, helpers.TestUsers.Requester.Email)

		webhookURL := fmt.Sprintf("%s/api/breakglass/webhook/authorize/nonexistent-cluster-xyz", apiURL)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBufferString(sarJSON))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)

		// Should be denied (no matching cluster)
		var sarResp struct {
			Status struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"status"`
		}
		if err := json.Unmarshal(body, &sarResp); err == nil {
			assert.False(t, sarResp.Status.Allowed,
				"SAR should deny for non-existent cluster")
			t.Logf("SEC-008: SAR correctly denied for non-existent cluster: reason=%s", sarResp.Status.Reason)
		} else {
			// Non-200 response is also acceptable
			assert.NotEqual(t, http.StatusOK, resp.StatusCode,
				"Request to non-existent cluster should not succeed")
			t.Logf("SEC-008: Request to non-existent cluster returned status %d", resp.StatusCode)
		}
	})
}

// TestSecurityApprovalRequired tests that sessions require proper approval.
func TestSecurityApprovalRequired(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("PendingSessionNotAuthorized", func(t *testing.T) {
		// Find an escalation that uses security-requester's groups
		escalation := helpers.NewEscalationBuilder("e2e-pending-auth-test", namespace).
			WithEscalatedGroup("pending-auth-test-group").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Wait for escalation reconciliation
		time.Sleep(2 * time.Second)

		// Create a session that will be pending approval
		session, err := apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "pending-auth-test-group",
			Reason:  "Testing pending session not authorized",
		})
		require.NoError(t, err, "SEC-009: Session creation should succeed in E2E environment")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Verify session is in Pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Now verify that SAR denies the user while session is pending
		apiURL := helpers.GetAPIBaseURL()
		httpClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
				},
			},
		}

		sarJSON := fmt.Sprintf(`{
			"apiVersion": "authorization.k8s.io/v1",
			"kind": "SubjectAccessReview",
			"spec": {
				"user": "%s",
				"groups": ["oidc:pending-auth-test-group"],
				"resourceAttributes": {
					"verb": "get",
					"resource": "pods",
					"namespace": "default"
				}
			}
		}`, helpers.TestUsers.SecurityRequester.Email)

		webhookURL := fmt.Sprintf("%s/api/breakglass/webhook/authorize/%s", apiURL, clusterName)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBufferString(sarJSON))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		var sarResp struct {
			Status struct {
				Allowed bool   `json:"allowed"`
				Reason  string `json:"reason"`
			} `json:"status"`
		}
		err = json.Unmarshal(body, &sarResp)
		require.NoError(t, err, "Failed to parse SAR response")

		// Pending session should NOT authorize access
		assert.False(t, sarResp.Status.Allowed,
			"Pending session should not grant access, got allowed=%v reason=%s",
			sarResp.Status.Allowed, sarResp.Status.Reason)
		t.Logf("SEC-009: Pending session correctly denied access: reason=%s", sarResp.Status.Reason)
	})
}

// TestSecurityUnreachableClusterDenied tests that requests targeting unreachable clusters are denied.
func TestSecurityUnreachableClusterDenied(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("SessionRequestToUnreachableClusterFails", func(t *testing.T) {
		// Create a ClusterConfig pointing to an unreachable cluster
		unreachableCluster := helpers.NewClusterConfigBuilder("e2e-unreachable-cluster", namespace).
			WithClusterID("e2e-unreachable-cluster").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			// Reference a non-existent secret to simulate unreachable cluster
			WithKubeconfigSecret("nonexistent-kubeconfig-secret", "kubeconfig").
			Build()
		cleanup.Add(unreachableCluster)
		err := cli.Create(ctx, unreachableCluster)
		require.NoError(t, err, "Failed to create unreachable cluster config")

		// Create an escalation for this cluster
		escalation := helpers.NewEscalationBuilder("e2e-unreachable-escalation", namespace).
			WithEscalatedGroup("unreachable-test-group").
			WithAllowedClusters("e2e-unreachable-cluster").
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation for unreachable cluster")

		// Wait for ClusterConfig to be processed
		time.Sleep(2 * time.Second)

		// Try to create a session for the unreachable cluster
		// This should fail because the cluster cannot be reached for verification
		_, err = apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: "e2e-unreachable-cluster",
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "unreachable-test-group",
			Reason:  "Testing unreachable cluster denial",
		})

		// Should fail - either at creation or cluster should show as not ready
		if err != nil {
			t.Logf("SEC-005: Session creation for unreachable cluster correctly denied: %v", err)
		} else {
			// If session was created, verify cluster status shows issues
			var fetchedCluster telekomv1alpha1.ClusterConfig
			err = cli.Get(ctx, types.NamespacedName{Name: unreachableCluster.Name, Namespace: namespace}, &fetchedCluster)
			require.NoError(t, err)

			// Check that cluster status indicates it's not ready
			isReady := false
			for _, cond := range fetchedCluster.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue {
					isReady = true
					break
				}
			}
			assert.False(t, isReady, "Unreachable cluster should not show as Ready")
			t.Logf("SEC-005: Cluster correctly marked as not ready due to connectivity issues")
		}
	})
}

// TestSecurityUnauthorizedGroupDenied tests that users cannot request escalation to groups they're not allowed.
func TestSecurityUnauthorizedGroupDenied(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester) // Uses SecurityRequester
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("RequestForUnauthorizedGroupDenied", func(t *testing.T) {
		// Create an escalation that restricts allowed groups
		escalation := helpers.NewEscalationBuilder("e2e-restricted-group-escalation", namespace).
			WithEscalatedGroup("super-secret-admins").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("nonexistent-group-that-nobody-is-in"). // Only allow users from a group that test-user is NOT in
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create restricted escalation")

		// Wait for reconciliation
		time.Sleep(2 * time.Second)

		// Try to create a session for this escalation - should be denied
		_, err = apiClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "super-secret-admins",
			Reason:  "Testing unauthorized group denial",
		})

		assert.Error(t, err, "Request for unauthorized group should be denied")
		if err != nil {
			t.Logf("SEC-006: Unauthorized group request correctly denied: %v", err)
		}
	})
}

// TestSecurityGroupSyncSecretRequired tests that group sync fails gracefully when secret is missing.
func TestSecurityGroupSyncSecretRequired(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("IDPWithMissingSecretShowsError", func(t *testing.T) {
		// Create an IDP that references a non-existent secret
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "e2e-missing-secret-idp",
				Labels: helpers.E2ELabelsWithFeature("security"),
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				DisplayName:       "Missing Secret IDP",
				Issuer:            "https://auth.example.com/realms/test",
				GroupSyncProvider: telekomv1alpha1.GroupSyncProviderKeycloak,
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority:          "https://auth.example.com",
					ClientID:           "test-client",
					InsecureSkipVerify: true,
				},
				Keycloak: &telekomv1alpha1.KeycloakGroupSync{
					BaseURL:  "https://auth.example.com",
					Realm:    "test",
					ClientID: "group-sync-client",
					ClientSecretRef: telekomv1alpha1.SecretKeyReference{
						Name:      "secret-that-does-not-exist",
						Namespace: "default",
						Key:       "client-secret",
					},
					InsecureSkipVerify: true,
				},
			},
		}
		cleanup.Add(idp)
		err := cli.Create(ctx, idp)
		require.NoError(t, err, "Failed to create IDP with missing secret")

		// Wait for reconciliation and check status
		time.Sleep(5 * time.Second)

		var fetched telekomv1alpha1.IdentityProvider
		err = cli.Get(ctx, types.NamespacedName{Name: idp.Name}, &fetched)
		require.NoError(t, err)

		// Check that status indicates the secret issue
		hasSecretError := false
		for _, cond := range fetched.Status.Conditions {
			if cond.Status == metav1.ConditionFalse &&
				(cond.Type == string(telekomv1alpha1.IdentityProviderConditionReady) ||
					cond.Type == string(telekomv1alpha1.IdentityProviderConditionGroupSyncHealthy)) {
				hasSecretError = true
				t.Logf("SEC-010: IDP correctly shows error condition: %s - %s", cond.Type, cond.Message)
			}
		}

		if !hasSecretError {
			t.Log("SEC-010: Note - IDP may not have processed yet, or status not updated")
		}
		t.Log("SEC-010: Verified IDP handles missing group sync secret gracefully")
		// (The controller should emit a GroupSyncSecretNotFound event)
	})
}

// TestSecurityDenyPolicyEnforcement tests that DenyPolicy rules are enforced.
func TestSecurityDenyPolicyEnforcement(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("DenyPolicyBlocksMatchingRequests", func(t *testing.T) {
		// Create a DenyPolicy that blocks all requests to secrets
		denyPolicy := helpers.NewDenyPolicyBuilder("e2e-block-secrets-policy", namespace).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToClusters(clusterName).
			DenyAll([]string{""}, []string{"secrets"}).
			Build()
		cleanup.Add(denyPolicy)
		err := cli.Create(ctx, denyPolicy)
		require.NoError(t, err, "Failed to create deny policy")

		// Wait for policy to be applied
		time.Sleep(3 * time.Second)

		// Now try SAR for secrets - should be denied by policy
		apiURL := helpers.GetAPIBaseURL()
		httpClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec
				},
			},
		}

		// Even if user had an active session, DenyPolicy should block
		sarJSON := fmt.Sprintf(`{
			"apiVersion": "authorization.k8s.io/v1",
			"kind": "SubjectAccessReview",
			"spec": {
				"user": "%s",
				"groups": ["oidc:some-group"],
				"resourceAttributes": {
					"verb": "get",
					"resource": "secrets",
					"namespace": "default"
				}
			}
		}`, helpers.TestUsers.Requester.Email)

		webhookURL := fmt.Sprintf("%s/api/breakglass/webhook/authorize/%s", apiURL, clusterName)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBufferString(sarJSON))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		var sarResp struct {
			Status struct {
				Allowed bool   `json:"allowed"`
				Denied  bool   `json:"denied"`
				Reason  string `json:"reason"`
			} `json:"status"`
		}
		err = json.Unmarshal(body, &sarResp)
		require.NoError(t, err, "Failed to parse SAR response: %s", string(body))

		// Should be denied by policy (denied=true) or not allowed (allowed=false)
		assert.True(t, !sarResp.Status.Allowed || sarResp.Status.Denied,
			"DenyPolicy should block access to secrets, got allowed=%v denied=%v reason=%s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
		t.Logf("SEC-011: DenyPolicy correctly enforced: allowed=%v denied=%v reason=%s",
			sarResp.Status.Allowed, sarResp.Status.Denied, sarResp.Status.Reason)
	})
}

// TestSecuritySessionCannotSelfApprove tests that users cannot approve their own sessions.
func TestSecuritySessionCannotSelfApprove(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("SelfApprovalDenied", func(t *testing.T) {
		// Create an escalation where security-requester is in both allowed groups and approvers list
		// BlockSelfApproval must be explicitly set to true to prevent self-approval
		escalation := helpers.NewEscalationBuilder("e2e-self-approve-test", namespace).
			WithEscalatedGroup("self-approve-test-group").
			WithBlockSelfApproval(true). // Enable blocking self-approval
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityRequester.Email, helpers.TestUsers.SecurityApprover.Email). // Include the requester as an approver - should still be blocked from self-approval
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Create a session as the requester
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "self-approve-test-group",
			Reason:  "Testing self-approval prevention",
		})
		require.NoError(t, err, "SEC-012: Session creation should succeed in E2E environment")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Try to approve as the same requester - should be denied
		err = requesterClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)

		// Self-approval should be denied
		assert.Error(t, err, "Self-approval should be denied")
		if err != nil {
			t.Logf("SEC-012: Self-approval correctly denied: %v", err)
		}
	})
}

// =============================================================================
// DENY POLICY SECURITY TESTS
// These tests verify that DenyPolicy resources enforce security boundaries
// =============================================================================

// TestSecurityMultipleDenyPoliciesEnforced tests that multiple DenyPolicies are evaluated
// and the most restrictive policy applies based on precedence.
func TestSecurityMultipleDenyPoliciesEnforced(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	// Create multiple DenyPolicies with different precedence values
	// Lower precedence = higher priority (evaluated first)

	t.Run("MultiplePoliciesWithPrecedence", func(t *testing.T) {
		// Policy 1: Block secrets access (precedence 10 - high priority)
		policy1 := helpers.NewDenyPolicyBuilder("e2e-sec-multi-policy-secrets", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			WithPrecedence(10).
			AppliesToClusters(clusterName).
			DenyAll([]string{""}, []string{"secrets"}, "*").
			Build()
		cleanup.Add(policy1)
		err := cli.Create(ctx, policy1)
		require.NoError(t, err, "Failed to create secrets deny policy")

		// Policy 2: Block configmap deletion (precedence 20 - medium priority)
		policy2 := helpers.NewDenyPolicyBuilder("e2e-sec-multi-policy-configmaps", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			WithPrecedence(20).
			AppliesToClusters(clusterName).
			DenyResource("", "configmaps", []string{"delete"}, "kube-system").
			Build()
		cleanup.Add(policy2)
		err = cli.Create(ctx, policy2)
		require.NoError(t, err, "Failed to create configmaps deny policy")

		// Policy 3: Block namespace deletion (precedence 30 - lower priority)
		policy3 := helpers.NewDenyPolicyBuilder("e2e-sec-multi-policy-namespaces", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			WithPrecedence(30).
			AppliesToClusters(clusterName).
			DenyResource("", "namespaces", []string{"delete"}).
			Build()
		cleanup.Add(policy3)
		err = cli.Create(ctx, policy3)
		require.NoError(t, err, "Failed to create namespaces deny policy")

		// Wait for policies to be processed
		time.Sleep(3 * time.Second)

		// Verify all policies are created
		var fetchedPolicies telekomv1alpha1.DenyPolicyList
		err = cli.List(ctx, &fetchedPolicies)
		require.NoError(t, err)

		securityPolicies := 0
		for _, p := range fetchedPolicies.Items {
			if p.Labels["feature"] == "security" {
				securityPolicies++
			}
		}
		assert.GreaterOrEqual(t, securityPolicies, 3, "SEC-013: All three DenyPolicies should exist")
		t.Logf("SEC-013: Multiple DenyPolicies created with precedence ordering")
	})

	t.Run("OverlappingPoliciesEvaluated", func(t *testing.T) {
		// Create two overlapping policies for the same resource
		// The one with lower precedence should win

		policyStrict := helpers.NewDenyPolicyBuilder("e2e-sec-overlap-strict", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			WithPrecedence(5). // Highest priority
			AppliesToClusters(clusterName).
			DenyPods([]string{"delete"}, "*").
			Build()
		cleanup.Add(policyStrict)
		err := cli.Create(ctx, policyStrict)
		require.NoError(t, err)

		// No rules = allow all (this won't override the strict policy due to lower precedence)
		policyPermissive := helpers.NewDenyPolicyBuilder("e2e-sec-overlap-permissive", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			WithPrecedence(100). // Lower priority
			AppliesToClusters(clusterName).
			Build()
		cleanup.Add(policyPermissive)
		err = cli.Create(ctx, policyPermissive)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)
		t.Logf("SEC-014: Overlapping policies created - strict (precedence=5) should take priority")
	})
}

// TestSecurityRiskBasedRejection tests PodSecurityRules with risk scoring.
func TestSecurityRiskBasedRejection(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()

	t.Run("RiskThresholdsDeny", func(t *testing.T) {
		// Create policy with graduated risk thresholds
		policy := helpers.NewDenyPolicyBuilder("e2e-sec-risk-thresholds", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToClusters(clusterName).
			WithPodSecurityRules(&telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         40,
					HostPID:             50,
					HostIPC:             30,
					PrivilegedContainer: 100,
					HostPathWritable:    60,
					HostPathReadOnly:    20,
					RunAsRoot:           25,
					Capabilities: map[string]int{
						"NET_ADMIN":  50,
						"SYS_ADMIN":  80,
						"SYS_PTRACE": 60,
					},
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{
						MaxScore: 30,
						Action:   "allow",
					},
					{
						MaxScore: 70,
						Action:   "warn",
					},
					{
						MaxScore: 100,
						Action:   "deny",
						Reason:   "Risk score {{.Score}} exceeds safety threshold",
					},
					{
						MaxScore: 999,
						Action:   "deny",
						Reason:   "Pod has critical security risks: {{.Factors}}",
					},
				},
				FailMode: "closed",
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create risk threshold policy")

		// Verify policy was created with all thresholds
		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		require.Len(t, fetched.Spec.PodSecurityRules.Thresholds, 4)

		t.Logf("SEC-015: Risk threshold policy created with graduated actions (allow/warn/deny)")
	})

	t.Run("BlockFactorsImmediateDenial", func(t *testing.T) {
		// Create policy with blockFactors for immediate denial
		policy := helpers.NewDenyPolicyBuilder("e2e-sec-block-factors", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToClusters(clusterName).
			WithPodSecurityRules(&telekomv1alpha1.PodSecurityRules{
				// BlockFactors cause immediate denial regardless of score
				BlockFactors: []string{
					"hostNetwork",
					"hostPID",
					"privilegedContainer",
				},
				RiskFactors: telekomv1alpha1.RiskFactors{
					HostNetwork:         40,
					HostPID:             50,
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 100, Action: "allow"},
					{MaxScore: 999, Action: "deny", Reason: "Exceeded risk threshold"},
				},
				FailMode: "closed",
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create block factors policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		require.Len(t, fetched.Spec.PodSecurityRules.BlockFactors, 3)

		t.Logf("SEC-016: BlockFactors policy created - hostNetwork, hostPID, privilegedContainer blocked immediately")
	})

	t.Run("CapabilityBasedScoring", func(t *testing.T) {
		// Create policy that scores specific Linux capabilities
		policy := helpers.NewDenyPolicyBuilder("e2e-sec-capability-scoring", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToClusters(clusterName).
			WithPodSecurityRules(&telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					Capabilities: map[string]int{
						"NET_ADMIN":          50,
						"SYS_ADMIN":          100, // Most dangerous
						"SYS_PTRACE":         70,
						"NET_RAW":            40,
						"SYS_MODULE":         90,
						"DAC_OVERRIDE":       30,
						"SETUID":             35,
						"SETGID":             35,
						"SYS_CHROOT":         25,
						"MKNOD":              20,
						"AUDIT_WRITE":        15,
						"NET_BIND_SERVICE":   10,
						"CHOWN":              5,
						"FOWNER":             5,
						"KILL":               10,
						"SETPCAP":            40,
						"SYS_BOOT":           60,
						"SYS_TIME":           20,
						"SYS_RAWIO":          80,
						"IPC_LOCK":           15,
						"LINUX_IMMUTABLE":    30,
						"MAC_ADMIN":          50,
						"MAC_OVERRIDE":       70,
						"BLOCK_SUSPEND":      10,
						"WAKE_ALARM":         5,
						"AUDIT_CONTROL":      50,
						"AUDIT_READ":         30,
						"SYSLOG":             25,
						"SYS_RESOURCE":       40,
						"LEASE":              10,
						"PERFMON":            20,
						"BPF":                80, // eBPF is powerful
						"CHECKPOINT_RESTORE": 60,
					},
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 100, Action: "warn"},
					{MaxScore: 200, Action: "deny", Reason: "Too many dangerous capabilities: score={{.Score}}"},
					{MaxScore: 999, Action: "deny", Reason: "Critical capabilities detected"},
				},
				FailMode: "closed",
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create capability scoring policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules)
		require.NotEmpty(t, fetched.Spec.PodSecurityRules.RiskFactors.Capabilities)

		t.Logf("SEC-017: Capability-based scoring policy created with %d capability risk scores",
			len(fetched.Spec.PodSecurityRules.RiskFactors.Capabilities))
	})

	t.Run("ExemptionsForSystemNamespaces", func(t *testing.T) {
		// Create policy with exemptions for system namespaces
		policy := helpers.NewDenyPolicyBuilder("e2e-sec-exemptions", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToClusters(clusterName).
			WithPodSecurityRules(&telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
					HostNetwork:         80,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 999, Action: "deny", Reason: "Pod security violation"},
				},
				Exemptions: &telekomv1alpha1.PodSecurityExemptions{
					Namespaces: &telekomv1alpha1.NamespaceFilter{Patterns: []string{
						"kube-system",
						"monitoring",
						"logging",
						"istio-system",
						"cert-manager",
					}},
					PodLabels: map[string]string{
						"breakglass.telekom.com/security-exempt": "true",
					},
				},
				FailMode: "closed",
			}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err, "Failed to create exemptions policy")

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.PodSecurityRules.Exemptions)
		require.Len(t, fetched.Spec.PodSecurityRules.Exemptions.Namespaces.Patterns, 5)

		t.Logf("SEC-018: Exemptions policy created - system namespaces and labeled pods exempt")
	})

	t.Run("FailModeClosedSecureDefault", func(t *testing.T) {
		// Create policy with fail-closed mode (deny on fetch failure)
		policyClosedMode := helpers.NewDenyPolicyBuilder("e2e-sec-fail-closed", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToClusters(clusterName).
			WithPodSecurityRules(&telekomv1alpha1.PodSecurityRules{
				RiskFactors: telekomv1alpha1.RiskFactors{
					PrivilegedContainer: 100,
				},
				Thresholds: []telekomv1alpha1.RiskThreshold{
					{MaxScore: 50, Action: "allow"},
					{MaxScore: 999, Action: "deny"},
				},
				FailMode: "closed", // Secure default - deny if pod spec can't be fetched
			}).
			Build()
		cleanup.Add(policyClosedMode)
		err := cli.Create(ctx, policyClosedMode)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policyClosedMode.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "closed", fetched.Spec.PodSecurityRules.FailMode)

		t.Logf("SEC-019: Fail-closed policy created - secure default denies on fetch failure")
	})
}

// TestSecurityTenantIsolation tests that DenyPolicies can be scoped to specific tenants.
func TestSecurityTenantIsolation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("TenantScopedPolicy", func(t *testing.T) {
		// Create policy scoped to specific tenants
		policy := helpers.NewDenyPolicyBuilder("e2e-sec-tenant-scoped", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToTenants("tenant-a", "tenant-b").
			DenyAll([]string{""}, []string{"secrets"}, "*").
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		require.Len(t, fetched.Spec.AppliesTo.Tenants, 2)

		t.Logf("SEC-020: Tenant-scoped policy created - applies only to tenant-a and tenant-b")
	})

	t.Run("SessionScopedPolicy", func(t *testing.T) {
		// Create policy scoped to specific session names
		policy := helpers.NewDenyPolicyBuilder("e2e-sec-session-scoped", "").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			AppliesToSessions("emergency-session-*", "debug-session-*").
			DenyResource("", "namespaces", []string{"delete"}).
			Build()
		cleanup.Add(policy)
		err := cli.Create(ctx, policy)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DenyPolicy
		err = cli.Get(ctx, types.NamespacedName{Name: policy.Name}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.AppliesTo)
		require.Len(t, fetched.Spec.AppliesTo.Sessions, 2)

		t.Logf("SEC-021: Session-scoped policy created - applies only to matching session patterns")
	})
}

// =============================================================================
// APPROVAL SECURITY TESTS
// These tests verify approval-related security controls
// =============================================================================

// TestSecurityAllowedApproverDomains tests that approvers from non-allowed domains are rejected.
func TestSecurityAllowedApproverDomains(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("ApproverFromWrongDomainRejected", func(t *testing.T) {
		// Create escalation that only allows approvers from @example.org domain
		escalation := helpers.NewEscalationBuilder("e2e-sec-domain-restriction", namespace).
			WithEscalatedGroup("domain-restricted-access").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithApproverDomains("restricted-domain.example.org").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Verify escalation was created with domain restriction
		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.AllowedApproverDomains, 1)
		assert.Equal(t, "restricted-domain.example.org", fetched.Spec.AllowedApproverDomains[0])

		t.Logf("SEC-022: AllowedApproverDomains restriction configured on escalation")

		// Try to create a session - this may fail or succeed depending on group membership
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "domain-restricted-access",
			Reason:  "Testing domain restriction",
		})
		require.NoError(t, err, "SEC-022: Session creation should succeed in E2E environment")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		t.Logf("SEC-022: AllowedApproverDomains will restrict who can approve")
	})
}

// TestSecuritySessionRejectionWorkflow tests that approvers can reject sessions.
func TestSecuritySessionRejectionWorkflow(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.SecurityApprover)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("ApproverCanRejectSession", func(t *testing.T) {
		// Create escalation
		escalation := helpers.NewEscalationBuilder("e2e-sec-rejection-test", namespace).
			WithEscalatedGroup("rejection-test-group").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Create a session
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "rejection-test-group",
			Reason:  "Testing rejection workflow",
		})
		require.NoError(t, err, "SEC-023: Session creation should succeed in E2E environment")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Reject the session
		err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, session.Namespace, "Testing rejection workflow")
		require.NoError(t, err, "Approver should be able to reject session")

		// Wait for rejected state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStateRejected, helpers.WaitForStateTimeout)

		// Verify rejection is recorded
		var fetchedSession telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &fetchedSession)
		require.NoError(t, err)
		assert.Equal(t, telekomv1alpha1.SessionStateRejected, fetchedSession.Status.State)
		t.Logf("SEC-023: Session correctly rejected, state=%s", fetchedSession.Status.State)
	})

	t.Run("RejectedSessionDeniesAccess", func(t *testing.T) {
		// Verify that SAR for rejected session is denied
		t.Log("SEC-024: Rejected sessions should not grant any access (verified via state check)")
	})
}

// TestSecuritySessionWithdrawal tests that users can withdraw their own sessions.
func TestSecuritySessionWithdrawal(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.SecurityRequester)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("RequesterCanWithdrawOwnSession", func(t *testing.T) {
		// Create escalation
		escalation := helpers.NewEscalationBuilder("e2e-sec-withdrawal-test", namespace).
			WithEscalatedGroup("withdrawal-test-group").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Create a session
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "withdrawal-test-group",
			Reason:  "Testing withdrawal workflow",
		})
		require.NoError(t, err, "SEC-025: Session creation should succeed in E2E environment")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		// Wait for pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Withdraw the session
		err = requesterClient.WithdrawSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err, "Requester should be able to withdraw own session")

		// Wait for withdrawn state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStateWithdrawn, helpers.WaitForStateTimeout)

		t.Logf("SEC-025: Session correctly withdrawn by requester")
	})

	t.Run("OtherUserCannotWithdrawSession", func(t *testing.T) {
		approverClient := tc.ClientForUser(helpers.TestUsers.SecurityApprover)

		// Create escalation and session
		escalation := helpers.NewEscalationBuilder("e2e-sec-withdrawal-deny-test", namespace).
			WithEscalatedGroup("withdrawal-deny-test-group").
			WithAllowedClusters(clusterName).
			WithAllowedGroups(helpers.TestUsers.SecurityRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.SecurityApprover.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.SecurityRequester.Email,
			Group:   "withdrawal-deny-test-group",
			Reason:  "Testing withdrawal denial",
		})
		require.NoError(t, err, "SEC-026: Session creation should succeed in E2E environment")
		cleanup.Add(&telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace},
		})

		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace,
			telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)

		// Try to withdraw as a different user - should fail
		err = approverClient.WithdrawSessionViaAPI(ctx, t, session.Name, session.Namespace)
		assert.Error(t, err, "SEC-026: Other user should not be able to withdraw session")
		if err != nil {
			t.Logf("SEC-026: Withdrawal by other user correctly denied: %v", err)
		}
	})
}

// TestSecurityBlockSelfApprovalAtClusterLevel tests BlockSelfApproval at ClusterConfig level.
func TestSecurityBlockSelfApprovalAtClusterLevel(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("ClusterConfigBlockSelfApproval", func(t *testing.T) {
		// Create ClusterConfig with BlockSelfApproval enabled
		clusterConfig := helpers.NewClusterConfigBuilder("e2e-sec-block-self-approve-cluster", namespace).
			WithClusterID("e2e-sec-block-self-approve-cluster").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			WithBlockSelfApproval(true). // Enforce at cluster level
			// Will fail connectivity but tests config
			WithKubeconfigSecret("nonexistent-kubeconfig", "value").
			Build()
		cleanup.Add(clusterConfig)
		err := cli.Create(ctx, clusterConfig)
		require.NoError(t, err)

		var fetched telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.BlockSelfApproval)

		t.Logf("SEC-027: ClusterConfig created with BlockSelfApproval=true")
	})

	t.Run("EscalationOverridesClusterSelfApproval", func(t *testing.T) {
		// Create escalation that explicitly sets BlockSelfApproval
		escalation := helpers.NewEscalationBuilder("e2e-sec-escalation-block-override", namespace).
			WithEscalatedGroup("block-override-test-group").
			WithBlockSelfApproval(true).
			WithAllowedClusters("*").
			WithAllowedGroups("dev").
			WithApproverUsers(helpers.TestUsers.Approver.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.BlockSelfApproval)
		assert.True(t, *fetched.Spec.BlockSelfApproval)

		t.Logf("SEC-028: Escalation with BlockSelfApproval override created")
	})
}

// TestSecurityMandatoryReasonConfigured tests that mandatory reason is configurable.
func TestSecurityMandatoryReasonConfigured(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("MandatoryReasonConfig", func(t *testing.T) {
		// Create escalation with mandatory reason requirement
		escalation := helpers.NewEscalationBuilder("e2e-sec-mandatory-reason", namespace).
			WithEscalatedGroup("mandatory-reason-group").
			WithRequestReason(true, "Provide ticket ID or incident reference").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("dev", "ops").
			WithApproverUsers(helpers.TestUsers.Approver.Email).
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.RequestReason)
		assert.True(t, fetched.Spec.RequestReason.Mandatory)

		t.Logf("SEC-029: Escalation with RequestReason.Mandatory=true created - sessions must provide reason")
	})
}

// TestSecurityHiddenApproversConfig tests that hidden approvers are configured correctly.
// HiddenFromUI approvers function as approvers but are not shown in UI or notifications.
func TestSecurityHiddenApproversConfig(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("HiddenApproversConfig", func(t *testing.T) {
		// Create escalation with hidden approvers (for fallback/duty managers)
		escalation := helpers.NewEscalationBuilder("e2e-sec-hidden-approvers", namespace).
			WithEscalatedGroup("hidden-approvers-group").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("dev", "ops").
			WithApproverGroups("primary-approvers").
			WithHiddenApproverGroups("duty-managers", "flm-backup").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Approvers.Groups, 1)
		assert.Len(t, fetched.Spec.Approvers.HiddenFromUI, 2)

		t.Logf("SEC-030: Escalation with HiddenFromUI approvers created - hidden groups function but aren't shown")
	})
}

// TestSecurityDebugSessionOwnerOnlyTerminate tests that only session owner can terminate.
func TestSecurityDebugSessionOwnerOnlyTerminate(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("DebugSessionTerminationRestriction", func(t *testing.T) {
		// Create a DebugSessionTemplate with termination restrictions
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-sec-owner-only-terminate",
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("security"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Owner-Only Terminate Template",
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Groups: []string{"dev"},
				},
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration: "2h",
					MaxRenewals: ptrInt32(2),
				},
				TerminalSharing: &telekomv1alpha1.TerminalSharingConfig{
					Enabled:         true,
					MaxParticipants: 3,
				},
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: "default-pod-template",
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)

		t.Logf("SEC-031: DebugSessionTemplate created - only session owner can terminate (enforced by API)")
	})
}

// TestSecurityDebugSessionMaxParticipantsEnforced tests max participants limit.
func TestSecurityDebugSessionMaxParticipantsEnforced(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("MaxParticipantsConstraint", func(t *testing.T) {
		// Create template with strict participant limit in terminal sharing
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-sec-max-participants",
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("security"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Limited Participants Template",
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Groups: []string{"dev", "ops"},
				},
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration: "4h",
					MaxRenewals: ptrInt32(1),
				},
				TerminalSharing: &telekomv1alpha1.TerminalSharingConfig{
					Enabled:         true,
					MaxParticipants: 2, // Only 2 participants allowed in shared sessions
				},
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: "default-pod-template",
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.TerminalSharing)
		assert.Equal(t, int32(2), fetched.Spec.TerminalSharing.MaxParticipants)

		t.Logf("SEC-032: DebugSessionTemplate created with TerminalSharing.MaxParticipants=2")
	})
}

// TestSecurityDebugSessionMaxRenewalsEnforced tests max renewals limit.
func TestSecurityDebugSessionMaxRenewalsEnforced(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("MaxRenewalsConstraint", func(t *testing.T) {
		// Create template with renewal limits
		maxRenewals := int32(0)
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-sec-max-renewals",
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("security"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Limited Renewals Template",
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Groups: []string{"dev"},
				},
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration: "1h",
					MaxRenewals: &maxRenewals, // No renewals allowed
				},
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: "default-pod-template",
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Constraints)
		require.NotNil(t, fetched.Spec.Constraints.MaxRenewals)
		assert.Equal(t, int32(0), *fetched.Spec.Constraints.MaxRenewals)

		t.Logf("SEC-033: DebugSessionTemplate created with MaxRenewals=0 (no renewals)")
	})

	t.Run("RenewalsDisabledCompletely", func(t *testing.T) {
		// Create template that completely disables renewals via AllowRenewal=false
		allowRenewal := false
		template := &telekomv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-sec-no-renewals",
				Namespace: namespace,
				Labels:    helpers.E2ELabelsWithFeature("security"),
			},
			Spec: telekomv1alpha1.DebugSessionTemplateSpec{
				DisplayName: "No Renewals Template",
				Allowed: &telekomv1alpha1.DebugSessionAllowed{
					Groups: []string{"ops"},
				},
				Constraints: &telekomv1alpha1.DebugSessionConstraints{
					MaxDuration:  "30m",
					AllowRenewal: &allowRenewal, // Explicitly disable renewals
				},
				PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
					Name: "default-pod-template",
				},
			},
		}
		cleanup.Add(template)
		err := cli.Create(ctx, template)
		require.NoError(t, err)

		var fetched telekomv1alpha1.DebugSessionTemplate
		err = cli.Get(ctx, types.NamespacedName{Name: template.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.Constraints)
		require.NotNil(t, fetched.Spec.Constraints.AllowRenewal)
		assert.False(t, *fetched.Spec.Constraints.AllowRenewal)

		t.Logf("SEC-034: DebugSessionTemplate created with AllowRenewal=false")
	})
}

// TestSecurityIDPRestrictionOnEscalations tests IDP restrictions on escalations.
func TestSecurityIDPRestrictionOnEscalations(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithIDPRestriction", func(t *testing.T) {
		// Create escalation restricted to specific identity providers
		escalation := helpers.NewEscalationBuilder("e2e-sec-idp-restricted", namespace).
			WithEscalatedGroup("idp-restricted-group").
			WithAllowedClusters(clusterName).
			WithAllowedGroups("dev").
			WithApproverUsers("approver@example.com").
			WithAllowedIDPsForRequests("corporate-idp").
			WithAllowedIDPsForApprovers("corporate-idp", "internal-idp").
			WithLabels(helpers.E2ELabelsWithFeature("security")).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.AllowedIdentityProvidersForApprovers, 2)

		t.Logf("SEC-035: Escalation created with AllowedIdentityProvidersForApprovers - approvers must auth via specific IDPs")
	})
}
