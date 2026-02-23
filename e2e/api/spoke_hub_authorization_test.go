//go:build multicluster
// +build multicluster

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
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

func init() {
	_ = breakglassv1alpha1.AddToScheme(scheme.Scheme)
}

// SpokeHubAuthorizationSuite tests the complete user journey for multi-cluster breakglass access.
//
// This suite simulates real user interactions:
// 1. User authenticates with Keycloak to get an OIDC token
// 2. User creates a breakglass session via the API (authenticated)
// 3. Approver authenticates and approves the session via API
// 4. User accesses spoke cluster resources using their OIDC token
//
// The spoke cluster's apiserver is configured to:
// - Use Keycloak OIDC for authentication
// - Use the hub's breakglass webhook for authorization
//
// This verifies the full spoke→hub authorization flow works end-to-end.
//
// Each test uses a UNIQUE user to avoid conflicts between tests:
// - TestUserWithoutSessionDenied: SecurityRequester
// - TestUserWithApprovedSessionAllowed: Requester (breakglass-pods-reader)
// - TestSessionClusterScopeEnforced: DevAlpha (breakglass-pods-admin)
// - TestDenyPolicyEnforcedOnSpoke: PolicyTestRequester (breakglass-limited-access)
// - TestExpiredSessionDenied: SchedulingTestRequester (breakglass-read-only)
// - TestMultipleUsersIndependentSessions: WebhookTestRequester (breakglass-emergency-admin)
type SpokeHubAuthorizationSuite struct {
	suite.Suite
	ctx       context.Context
	cancel    context.CancelFunc
	hubClient client.Client
	mcCtx     *helpers.MultiClusterTestContext
	cleanup   *helpers.Cleanup
	namespace string

	// Approver API client (shared across tests - approver doesn't conflict)
	approverAPI *helpers.APIClient
}

func TestSpokeHubAuthorizationSuite(t *testing.T) {
	if !helpers.IsMultiClusterEnabled() {
		t.Skip("Multi-cluster tests disabled. Set E2E_MULTI_CLUSTER=true to enable.")
	}
	suite.Run(t, new(SpokeHubAuthorizationSuite))
}

func (s *SpokeHubAuthorizationSuite) SetupSuite() {
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 30*time.Minute)
	s.mcCtx = helpers.NewMultiClusterTestContext()
	s.namespace = helpers.GetTestNamespace()

	// Validate configuration - all these MUST be set in multi-cluster mode
	s.Require().NotEmpty(s.mcCtx.Config.HubKubeconfig, "E2E_HUB_KUBECONFIG must be set")
	s.Require().NotEmpty(s.mcCtx.Config.SpokeAKubeconfig, "E2E_SPOKE_A_KUBECONFIG must be set")
	s.Require().NotEmpty(s.mcCtx.Config.SpokeBKubeconfig, "E2E_SPOKE_B_KUBECONFIG must be set for cluster scope tests")
	s.Require().NotEmpty(s.mcCtx.Config.HubAPIURL, "E2E_HUB_API_URL must be set for API-based tests")
	s.Require().NotEmpty(s.mcCtx.Config.HubWebhookURL, "E2E_HUB_WEBHOOK_URL must be set for webhook accessibility tests")

	// Create hub client
	hubCfg, err := clientcmd.BuildConfigFromFlags("", s.mcCtx.Config.HubKubeconfig)
	s.Require().NoError(err, "Failed to build hub kubeconfig")
	s.hubClient, err = client.New(hubCfg, client.Options{Scheme: scheme.Scheme})
	s.Require().NoError(err, "Failed to create hub client")

	// Initialize cleanup helper
	s.cleanup = helpers.NewCleanup(s.T(), s.hubClient)

	// Setup approver API client (shared across tests)
	approverToken := s.mcCtx.GetApproverToken(s.T(), s.ctx)
	s.approverAPI = helpers.NewAPIClientWithAuth(approverToken)
	s.approverAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	s.T().Log("✓ Approver authenticated with Keycloak and API client ready")
}

// createAPIClientForUser creates an API client authenticated as the specified TestUser
func (s *SpokeHubAuthorizationSuite) createAPIClientForUser(user helpers.TestUser) *helpers.APIClient {
	token := s.mcCtx.GetTokenForTestUser(s.T(), s.ctx, user)
	apiClient := helpers.NewAPIClientWithAuth(token)
	apiClient.BaseURL = s.mcCtx.Config.HubAPIURL
	return apiClient.WithCleanupClient(s.hubClient, s.namespace)
}

func (s *SpokeHubAuthorizationSuite) TearDownSuite() {
	if s.cancel != nil {
		s.cancel()
	}
}

// TestUserWithoutSessionDenied verifies that a user without an active breakglass session
// is denied access when making kubectl requests to a spoke cluster.
// Uses: SecurityRequester (unique user for this test)
//
// User Flow:
// 1. User authenticates with Keycloak → gets OIDC token
// 2. User attempts kubectl on spoke cluster with token
// 3. Spoke apiserver sends SAR to hub webhook
// 4. Hub webhook finds no active session → denies access
//
// Uses SecurityRequester - a user with minimal permissions, perfect for denial testing.
func (s *SpokeHubAuthorizationSuite) TestUserWithoutSessionDenied() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.SecurityRequester

	t.Log("=== Test: User without session is denied ===")
	t.Logf("Using user: %s", testUser.Email)

	t.Log("Step 1: User authenticates with Keycloak")
	token := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	t.Logf("✓ Got OIDC token for user: %s", testUser.Email)

	t.Log("Step 2: User attempts kubectl get pods on spoke cluster")
	// Use OIDC-only kubeconfig (no client certs) so kubectl uses the --token for auth
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)
	s.Require().NotEmpty(kubeconfig, "Spoke kubeconfig must be set")

	output, err := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")

	t.Log("Step 3: Spoke apiserver consults hub webhook → no session found → denied")
	s.Require().Error(err, "Should be denied without active session")
	s.Assert().True(
		strings.Contains(output, "forbidden") || strings.Contains(output, "Forbidden"),
		"Error should indicate forbidden, got: %s", output,
	)

	t.Logf("✓ User correctly denied access: %s", strings.TrimSpace(output))
}

// TestUserWithApprovedSessionAllowed verifies that a user with an approved breakglass session
// can successfully access the spoke cluster.
// Uses: Requester with breakglass-pods-reader group
//
// User Flow (Complete Breakglass Journey):
// 1. Employee authenticates with Keycloak → gets OIDC token
// 2. Employee creates breakglass session via API (using token)
// 3. Session is created in Pending state
// 4. Approver authenticates with Keycloak → gets OIDC token
// 5. Approver approves session via API (using their token)
// 6. Session transitions to Approved state
// 7. Employee accesses spoke cluster with their OIDC token → success!
func (s *SpokeHubAuthorizationSuite) TestUserWithApprovedSessionAllowed() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.Requester

	t.Log("=== Test: Complete Breakglass User Journey ===")
	t.Logf("Using user: %s", testUser.Email)

	// Create API client for this specific user
	userAPI := s.createAPIClientForUser(testUser)

	// Step 1-2: Employee requests access via API
	t.Log("Step 1: Employee authenticates with Keycloak")
	t.Logf("✓ Employee: %s", testUser.Email)

	t.Log("Step 2: Employee requests breakglass access via API")
	session, err := userAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-pods-reader",
		Reason:  "E2E Test: Complete user journey - investigating pod issues",
	})
	s.Require().NoError(err, "Employee should be able to create session via API")
	s.cleanup.Add(session)
	t.Logf("✓ Session created via API: %s (state: Pending)", session.Name)

	// Step 3: Wait for session to be pending
	t.Log("Step 3: Session enters Pending state, awaiting approval")
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStatePending, 30*time.Second)
	t.Log("✓ Session is Pending")

	// Step 4-5: Approver authenticates and approves via API
	t.Log("Step 4: Approver authenticates with Keycloak")
	t.Logf("✓ Approver: %s", helpers.TestUsers.Approver.Email)

	t.Log("Step 5: Approver approves the session via API")
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err, "Approver should be able to approve session via API")
	t.Log("✓ Session approved via API")

	// Step 6: Verify session is approved
	t.Log("Step 6: Session transitions to Approved state")
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session is now Active")

	// Step 7: Employee accesses spoke cluster
	t.Log("Step 7: Employee accesses spoke cluster with their OIDC token")
	userToken := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)

	output, err := s.runKubectlWithToken(kubeconfig, userToken, "get", "pods", "-n", "default")
	s.Require().NoError(err, "Employee should now have access, got: %s", output)
	t.Logf("✓ kubectl get pods succeeded:\n%s", strings.TrimSpace(output))

	t.Log("=== Complete User Journey Test Passed! ===")
}

// TestSessionClusterScopeEnforced verifies that a session on one cluster does not
// grant access to a different cluster.
// Uses: DevAlpha with breakglass-pods-admin group
//
// User Flow:
// 1. Employee creates session for spoke-cluster-a via API
// 2. Session is approved via API
// 3. Employee CAN access spoke-cluster-a
// 4. Employee CANNOT access spoke-cluster-b (different cluster)
func (s *SpokeHubAuthorizationSuite) TestSessionClusterScopeEnforced() {
	t := s.T()
	spokeA := s.mcCtx.Config.SpokeAClusterName
	spokeB := s.mcCtx.Config.SpokeBClusterName
	testUser := helpers.TestUsers.DevAlpha

	// SpokeBKubeconfig is validated in SetupSuite - this should never be empty
	s.Require().NotEmpty(s.mcCtx.Config.SpokeBKubeconfig, "SpokeBKubeconfig must be set")

	t.Log("=== Test: Session Cluster Scope Enforcement ===")
	t.Logf("Using user: %s", testUser.Email)

	// Create API client for this specific user
	userAPI := s.createAPIClientForUser(testUser)

	// Create session for spoke-cluster-a ONLY via API
	t.Logf("Step 1: Employee requests access to %s only via API", spokeA)
	session, err := userAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeA,
		User:    testUser.Email,
		Group:   "breakglass-pods-admin",
		Reason:  "E2E Test: Cluster scope verification",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	// Approve via API
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, 30*time.Second)
	t.Logf("✓ Session approved for %s", spokeA)

	// Get user token
	token := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)

	// Should be allowed on spoke-a
	t.Logf("Step 2: Employee accesses %s - should succeed", spokeA)
	kubeconfigA := s.getOIDCKubeconfig(spokeA)
	outputA, errA := s.runKubectlWithToken(kubeconfigA, token, "get", "pods", "-n", "default")
	s.Require().NoError(errA, "Should be allowed on spoke-a: %s", outputA)
	t.Logf("✓ Access to %s: ALLOWED", spokeA)

	// Should be DENIED on spoke-b (different cluster)
	t.Logf("Step 3: Employee attempts %s - should be denied", spokeB)
	kubeconfigB := s.getOIDCKubeconfig(spokeB)
	outputB, errB := s.runKubectlWithToken(kubeconfigB, token, "get", "pods", "-n", "default")
	s.Require().Error(errB, "Should be denied on spoke-b with session for spoke-a")
	s.Assert().True(
		strings.Contains(outputB, "forbidden") || strings.Contains(outputB, "Forbidden"),
		"Error should indicate forbidden for wrong cluster",
	)
	t.Logf("✓ Access to %s: DENIED (as expected)", spokeB)

	t.Log("=== Cluster Scope Enforcement Test Passed! ===")
}

// TestDenyPolicyEnforcedOnSpoke verifies that DenyPolicies attached to escalations
// are enforced when the spoke apiserver consults the hub webhook.
// Uses: PolicyTestRequester with breakglass-limited-access group
//
// User Flow:
// 1. User requests access with "limited-access" group (has DenyPolicy for secrets)
// 2. Session is approved via API
// 3. User CAN access pods
// 4. User CANNOT access secrets (blocked by DenyPolicy)
func (s *SpokeHubAuthorizationSuite) TestDenyPolicyEnforcedOnSpoke() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.PolicyTestRequester

	t.Log("=== Test: DenyPolicy Enforcement on Spoke Cluster ===")
	t.Logf("Using user: %s", testUser.Email)

	// Create API client for this specific user
	userAPI := s.createAPIClientForUser(testUser)

	// Create session with limited access group via API
	t.Log("Step 1: User requests limited access (with DenyPolicy for secrets) via API")
	session, err := userAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-limited-access",
		Reason:  "E2E Test: DenyPolicy enforcement verification",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	// Approve via API
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session approved with limited access")

	token := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)

	// Pods should be allowed
	t.Log("Step 2: User accesses pods - should succeed")
	outputPods, errPods := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(errPods, "Pods should be allowed: %s", outputPods)
	t.Log("✓ Pods access: ALLOWED")

	// Secrets should be denied by DenyPolicy
	t.Log("Step 3: User attempts to access secrets - should be denied by DenyPolicy")
	outputSecrets, errSecrets := s.runKubectlWithToken(kubeconfig, token, "get", "secrets", "-n", "default")
	s.Require().Error(errSecrets, "Secrets should be denied by DenyPolicy")
	s.Assert().True(
		strings.Contains(outputSecrets, "forbidden") ||
			strings.Contains(outputSecrets, "denied") ||
			strings.Contains(outputSecrets, "Forbidden"),
		"Error should indicate secrets are denied, got: %s", outputSecrets,
	)
	t.Log("✓ Secrets access: DENIED by DenyPolicy")

	t.Log("=== DenyPolicy Enforcement Test Passed! ===")
}

// TestExpiredSessionDenied verifies that access is denied after a session expires.
// Uses: SchedulingTestRequester with breakglass-read-only group
//
// User Flow:
// 1. User requests access and session is approved
// 2. User CAN access resources initially
// 3. Session is manually expired (simulating time passage)
// 4. User CANNOT access resources anymore
//
// Note: We cannot create sessions with <60s duration via API (validation enforces minimum).
// Instead, we manually update the session status to simulate expiry.
func (s *SpokeHubAuthorizationSuite) TestExpiredSessionDenied() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.SchedulingTestRequester

	t.Log("=== Test: Expired Session Access Denial ===")
	t.Logf("Using user: %s", testUser.Email)

	// Create API client for this specific user
	userAPI := s.createAPIClientForUser(testUser)

	// First, expire ALL existing sessions for this user on this cluster
	// to ensure we're testing with a clean slate (other tests may have created sessions)
	t.Log("Step 0: Expiring any existing sessions for this user")
	sessionList := &breakglassv1alpha1.BreakglassSessionList{}
	err := s.hubClient.List(s.ctx, sessionList, client.InNamespace(s.namespace))
	s.Require().NoError(err, "Failed to list sessions")

	for i := range sessionList.Items {
		session := &sessionList.Items[i]
		if session.Spec.User == testUser.Email &&
			session.Spec.Cluster == spokeCluster &&
			session.Status.State == breakglassv1alpha1.SessionStateApproved {
			t.Logf("Expiring pre-existing session: %s", session.Name)
			session.Status.State = breakglassv1alpha1.SessionStateExpired
			session.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Minute))
			_ = s.hubClient.Status().Update(s.ctx, session)
		}
	}

	// Create a normal session via API
	t.Log("Step 1: Creating session via API")
	session, err := userAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-read-only",
		Reason:  "E2E Test: Session expiry verification",
	})
	s.Require().NoError(err, "Failed to create session via API")
	s.cleanup.Add(session)
	t.Logf("✓ Created session via API: %s", session.Name)

	// Approve via API
	t.Log("Step 2: Approving session via API")
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err, "Failed to approve session via API")

	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session approved and active")

	// Quick check - should be allowed initially
	t.Log("Step 3: User accesses cluster immediately - should succeed")
	token := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)

	output1, err1 := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	if err1 == nil {
		t.Log("✓ Initial access: ALLOWED")
	} else {
		t.Logf("Note: Initial access may have been denied if session processing was slow: %s", output1)
	}

	// Manually expire the session by updating status directly
	// This simulates time passage without waiting for the actual duration
	// Also expire any other sessions that may have been created by parallel tests
	t.Log("Step 4: Expiring ALL sessions for this user (simulating time passage)...")

	// Re-list and expire ALL sessions for this user on this cluster
	// This handles sessions created by parallel tests after our initial cleanup
	sessionList = &breakglassv1alpha1.BreakglassSessionList{}
	err = s.hubClient.List(s.ctx, sessionList, client.InNamespace(s.namespace))
	s.Require().NoError(err, "Failed to list sessions for expiry")

	expiredCount := 0
	for i := range sessionList.Items {
		sess := &sessionList.Items[i]
		if sess.Spec.User == testUser.Email &&
			sess.Spec.Cluster == spokeCluster &&
			sess.Status.State == breakglassv1alpha1.SessionStateApproved {
			t.Logf("Expiring session: %s", sess.Name)
			sess.Status.State = breakglassv1alpha1.SessionStateExpired
			sess.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Minute))
			if err := s.hubClient.Status().Update(s.ctx, sess); err != nil {
				t.Logf("Warning: failed to expire session %s: %v", sess.Name, err)
			} else {
				expiredCount++
			}
		}
	}
	t.Logf("✓ Expired %d session(s)", expiredCount)

	// Brief wait for controller to process status update
	// Note: Webhook cache TTL is 0s in e2e, so no cache delay
	time.Sleep(500 * time.Millisecond)

	// Should now be denied
	t.Log("Step 5: Employee attempts access after expiry - should be denied")
	output2, err2 := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().Error(err2, "Should be denied after session expires")
	s.Assert().True(
		strings.Contains(output2, "forbidden") || strings.Contains(output2, "Forbidden"),
		"Error should indicate forbidden after expiry, got: %s", output2,
	)
	t.Log("✓ Access after expiry: DENIED")

	t.Log("=== Expired Session Test Passed! ===")
}

// TestWebhookEndpointAccessibleFromSpoke verifies the hub webhook endpoint is reachable
// from the spoke clusters (network path validation).
func (s *SpokeHubAuthorizationSuite) TestWebhookEndpointAccessibleFromSpoke() {
	t := s.T()

	// HubWebhookURL is validated in SetupSuite - this should never be empty
	webhookURL := s.mcCtx.Config.HubWebhookURL
	s.Require().NotEmpty(webhookURL, "E2E_HUB_WEBHOOK_URL must be set")

	t.Log("=== Test: Hub Webhook Endpoint Accessibility ===")

	healthURL := webhookURL + "/healthz"
	t.Logf("Checking webhook health endpoint: %s", healthURL)

	cmd := exec.CommandContext(s.ctx, "curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}", healthURL)
	output, err := cmd.Output()
	s.Require().NoError(err, "Should be able to reach webhook health endpoint")
	s.Assert().Equal("200", string(output), "Webhook health should return 200")

	t.Log("✓ Hub webhook endpoint accessible and healthy")
}

// TestMultipleUsersIndependentSessions verifies that sessions are user-specific
// and one user's session doesn't affect another user.
// Uses: WebhookTestRequester with breakglass-emergency-admin group
func (s *SpokeHubAuthorizationSuite) TestMultipleUsersIndependentSessions() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.WebhookTestRequester
	// UnauthorizedUser is a user who won't have a session in this test
	userWithoutSession := helpers.TestUsers.UnauthorizedUser

	t.Log("=== Test: Multiple Users with Independent Sessions ===")
	t.Logf("User with session: %s", testUser.Email)
	t.Logf("User without session: %s", userWithoutSession.Email)

	// Create API client for the user who will have a session
	userAPI := s.createAPIClientForUser(testUser)

	// Only testUser has a session, not userWithoutSession
	t.Log("Step 1: First user requests and gets session approved via API")
	session, err := userAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-emergency-admin",
		Reason:  "E2E Test: Multi-user session isolation",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, 30*time.Second)
	t.Logf("✓ First user session approved: %s", session.Name)

	kubeconfig := s.getOIDCKubeconfig(spokeCluster)

	// User with session should have access
	t.Log("Step 2: User with session accesses cluster - should succeed")
	userToken := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	output1, err1 := s.runKubectlWithToken(kubeconfig, userToken, "get", "pods", "-n", "default")
	s.Require().NoError(err1, "User with session should have access: %s", output1)
	t.Log("✓ User with session access: ALLOWED")

	// User without session should NOT have access
	t.Log("Step 3: User without session accesses cluster - should be denied")
	otherUserToken := s.mcCtx.GetTokenForTestUser(t, s.ctx, userWithoutSession)
	output2, err2 := s.runKubectlWithToken(kubeconfig, otherUserToken, "get", "pods", "-n", "default")
	s.Require().Error(err2, "User without session should NOT have access (no session for them)")
	t.Logf("✓ User without session access: DENIED (as expected) - %s", strings.TrimSpace(output2))

	t.Log("=== Multi-User Session Isolation Test Passed! ===")
}

// Helper methods

// getOIDCKubeconfig returns the OIDC-only kubeconfig for token-based authentication.
// This kubeconfig has no client certificates, forcing kubectl to use only the --token
// flag for authentication. This is required for testing OIDC-based authorization flows.
// Falls back to regular kubeconfig if OIDC kubeconfig is not available.
func (s *SpokeHubAuthorizationSuite) getOIDCKubeconfig(clusterName string) string {
	kubeconfig := s.mcCtx.GetSpokeOIDCKubeconfig(clusterName)
	if kubeconfig == "" {
		// Fall back to regular kubeconfig if OIDC kubeconfig not available
		kubeconfig = s.mcCtx.GetSpokeKubeconfig(clusterName)
	}
	return kubeconfig
}

func (s *SpokeHubAuthorizationSuite) runKubectlWithToken(kubeconfig, token string, args ...string) (string, error) {
	fullArgs := append([]string{
		"--kubeconfig", kubeconfig,
		"--token", token,
	}, args...)

	cmd := exec.CommandContext(s.ctx, "kubectl", fullArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
