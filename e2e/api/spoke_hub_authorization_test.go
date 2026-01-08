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
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

func init() {
	_ = telekomv1alpha1.AddToScheme(scheme.Scheme)
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
type SpokeHubAuthorizationSuite struct {
	suite.Suite
	ctx       context.Context
	cancel    context.CancelFunc
	hubClient client.Client
	mcCtx     *helpers.MultiClusterTestContext
	cleanup   *helpers.Cleanup
	namespace string

	// API clients for realistic user flows
	employeeAPI *helpers.APIClient
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

	// Validate configuration
	s.Require().NotEmpty(s.mcCtx.Config.HubKubeconfig, "E2E_HUB_KUBECONFIG must be set")
	s.Require().NotEmpty(s.mcCtx.Config.SpokeAKubeconfig, "E2E_SPOKE_A_KUBECONFIG must be set")
	s.Require().NotEmpty(s.mcCtx.Config.HubAPIURL, "E2E_HUB_API_URL must be set for API-based tests")

	// Create hub client
	hubCfg, err := clientcmd.BuildConfigFromFlags("", s.mcCtx.Config.HubKubeconfig)
	s.Require().NoError(err, "Failed to build hub kubeconfig")
	s.hubClient, err = client.New(hubCfg, client.Options{Scheme: scheme.Scheme})
	s.Require().NoError(err, "Failed to create hub client")

	// Initialize cleanup helper
	s.cleanup = helpers.NewCleanup(s.T(), s.hubClient)

	// Create API clients authenticated as different users
	// This simulates the real user flow: login → get token → use API
	s.setupAuthenticatedAPIClients()
}

func (s *SpokeHubAuthorizationSuite) setupAuthenticatedAPIClients() {
	t := s.T()

	// Employee (requester) authenticates with Keycloak
	employeeToken := s.mcCtx.GetEmployeeToken(t, s.ctx)
	s.employeeAPI = helpers.NewAPIClientWithAuth(employeeToken)
	s.employeeAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	s.employeeAPI = s.employeeAPI.WithCleanupClient(s.hubClient, s.namespace)
	t.Log("✓ Employee authenticated with Keycloak and API client ready")

	// Approver authenticates with Keycloak
	approverToken := s.mcCtx.GetApproverToken(t, s.ctx)
	s.approverAPI = helpers.NewAPIClientWithAuth(approverToken)
	s.approverAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	t.Log("✓ Approver authenticated with Keycloak and API client ready")
}

func (s *SpokeHubAuthorizationSuite) TearDownSuite() {
	if s.cancel != nil {
		s.cancel()
	}
}

// TestUserWithoutSessionDenied verifies that a user without an active breakglass session
// is denied access when making kubectl requests to a spoke cluster.
//
// User Flow:
// 1. User authenticates with Keycloak → gets OIDC token
// 2. User attempts kubectl on spoke cluster with token
// 3. Spoke apiserver sends SAR to hub webhook
// 4. Hub webhook finds no active session → denies access
func (s *SpokeHubAuthorizationSuite) TestUserWithoutSessionDenied() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName

	t.Log("=== Test: User without session is denied ===")
	t.Log("Step 1: User authenticates with Keycloak")
	token := s.mcCtx.GetEmployeeToken(t, s.ctx)
	t.Logf("✓ Got OIDC token for user: %s", helpers.MultiClusterTestUsers.Employee.Email)

	t.Log("Step 2: User attempts kubectl get pods on spoke cluster")
	kubeconfig := s.mcCtx.GetSpokeKubeconfig(spokeCluster)
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

	t.Log("=== Test: Complete Breakglass User Journey ===")

	// Step 1-2: Employee requests access via API
	t.Log("Step 1: Employee authenticates with Keycloak")
	t.Logf("✓ Employee: %s", helpers.MultiClusterTestUsers.Employee.Email)

	t.Log("Step 2: Employee requests breakglass access via API")
	session, err := s.employeeAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Employee.Email,
		Group:   "breakglass-pods-reader",
		Reason:  "E2E Test: Complete user journey - investigating pod issues",
	})
	s.Require().NoError(err, "Employee should be able to create session via API")
	s.cleanup.Add(session)
	t.Logf("✓ Session created via API: %s (state: Pending)", session.Name)

	// Step 3: Wait for session to be pending
	t.Log("Step 3: Session enters Pending state, awaiting approval")
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	t.Log("✓ Session is Pending")

	// Step 4-5: Approver authenticates and approves via API
	t.Log("Step 4: Approver authenticates with Keycloak")
	t.Logf("✓ Approver: %s", helpers.MultiClusterTestUsers.Approver.Email)

	t.Log("Step 5: Approver approves the session via API")
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err, "Approver should be able to approve session via API")
	t.Log("✓ Session approved via API")

	// Step 6: Verify session is approved
	t.Log("Step 6: Session transitions to Approved state")
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session is now Active")

	// Step 7: Employee accesses spoke cluster
	t.Log("Step 7: Employee accesses spoke cluster with their OIDC token")
	employeeToken := s.mcCtx.GetEmployeeToken(t, s.ctx)
	kubeconfig := s.mcCtx.GetSpokeKubeconfig(spokeCluster)

	output, err := s.runKubectlWithToken(kubeconfig, employeeToken, "get", "pods", "-n", "default")
	s.Require().NoError(err, "Employee should now have access, got: %s", output)
	t.Logf("✓ kubectl get pods succeeded:\n%s", strings.TrimSpace(output))

	t.Log("=== Complete User Journey Test Passed! ===")
}

// TestSessionClusterScopeEnforced verifies that a session on one cluster does not
// grant access to a different cluster.
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

	if s.mcCtx.Config.SpokeBKubeconfig == "" {
		t.Skip("Spoke-B kubeconfig not configured, skipping cluster scope test")
	}

	t.Log("=== Test: Session Cluster Scope Enforcement ===")

	// Create session for spoke-cluster-a ONLY via API
	t.Logf("Step 1: Employee requests access to %s only via API", spokeA)
	session, err := s.employeeAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeA,
		User:    helpers.MultiClusterTestUsers.Employee.Email,
		Group:   "breakglass-pods-reader",
		Reason:  "E2E Test: Cluster scope verification",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	// Approve via API
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Logf("✓ Session approved for %s", spokeA)

	// Get employee token
	token := s.mcCtx.GetEmployeeToken(t, s.ctx)

	// Should be allowed on spoke-a
	t.Logf("Step 2: Employee accesses %s - should succeed", spokeA)
	kubeconfigA := s.mcCtx.GetSpokeKubeconfig(spokeA)
	outputA, errA := s.runKubectlWithToken(kubeconfigA, token, "get", "pods", "-n", "default")
	s.Require().NoError(errA, "Should be allowed on spoke-a: %s", outputA)
	t.Logf("✓ Access to %s: ALLOWED", spokeA)

	// Should be DENIED on spoke-b (different cluster)
	t.Logf("Step 3: Employee attempts %s - should be denied", spokeB)
	kubeconfigB := s.mcCtx.GetSpokeKubeconfig(spokeB)
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
//
// User Flow:
// 1. Employee requests access with "limited-access" group (has DenyPolicy for secrets)
// 2. Session is approved via API
// 3. Employee CAN access pods
// 4. Employee CANNOT access secrets (blocked by DenyPolicy)
func (s *SpokeHubAuthorizationSuite) TestDenyPolicyEnforcedOnSpoke() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName

	t.Log("=== Test: DenyPolicy Enforcement on Spoke Cluster ===")

	// Create session with limited access group via API
	t.Log("Step 1: Employee requests limited access (with DenyPolicy for secrets) via API")
	session, err := s.employeeAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Employee.Email,
		Group:   "breakglass-limited-access",
		Reason:  "E2E Test: DenyPolicy enforcement verification",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	// Approve via API
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session approved with limited access")

	token := s.mcCtx.GetEmployeeToken(t, s.ctx)
	kubeconfig := s.mcCtx.GetSpokeKubeconfig(spokeCluster)

	// Pods should be allowed
	t.Log("Step 2: Employee accesses pods - should succeed")
	outputPods, errPods := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(errPods, "Pods should be allowed: %s", outputPods)
	t.Log("✓ Pods access: ALLOWED")

	// Secrets should be denied by DenyPolicy
	t.Log("Step 3: Employee attempts to access secrets - should be denied by DenyPolicy")
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
//
// User Flow:
// 1. Employee requests access with very short duration (5 seconds)
// 2. Session is approved
// 3. Employee CAN access resources immediately
// 4. After 10 seconds, session expires
// 5. Employee CANNOT access resources anymore
func (s *SpokeHubAuthorizationSuite) TestExpiredSessionDenied() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName

	t.Log("=== Test: Expired Session Access Denial ===")

	// Create session with very short duration directly (API may have minimum duration limits)
	t.Log("Step 1: Creating session with 5-second duration")
	sessionName := fmt.Sprintf("e2e-short-session-%d", time.Now().UnixNano())
	session := &telekomv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sessionName,
			Namespace: s.namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Spec: telekomv1alpha1.BreakglassSessionSpec{
			Cluster:       spokeCluster,
			User:          helpers.MultiClusterTestUsers.Employee.Email,
			GrantedGroup:  "breakglass-pods-reader",
			MaxValidFor:   "5s",
			RequestReason: "E2E Test: Session expiry verification",
		},
	}
	s.cleanup.Add(session)
	err := s.hubClient.Create(s.ctx, session)
	s.Require().NoError(err, "Failed to create short-duration session")
	t.Logf("✓ Created session: %s with 5s duration", session.Name)

	// Approve directly via status update (for short duration test)
	t.Log("Step 2: Approving session")
	s.approveSession(t, session)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session approved and active")

	// Quick check - should be allowed initially
	t.Log("Step 3: Employee accesses cluster immediately - should succeed")
	token := s.mcCtx.GetEmployeeToken(t, s.ctx)
	kubeconfig := s.mcCtx.GetSpokeKubeconfig(spokeCluster)

	output1, err1 := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	if err1 == nil {
		t.Log("✓ Initial access: ALLOWED")
	} else {
		t.Logf("Note: Initial access may have been denied if session processing was slow: %s", output1)
	}

	// Wait for session to expire
	t.Log("Step 4: Waiting for session to expire (10 seconds)...")
	time.Sleep(10 * time.Second)

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

	webhookURL := s.mcCtx.Config.HubWebhookURL
	if webhookURL == "" {
		t.Skip("E2E_HUB_WEBHOOK_URL not set, skipping webhook accessibility test")
	}

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
func (s *SpokeHubAuthorizationSuite) TestMultipleUsersIndependentSessions() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName

	t.Log("=== Test: Multiple Users with Independent Sessions ===")

	// Only employee has a session, not approver (who is a different user)
	t.Log("Step 1: Employee requests and gets session approved via API")
	session, err := s.employeeAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Employee.Email,
		Group:   "breakglass-pods-reader",
		Reason:  "E2E Test: Multi-user session isolation",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Logf("✓ Employee session approved: %s", session.Name)

	kubeconfig := s.mcCtx.GetSpokeKubeconfig(spokeCluster)

	// Employee should have access
	t.Log("Step 2: Employee (with session) accesses cluster - should succeed")
	employeeToken := s.mcCtx.GetEmployeeToken(t, s.ctx)
	output1, err1 := s.runKubectlWithToken(kubeconfig, employeeToken, "get", "pods", "-n", "default")
	s.Require().NoError(err1, "Employee should have access: %s", output1)
	t.Log("✓ Employee access: ALLOWED")

	// Approver (different user, no session for them) should NOT have access
	t.Log("Step 3: Approver (without their own session) accesses cluster - should be denied")
	approverToken := s.mcCtx.GetApproverToken(t, s.ctx)
	output2, err2 := s.runKubectlWithToken(kubeconfig, approverToken, "get", "pods", "-n", "default")
	s.Require().Error(err2, "Approver should NOT have access (no session for them)")
	t.Logf("✓ Approver access: DENIED (as expected) - %s", strings.TrimSpace(output2))

	t.Log("=== Multi-User Session Isolation Test Passed! ===")
}

// Helper methods

func (s *SpokeHubAuthorizationSuite) runKubectlWithToken(kubeconfig, token string, args ...string) (string, error) {
	fullArgs := append([]string{
		"--kubeconfig", kubeconfig,
		"--token", token,
	}, args...)

	cmd := exec.CommandContext(s.ctx, "kubectl", fullArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *SpokeHubAuthorizationSuite) approveSession(t *testing.T, session *telekomv1alpha1.BreakglassSession) {
	// Fetch latest version
	var latest telekomv1alpha1.BreakglassSession
	err := s.hubClient.Get(s.ctx, client.ObjectKey{
		Namespace: session.Namespace,
		Name:      session.Name,
	}, &latest)
	require.NoError(t, err, "Failed to get session for approval")

	// Update status to approved
	now := metav1.Now()
	latest.Status.Approver = helpers.MultiClusterTestUsers.Approver.Email
	latest.Status.Approvers = []string{helpers.MultiClusterTestUsers.Approver.Email}
	latest.Status.ApprovedAt = now
	latest.Status.ApprovalReason = "E2E Test auto-approval"
	latest.Status.State = telekomv1alpha1.SessionStateApproved

	err = s.hubClient.Status().Update(s.ctx, &latest)
	require.NoError(t, err, "Failed to approve session")
}
