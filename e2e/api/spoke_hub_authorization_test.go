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
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
// - TestExpiredSessionDenied: SchedulingTestRequester (breakglass-pods-admin)
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

// holdSessionExpiryCleanup pauses only the controller's periodic cleanup loop
// while leaving its webhook pod serving. This makes the status-admission proof
// deterministic: the first post-boundary write is evaluated while the stored
// session is still Approved, then the normal controller expiry is restored and
// verified separately.
func (s *SpokeHubAuthorizationSuite) holdSessionExpiryCleanup() (func(), time.Duration) {
	const deploymentName = "breakglass-manager"
	const deploymentNamespace = "breakglass-system"
	const cleanupEnv = "CLEANUP_INTERVAL"

	var deployment appsv1.Deployment
	err := s.hubClient.Get(s.ctx, client.ObjectKey{Namespace: deploymentNamespace, Name: deploymentName}, &deployment)
	s.Require().NoError(err, "hard-expiry proof requires the breakglass controller deployment")

	original := deployment.DeepCopy()
	patched := deployment.DeepCopy()
	found := false
	var originalInterval time.Duration
	for containerIndex := range patched.Spec.Template.Spec.Containers {
		container := &patched.Spec.Template.Spec.Containers[containerIndex]
		containerFound := false
		for envIndex := range container.Env {
			if container.Env[envIndex].Name == cleanupEnv {
				parsed, parseErr := time.ParseDuration(container.Env[envIndex].Value)
				s.Require().NoError(parseErr, "controller cleanup interval must be a valid duration")
				s.Require().Positive(parsed, "controller cleanup interval must be positive")
				originalInterval = parsed
				container.Env[envIndex].Value = "1h"
				found = true
				containerFound = true
			}
		}
		if !containerFound {
			container.Env = append(container.Env, corev1.EnvVar{Name: cleanupEnv, Value: "1h"})
			found = true
		}
	}
	s.Require().True(found, "breakglass controller deployment must have a writable cleanup interval")
	s.Require().Positive(originalInterval, "breakglass controller deployment must expose its cleanup cadence")
	s.Require().NoError(s.hubClient.Update(s.ctx, patched), "pause cleanup loop before expiry boundary")
	s.waitForControllerDeployment(s.ctx, deploymentNamespace, deploymentName, patched.Generation)

	return func() {
		var current appsv1.Deployment
		if err := s.hubClient.Get(context.Background(), client.ObjectKey{Namespace: deploymentNamespace, Name: deploymentName}, &current); err != nil {
			s.T().Logf("cleanup-loop restore skipped: controller deployment unavailable: %v", err)
			return
		}
		current.Spec.Template.Spec.Containers = original.Spec.Template.Spec.Containers
		if err := s.hubClient.Update(context.Background(), &current); err != nil {
			s.T().Logf("cleanup-loop restore failed: %v", err)
			return
		}
		s.waitForControllerDeployment(context.Background(), deploymentNamespace, deploymentName, current.Generation)
	}, originalInterval
}

func (s *SpokeHubAuthorizationSuite) waitForControllerDeployment(ctx context.Context, namespace, name string, generation int64) {
	s.Require().Eventually(func() bool {
		var deployment appsv1.Deployment
		if err := s.hubClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &deployment); err != nil {
			return false
		}
		return deployment.Generation >= generation &&
			deployment.Status.ObservedGeneration >= generation &&
			deployment.Status.ReadyReplicas >= 1 &&
			deployment.Status.UpdatedReplicas >= 1
	}, 2*time.Minute, 500*time.Millisecond, "controller deployment %s/%s did not become ready for generation %d", namespace, name, generation)
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
	session, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-pods-reader",
		Reason:  "E2E Test - Complete user journey - investigating pod issues",
	}, helpers.WaitForStateTimeout)
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

// TestRevokedSessionRemovesSpokeAccess verifies that an approved session is
// removed from the hub webhook's selection path when an approver cancels it.
// This is a new cross-cluster lifecycle assertion rather than a defect-fix
// test: it exercises the real API, cache, webhook and tenant apiserver wiring.
func (s *SpokeHubAuthorizationSuite) TestRevokedSessionRemovesSpokeAccess() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.MultiClusterTestUsers.Employee

	t.Log("=== Test: Revoking an approved session removes spoke access ===")
	userToken := s.mcCtx.GetEmployeeToken(t, s.ctx)
	userAPI := helpers.NewAPIClientWithAuth(userToken)
	userAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	userAPI = userAPI.WithCleanupClient(s.hubClient, s.namespace)

	session, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-read-only",
		Reason:  "E2E Test - approved session revocation removes spoke access",
	}, helpers.WaitForStateTimeout)
	s.Require().NoError(err, "session should be created through the management API")
	s.cleanup.Add(session)

	s.Require().NoError(
		s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace),
		"approver should approve the session through the management API",
	)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	kubeconfig := s.getOIDCKubeconfig(spokeCluster)
	output, err := s.runKubectlWithToken(kubeconfig, userToken, "get", "pods", "-n", "default")
	s.Require().NoError(err, "approved session should allow spoke access: %s", output)

	s.Require().NoError(
		s.approverAPI.CancelSessionViaAPI(s.ctx, t, session.Name, session.Namespace),
		"approver should cancel the approved session through the management API",
	)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.SessionStateExpired, helpers.WaitForStateTimeout)

	var deniedOutput string
	require.Eventually(t, func() bool {
		var requestErr error
		deniedOutput, requestErr = s.runKubectlWithToken(kubeconfig, userToken, "get", "pods", "-n", "default")
		return requestErr != nil &&
			(strings.Contains(deniedOutput, "forbidden") || strings.Contains(deniedOutput, "Forbidden"))
	}, 30*time.Second, helpers.PollInterval, "cancelled session must no longer allow spoke access")
	t.Logf("Revoked-session authorization response: %s", strings.TrimSpace(deniedOutput))
	t.Log("=== Session revocation removed spoke access as expected ===")
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
	session, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeA,
		User:    testUser.Email,
		Group:   "breakglass-pods-admin",
		Reason:  "E2E Test - Cluster scope verification",
	}, helpers.WaitForStateTimeout)
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
	session, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-limited-access",
		Reason:  "E2E Test - DenyPolicy enforcement verification",
	}, helpers.WaitForStateTimeout)
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
// Uses: SchedulingTestRequester with breakglass-pods-admin group
//
// User Flow:
// 1. User requests a 60-second session and it is approved
// 2. User CAN access resources initially
// 3. The test reads the persisted expiresAt and waits for that boundary
// 4. User CANNOT access resources anymore
//
// This is deliberately a real-time expiry proof: it does not rewrite status to
// manufacture an expired object, and the spoke apiserver has positive webhook
// authorization caching disabled by kind-setup-multi.sh.
func (s *SpokeHubAuthorizationSuite) TestExpiredSessionDenied() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.SchedulingTestRequester
	const streamPodName = "hard-expiry-stream"

	t.Log("=== Test: Expired Session Access Denial ===")
	t.Logf("Using user: %s", testUser.Email)

	// Create API client for this specific user
	userAPI := s.createAPIClientForUser(testUser)
	token := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	kubeconfig := s.mcCtx.GetSpokeOIDCKubeconfig(spokeCluster)
	s.Require().NotEmpty(kubeconfig, "hard-expiry proof requires the OIDC-only spoke kubeconfig")

	// Establish the denied baseline using the exact request and identity that
	// will be used after approval. The OIDC-only kubeconfig prevents an admin
	// client certificate from bypassing the webhook under test.
	baselineOutput, baselineErr := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().Error(baselineErr, "access must be denied before the session exists: %s", baselineOutput)
	s.Require().Contains(strings.ToLower(baselineOutput), "forbidden", "baseline denial must come from Kubernetes authorization: %s", baselineOutput)

	// Create a workload with an administrator-only fixture client. All requests
	// under test continue to use the OIDC-only kubeconfig above, so no client
	// certificate or ambient RBAC permission can mask the webhook decision.
	adminKubeconfig := s.mcCtx.GetSpokeKubeconfig(spokeCluster)
	s.Require().NotEmpty(adminKubeconfig, "hard-expiry stream fixture requires the spoke administrator kubeconfig")
	fixtureArgs := []string{
		"-n", "default", "run", streamPodName,
		"--image=busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662", "--restart=Never", "--command", "--",
		"sh", "-c", "while true; do echo hard-expiry-heartbeat; sleep 1; done",
	}
	fixtureOutput, fixtureErr := s.runKubectlWithKubeconfig(s.ctx, adminKubeconfig, fixtureArgs...)
	s.Require().NoError(fixtureErr, "administrator fixture pod must be created: %s", fixtureOutput)
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, cleanupErr := s.runKubectlWithKubeconfig(cleanupCtx, adminKubeconfig,
			"-n", "default", "delete", "pod", streamPodName, "--ignore-not-found=true")
		if cleanupErr != nil {
			t.Logf("stream fixture cleanup failed: %v", cleanupErr)
		}
	}()
	waitOutput, waitErr := s.runKubectlWithKubeconfig(s.ctx, adminKubeconfig,
		"-n", "default", "wait", "--for=condition=Ready", "pod/"+streamPodName, "--timeout=60s")
	s.Require().NoError(waitErr, "administrator fixture pod must become ready: %s", waitOutput)

	// Create a normal session via API
	t.Log("Step 1: Creating session via API")
	session, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster:  spokeCluster,
		User:     testUser.Email,
		Group:    "breakglass-pods-admin",
		Reason:   "E2E Test - Session expiry verification",
		Duration: 60,
	}, helpers.WaitForStateTimeout)
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

	// Read the server-persisted lease after approval. Never infer the deadline
	// from the request duration: controller/API processing consumes part of it.
	persisted := &breakglassv1alpha1.BreakglassSession{}
	s.Require().Eventually(func() bool {
		if err := s.hubClient.Get(s.ctx, client.ObjectKeyFromObject(session), persisted); err != nil {
			return false
		}
		return persisted.Status.State == breakglassv1alpha1.SessionStateApproved && !persisted.Status.ExpiresAt.IsZero()
	}, 30*time.Second, 500*time.Millisecond, "approved session must persist a non-zero expiresAt")
	expiresAt := persisted.Status.ExpiresAt.Time
	s.Require().True(expiresAt.After(time.Now()), "persisted expiresAt must initially be in the future")

	// Quick check - should be allowed initially
	t.Log("Step 3: User accesses cluster immediately - should succeed")
	output1, err1 := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(err1, "Initial access must be allowed before expiresAt: %s", output1)
	t.Log("✓ Initial access: ALLOWED")

	// Hold periodic cleanup while this test crosses the boundary. The webhook
	// remains available, but the session stays Approved for the immediate
	// post-boundary status-admission proof; natural terminalization is checked
	// after the original cleanup interval is restored.
	restoreCleanup, cleanupInterval := s.holdSessionExpiryCleanup()
	restoredCleanup := false
	defer func() {
		if !restoredCleanup {
			restoreCleanup()
		}
	}()

	// Start one native exec stream while the lease is still live. Kubernetes
	// does not provide a revocation hook for an already-established exec,
	// attach, logs or port-forward stream; this lane characterizes that
	// limitation while all new requests below are required to deny at the hard
	// boundary. The stream handshake reads a response before the deadline, and
	// the post-boundary heartbeat proves the same bidirectional stream remains
	// established rather than merely observing a still-running kubectl process.
	const streamLead = 8 * time.Second
	for time.Until(expiresAt.Add(-streamLead)) > 0 {
		remaining := time.Until(expiresAt.Add(-streamLead))
		if remaining > time.Second {
			remaining = time.Second
		}
		select {
		case <-s.ctx.Done():
			s.Require().FailNow("test context cancelled while preparing the pre-boundary native stream")
		case <-time.After(remaining):
		}
	}
	streamCtx, streamCancel := context.WithCancel(s.ctx)
	streamCmd := s.newLongLivedKubectlWithToken(streamCtx, kubeconfig, token,
		"exec", "-i", streamPodName, "--", "sh", "-c", "while IFS= read -r line; do printf 'ack:%s\\n' \"$line\"; done")
	streamStdin, err := streamCmd.StdinPipe()
	s.Require().NoError(err, "pre-boundary exec stream must provide stdin")
	streamStdout, err := streamCmd.StdoutPipe()
	s.Require().NoError(err, "pre-boundary exec stream must provide stdout")
	streamCmd.Stderr = io.Discard
	streamStartedAt := time.Now()
	s.Require().NoError(streamCmd.Start(), "pre-boundary exec stream must start")
	streamDone := make(chan error, 1)
	go func() { streamDone <- streamCmd.Wait() }()
	streamReader := bufio.NewReader(streamStdout)
	readHeartbeat := func(expected, phase string) {
		response := make(chan struct {
			line string
			err  error
		}, 1)
		go func() {
			line, readErr := streamReader.ReadString('\n')
			response <- struct {
				line string
				err  error
			}{line: line, err: readErr}
		}()
		select {
		case result := <-response:
			s.Require().NoError(result.err, "%s stream heartbeat read failed", phase)
			s.Require().Equal("ack:"+expected+"\n", result.line, "%s stream heartbeat mismatch", phase)
		case <-time.After(2 * time.Second):
			s.Require().FailNow("timed out waiting for %s stream heartbeat", phase)
		}
	}
	_, err = io.WriteString(streamStdin, "before-expiry\n")
	s.Require().NoError(err, "pre-boundary exec stream must accept its first heartbeat")
	streamAcceptedAt := time.Now()
	readHeartbeat("before-expiry", "pre-boundary")
	streamHandshakeCompletedAt := time.Now()
	s.Require().True(streamAcceptedAt.Before(expiresAt) && streamHandshakeCompletedAt.Before(expiresAt),
		"pre-boundary exec stream handshake must complete before expiresAt: accepted=%s completed=%s expires=%s",
		streamAcceptedAt, streamHandshakeCompletedAt, expiresAt)
	select {
	case streamErr := <-streamDone:
		streamCancel()
		s.Require().NoError(streamErr, "pre-boundary exec stream must remain established after its handshake")
	case <-time.After(750 * time.Millisecond):
		// The explicit heartbeat above, rather than process liveness, proves the
		// stream was accepted before the boundary.
	}
	defer func() {
		_ = streamStdin.Close()
		streamCancel()
		select {
		case <-streamDone:
		case <-time.After(5 * time.Second):
			_ = streamCmd.Process.Kill()
			<-streamDone
		}
	}()

	// Probe the exact same OIDC request every 150ms from T-3s through T+3s.
	// Requests that straddle the boundary are deliberately unclassified; every
	// request that starts at or after the boundary must be denied.
	const probeWindow = 3 * time.Second
	const probeInterval = 150 * time.Millisecond
	t.Logf("Step 4: Probing persisted expiresAt boundary (%s)", expiresAt.UTC().Format(time.RFC3339Nano))
	for time.Until(expiresAt.Add(-probeWindow)) > 0 {
		remaining := time.Until(expiresAt.Add(-probeWindow))
		if remaining > time.Second {
			remaining = time.Second
		}
		select {
		case <-s.ctx.Done():
			s.Require().FailNow("test context cancelled while waiting for the expiry probe window")
		case <-time.After(remaining):
		}
	}

	var preBoundaryAllows, postBoundaryDenials, probes int
	resurrectionAttempted := false
	var beforeResurrectionUID string
	for time.Now().Before(expiresAt.Add(probeWindow)) {
		probeStart := time.Now()
		probeOutput, probeErr := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
		probeComplete := time.Now()
		probes++
		t.Logf("expiry probe %d: started=%s completed=%s duration=%s result=%v output=%q",
			probes, probeStart.UTC().Format(time.RFC3339Nano), probeComplete.UTC().Format(time.RFC3339Nano),
			probeComplete.Sub(probeStart), probeErr == nil, strings.TrimSpace(probeOutput))

		switch {
		case probeStart.Before(expiresAt) && probeComplete.Before(expiresAt):
			preBoundaryAllows++
			s.Require().NoError(probeErr, "request completed before expiresAt but was denied (started %s, completed %s): %s", probeStart, probeComplete, probeOutput)
		case !probeStart.Before(expiresAt):
			postBoundaryDenials++
			s.Require().Error(probeErr, "request started at/after expiresAt must be denied immediately (started %s, expires %s): %s", probeStart, expiresAt, probeOutput)
			s.Require().Less(probeComplete.Sub(probeStart), 5*time.Second, "post-boundary denial must return before the kubectl request timeout")
			s.Require().True(strings.Contains(strings.ToLower(probeOutput), "forbidden") || strings.Contains(strings.ToLower(probeOutput), "denied"),
				"post-boundary denial should be reported as forbidden, got: %s", probeOutput)

			if postBoundaryDenials == 1 {
				// Exercise fresh authorization requests for each native pod
				// subresource immediately after the boundary. These must all
				// deny even though the pre-boundary exec stream remains open.
				s.requireFreshSubresourceDenials(kubeconfig, token, streamPodName)
				// Keep the native stream open beyond the old five-second kubectl
				// request timeout before sending the second heartbeat. This proves
				// the dedicated long-lived helper really has no inherited timeout.
				streamProofAt := streamStartedAt.Add(7 * time.Second)
				postHeartbeatAt := expiresAt.Add(2 * time.Second)
				if postHeartbeatAt.Before(streamProofAt) {
					postHeartbeatAt = streamProofAt
				}
				if delay := time.Until(postHeartbeatAt); delay > 0 {
					select {
					case <-s.ctx.Done():
						s.Require().FailNow("test context cancelled while proving the long-lived stream")
					case <-time.After(delay):
					}
				}
				select {
				case streamErr := <-streamDone:
					s.Require().NoError(streamErr, "a native exec stream established before expiry should remain open across expiry")
				default:
					_, err = io.WriteString(streamStdin, "after-expiry\n")
					s.Require().NoError(err, "pre-boundary exec stream must accept a heartbeat after expiry")
					readHeartbeat("after-expiry", "post-boundary")
					streamHeartbeatAt := time.Now()
					s.Require().GreaterOrEqual(streamHeartbeatAt.Sub(streamStartedAt), 7*time.Second,
						"post-boundary heartbeat must be beyond the legacy five-second kubectl timeout")
					t.Logf("pre-boundary native exec stream remains bidirectional after expiry (Kubernetes stream limitation); age=%s", streamHeartbeatAt.Sub(streamStartedAt))
				}
			}

			// The status webhook is part of the same hard-expiry boundary. This
			// happens on the first post-boundary request while cleanup is paused,
			// so the stored object is provably still Approved.
			if !resurrectionAttempted {
				resurrectionAttempted = true
				var current breakglassv1alpha1.BreakglassSession
				s.Require().NoError(s.hubClient.Get(s.ctx, client.ObjectKeyFromObject(session), &current))
				s.Require().Equal(breakglassv1alpha1.SessionStateApproved, current.Status.State,
					"the first post-boundary resurrection attempt must target the still-Approved persisted session")
				beforeResurrectionUID = string(current.UID)
				beforeResurrectionState := current.Status.State
				beforeResurrectionExpiry := current.Status.ExpiresAt.Time
				resurrection := current.DeepCopy()
				resurrection.Status.ExpiresAt = metav1.NewTime(expiresAt.Add(time.Hour))
				resurrectionErr := s.hubClient.Status().Update(s.ctx, resurrection)
				s.Require().Error(resurrectionErr, "status future-expiry write after the boundary must be rejected")
				s.Require().True(apierrors.IsInvalid(resurrectionErr), "future-expiry status write must be an admission validation error: %v", resurrectionErr)

				var afterRejectedWrite breakglassv1alpha1.BreakglassSession
				s.Require().NoError(s.hubClient.Get(s.ctx, client.ObjectKeyFromObject(session), &afterRejectedWrite))
				s.Require().Equal(beforeResurrectionUID, string(afterRejectedWrite.UID), "rejected status write must not replace the session object")
				s.Require().Equal(beforeResurrectionState, afterRejectedWrite.Status.State, "rejected status write must not change terminal state")
				s.Require().Equal(beforeResurrectionExpiry, afterRejectedWrite.Status.ExpiresAt.Time,
					"rejected status write must leave the persisted expiry unchanged")
			}
			// A request that starts before expiry but completes after it is a
			// straddler. It is intentionally not classified by this proof.
		}

		nextProbe := probeStart.Add(probeInterval)
		if delay := time.Until(nextProbe); delay > 0 {
			select {
			case <-s.ctx.Done():
				s.Require().FailNow("test context cancelled while probing the expiry boundary")
			case <-time.After(delay):
			}
		}
	}
	s.Require().Greater(probes, 0, "expiry probe loop must execute at least once")
	s.Require().Greater(preBoundaryAllows, 0, "expiry probe loop must observe an allowed request completed before the boundary")
	s.Require().Greater(postBoundaryDenials, 0, "expiry probe loop must observe an immediate denial starting at/after the boundary")
	s.Require().True(resurrectionAttempted, "expiry probe loop must attempt post-boundary status resurrection while Approved")

	// Restore the normal cleanup interval and separately prove controller-owned
	// terminalization. This is intentionally after the immediate status proof.
	restoreCleanup()
	restoredCleanup = true

	// Only after the immediate rejected write has been checked do we wait for
	// the controller to record its normal terminal state.
	s.waitForSessionExpiredAfterCleanup(session, cleanupInterval)
	var terminal breakglassv1alpha1.BreakglassSession
	s.Require().NoError(s.hubClient.Get(s.ctx, client.ObjectKeyFromObject(session), &terminal))
	s.Require().Equal(beforeResurrectionUID, string(terminal.UID), "expiry cleanup must not replace the session object")
	s.Require().Equal(breakglassv1alpha1.SessionStateExpired, terminal.Status.State,
		"a rejected post-boundary status write must not prevent terminal expiry")
	output3, err3 := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().Error(err3, "access must remain denied after rejected resurrection write: %s", output3)
	s.Require().True(strings.Contains(output3, "forbidden") || strings.Contains(output3, "Forbidden") || strings.Contains(output3, "denied"),
		"continued denial should be reported as forbidden after rejected resurrection write, got: %s", output3)
	t.Log("✓ Access after expiry: DENIED")

	// Restoring CLEANUP_INTERVAL rolls the controller Deployment and briefly
	// removes the service endpoint. The focused lane keeps the API port-forward
	// alive across that rollout, but the restart window is still observable to a
	// client. Wait for a real API response before the next suite test starts, so
	// an expected rollout gap cannot masquerade as an API failure.
	s.Require().NoError(s.approverAPI.WaitForAPIReady(s.ctx, 60*time.Second),
		"hub API must be ready after restoring the controller deployment")

	t.Log("=== Expired Session Test Passed! ===")
}

// TestHardExpiryMultipleIndependentSessions is reserved for the focused hard-
// expiry CI lane. Keeping the gate here prevents the regular 1.36 suite from
// duplicating this deliberately time-bound authorization proof.
//
// Two different session groups authorize the same request. Once the shorter
// lease has elapsed, access must remain allowed through the still-live second
// candidate; once both leases have elapsed, the same OIDC request must deny.
func (s *SpokeHubAuthorizationSuite) TestHardExpiryMultipleIndependentSessions() {
	if os.Getenv("E2E_HARD_EXPIRY") != "true" {
		s.T().Skip("focused hard-expiry lane only")
	}
	t := s.T()
	s.Require().NoError(s.approverAPI.WaitForAPIReady(s.ctx, 60*time.Second),
		"hub API must be ready before creating independent hard-expiry sessions")
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	testUser := helpers.TestUsers.SchedulingTestRequester
	userAPI := s.createAPIClientForUser(testUser)
	token := s.mcCtx.GetTokenForTestUser(t, s.ctx, testUser)
	kubeconfig := s.mcCtx.GetSpokeOIDCKubeconfig(spokeCluster)
	s.Require().NotEmpty(kubeconfig, "independent-session proof requires the OIDC-only spoke kubeconfig")

	short, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster, User: testUser.Email, Group: "breakglass-read-only",
		Reason: "Focused hard-expiry proof - first independent lease", Duration: 60,
	}, helpers.WaitForStateTimeout)
	s.Require().NoError(err)
	s.cleanup.Add(short)
	long, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster, User: testUser.Email, Group: "breakglass-pods-reader",
		Reason: "Focused hard-expiry proof - second independent lease", Duration: 90,
	}, helpers.WaitForStateTimeout)
	s.Require().NoError(err)
	s.cleanup.Add(long)

	for _, session := range []*breakglassv1alpha1.BreakglassSession{short, long} {
		s.Require().NoError(s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace))
		helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
			breakglassv1alpha1.SessionStateApproved, 30*time.Second)
	}

	var shortLive, longLive breakglassv1alpha1.BreakglassSession
	s.Require().NoError(s.hubClient.Get(s.ctx, client.ObjectKeyFromObject(short), &shortLive))
	s.Require().NoError(s.hubClient.Get(s.ctx, client.ObjectKeyFromObject(long), &longLive))
	s.Require().True(shortLive.Status.ExpiresAt.Time.Before(longLive.Status.ExpiresAt.Time),
		"independent leases must have staggered persisted deadlines: short=%s long=%s",
		shortLive.Status.ExpiresAt.Time, longLive.Status.ExpiresAt.Time)
	s.Require().Greater(longLive.Status.ExpiresAt.Sub(shortLive.Status.ExpiresAt.Time), 5*time.Second,
		"staggered deadlines must leave an unambiguous second-session window")

	initialOutput, initialErr := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(initialErr, "same request must be allowed while both sessions are live: %s", initialOutput)

	wait := time.Until(shortLive.Status.ExpiresAt.Time) + 250*time.Millisecond
	if wait > 0 {
		select {
		case <-s.ctx.Done():
			s.Require().FailNow("context cancelled while waiting for first independent lease")
		case <-time.After(wait):
		}
	}
	firstExpiredOutput, firstExpiredErr := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(firstExpiredErr,
		"the still-live independent session must preserve access after the first expiry: %s", firstExpiredOutput)

	wait = time.Until(longLive.Status.ExpiresAt.Time) + 250*time.Millisecond
	if wait > 0 {
		select {
		case <-s.ctx.Done():
			s.Require().FailNow("context cancelled while waiting for second independent lease")
		case <-time.After(wait):
		}
	}
	finalOutput, finalErr := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().Error(finalErr, "same request must be denied after both independent leases expire: %s", finalOutput)
	s.Require().Contains(strings.ToLower(finalOutput), "forbidden",
		"final denial must be an authorization denial: %s", finalOutput)
}

// TestRetiredEphemeralAdmissionRouteAndAPIMediatedInjection proves the
// replacement for the retired direct admission endpoint using a real hub API,
// target-cluster API, and an actual ephemeral-container subresource update.
// The direct route must be unavailable, while the authenticated
// DebugSession-mediated operation must persist both the target mutation and
// session evidence. Once the lease reaches its persisted expiry boundary, the
// same operation must fail closed and must not mutate the target Pod.
//
// This deliberately runs only in the focused hard-expiry lane. The regular
// multicluster suite already exercises the general API and webhook flows, and
// this test waits for a real short-lived lease boundary.
func (s *SpokeHubAuthorizationSuite) TestRetiredEphemeralAdmissionRouteAndAPIMediatedInjection() {
	if os.Getenv("E2E_HARD_EXPIRY") != "true" {
		s.T().Skip("focused hard-expiry lane only")
	}

	t := s.T()
	ctx := s.ctx
	spokeCluster := s.mcCtx.Config.SpokeAClusterName
	user := helpers.TestUsers.DebugSessionRequester
	allowRenewal := false

	// The old endpoint accepted AdmissionReview traffic independently of the
	// authenticated DebugSession API. Its retirement is proved behaviorally by
	// posting a real AdmissionReview-shaped request and requiring an HTTP 404.
	webhookURL := strings.TrimRight(s.mcCtx.Config.HubWebhookURL, "/")
	admissionReview := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"hard-expiry-retired-route","operation":"UPDATE","resource":{"group":"","version":"v1","resource":"pods"},"object":{},"oldObject":{}}}`
	routeCmd := exec.CommandContext(ctx, "curl", "-k", "-sS", "-X", "POST",
		"-H", "Content-Type: application/json", "--data", admissionReview,
		"-o", "/dev/null", "-w", "%{http_code}", webhookURL+"/api/breakglass/webhook/validate-ephemeral-containers")
	routeOutput, routeErr := routeCmd.Output()
	s.Require().NoError(routeErr, "retired ephemeral admission route probe must complete")
	s.Require().Equal("404", strings.TrimSpace(string(routeOutput)),
		"retired /validate-ephemeral-containers must be unavailable")

	// Use an administrator kubeconfig only for the target fixture and
	// observation. All Breakglass operations below use the authenticated API
	// client, so target-cluster administrator RBAC cannot mask the API flow.
	spokeConfig, err := clientcmd.BuildConfigFromFlags("", s.mcCtx.Config.SpokeAKubeconfig)
	s.Require().NoError(err, "spoke administrator kubeconfig must be usable")
	spokeClient, err := client.New(spokeConfig, client.Options{Scheme: scheme.Scheme})
	s.Require().NoError(err, "spoke administrator client must be usable")

	targetPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      helpers.GenerateUniqueName("hard-expiry-ephemeral-target"),
			Namespace: "default",
			Labels:    map[string]string{"e2e-test": "hard-expiry-ephemeral"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
				Command: []string{"sh", "-c", "while true; do sleep 1; done"},
			}},
		},
	}
	s.Require().NoError(spokeClient.Create(ctx, targetPod), "target fixture pod must be created")
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if cleanupErr := spokeClient.Delete(cleanupCtx, targetPod); cleanupErr != nil && !apierrors.IsNotFound(cleanupErr) {
			t.Logf("ephemeral target cleanup failed: %v", cleanupErr)
		}
	}()
	s.Require().NoError(helpers.WaitForPodReady(ctx, spokeClient, targetPod.Namespace, targetPod.Name, 90*time.Second), "target fixture pod must become ready")

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: helpers.GenerateUniqueName("hard-expiry-ephemeral-template"),
		},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName:     "Hard-expiry API-mediated ephemeral-container proof",
			Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
			TargetNamespace: "default",
			KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
				EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled:           true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"default"}},
					AllowedImages:     []string{"busybox:*"},
					RequireNonRoot:    true,
				},
			},
			Allowed: &breakglassv1alpha1.DebugSessionAllowed{
				Clusters: []string{spokeCluster},
				Groups:   []string{"debug-session-test-group"},
			},
			Constraints: &breakglassv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2m",
				DefaultDuration: "2m",
				AllowRenewal:    &allowRenewal,
			},
		},
	}
	s.Require().NoError(s.hubClient.Create(ctx, template), "ephemeral proof template must be created")
	s.cleanup.Add(template)

	userAPI := s.createAPIClientForUser(user)
	session, err := userAPI.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		TemplateRef:       template.Name,
		Cluster:           spokeCluster,
		RequestedDuration: "2m",
		TargetNamespace:   "default",
		Reason:            "Focused hard-expiry proof - API-mediated ephemeral injection",
	})
	s.Require().NoError(err, "debug session must be created through the authenticated API")
	s.cleanup.Add(session)
	session = helpers.WaitForDebugSessionState(t, ctx, s.hubClient, session.Name, session.Namespace,
		breakglassv1alpha1.DebugSessionStateActive, 90*time.Second)

	image := "busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
	containerName := "hard-expiry-debug"
	runAsNonRoot := true
	s.Require().NoError(userAPI.InjectEphemeralContainer(ctx, t, session.Name, helpers.EphemeralContainerRequest{
		Namespace:     targetPod.Namespace,
		PodName:       targetPod.Name,
		ContainerName: containerName,
		Image:         image,
		Command:       []string{"sh", "-c", "sleep 60"},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot: &runAsNonRoot,
		},
	}), "supported API-mediated ephemeral injection must succeed")

	var injectedPod corev1.Pod
	s.Require().Eventually(func() bool {
		if getErr := spokeClient.Get(ctx, client.ObjectKeyFromObject(targetPod), &injectedPod); getErr != nil {
			return false
		}
		for _, container := range injectedPod.Spec.EphemeralContainers {
			if container.Name == containerName && container.Image == image {
				return true
			}
		}
		return false
	}, 60*time.Second, 500*time.Millisecond, "target API must persist the requested ephemeral container")

	var persisted breakglassv1alpha1.DebugSession
	s.Require().Eventually(func() bool {
		if getErr := s.hubClient.Get(ctx, client.ObjectKeyFromObject(session), &persisted); getErr != nil || persisted.Status.KubectlDebugStatus == nil {
			return false
		}
		for _, ref := range persisted.Status.KubectlDebugStatus.EphemeralContainersInjected {
			if ref.Namespace == targetPod.Namespace && ref.PodName == targetPod.Name && ref.ContainerName == containerName && ref.Image == image && ref.InjectedBy != "" {
				return true
			}
		}
		return false
	}, 60*time.Second, 500*time.Millisecond, "session status must persist evidence for the target mutation")
	s.Require().NotNil(persisted.Status.ExpiresAt, "session must persist its lease deadline")

	if wait := time.Until(persisted.Status.ExpiresAt.Time) + 500*time.Millisecond; wait > 0 {
		select {
		case <-ctx.Done():
			s.Require().FailNow("context cancelled while waiting for the debug-session expiry boundary")
		case <-time.After(wait):
		}
	}

	// The same authenticated operation must fail after the persisted boundary,
	// regardless of whether periodic cleanup has already terminalized the CR.
	err = userAPI.InjectEphemeralContainer(ctx, t, session.Name, helpers.EphemeralContainerRequest{
		Namespace:     targetPod.Namespace,
		PodName:       targetPod.Name,
		ContainerName: "hard-expiry-after-boundary",
		Image:         image,
		Command:       []string{"sh", "-c", "sleep 60"},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot: &runAsNonRoot,
		},
	})
	s.Require().Error(err, "API-mediated ephemeral injection must fail closed after expiresAt")

	var afterExpiry corev1.Pod
	s.Require().NoError(spokeClient.Get(ctx, client.ObjectKeyFromObject(targetPod), &afterExpiry), "target pod must remain observable after denied operation")
	for _, container := range afterExpiry.Spec.EphemeralContainers {
		s.Require().NotEqual("hard-expiry-after-boundary", container.Name,
			"a denied post-expiry operation must not mutate the target Pod")
	}
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
	session, err := userAPI.CreateSessionAndWaitForPending(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    testUser.Email,
		Group:   "breakglass-emergency-admin",
		Reason:  "E2E Test - Multi-user session isolation",
	}, helpers.WaitForStateTimeout)
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
// flag for authentication. This is required for testing OIDC-based authorization flows;
// callers must not fall back to an administrator client certificate.
func (s *SpokeHubAuthorizationSuite) getOIDCKubeconfig(clusterName string) string {
	return s.mcCtx.GetSpokeOIDCKubeconfig(clusterName)
}

func (s *SpokeHubAuthorizationSuite) runKubectlWithToken(kubeconfig, token string, args ...string) (string, error) {
	return s.runKubectlWithTokenContext(s.ctx, kubeconfig, token, args...)
}

func (s *SpokeHubAuthorizationSuite) runKubectlWithTokenContext(ctx context.Context, kubeconfig, token string, args ...string) (string, error) {
	cmd := s.newKubectlWithToken(ctx, kubeconfig, token, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *SpokeHubAuthorizationSuite) runKubectlWithKubeconfig(ctx context.Context, kubeconfig string, args ...string) (string, error) {
	fullArgs := append([]string{"--kubeconfig", kubeconfig, "--request-timeout=5s"}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", fullArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *SpokeHubAuthorizationSuite) newKubectlWithToken(ctx context.Context, kubeconfig, token string, args ...string) *exec.Cmd {
	fullArgs := append([]string{
		"--kubeconfig", kubeconfig,
		"--token", token,
		"--request-timeout=5s",
	}, args...)
	return exec.CommandContext(ctx, "kubectl", fullArgs...)
}

// newLongLivedKubectlWithToken starts a native Kubernetes stream without a
// request timeout. The caller owns its lifetime through ctx and must arrange
// explicit cleanup. This is intentionally separate from ordinary requests,
// which retain the five-second timeout to keep authorization probes bounded.
func (s *SpokeHubAuthorizationSuite) newLongLivedKubectlWithToken(ctx context.Context, kubeconfig, token string, args ...string) *exec.Cmd {
	fullArgs := append([]string{
		"--kubeconfig", kubeconfig,
		"--token", token,
	}, args...)
	return exec.CommandContext(ctx, "kubectl", fullArgs...)
}

// waitForSessionExpiredAfterCleanup waits for the controller's normal cleanup
// loop after its deployment rollout has become ready. The bound is derived
// from the actual configured cadence, and each poll reads the live object so a
// timeout reports the last observed state and expiry instead of hiding a
// controller or rollout failure behind a fixed sleep.
func (s *SpokeHubAuthorizationSuite) waitForSessionExpiredAfterCleanup(session *breakglassv1alpha1.BreakglassSession, cleanupInterval time.Duration) {
	timeout := 3*cleanupInterval + 30*time.Second
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	var last breakglassv1alpha1.BreakglassSession
	var lastErr error
	s.Require().Eventually(func() bool {
		lastErr = s.hubClient.Get(ctx, client.ObjectKeyFromObject(session), &last)
		if lastErr != nil {
			return false
		}
		return last.Status.State == breakglassv1alpha1.SessionStateExpired
	}, timeout, 500*time.Millisecond,
		"session %s did not reach Expired after restored cleanup cadence %s (last state=%q expiresAt=%s retainedUntil=%s error=%v)",
		session.Name, cleanupInterval, last.Status.State, last.Status.ExpiresAt.Time.UTC().Format(time.RFC3339Nano),
		last.Status.RetainedUntil.Time.UTC().Format(time.RFC3339Nano), lastErr)
}

// requireFreshSubresourceDenials checks the requests that can create or open
// native Kubernetes pod streams. Each command is started only after the
// session deadline and has a bounded context, so an accidentally allowed
// streaming request cannot hang the focused lane.
func (s *SpokeHubAuthorizationSuite) requireFreshSubresourceDenials(kubeconfig, token, podName string) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "pods/exec", args: []string{"exec", podName, "--", "true"}},
		{name: "pods/attach", args: []string{"attach", podName, "--stdin=false", "--tty=false"}},
		{name: "pods/portforward", args: []string{"port-forward", "pod/" + podName, "18080:80"}},
		{name: "pods/log", args: []string{"logs", "-f", podName, "--tail=1"}},
	}
	for _, tc := range cases {
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		output, err := s.runKubectlWithTokenContext(ctx, kubeconfig, token, tc.args...)
		cancel()
		lowerOutput := strings.ToLower(output)
		s.Require().Error(err, "%s started after expiry must be denied: %s", tc.name, output)
		s.Require().True(strings.Contains(lowerOutput, "forbidden") || strings.Contains(lowerOutput, "denied"),
			"%s must return an authorization denial, got: %s", tc.name, output)
	}
}
