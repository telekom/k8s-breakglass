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
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

func init() {
	_ = telekomv1alpha1.AddToScheme(scheme.Scheme)
}

// MultiIDPAuthorizationSuite tests authorization flows with multiple identity providers.
//
// This suite simulates real user interactions with multiple IDPs:
// 1. Employee users authenticate with the main Keycloak realm → get OIDC token
// 2. Contractor users authenticate with the contractors realm → get different OIDC token
// 3. Users create/approve sessions via API using their tokens
// 4. IDP restrictions on BreakglassEscalation are enforced
//
// Tests verify:
// - Employee users (main realm) can access employee-only clusters
// - Contractor users (contractors realm) are denied on employee-only clusters
// - Contractor users can access clusters that allow contractors
// - Session creation with wrong IDP is rejected
type MultiIDPAuthorizationSuite struct {
	suite.Suite
	ctx       context.Context
	cancel    context.CancelFunc
	hubClient client.Client
	mcCtx     *helpers.MultiClusterTestContext
	cleanup   *helpers.Cleanup
	namespace string

	// API clients for realistic user flows
	employeeAPI   *helpers.APIClient
	approverAPI   *helpers.APIClient
	contractorAPI *helpers.APIClient
}

func TestMultiIDPAuthorizationSuite(t *testing.T) {
	if !helpers.IsMultiClusterEnabled() {
		t.Skip("Multi-cluster tests disabled. Set E2E_MULTI_CLUSTER=true to enable.")
	}
	suite.Run(t, new(MultiIDPAuthorizationSuite))
}

func (s *MultiIDPAuthorizationSuite) SetupSuite() {
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 30*time.Minute)
	s.mcCtx = helpers.NewMultiClusterTestContext()
	s.namespace = helpers.GetTestNamespace()

	// Validate configuration - all these MUST be set in multi-cluster mode
	s.Require().NotEmpty(s.mcCtx.Config.HubKubeconfig, "E2E_HUB_KUBECONFIG must be set")
	s.Require().NotEmpty(s.mcCtx.Config.SpokeAKubeconfig, "E2E_SPOKE_A_KUBECONFIG must be set")
	s.Require().NotEmpty(s.mcCtx.Config.SpokeBKubeconfig, "E2E_SPOKE_B_KUBECONFIG must be set for contractor tests")
	s.Require().NotEmpty(s.mcCtx.Config.ContractorsRealm, "KEYCLOAK_CONTRACTORS_REALM must be set")
	s.Require().NotEmpty(s.mcCtx.Config.HubAPIURL, "E2E_HUB_API_URL must be set for API-based tests")

	// Create hub client
	hubCfg, err := clientcmd.BuildConfigFromFlags("", s.mcCtx.Config.HubKubeconfig)
	s.Require().NoError(err, "Failed to build hub kubeconfig")
	s.hubClient, err = client.New(hubCfg, client.Options{Scheme: scheme.Scheme})
	s.Require().NoError(err, "Failed to create hub client")

	// Initialize cleanup helper
	s.cleanup = helpers.NewCleanup(s.T(), s.hubClient)

	// Create API clients authenticated as different users/IDPs
	s.setupAuthenticatedAPIClients()
}

func (s *MultiIDPAuthorizationSuite) setupAuthenticatedAPIClients() {
	t := s.T()

	// Employee (main realm) authenticates with Keycloak
	employeeToken := s.mcCtx.GetEmployeeToken(t, s.ctx)
	s.employeeAPI = helpers.NewAPIClientWithAuth(employeeToken)
	s.employeeAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	s.employeeAPI = s.employeeAPI.WithCleanupClient(s.hubClient, s.namespace)
	t.Log("✓ Employee authenticated with main Keycloak realm")

	// Approver (main realm) authenticates with Keycloak
	approverToken := s.mcCtx.GetApproverToken(t, s.ctx)
	s.approverAPI = helpers.NewAPIClientWithAuth(approverToken)
	s.approverAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	t.Log("✓ Approver authenticated with main Keycloak realm")

	// Contractor (contractors realm) authenticates with Keycloak
	contractorToken := s.mcCtx.GetContractorToken(t, s.ctx)
	s.contractorAPI = helpers.NewAPIClientWithAuth(contractorToken)
	s.contractorAPI.BaseURL = s.mcCtx.Config.HubAPIURL
	s.contractorAPI = s.contractorAPI.WithCleanupClient(s.hubClient, s.namespace)
	t.Log("✓ Contractor authenticated with contractors Keycloak realm")
}

func (s *MultiIDPAuthorizationSuite) TearDownSuite() {
	if s.cancel != nil {
		s.cancel()
	}
}

// TestEmployeeAccessEmployeeOnlyCluster verifies that employees using the main IDP
// can access clusters configured for employee access only.
//
// User Flow:
// 1. Employee authenticates with main Keycloak realm → gets OIDC token
// 2. Employee creates breakglass session via API
// 3. Approver approves session via API
// 4. Employee accesses spoke cluster → success
func (s *MultiIDPAuthorizationSuite) TestEmployeeAccessEmployeeOnlyCluster() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName // Assume spoke-a is employee-only

	t.Log("=== Test: Employee Access to Employee-Only Cluster ===")

	// Step 1: Employee creates session via API
	t.Log("Step 1: Employee (main realm) requests access via API")
	session, err := s.employeeAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Employee.Email,
		Group:   "breakglass-employee-access",
		Reason:  "E2E Test: Employee IDP access verification",
	})
	s.Require().NoError(err, "Employee should be able to create session via API")
	s.cleanup.Add(session)
	t.Logf("✓ Session created via API: %s", session.Name)

	// Step 2: Approver approves via API
	t.Log("Step 2: Approver approves session via API")
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session approved")

	// Step 3: Employee accesses cluster
	t.Log("Step 3: Employee accesses spoke cluster with their OIDC token")
	token := s.mcCtx.GetEmployeeToken(t, s.ctx)
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)
	s.Require().NotEmpty(kubeconfig)

	output, err := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(err, "Employee should have access to employee-only cluster: %s", output)
	t.Log("✓ Employee access: ALLOWED")

	t.Log("=== Employee Access Test Passed! ===")
}

// TestContractorDeniedOnEmployeeOnlyCluster verifies that contractors using the contractors IDP
// cannot access clusters that are restricted to employees only.
//
// User Flow:
// 1. Contractor authenticates with contractors Keycloak realm → gets OIDC token
// 2. Contractor attempts to create session via API for employee-only cluster
// 3. API/webhook should reject due to IDP restrictions
func (s *MultiIDPAuthorizationSuite) TestContractorDeniedOnEmployeeOnlyCluster() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName // Assume spoke-a is employee-only

	t.Log("=== Test: Contractor Denied on Employee-Only Cluster ===")

	t.Log("Step 1: Contractor (contractors realm) attempts to request access via API")
	session, err := s.contractorAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Contractor1.Email,
		Group:   "breakglass-employee-access", // Employee-only escalation
		Reason:  "E2E Test: Contractor denied verification",
	})

	// The session creation might be rejected by webhook or API
	if err != nil {
		s.Assert().True(
			strings.Contains(err.Error(), "identity") ||
				strings.Contains(err.Error(), "IDP") ||
				strings.Contains(err.Error(), "not allowed") ||
				strings.Contains(err.Error(), "denied") ||
				strings.Contains(err.Error(), "forbidden"),
			"Error should indicate IDP restriction: %v", err,
		)
		t.Logf("✓ Contractor session creation correctly rejected via API: %v", err)
		return
	}

	// If session was created, clean it up and check if it gets rejected
	s.cleanup.Add(session)
	t.Logf("Note: Session created: %s - checking if it gets rejected by controller", session.Name)

	// Wait for processing
	time.Sleep(5 * time.Second)

	var fetched telekomv1alpha1.BreakglassSession
	fetchErr := s.hubClient.Get(s.ctx, client.ObjectKey{
		Namespace: session.Namespace,
		Name:      session.Name,
	}, &fetched)

	if fetchErr == nil {
		// Session exists - verify it's in a rejected state or verify kubectl fails
		if fetched.Status.State == telekomv1alpha1.SessionStateRejected ||
			fetched.Status.State == telekomv1alpha1.SessionStateTimeout {
			t.Logf("✓ Contractor session correctly rejected with state: %s", fetched.Status.State)
			return
		}

		// If session wasn't auto-rejected, try to use it and verify access is denied
		t.Log("Step 2: Verifying contractor cannot access cluster even if session exists")
		contractorToken := s.mcCtx.GetContractorToken(t, s.ctx)
		kubeconfig := s.getOIDCKubeconfig(spokeCluster)

		output, kubectlErr := s.runKubectlWithToken(kubeconfig, contractorToken, "get", "pods", "-n", "default")
		s.Require().Error(kubectlErr, "Contractor should NOT have access to employee-only cluster")
		t.Logf("✓ Contractor access correctly denied: %s", strings.TrimSpace(output))
	}

	t.Log("=== Contractor Denied Test Passed! ===")
}

// TestContractorAccessContractorCluster verifies that contractors can access clusters
// that are configured to allow the contractors IDP.
//
// User Flow:
// 1. Contractor authenticates with contractors Keycloak realm → gets OIDC token
// 2. Contractor creates session via API for contractor-allowed cluster
// 3. Approver approves via API
// 4. Contractor accesses spoke cluster → success
func (s *MultiIDPAuthorizationSuite) TestContractorAccessContractorCluster() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeBClusterName // Assume spoke-b allows contractors

	// SpokeBKubeconfig is validated in SetupSuite - this should never be empty
	s.Require().NotEmpty(s.mcCtx.Config.SpokeBKubeconfig, "SpokeBKubeconfig must be set")

	t.Log("=== Test: Contractor Access to Contractor-Allowed Cluster ===")

	// Step 1: Contractor creates session via API
	t.Log("Step 1: Contractor (contractors realm) requests access via API")
	session, err := s.contractorAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Contractor1.Email,
		Group:   "breakglass-contractor-access",
		Reason:  "E2E Test: Contractor IDP access verification",
	})
	s.Require().NoError(err, "Contractor should be able to create session for contractor-allowed cluster")
	s.cleanup.Add(session)
	t.Logf("✓ Session created via API: %s", session.Name)

	// Step 2: Approver approves via API
	t.Log("Step 2: Approver approves session via API")
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Session approved")

	// Step 3: Contractor accesses cluster
	t.Log("Step 3: Contractor accesses spoke cluster with their OIDC token")
	token := s.mcCtx.GetContractorToken(t, s.ctx)
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)
	s.Require().NotEmpty(kubeconfig)

	output, err := s.runKubectlWithToken(kubeconfig, token, "get", "pods", "-n", "default")
	s.Require().NoError(err, "Contractor should have access to contractor-allowed cluster: %s", output)
	t.Log("✓ Contractor access: ALLOWED")

	t.Log("=== Contractor Access Test Passed! ===")
}

// TestIDPMismatchDenied verifies that using a token from one IDP while session was created
// with a different IDP is denied.
//
// User Flow:
// 1. Employee creates session via API
// 2. Session is approved
// 3. Contractor attempts to access cluster using their token (wrong IDP)
// 4. Access is denied - token IDP doesn't match session's user
func (s *MultiIDPAuthorizationSuite) TestIDPMismatchDenied() {
	t := s.T()
	spokeCluster := s.mcCtx.Config.SpokeAClusterName

	t.Log("=== Test: IDP Mismatch Denial ===")

	// Step 1: Employee creates session via API
	t.Log("Step 1: Employee creates session via API")
	session, err := s.employeeAPI.CreateSession(s.ctx, t, helpers.SessionRequest{
		Cluster: spokeCluster,
		User:    helpers.MultiClusterTestUsers.Employee.Email,
		Group:   "breakglass-employee-access",
		Reason:  "E2E Test: IDP mismatch verification",
	})
	s.Require().NoError(err)
	s.cleanup.Add(session)

	// Step 2: Approve via API
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStatePending, 30*time.Second)
	err = s.approverAPI.ApproveSessionViaAPI(s.ctx, t, session.Name, session.Namespace)
	s.Require().NoError(err)
	helpers.WaitForSessionState(t, s.ctx, s.hubClient, session.Name, session.Namespace,
		telekomv1alpha1.SessionStateApproved, 30*time.Second)
	t.Log("✓ Employee session approved")

	// Step 3: Contractor tries to use employee's session with their own token
	t.Log("Step 2: Contractor attempts to access cluster (wrong IDP)")
	contractorToken := s.mcCtx.GetContractorToken(t, s.ctx)
	kubeconfig := s.getOIDCKubeconfig(spokeCluster)

	output, err := s.runKubectlWithToken(kubeconfig, contractorToken, "get", "pods", "-n", "default")
	s.Require().Error(err, "Should be denied with mismatched IDP token")
	// The contractor's token is valid (authenticates) but they don't have a session
	// so they should get Forbidden (403) from the authorization webhook, not Unauthorized (401).
	// If we get Unauthorized, it means the spoke apiserver doesn't trust the contractors realm.
	s.Require().True(
		strings.Contains(output, "forbidden") || strings.Contains(output, "Forbidden"),
		"Error should indicate forbidden (403) for IDP mismatch, not unauthorized (401). "+
			"If you see Unauthorized, verify the spoke apiserver trusts the contractors realm. "+
			"Actual output: %s", output,
	)
	t.Logf("✓ IDP mismatch correctly denied: %s", strings.TrimSpace(output))

	t.Log("=== IDP Mismatch Test Passed! ===")
}

// TestMultipleIDPsConfigured verifies that multiple IdentityProviders exist and are configured.
func (s *MultiIDPAuthorizationSuite) TestMultipleIDPsConfigured() {
	t := s.T()

	// List all IdentityProviders (cluster-scoped)
	var idpList telekomv1alpha1.IdentityProviderList
	err := s.hubClient.List(s.ctx, &idpList)
	s.Require().NoError(err, "Should be able to list IdentityProviders")

	// Verify we have at least 2 IDPs configured
	s.Assert().GreaterOrEqual(len(idpList.Items), 2,
		"Should have at least 2 IdentityProviders (main + contractors)")

	// Log the configured IDPs
	for _, idp := range idpList.Items {
		t.Logf("Found IDP: %s (authority: %s)", idp.Name, idp.Spec.OIDC.Authority)
	}

	t.Logf("✓ Multiple IDPs configured: %d total", len(idpList.Items))
}

// Helper methods

// getOIDCKubeconfig returns the OIDC-only kubeconfig for token-based authentication.
// This kubeconfig has no client certificates, forcing kubectl to use only the --token
// flag for authentication. This is required for testing OIDC-based authorization flows.
// Falls back to regular kubeconfig if OIDC kubeconfig is not available.
func (s *MultiIDPAuthorizationSuite) getOIDCKubeconfig(clusterName string) string {
	kubeconfig := s.mcCtx.GetSpokeOIDCKubeconfig(clusterName)
	if kubeconfig == "" {
		// Fall back to regular kubeconfig if OIDC kubeconfig not available
		kubeconfig = s.mcCtx.GetSpokeKubeconfig(clusterName)
	}
	return kubeconfig
}

func (s *MultiIDPAuthorizationSuite) runKubectlWithToken(kubeconfig, token string, args ...string) (string, error) {
	fullArgs := append([]string{
		"--kubeconfig", kubeconfig,
		"--token", token,
	}, args...)

	cmd := exec.CommandContext(s.ctx, "kubectl", fullArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
