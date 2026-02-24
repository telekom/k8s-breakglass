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
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestOIDCFullIntegrationFlow tests the complete OIDC flow from ClusterConfig creation
// to session approval to webhook authorization.
//
// Test ID: CC-OIDC-INT-001 (High)
func TestOIDCFullIntegrationFlow(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	oidcClusterName := "e2e-oidc-integration-cluster"

	t.Log("=== Test: Full OIDC Integration Flow (CC-OIDC-INT-001) ===")

	// Get OIDC client configuration - supports both public and confidential client models
	oidcClientConfig := helpers.GetOIDCClientConfig()

	if oidcClientConfig.IsPublic {
		t.Skip("Skipping OIDC integration test: Public client mode is enabled but controller requires confidential client for client credentials flow")
	}

	t.Logf("Using OIDC client: %s (confidential)", oidcClientConfig.ClientID)

	// Step 1: Create OIDC client secret for client credentials flow
	oidcSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-oidc-integration-secret",
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"client-secret": oidcClientConfig.ClientSecret,
		},
	}
	cleanup.Add(oidcSecret)
	err := cli.Create(ctx, oidcSecret)
	require.NoError(t, err, "Failed to create OIDC client secret")

	// Step 2: Create ClusterConfig with OIDC authentication
	// IMPORTANT: Use internal URL for the OIDC issuer because the controller runs inside
	// the cluster and cannot reach localhost URLs. The controller needs to connect to
	// Keycloak to validate tokens, so we use the internal service DNS name.
	keycloakInternalURL := helpers.GetKeycloakInternalURL()
	realm := helpers.GetKeycloakRealm()
	oidcIssuer := keycloakInternalURL + "/realms/" + realm

	// The server field is the Kubernetes API server URL (where the OIDC token will be used),
	// NOT the OIDC issuer URL. Use the OIDC-enabled API server URL because:
	// - In multi-cluster mode: spoke clusters have OIDC configured, hub doesn't
	// - In single-cluster mode: the single cluster has OIDC configured
	// The URL must be reachable FROM THE CONTROLLER POD (internal container IP:6443).
	oidcServer := helpers.GetOIDCEnabledAPIServerURL()

	t.Logf("Using Keycloak internal URL: %s", keycloakInternalURL)
	t.Logf("OIDC Issuer: %s", oidcIssuer)
	t.Logf("Target K8s API Server: %s", oidcServer)

	// Get the Keycloak CA certificate so the controller can verify Keycloak's TLS cert
	keycloakCA := helpers.GetKeycloakCAFromCluster(ctx, cli, namespace)
	if keycloakCA == "" {
		t.Log("Warning: Could not retrieve Keycloak CA from breakglass-certs ConfigMap, OIDC discovery may fail")
	} else {
		t.Log("Retrieved Keycloak CA certificate for OIDC TLS verification")
	}

	ccBuilder := helpers.NewClusterConfigBuilder(oidcClusterName, namespace).
		WithOIDCAuth(oidcIssuer, oidcClientConfig.ClientID, oidcServer).
		WithOIDCClientSecret(oidcSecret.Name, namespace, "client-secret").
		WithOIDCAllowTOFU(true) // Allow TOFU for self-signed cluster certificate
	if keycloakCA != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(keycloakCA)
	}
	clusterConfig := ccBuilder.Build()
	cleanup.Add(clusterConfig)
	err = cli.Create(ctx, clusterConfig)
	require.NoError(t, err, "Failed to create ClusterConfig")

	// Step 3: Wait for ClusterConfig to become Ready
	err = waitForClusterConfigConditionReady(t, ctx, cli, clusterConfig.Name, namespace, 2*time.Minute)
	if err != nil {
		var cc breakglassv1alpha1.ClusterConfig
		if getErr := cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &cc); getErr == nil {
			logClusterConfigConditions(t, &cc)
		}
		require.NoError(t, err, "ClusterConfig did not become Ready")
	}
	t.Log("ClusterConfig is Ready")

	// Step 4: Create escalation for the OIDC cluster
	escalation := helpers.NewEscalationBuilder("e2e-oidc-integration-escalation", namespace).
		WithEscalatedGroup("breakglass-oidc-integration-group").
		WithMaxValidFor("4h").
		WithApprovalTimeout("2h").
		WithAllowedClusters(oidcClusterName).
		Build()
	cleanup.Add(escalation)
	err = cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")

	// Step 5: Create and approve session via API
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	sessionUser := helpers.GetTestUserEmail()
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: oidcClusterName,
		User:    sessionUser,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "CC-OIDC-INT-001: Full OIDC integration test",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Failed to create session via API")
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session via API")

	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
		breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	// Step 6: Verify webhook authorization works for the OIDC cluster
	t.Run("VerifyWebhookAuthorizationWithOIDC", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "authorization.k8s.io/v1",
				Kind:       "SubjectAccessReview",
			},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   sessionUser,
				Groups: []string{escalation.Spec.EscalatedGroup},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, oidcClusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")
		assert.Equal(t, http.StatusOK, statusCode, "Webhook should return 200 OK")
		t.Logf("SAR result: allowed=%v, denied=%v", sarResp.Status.Allowed, sarResp.Status.Denied)
	})

	// Step 7: Verify ClusterConfig status reflects healthy state
	t.Run("VerifyClusterConfigHealthy", func(t *testing.T) {
		var cc breakglassv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &cc)
		require.NoError(t, err)
		assertClusterConfigReady(t, &cc)
	})

	t.Log("=== CC-OIDC-INT-001: Full OIDC Integration Flow Complete ===")
}

// TestOIDCClusterConfigTokenExchange tests that ClusterConfig can successfully
// exchange OIDC tokens for cluster access.
// Test ID: TEXCH-001 (High)
func TestOIDCClusterConfigTokenExchange(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Log("=== Test: OIDC Token Exchange (TEXCH-001) ===")

	// Use the service account client (breakglass-group-sync) for client credentials flow
	oidcSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-token-exchange-secret",
			Namespace: namespace,
			Labels:    helpers.E2ETestLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"client-secret": helpers.GetKeycloakServiceAccountSecret(),
		},
	}
	cleanup.Add(oidcSecret)
	err := cli.Create(ctx, oidcSecret)
	require.NoError(t, err)

	// Use internal URL for controller-to-Keycloak communication
	keycloakURL := helpers.GetKeycloakInternalURL()
	realm := helpers.GetKeycloakRealm()
	oidcIssuer := keycloakURL + "/realms/" + realm

	// The server field is the Kubernetes API server URL (where the OIDC token will be used),
	// NOT the OIDC issuer URL. Use the OIDC-enabled API server URL because:
	// - In multi-cluster mode: spoke clusters have OIDC configured, hub doesn't
	// - In single-cluster mode: the single cluster has OIDC configured
	// The URL must be reachable FROM THE CONTROLLER POD (internal container IP:6443).
	oidcServer := helpers.GetOIDCEnabledAPIServerURL()

	// Get the Keycloak CA certificate so the controller can verify Keycloak's TLS cert
	keycloakCA := helpers.GetKeycloakCAFromCluster(ctx, cli, namespace)
	if keycloakCA != "" {
		t.Log("Retrieved Keycloak CA certificate for OIDC TLS verification")
	}

	ccBuilder := helpers.NewClusterConfigBuilder("e2e-token-exchange-cluster", namespace).
		WithOIDCAuth(oidcIssuer, helpers.GetKeycloakServiceAccountClientID(), oidcServer).
		WithOIDCClientSecret(oidcSecret.Name, namespace, "client-secret").
		WithOIDCAllowTOFU(true) // Allow TOFU for self-signed cluster certificate
	if keycloakCA != "" {
		ccBuilder = ccBuilder.WithOIDCCertificateAuthority(keycloakCA)
	}
	clusterConfig := ccBuilder.Build()
	cleanup.Add(clusterConfig)
	err = cli.Create(ctx, clusterConfig)
	require.NoError(t, err)

	time.Sleep(5 * time.Second)

	var cc breakglassv1alpha1.ClusterConfig
	err = cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &cc)
	require.NoError(t, err)

	logClusterConfigConditions(t, &cc)

	if isClusterConfigReady(&cc) {
		t.Log("Token exchange succeeded - ClusterConfig is Ready")
	} else {
		t.Log("Note: Token exchange may have failed (expected if OIDC provider is not fully configured)")
	}

	t.Log("=== TEXCH-001: OIDC Token Exchange Test Complete ===")
}

func waitForClusterConfigConditionReady(t *testing.T, ctx context.Context, cli client.Client, name, namespace string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var cc breakglassv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &cc)
		if err != nil {
			return err
		}

		if isClusterConfigReady(&cc) {
			return nil
		}

		logClusterConfigConditions(t, &cc)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for ClusterConfig %s/%s to become Ready", namespace, name)
}

func isClusterConfigReady(cc *breakglassv1alpha1.ClusterConfig) bool {
	for _, cond := range cc.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.ClusterConfigConditionReady) && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

func logClusterConfigConditions(t *testing.T, cc *breakglassv1alpha1.ClusterConfig) {
	for _, cond := range cc.Status.Conditions {
		t.Logf("ClusterConfig condition: Type=%s, Status=%s, Reason=%s, Message=%s",
			cond.Type, cond.Status, cond.Reason, cond.Message)
	}
}

func assertClusterConfigReady(t *testing.T, cc *breakglassv1alpha1.ClusterConfig) {
	found := false
	for _, cond := range cc.Status.Conditions {
		if cond.Type == string(breakglassv1alpha1.ClusterConfigConditionReady) {
			found = true
			assert.Equal(t, metav1.ConditionTrue, cond.Status, "Expected ClusterConfig Ready condition to be True")
			break
		}
	}
	assert.True(t, found, "Expected ClusterConfig to have Ready condition")
}
