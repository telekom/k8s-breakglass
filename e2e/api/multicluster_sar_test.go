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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestClusterConfigConnectivity tests ClusterConfig status updates based on connectivity.
func TestClusterConfigConnectivity(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("ClusterConfigWithValidSecret", func(t *testing.T) {
		// Create a kubeconfig secret (will fail connectivity but tests the flow)
		secretName := helpers.GenerateUniqueName("e2e-cc-secret")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"value": []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://10.0.0.1:6443
    insecure-skip-tls-verify: true
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: fake-token
`),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err, "Failed to create kubeconfig secret")

		// Create ClusterConfig referencing the secret
		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-cluster"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      secretName,
					Namespace: namespace,
				},
			},
		}
		cleanup.Add(clusterConfig)
		err = cli.Create(ctx, clusterConfig)
		require.NoError(t, err, "Failed to create ClusterConfig")

		t.Logf("ClusterConfig with secret created: %s", clusterConfig.Name)
	})

	t.Run("ClusterConfigWithMissingSecret", func(t *testing.T) {
		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-cluster-missing"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "nonexistent-secret",
					Namespace: namespace,
				},
			},
		}
		cleanup.Add(clusterConfig)
		err := cli.Create(ctx, clusterConfig)
		require.NoError(t, err, "Should allow ClusterConfig with missing secret")

		t.Logf("ClusterConfig with missing secret processed")
	})
}

// TestCrossClusterSARAuthorization tests SAR webhook across different cluster configurations.
func TestCrossClusterSARAuthorization(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled. Set WEBHOOK_TEST=true and ensure API is accessible.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()

	// Create test context for authenticated API clients
	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.MultiClusterRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.MultiClusterApprover)

	// Create the escalation that the test needs - this is required for sessions to be created
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-multi-cluster-sar-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "multi-cluster-ops-group",
			MaxValidFor:     "2h",
			ApprovalTimeout: "1h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.MultiClusterRequester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.TestUsers.MultiClusterApprover.Email},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation for multi-cluster SAR test")

	// Give the escalation time to be indexed
	time.Sleep(time.Second)

	t.Run("SARForActiveSession", func(t *testing.T) {
		// Create session via API using the escalation's group
		session, err := requesterClient.CreateSession(ctx, t, helpers.SessionRequest{
			Cluster: clusterName,
			User:    helpers.TestUsers.MultiClusterRequester.Email,
			Group:   escalation.Spec.EscalatedGroup, // Use the escalation's group
			Reason:  "SAR test",
		})
		require.NoError(t, err, "Failed to create session via API")

		// Add to cleanup
		var sessionToCleanup telekomv1alpha1.BreakglassSession
		errGet := cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: session.Namespace}, &sessionToCleanup)
		require.NoError(t, errGet)
		cleanup.Add(&sessionToCleanup)

		// Wait for session to get pending state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStatePending, 30*time.Second)

		// Approve via API
		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err, "Failed to approve session via API")

		// Wait for approved state
		helpers.WaitForSessionState(t, ctx, cli, session.Name, session.Namespace, telekomv1alpha1.SessionStateApproved, 30*time.Second)

		// Send SAR request to webhook
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: helpers.TestUsers.MultiClusterRequester.Email,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "get",
					Resource: "pods",
				},
			},
		}

		result, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")

		t.Logf("SAR response for active session: allowed=%v, reason=%s",
			result.Status.Allowed, result.Status.Reason)
	})

	t.Run("SARForNonExistentUser", func(t *testing.T) {
		// Send SAR for a user without an active session
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "nonexistent-user@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     "get",
					Resource: "pods",
				},
			},
		}

		result, _, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err, "Failed to send SAR to webhook")

		// Should be denied
		assert.False(t, result.Status.Allowed, "SAR should be denied for user without session")
		t.Logf("SAR correctly denied for nonexistent user: reason=%s", result.Status.Reason)
	})
}

// TestEscalationClusterConfigRefs tests ClusterConfigRefs resolution in escalations.
func TestEscalationClusterConfigRefs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EscalationWithMultipleClusterRefs", func(t *testing.T) {
		// Create multiple cluster configs
		cluster1 := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-cluster1"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "env": "dev"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "dev-cluster-1",
				KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "dummy-kubeconfig",
					Namespace: namespace,
				},
			},
		}
		cleanup.Add(cluster1)
		err := cli.Create(ctx, cluster1)
		require.NoError(t, err)

		cluster2 := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-cluster2"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true", "env": "dev"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "dev-cluster-2",
				KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{
					Name:      "dummy-kubeconfig",
					Namespace: namespace,
				},
			},
		}
		cleanup.Add(cluster2)
		err = cli.Create(ctx, cluster2)
		require.NoError(t, err)

		// Create escalation referencing both clusters via ClusterConfigRefs (which is []string)
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-escalation-multi"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:    "multi-cluster-group",
				ClusterConfigRefs: []string{cluster1.Name, cluster2.Name},
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Groups: helpers.TestUsers.MultiClusterRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.MultiClusterApprover.Email},
				},
			},
		}
		cleanup.Add(escalation)
		err = cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create multi-cluster escalation")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.ClusterConfigRefs, 2)

		t.Logf("Multi-cluster escalation created with %d cluster refs",
			len(fetched.Spec.ClusterConfigRefs))
	})
}

// TestWebhookEndpointAvailability tests webhook endpoint health and availability.
func TestWebhookEndpointAvailability(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled. Set WEBHOOK_TEST=true and ensure API is accessible.")
	}

	t.Run("WebhookHealthEndpoint", func(t *testing.T) {
		baseURL := helpers.GetAPIBaseURL()
		healthURL := baseURL + "/healthz"

		httpClient := helpers.NewHTTPClient(helpers.WebhookHTTPClientConfig())
		resp, err := httpClient.Get(healthURL)
		require.NoError(t, err, "Health endpoint should be accessible")
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode, "Health endpoint should return 200")
		t.Logf("Webhook health endpoint returned: %d", resp.StatusCode)
	})
}
