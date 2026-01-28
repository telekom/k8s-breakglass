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

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestMultiClusterConfiguration tests ClusterConfig lifecycle and multi-cluster scenarios.
//
// Test coverage for issue #48:
// - Create ClusterConfig for spoke clusters
// - Verify cluster configuration is reconciled
// - Test cross-cluster escalation setup
// - Verify kubeconfig secret reference handling
func TestMultiClusterConfiguration(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("CreateClusterConfig", func(t *testing.T) {
		// First create a secret to hold the kubeconfig (even if mock)
		kubeconfigSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-spoke-kubeconfig",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"kubeconfig": `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://spoke-cluster.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
  name: spoke-cluster
contexts:
- context:
    cluster: spoke-cluster
    user: spoke-admin
  name: spoke-cluster
current-context: spoke-cluster
users:
- name: spoke-admin
  user:
    token: test-token
`,
			},
		}
		cleanup.Add(kubeconfigSecret)
		err := cli.Create(ctx, kubeconfigSecret)
		require.NoError(t, err, "Failed to create kubeconfig secret")

		// Create ClusterConfig referencing the secret
		clusterConfig := helpers.NewClusterConfigBuilder("e2e-test-spoke-cluster", namespace).
			WithClusterID("spoke-cluster").
			WithTenant("test-tenant").
			WithEnvironment("e2e-test").
			WithLocation("eu-central-1").
			WithKubeconfigSecret(kubeconfigSecret.Name, "kubeconfig").
			WithLabels(map[string]string{
				"e2e-test":    "true",
				"environment": "test",
			}).
			Build()

		cleanup.Add(clusterConfig)
		err = cli.Create(ctx, clusterConfig)
		require.NoError(t, err, "Failed to create ClusterConfig")

		// Verify it can be fetched
		var fetched telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err, "Failed to get ClusterConfig")
		require.Equal(t, "spoke-cluster", fetched.Spec.ClusterID)
		require.Equal(t, "test-tenant", fetched.Spec.Tenant)
		require.Equal(t, "e2e-test", fetched.Spec.Environment)
	})

	t.Run("UpdateClusterConfig", func(t *testing.T) {
		var clusterConfig telekomv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-spoke-cluster", Namespace: namespace}, &clusterConfig)
		require.NoError(t, err)

		// Use retry to handle conflicts with the ClusterConfigReconciler
		err = helpers.UpdateWithRetry(ctx, cli, &clusterConfig, func(cc *telekomv1alpha1.ClusterConfig) error {
			cc.Spec.Location = "us-west-2"
			cc.Spec.Site = "primary"
			return nil
		})
		require.NoError(t, err, "Failed to update ClusterConfig")

		// Verify the update
		var fetched telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, "us-west-2", fetched.Spec.Location)
		require.Equal(t, "primary", fetched.Spec.Site)
	})

	t.Run("ClusterConfigWithIdentityProviderRefs", func(t *testing.T) {
		// First create the IdentityProviders that will be referenced
		primaryIDP := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "primary-idp",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "primary-client",
				},
				DisplayName: "Primary IDP",
				Primary:     true,
			},
		}
		cleanup.Add(primaryIDP)
		err := cli.Create(ctx, primaryIDP)
		require.NoError(t, err, "Failed to create primary IDP")

		backupIDP := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "backup-idp",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://backup-auth.example.com",
					ClientID:  "backup-client",
				},
				DisplayName: "Backup IDP",
			},
		}
		cleanup.Add(backupIDP)
		err = cli.Create(ctx, backupIDP)
		require.NoError(t, err, "Failed to create backup IDP")

		kubeconfigSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-idp-cluster-kubeconfig",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"kubeconfig": `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://idp-cluster.example.com:6443
  name: idp-cluster
contexts:
- context:
    cluster: idp-cluster
    user: admin
  name: idp-cluster
current-context: idp-cluster
users:
- name: admin
  user:
    token: test-token
`,
			},
		}
		cleanup.Add(kubeconfigSecret)
		err = cli.Create(ctx, kubeconfigSecret)
		require.NoError(t, err)

		clusterConfig := helpers.NewClusterConfigBuilder("e2e-test-idp-cluster", namespace).
			WithClusterID("idp-cluster").
			WithKubeconfigSecret(kubeconfigSecret.Name, "kubeconfig").
			WithIdentityProviderRefs("primary-idp", "backup-idp").
			WithBlockSelfApproval(true).
			Build()

		cleanup.Add(clusterConfig)
		err = cli.Create(ctx, clusterConfig)
		require.NoError(t, err, "Failed to create ClusterConfig with IDP refs")

		var fetched telekomv1alpha1.ClusterConfig
		err = cli.Get(ctx, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.IdentityProviderRefs, 2)
		require.True(t, fetched.Spec.BlockSelfApproval)
	})

	t.Run("DeleteClusterConfig", func(t *testing.T) {
		var clusterConfig telekomv1alpha1.ClusterConfig
		err := cli.Get(ctx, types.NamespacedName{Name: "e2e-test-spoke-cluster", Namespace: namespace}, &clusterConfig)
		require.NoError(t, err)

		err = cli.Delete(ctx, &clusterConfig)
		require.NoError(t, err, "Failed to delete ClusterConfig")

		err = helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &telekomv1alpha1.ClusterConfig{}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "ClusterConfig was not deleted")
	})
}

// TestCrossClusterEscalation tests escalation setup spanning multiple clusters.
func TestCrossClusterEscalation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EscalationWithMultipleClusters", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder("e2e-test-multi-cluster-escalation", namespace).
			WithEscalatedGroup("cross-cluster-group").
			WithMaxValidFor("2h").
			WithAllowedClusters("cluster-a", "cluster-b", "cluster-c").
			WithAllowedGroups("sre-team@example.com").
			WithApproverUsers(helpers.GetTestApproverEmail()).
			Build()

		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create multi-cluster escalation")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.Allowed.Clusters, 3)
		require.Contains(t, fetched.Spec.Allowed.Clusters, "cluster-a")
		require.Contains(t, fetched.Spec.Allowed.Clusters, "cluster-b")
		require.Contains(t, fetched.Spec.Allowed.Clusters, "cluster-c")
	})

	t.Run("EscalationWithClusterConfigRefs", func(t *testing.T) {
		// Create an escalation that uses ClusterConfigRefs instead of explicit cluster list
		escalation := helpers.NewEscalationBuilder("e2e-test-clusterconfig-ref-escalation", namespace).
			WithEscalatedGroup("clusterconfig-ref-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithClusterConfigRefs("e2e-test-clusterconfig").
			WithAllowedGroups("platform-team@example.com").
			WithApproverGroups("security-approvers").
			Build()

		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create ClusterConfigRefs escalation")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Len(t, fetched.Spec.ClusterConfigRefs, 1)
		require.Equal(t, "e2e-test-clusterconfig", fetched.Spec.ClusterConfigRefs[0])
	})

	t.Run("SessionTargetingSpecificCluster", func(t *testing.T) {
		// Create escalation first
		escalation := helpers.NewEscalationBuilder("e2e-test-target-cluster-escalation", namespace).
			WithEscalatedGroup("target-cluster-group").
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			WithAllowedClusters(helpers.GetTestClusterName(), "secondary-cluster").
			WithAllowedGroups(helpers.TestUsers.MultiClusterRequester.Groups...).
			WithApproverUsers(helpers.TestUsers.MultiClusterApprover.Email).
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create session via API targeting specific cluster
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.RequesterClient()

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - targeting specific cluster",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err, "Failed to create session targeting specific cluster via API")
		cleanup.Add(session)

		var fetched telekomv1alpha1.BreakglassSession
		err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.Equal(t, helpers.GetTestClusterName(), fetched.Spec.Cluster)
	})
}

// TestClusterConfigValidation tests ClusterConfig validation rules.
func TestClusterConfigValidation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("RejectMissingKubeconfigSecretRef", func(t *testing.T) {
		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-invalid-no-secret",
				Namespace: namespace,
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "invalid-cluster",
				// Missing KubeconfigSecretRef
			},
		}

		cleanup.Add(clusterConfig)
		err := cli.Create(ctx, clusterConfig)
		require.Error(t, err, "Should reject ClusterConfig without kubeconfigSecretRef")
	})

	t.Run("AcceptValidClusterConfig", func(t *testing.T) {
		// Create secret first
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-valid-kubeconfig",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Type: corev1.SecretTypeOpaque,
			StringData: map[string]string{
				"kubeconfig": "apiVersion: v1\nkind: Config\n",
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err)

		clusterConfig := helpers.NewClusterConfigBuilder("e2e-test-valid-cluster", namespace).
			WithKubeconfigSecret(secret.Name, "kubeconfig").
			Build()

		cleanup.Add(clusterConfig)
		err = cli.Create(ctx, clusterConfig)
		require.NoError(t, err, "Valid ClusterConfig should be created")
	})
}
