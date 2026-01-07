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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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
		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-spoke-cluster",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test":    "true",
					"environment": "test",
				},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID:   "spoke-cluster",
				Tenant:      "test-tenant",
				Environment: "e2e-test",
				Location:    "eu-central-1",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      kubeconfigSecret.Name,
					Namespace: namespace,
					Key:       "kubeconfig",
				},
			},
		}

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

		// Update the cluster config
		clusterConfig.Spec.Location = "us-west-2"
		clusterConfig.Spec.Site = "primary"
		err = cli.Update(ctx, &clusterConfig)
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

		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-idp-cluster",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "idp-cluster",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      kubeconfigSecret.Name,
					Namespace: namespace,
					Key:       "kubeconfig",
				},
				IdentityProviderRefs: []string{"primary-idp", "backup-idp"},
				BlockSelfApproval:    true,
			},
		}

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

		err = helpers.WaitForResourceDeleted(ctx, cli, types.NamespacedName{Name: clusterConfig.Name, Namespace: namespace}, &telekomv1alpha1.ClusterConfig{}, 30*time.Second)
		require.NoError(t, err, "ClusterConfig was not deleted")
	})
}

// TestCrossClusterEscalation tests escalation setup spanning multiple clusters.
func TestCrossClusterEscalation(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EscalationWithMultipleClusters", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-multi-cluster-escalation",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "cross-cluster-group",
				MaxValidFor:    "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{
						"cluster-a",
						"cluster-b",
						"cluster-c",
					},
					Groups: []string{"sre-team@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}

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
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-clusterconfig-ref-escalation",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "clusterconfig-ref-group",
				MaxValidFor:     "2h",
				ApprovalTimeout: "1h",
				// Use ClusterConfigRefs to reference ClusterConfig objects by name
				ClusterConfigRefs: []string{"e2e-test-clusterconfig"},
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"platform-team@example.com"},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"security-approvers"},
				},
			},
		}

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
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-target-cluster-escalation",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "target-cluster-group",
				MaxValidFor:     "2h",
				ApprovalTimeout: "1h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName(), "secondary-cluster"},
					Groups:   helpers.TestUsers.MultiClusterRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.MultiClusterApprover.Email},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		// Create session via API targeting specific cluster
		tc := helpers.NewTestContext(t, ctx)
		apiClient := tc.ClientForUser(helpers.TestUsers.MultiClusterRequester)

		session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.GetTestUserEmail(),
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "E2E test - targeting specific cluster",
		}, 30*time.Second)
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
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

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

		clusterConfig := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-test-valid-cluster",
				Namespace: namespace,
				Labels: map[string]string{
					"e2e-test": "true",
				},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      secret.Name,
					Namespace: namespace,
					Key:       "kubeconfig",
				},
			},
		}

		cleanup.Add(clusterConfig)
		err = cli.Create(ctx, clusterConfig)
		require.NoError(t, err, "Valid ClusterConfig should be created")
	})
}
