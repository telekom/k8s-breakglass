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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestHelmChartDeployment [HELM-001] tests that the escalation-config helm chart
// can deploy ClusterConfig and BreakglassEscalation resources successfully.
func TestHelmChartDeployment(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Get the project root directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Join(wd, "../..")
	chartPath := filepath.Join(projectRoot, "charts", "escalation-config")

	// Verify chart exists
	_, err = os.Stat(chartPath)
	require.NoError(t, err, "Helm chart not found at %s", chartPath)

	// Create prerequisite: kubeconfig secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "helm-test-kubeconfig",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "helm-chart"},
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test
current-context: test
users:
- name: test-user
  user:
    token: dummy-token
`),
		},
	}
	cleanup.Add(secret)
	err = cli.Create(ctx, secret)
	require.NoError(t, err, "Failed to create kubeconfig secret")

	// Deploy using helm template + kubectl apply (avoids Tiller/Helm dependency in CI)
	releaseName := "e2e-helm-test"
	valuesFile := filepath.Join(chartPath, "test-values", "simple.yaml")

	// Generate manifests using helm template
	templateCmd := exec.CommandContext(ctx, "helm", "template", releaseName,
		chartPath,
		"--namespace", namespace,
		"--values", valuesFile,
		"--set", "cluster.kubeconfigSecretRef.name=helm-test-kubeconfig",
		"--set", "cluster.kubeconfigSecretRef.namespace="+namespace,
		"--set", "cluster.clusterID=helm-e2e-cluster",
		"--set", "cluster.tenant=helm-tenant",
		"--set", "cluster.environment=e2e",
	)
	output, err := templateCmd.CombinedOutput()
	require.NoError(t, err, "helm template failed: %s", string(output))

	// Write manifests to temp file
	tmpDir := t.TempDir()
	manifestsFile := filepath.Join(tmpDir, "manifests.yaml")
	err = os.WriteFile(manifestsFile, output, 0644)
	require.NoError(t, err)

	// Apply manifests
	applyCmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", manifestsFile)
	applyCmd.Env = append(os.Environ(), "KUBECONFIG="+os.Getenv("KUBECONFIG"))
	applyOutput, err := applyCmd.CombinedOutput()
	require.NoError(t, err, "kubectl apply failed: %s", string(applyOutput))

	// Wait for ClusterConfig to be created
	var clusterConfig breakglassv1alpha1.ClusterConfig
	require.Eventually(t, func() bool {
		err := cli.Get(ctx, types.NamespacedName{
			Name:      "helm-e2e-cluster",
			Namespace: namespace,
		}, &clusterConfig)
		return err == nil
	}, helpers.WaitForStateTimeout, 1*time.Second, "ClusterConfig not created by helm chart")

	// Add to cleanup
	cleanup.Add(&clusterConfig)

	// Verify ClusterConfig fields
	assert.Equal(t, "helm-e2e-cluster", clusterConfig.Spec.ClusterID)
	assert.Equal(t, "helm-tenant", clusterConfig.Spec.Tenant)
	assert.Equal(t, "e2e", clusterConfig.Spec.Environment)
	assert.NotNil(t, clusterConfig.Spec.KubeconfigSecretRef)
	assert.Equal(t, "helm-test-kubeconfig", clusterConfig.Spec.KubeconfigSecretRef.Name)
	assert.Equal(t, namespace, clusterConfig.Spec.KubeconfigSecretRef.Namespace)

	t.Logf("✓ Helm chart successfully deployed ClusterConfig: %s", clusterConfig.Name)
}

// TestHelmChartOIDCDeployment [HELM-002] tests that the escalation-config helm chart
// can deploy ClusterConfig with OIDC authentication.
func TestHelmChartOIDCDeployment(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Get the project root directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Join(wd, "../..")
	chartPath := filepath.Join(projectRoot, "charts", "escalation-config")

	// Create prerequisite: OIDC client secret
	oidcSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "helm-test-oidc-secret",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "helm-chart"},
		},
		StringData: map[string]string{
			"client-secret": "test-client-secret-value",
		},
	}
	cleanup.Add(oidcSecret)
	err = cli.Create(ctx, oidcSecret)
	require.NoError(t, err, "Failed to create OIDC client secret")

	// Deploy using helm template + kubectl apply with OIDC values
	releaseName := "e2e-helm-oidc-test"
	valuesFile := filepath.Join(chartPath, "test-values", "oidc-example.yaml")

	// Generate manifests using helm template
	templateCmd := exec.CommandContext(ctx, "helm", "template", releaseName,
		chartPath,
		"--namespace", namespace,
		"--values", valuesFile,
		"--set", "cluster.clusterID=helm-oidc-cluster",
		"--set", "cluster.oidcAuth.clientSecretRef.name=helm-test-oidc-secret",
		"--set", "cluster.oidcAuth.clientSecretRef.namespace="+namespace,
	)
	output, err := templateCmd.CombinedOutput()
	require.NoError(t, err, "helm template failed: %s", string(output))

	// Write manifests to temp file
	tmpDir := t.TempDir()
	manifestsFile := filepath.Join(tmpDir, "manifests-oidc.yaml")
	err = os.WriteFile(manifestsFile, output, 0644)
	require.NoError(t, err)

	// Apply manifests
	applyCmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", manifestsFile)
	applyCmd.Env = append(os.Environ(), "KUBECONFIG="+os.Getenv("KUBECONFIG"))
	applyOutput, err := applyCmd.CombinedOutput()
	require.NoError(t, err, "kubectl apply failed: %s", string(applyOutput))

	// Wait for ClusterConfig to be created
	var clusterConfig breakglassv1alpha1.ClusterConfig
	require.Eventually(t, func() bool {
		err := cli.Get(ctx, types.NamespacedName{
			Name:      "helm-oidc-cluster",
			Namespace: namespace,
		}, &clusterConfig)
		return err == nil
	}, helpers.WaitForStateTimeout, 1*time.Second, "OIDC ClusterConfig not created by helm chart")

	// Add to cleanup
	cleanup.Add(&clusterConfig)

	// Verify ClusterConfig OIDC fields
	assert.Equal(t, "helm-oidc-cluster", clusterConfig.Spec.ClusterID)
	assert.Equal(t, breakglassv1alpha1.ClusterAuthTypeOIDC, clusterConfig.Spec.AuthType)
	assert.NotNil(t, clusterConfig.Spec.OIDCAuth)
	assert.NotEmpty(t, clusterConfig.Spec.OIDCAuth.IssuerURL)
	assert.NotEmpty(t, clusterConfig.Spec.OIDCAuth.ClientID)
	assert.NotEmpty(t, clusterConfig.Spec.OIDCAuth.Server)
	assert.NotNil(t, clusterConfig.Spec.OIDCAuth.ClientSecretRef)
	assert.Equal(t, "helm-test-oidc-secret", clusterConfig.Spec.OIDCAuth.ClientSecretRef.Name)
	assert.Equal(t, namespace, clusterConfig.Spec.OIDCAuth.ClientSecretRef.Namespace)

	t.Logf("✓ Helm chart successfully deployed OIDC ClusterConfig: %s", clusterConfig.Name)
}

// TestHelmChartDebugSessionBindingDeployment [HELM-003] tests that the escalation-config helm chart
// can deploy DebugSessionClusterBinding resources with various configurations.
func TestHelmChartDebugSessionBindingDeployment(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	// Get the project root directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Join(wd, "../..")
	chartPath := filepath.Join(projectRoot, "charts", "escalation-config")

	// Verify chart exists
	_, err = os.Stat(chartPath)
	require.NoError(t, err, "Helm chart not found at %s", chartPath)

	// Create prerequisite: kubeconfig secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "helm-binding-test-kubeconfig",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "helm-chart-binding"},
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test
current-context: test
users:
- name: test-user
  user:
    token: dummy-token
`),
		},
	}
	cleanup.Add(secret)
	err = cli.Create(ctx, secret)
	require.NoError(t, err, "Failed to create kubeconfig secret")

	// Deploy using helm template + kubectl apply
	releaseName := "e2e-helm-binding-test"
	valuesFile := filepath.Join(chartPath, "test-values", "debug-session-bindings.yaml")

	// Generate manifests using helm template
	templateCmd := exec.CommandContext(ctx, "helm", "template", releaseName,
		chartPath,
		"--namespace", namespace,
		"--values", valuesFile,
		"--set", "cluster.kubeconfigSecretRef.name=helm-binding-test-kubeconfig",
		"--set", "cluster.kubeconfigSecretRef.namespace="+namespace,
		"--set", "cluster.clusterID=helm-binding-cluster",
		"--set", "cluster.tenant=helm-binding-tenant",
	)
	output, err := templateCmd.CombinedOutput()
	require.NoError(t, err, "helm template failed: %s", string(output))

	// Write manifests to temp file
	tmpDir := t.TempDir()
	manifestsFile := filepath.Join(tmpDir, "manifests-bindings.yaml")
	err = os.WriteFile(manifestsFile, output, 0644)
	require.NoError(t, err)

	// Apply manifests
	applyCmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", manifestsFile)
	applyCmd.Env = append(os.Environ(), "KUBECONFIG="+os.Getenv("KUBECONFIG"))
	applyOutput, err := applyCmd.CombinedOutput()
	require.NoError(t, err, "kubectl apply failed: %s", string(applyOutput))

	// Wait for ClusterConfig to be created
	var clusterConfig breakglassv1alpha1.ClusterConfig
	require.Eventually(t, func() bool {
		err := cli.Get(ctx, types.NamespacedName{
			Name:      "helm-binding-cluster",
			Namespace: namespace,
		}, &clusterConfig)
		return err == nil
	}, helpers.WaitForStateTimeout, 1*time.Second, "ClusterConfig not created by helm chart")
	cleanup.Add(&clusterConfig)

	t.Run("BasicBindingCreated", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "basic-debug-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "basic-debug-binding not created")
		cleanup.Add(&binding)

		// Verify binding fields
		assert.Equal(t, "Basic Debug Access", binding.Spec.DisplayName)
		assert.Equal(t, "Basic debug session binding for testing", binding.Spec.Description)
		assert.NotNil(t, binding.Spec.TemplateRef)
		assert.Equal(t, "standard-debug-template", binding.Spec.TemplateRef.Name)
		require.NotNil(t, binding.Spec.Allowed)
		assert.Contains(t, binding.Spec.Allowed.Groups, "dev")
		assert.Contains(t, binding.Spec.Allowed.Groups, "sre")
		require.NotNil(t, binding.Spec.Approvers)
		assert.Contains(t, binding.Spec.Approvers.Groups, "senior-sre")
		require.NotNil(t, binding.Spec.RequestReason)
		assert.True(t, binding.Spec.RequestReason.Mandatory)
		require.NotNil(t, binding.Spec.Constraints)
		assert.Equal(t, "2h", binding.Spec.Constraints.MaxDuration)
		assert.Equal(t, int32(10), *binding.Spec.Priority)

		t.Logf("✓ basic-debug-binding deployed correctly")
	})

	t.Run("SchedulingConstraintsBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "scheduled-debug-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "scheduled-debug-binding not created")
		cleanup.Add(&binding)

		// Verify scheduling constraints
		require.NotNil(t, binding.Spec.SchedulingConstraints)
		assert.NotEmpty(t, binding.Spec.SchedulingConstraints.NodeSelector)
		assert.Equal(t, "debug-nodes", binding.Spec.SchedulingConstraints.NodeSelector["node-pool"])
		assert.NotEmpty(t, binding.Spec.SchedulingConstraints.Tolerations)
		assert.NotEmpty(t, binding.Spec.SchedulingConstraints.TopologySpreadConstraints)
		assert.NotEmpty(t, binding.Spec.SchedulingConstraints.DeniedNodes)
		assert.Contains(t, binding.Spec.SchedulingConstraints.DeniedNodes, "control-plane-*")

		t.Logf("✓ scheduled-debug-binding with scheduling constraints deployed correctly")
	})

	t.Run("NamespaceConstraintsBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "namespace-restricted-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "namespace-restricted-binding not created")
		cleanup.Add(&binding)

		// Verify namespace constraints
		require.NotNil(t, binding.Spec.NamespaceConstraints)
		assert.Equal(t, "debug-workloads", binding.Spec.NamespaceConstraints.DefaultNamespace)
		assert.True(t, binding.Spec.NamespaceConstraints.AllowUserNamespace)

		t.Logf("✓ namespace-restricted-binding with namespace constraints deployed correctly")
	})

	t.Run("ImpersonationBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "impersonated-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "impersonated-binding not created")
		cleanup.Add(&binding)

		// Verify impersonation config
		require.NotNil(t, binding.Spec.Impersonation)
		require.NotNil(t, binding.Spec.Impersonation.ServiceAccountRef)
		assert.Equal(t, "debug-deployer", binding.Spec.Impersonation.ServiceAccountRef.Name)
		assert.Equal(t, "breakglass-system", binding.Spec.Impersonation.ServiceAccountRef.Namespace)
		assert.Contains(t, binding.Spec.RequiredAuxiliaryResourceCategories, "network-policy")
		assert.Contains(t, binding.Spec.RequiredAuxiliaryResourceCategories, "rbac")

		t.Logf("✓ impersonated-binding with impersonation config deployed correctly")
	})

	t.Run("TemplateSelectorBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "dev-all-templates",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "dev-all-templates not created")
		cleanup.Add(&binding)

		// Verify template selector
		require.NotNil(t, binding.Spec.TemplateSelector)
		assert.Equal(t, "development", binding.Spec.TemplateSelector.MatchLabels["tier"])
		assert.Equal(t, "[DEV] ", binding.Spec.DisplayNamePrefix)
		require.NotNil(t, binding.Spec.MaxActiveSessionsPerUser)
		assert.Equal(t, int32(2), *binding.Spec.MaxActiveSessionsPerUser)
		require.NotNil(t, binding.Spec.MaxActiveSessionsTotal)
		assert.Equal(t, int32(10), *binding.Spec.MaxActiveSessionsTotal)

		t.Logf("✓ dev-all-templates with template selector deployed correctly")
	})

	t.Run("SchedulingOptionsBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "multi-option-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "multi-option-binding not created")
		cleanup.Add(&binding)

		// Verify scheduling options
		require.NotNil(t, binding.Spec.SchedulingOptions)
		assert.True(t, binding.Spec.SchedulingOptions.Required)
		assert.Len(t, binding.Spec.SchedulingOptions.Options, 3)

		// Check option names
		optionNames := make([]string, 0, len(binding.Spec.SchedulingOptions.Options))
		for _, opt := range binding.Spec.SchedulingOptions.Options {
			optionNames = append(optionNames, opt.Name)
		}
		assert.Contains(t, optionNames, "standard")
		assert.Contains(t, optionNames, "high-memory")
		assert.Contains(t, optionNames, "gpu")

		t.Logf("✓ multi-option-binding with scheduling options deployed correctly")
	})

	t.Run("ClusterSelectorBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "env-based-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "env-based-binding not created")
		cleanup.Add(&binding)

		// Verify cluster selector
		require.NotNil(t, binding.Spec.ClusterSelector)
		assert.Equal(t, "staging", binding.Spec.ClusterSelector.MatchLabels["environment"])
		require.NotEmpty(t, binding.Spec.ClusterSelector.MatchExpressions)

		t.Logf("✓ env-based-binding with cluster selector deployed correctly")
	})

	t.Run("FullConfigBinding", func(t *testing.T) {
		var binding breakglassv1alpha1.DebugSessionClusterBinding
		require.Eventually(t, func() bool {
			err := cli.Get(ctx, types.NamespacedName{
				Name:      "full-config-binding",
				Namespace: namespace,
			}, &binding)
			return err == nil
		}, helpers.WaitForStateTimeout, 1*time.Second, "full-config-binding not created")
		cleanup.Add(&binding)

		// Verify full configuration
		assert.Equal(t, "Full Configuration Example", binding.Spec.DisplayName)
		assert.Equal(t, "Demonstrates all binding options", binding.Spec.Description)

		// Template ref
		require.NotNil(t, binding.Spec.TemplateRef)
		assert.Equal(t, "complete-template", binding.Spec.TemplateRef.Name)

		// Clusters
		assert.Contains(t, binding.Spec.Clusters, "full-test-cluster")

		// Allowed users and groups
		require.NotNil(t, binding.Spec.Allowed)
		assert.Contains(t, binding.Spec.Allowed.Groups, "admin-team")
		assert.Contains(t, binding.Spec.Allowed.Users, "special-user@example.com")

		// Approvers
		require.NotNil(t, binding.Spec.Approvers)
		assert.Contains(t, binding.Spec.Approvers.Groups, "security-team")
		assert.Contains(t, binding.Spec.Approvers.Users, "ciso@example.com")

		// Constraints
		require.NotNil(t, binding.Spec.Constraints)
		assert.Equal(t, "1h", binding.Spec.Constraints.MaxDuration)
		assert.Equal(t, "15m", binding.Spec.Constraints.DefaultDuration)
		assert.Equal(t, int32(3), *binding.Spec.Constraints.MaxRenewals)
		assert.True(t, *binding.Spec.Constraints.AllowRenewal)
		assert.Equal(t, int32(2), binding.Spec.Constraints.MaxConcurrentSessions)

		// Request/approval reasons
		require.NotNil(t, binding.Spec.RequestReason)
		assert.True(t, binding.Spec.RequestReason.Mandatory)
		require.NotNil(t, binding.Spec.ApprovalReason)
		assert.True(t, binding.Spec.ApprovalReason.Mandatory)

		// Session limits
		require.NotNil(t, binding.Spec.MaxActiveSessionsPerUser)
		assert.Equal(t, int32(1), *binding.Spec.MaxActiveSessionsPerUser)
		require.NotNil(t, binding.Spec.MaxActiveSessionsTotal)
		assert.Equal(t, int32(3), *binding.Spec.MaxActiveSessionsTotal)

		// Priority
		require.NotNil(t, binding.Spec.Priority)
		assert.Equal(t, int32(1), *binding.Spec.Priority)

		t.Logf("✓ full-config-binding with all options deployed correctly")
	})

	t.Logf("✓ All DebugSessionClusterBindings deployed successfully via Helm chart")
}
