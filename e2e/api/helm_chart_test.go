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

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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
	var clusterConfig telekomv1alpha1.ClusterConfig
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
	var clusterConfig telekomv1alpha1.ClusterConfig
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
	assert.Equal(t, telekomv1alpha1.ClusterAuthTypeOIDC, clusterConfig.Spec.AuthType)
	assert.NotNil(t, clusterConfig.Spec.OIDCAuth)
	assert.NotEmpty(t, clusterConfig.Spec.OIDCAuth.IssuerURL)
	assert.NotEmpty(t, clusterConfig.Spec.OIDCAuth.ClientID)
	assert.NotEmpty(t, clusterConfig.Spec.OIDCAuth.Server)
	assert.NotNil(t, clusterConfig.Spec.OIDCAuth.ClientSecretRef)
	assert.Equal(t, "helm-test-oidc-secret", clusterConfig.Spec.OIDCAuth.ClientSecretRef.Name)
	assert.Equal(t, namespace, clusterConfig.Spec.OIDCAuth.ClientSecretRef.Namespace)

	t.Logf("✓ Helm chart successfully deployed OIDC ClusterConfig: %s", clusterConfig.Name)
}
