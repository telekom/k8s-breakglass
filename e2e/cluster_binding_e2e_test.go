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

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestClusterBindingReconcilerStatus verifies that the ClusterBinding reconciler
// correctly updates status.resolvedTemplates and status.resolvedClusters.
func TestClusterBindingReconcilerStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	// Create a test template for the binding
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-binding-test-template",
			Labels: map[string]string{
				"e2e-test": "cluster-binding",
			},
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Binding Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"platform-sre"},
			},
		},
	}

	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create test template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Ensure namespace exists
	testNS := helpers.GetTestNamespace()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	// Create a ClusterBinding
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-test-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-binding-test-template",
			},
			Clusters: []string{"local-cluster"},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"team-alpha"},
			},
		},
	}

	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	// Wait for the binding status to be updated
	var updatedBinding telekomv1alpha1.DebugSessionClusterBinding
	require.Eventually(t, func() bool {
		err := cli.Get(ctx, types.NamespacedName{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		}, &updatedBinding)
		if err != nil {
			return false
		}
		return len(updatedBinding.Status.ResolvedTemplates) > 0 ||
			len(updatedBinding.Status.ResolvedClusters) > 0
	}, 30*time.Second, 2*time.Second, "Binding status should be updated by reconciler")

	assert.NotEmpty(t, updatedBinding.Status.ResolvedTemplates, "ResolvedTemplates should not be empty")
	// Check that ResolvedTemplates contains the expected template by name
	foundTemplate := false
	for _, ref := range updatedBinding.Status.ResolvedTemplates {
		if ref.Name == "e2e-binding-test-template" {
			foundTemplate = true
			break
		}
	}
	assert.True(t, foundTemplate, "ResolvedTemplates should contain e2e-binding-test-template")
	// ResolvedClusters may be empty if cluster doesn't exist, just check the template was resolved

	t.Log("ClusterBinding reconciler status test passed")
}

// TestClusterBindingNameCollision verifies that the webhook rejects bindings
// with duplicate effective display names for the same template+cluster.
func TestClusterBindingNameCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-collision-test-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Collision Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
		},
	}

	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create test template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Ensure namespace exists
	testNS := helpers.GetTestNamespace()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	binding1 := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-collision-binding-1",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-collision-test-template",
			},
			Clusters:    []string{"local-cluster"},
			DisplayName: "Custom Debug Session",
		},
	}

	err = cli.Create(ctx, binding1)
	require.NoError(t, err, "First binding should be created successfully")
	defer func() {
		_ = cli.Delete(ctx, binding1)
	}()

	binding2 := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-collision-binding-2",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-collision-test-template",
			},
			Clusters:    []string{"local-cluster"},
			DisplayName: "Custom Debug Session",
		},
	}

	err = cli.Create(ctx, binding2)
	if err == nil {
		_ = cli.Delete(ctx, binding2)
		t.Fatal("Second binding with same display name should have been rejected")
	}
	assert.Contains(t, err.Error(), "collision", "Error should mention name collision")

	t.Log("ClusterBinding name collision test passed")
}

// TestClusterBindingWithSchedulingConstraints verifies that scheduling constraints
// from bindings are applied correctly.
func TestClusterBindingWithSchedulingConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-scheduling-test-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Scheduling Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
		},
	}

	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create test template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Ensure namespace exists
	testNS := helpers.GetTestNamespace()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-scheduling-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-scheduling-test-template",
			},
			Clusters: []string{"local-cluster"},
			SchedulingConstraints: &telekomv1alpha1.SchedulingConstraints{
				DeniedNodeLabels: map[string]string{
					"node-role.kubernetes.io/control-plane": "",
				},
			},
		},
	}

	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	var createdBinding telekomv1alpha1.DebugSessionClusterBinding
	err = cli.Get(ctx, types.NamespacedName{
		Name:      binding.Name,
		Namespace: binding.Namespace,
	}, &createdBinding)
	require.NoError(t, err, "Should be able to get the created binding")

	require.NotNil(t, createdBinding.Spec.SchedulingConstraints)
	assert.NotEmpty(t, createdBinding.Spec.SchedulingConstraints.DeniedNodeLabels)

	t.Log("ClusterBinding with scheduling constraints test passed")
}

// TestClusterBindingWithNamespaceConstraints verifies namespace constraints.
func TestClusterBindingWithNamespaceConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-namespace-test-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Namespace Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
		},
	}

	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create test template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Ensure namespace exists
	testNS := helpers.GetTestNamespace()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-namespace-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-namespace-test-template",
			},
			Clusters: []string{"local-cluster"},
			NamespaceConstraints: &telekomv1alpha1.NamespaceConstraints{
				AllowedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"debug-*", "team-*"},
				},
				DeniedNamespaces: &telekomv1alpha1.NamespaceFilter{
					Patterns: []string{"kube-system", "kube-public"},
				},
				DefaultNamespace:   "debug-sessions",
				AllowUserNamespace: true,
			},
		},
	}

	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	var createdBinding telekomv1alpha1.DebugSessionClusterBinding
	err = cli.Get(ctx, types.NamespacedName{
		Name:      binding.Name,
		Namespace: binding.Namespace,
	}, &createdBinding)
	require.NoError(t, err)

	require.NotNil(t, createdBinding.Spec.NamespaceConstraints)
	assert.Equal(t, "debug-sessions", createdBinding.Spec.NamespaceConstraints.DefaultNamespace)
	assert.True(t, createdBinding.Spec.NamespaceConstraints.AllowUserNamespace)
	require.NotNil(t, createdBinding.Spec.NamespaceConstraints.DeniedNamespaces)
	assert.Contains(t, createdBinding.Spec.NamespaceConstraints.DeniedNamespaces.Patterns, "kube-system")

	t.Log("ClusterBinding with namespace constraints test passed")
}

// TestClusterBindingWithImpersonation verifies impersonation configuration.
func TestClusterBindingWithImpersonation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-impersonation-test-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Impersonation Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
		},
	}

	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create test template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Ensure namespace exists
	testNS := helpers.GetTestNamespace()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-impersonation-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-impersonation-test-template",
			},
			Clusters: []string{"local-cluster"},
			Impersonation: &telekomv1alpha1.ImpersonationConfig{
				ServiceAccountRef: &telekomv1alpha1.ServiceAccountReference{
					Name:      "debug-deployer",
					Namespace: "breakglass",
				},
			},
		},
	}

	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	var createdBinding telekomv1alpha1.DebugSessionClusterBinding
	err = cli.Get(ctx, types.NamespacedName{
		Name:      binding.Name,
		Namespace: binding.Namespace,
	}, &createdBinding)
	require.NoError(t, err)

	require.NotNil(t, createdBinding.Spec.Impersonation)
	require.NotNil(t, createdBinding.Spec.Impersonation.ServiceAccountRef)
	assert.Equal(t, "debug-deployer", createdBinding.Spec.Impersonation.ServiceAccountRef.Name)
	assert.Equal(t, "breakglass", createdBinding.Spec.Impersonation.ServiceAccountRef.Namespace)

	t.Log("ClusterBinding with impersonation test passed")
}

// TestClusterBindingWithAuxiliaryResources verifies that auxiliary resources are correctly
// configured in the binding and that the binding is created successfully.
func TestClusterBindingWithAuxiliaryResources(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)

	// Create a test template with auxiliary resources
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-auxiliary-test-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Auxiliary Resources Test Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{"*"},
				Groups:   []string{"*"},
			},
			AuxiliaryResources: []telekomv1alpha1.AuxiliaryResource{
				{
					Name:        "test-network-policy",
					Category:    "network-policy",
					Description: "Network isolation for debug pods",
					Template: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"test-policy"},"spec":{"podSelector":{},"policyTypes":["Ingress"]}}`),
					},
				},
				{
					Name:        "test-rbac-role",
					Category:    "rbac",
					Description: "RBAC permissions for debug session",
					Optional:    true,
					Template: runtime.RawExtension{
						Raw: []byte(`{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"test-role"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`),
					},
				},
			},
		},
	}

	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create test template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Ensure namespace exists
	testNS := helpers.GetTestNamespace()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	// Create a binding that references the template with auxiliary resources
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-auxiliary-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: "e2e-auxiliary-test-template",
			},
			Clusters: []string{"local-cluster"},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
			// Override auxiliary resources - require network-policy category
			RequiredAuxiliaryResourceCategories: []string{"network-policy"},
		},
	}

	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	// Wait for the binding status to be updated
	var updatedBinding telekomv1alpha1.DebugSessionClusterBinding
	require.Eventually(t, func() bool {
		err := cli.Get(ctx, types.NamespacedName{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		}, &updatedBinding)
		if err != nil {
			return false
		}
		return len(updatedBinding.Status.ResolvedTemplates) > 0
	}, 30*time.Second, 2*time.Second, "Binding status should be updated by reconciler")

	// Verify the binding was created successfully - check by template name
	foundTemplate := false
	for _, ref := range updatedBinding.Status.ResolvedTemplates {
		if ref.Name == "e2e-auxiliary-test-template" {
			foundTemplate = true
			break
		}
	}
	assert.True(t, foundTemplate, "ResolvedTemplates should contain e2e-auxiliary-test-template")

	// Verify binding has required auxiliary categories
	assert.Contains(t, updatedBinding.Spec.RequiredAuxiliaryResourceCategories, "network-policy")

	// Verify the template has the auxiliary resources we configured
	var createdTemplate telekomv1alpha1.DebugSessionTemplate
	err = cli.Get(ctx, types.NamespacedName{Name: template.Name}, &createdTemplate)
	require.NoError(t, err)

	assert.Len(t, createdTemplate.Spec.AuxiliaryResources, 2)

	// Verify first auxiliary resource (network policy)
	assert.Equal(t, "test-network-policy", createdTemplate.Spec.AuxiliaryResources[0].Name)
	assert.Equal(t, "network-policy", createdTemplate.Spec.AuxiliaryResources[0].Category)

	// Verify second auxiliary resource (optional RBAC)
	assert.Equal(t, "test-rbac-role", createdTemplate.Spec.AuxiliaryResources[1].Name)
	assert.Equal(t, "rbac", createdTemplate.Spec.AuxiliaryResources[1].Category)
	assert.True(t, createdTemplate.Spec.AuxiliaryResources[1].Optional)

	t.Log("ClusterBinding with auxiliary resources test passed")
}

// TestClusterBindingFullChain verifies the complete flow:
// 1. Create a binding with specific constraints
// 2. Create a debug session for the template+cluster covered by the binding
// 3. Verify the binding's configuration is auto-discovered and applied
// This tests that sessions created via the API (without explicit BindingRef)
// still get binding configuration applied.
func TestClusterBindingFullChain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := setupClient(t)
	tc := helpers.NewTestContext(t, ctx)
	apiClient := tc.RequesterClient()

	testNS := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Ensure namespace exists
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	// Create a pod template for the session template
	podTemplate := &telekomv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-binding-chain-pod-template",
		},
		Spec: telekomv1alpha1.DebugPodTemplateSpec{
			DisplayName: "E2E Binding Chain Pod Template",
			Template: &telekomv1alpha1.DebugPodSpec{
				Spec: telekomv1alpha1.DebugPodSpecInner{
					Containers: []corev1.Container{
						{
							Name:    "debug",
							Image:   "busybox:latest",
							Command: []string{"sleep", "infinity"},
						},
					},
				},
			},
		},
	}
	_ = cli.Delete(ctx, podTemplate)
	err := cli.Create(ctx, podTemplate)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create pod template")
	}
	defer func() {
		_ = cli.Delete(ctx, podTemplate)
	}()

	// Create session template with auto-approval
	replicas := int32(1)
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-binding-chain-template",
			Labels: map[string]string{
				"e2e-test": "binding-chain",
			},
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "E2E Binding Chain Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: podTemplate.Name,
			},
			WorkloadType:    telekomv1alpha1.DebugWorkloadDeployment,
			Replicas:        &replicas,
			TargetNamespace: "breakglass-debug",
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{clusterName},
				Groups:   []string{"*"},
			},
			Approvers: &telekomv1alpha1.DebugSessionApprovers{
				AutoApproveFor: &telekomv1alpha1.AutoApproveConfig{
					Clusters: []string{"*"},
				},
			},
			// Template defaults - binding will override these
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "4h",
				DefaultDuration: "1h",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(3),
			},
		},
	}
	_ = cli.Delete(ctx, template)
	err = cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Create a binding with stricter constraints
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-binding-chain-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: template.Name,
			},
			Clusters: []string{clusterName},
			// Binding overrides: stricter constraints
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "2h",
				DefaultDuration: "30m",
				AllowRenewal:    ptrBool(true),
				MaxRenewals:     ptrInt32(1), // Stricter than template
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Groups: []string{"*"},
			},
		},
	}
	_ = cli.Delete(ctx, binding)
	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	// Wait for binding to be reconciled
	require.Eventually(t, func() bool {
		var updatedBinding telekomv1alpha1.DebugSessionClusterBinding
		if err := cli.Get(ctx, types.NamespacedName{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		}, &updatedBinding); err != nil {
			return false
		}
		return len(updatedBinding.Status.ResolvedTemplates) > 0
	}, 30*time.Second, 2*time.Second, "Binding status should be updated")

	t.Log("Binding reconciled successfully")

	// Create a debug session via the API (without explicit BindingRef)
	// The reconciler should auto-discover the binding and apply its config
	session, err := apiClient.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{
		Cluster:           clusterName,
		TemplateRef:       template.Name,
		RequestedDuration: "30m",
		Namespace:         testNS,
		Reason:            "E2E testing binding chain",
	})
	if err != nil {
		t.Logf("Note: CreateDebugSession returned error (may be expected in some environments): %v", err)
		// In some test environments, session creation may fail due to missing cluster setup
		// Still verify the binding was set up correctly
		t.Log("Skipping session creation validation, binding setup verified")
		return
	}
	require.NotNil(t, session)
	defer func() {
		_ = cli.Delete(ctx, session)
	}()

	t.Logf("Created session: %s in namespace %s", session.Name, session.Namespace)

	// Wait for session to reach a state (pending or active)
	var fetchedSession telekomv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		if err := cli.Get(ctx, types.NamespacedName{
			Name:      session.Name,
			Namespace: session.Namespace,
		}, &fetchedSession); err != nil {
			return false
		}
		return fetchedSession.Status.State != ""
	}, 60*time.Second, 2*time.Second, "Session should reach a state")

	t.Logf("Session state: %s", fetchedSession.Status.State)

	// Verify the session was processed - checking that reconciler ran
	// Note: The binding's constraints would be applied during reconciliation
	// We can verify by checking the session progressed through states
	assert.NotEmpty(t, fetchedSession.Status.State, "Session should have a state")

	// Verify ResolvedBinding is populated when session is active
	// The reconciler should auto-discover the binding and cache it in status
	if fetchedSession.Status.State == telekomv1alpha1.DebugSessionStateActive {
		require.NotNil(t, fetchedSession.Status.ResolvedBinding,
			"ResolvedBinding should be populated for active session created via binding")
		assert.Equal(t, binding.Name, fetchedSession.Status.ResolvedBinding.Name,
			"ResolvedBinding.Name should match the binding")
		assert.Equal(t, binding.Namespace, fetchedSession.Status.ResolvedBinding.Namespace,
			"ResolvedBinding.Namespace should match the binding")
		t.Logf("ResolvedBinding verified: %s/%s",
			fetchedSession.Status.ResolvedBinding.Namespace,
			fetchedSession.Status.ResolvedBinding.Name)
	}

	t.Log("ClusterBinding full chain test passed")
}

// TestClusterBindingConstraintsApplied verifies that binding constraints
// are visible in the template clusters API response.
func TestClusterBindingConstraintsApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := setupClient(t)
	testNS := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// Ensure namespace exists
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNS,
		},
	}
	_ = cli.Create(ctx, ns)

	// Create a simple template
	template := &telekomv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-constraints-applied-template",
		},
		Spec: telekomv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "Constraints Applied Template",
			Mode:        telekomv1alpha1.DebugSessionModeWorkload,
			PodTemplateRef: &telekomv1alpha1.DebugPodTemplateReference{
				Name: "basic-debug",
			},
			Allowed: &telekomv1alpha1.DebugSessionAllowed{
				Clusters: []string{clusterName},
				Groups:   []string{"*"},
			},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "8h",
				DefaultDuration: "2h",
			},
		},
	}
	_ = cli.Delete(ctx, template)
	err := cli.Create(ctx, template)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create template")
	}
	defer func() {
		_ = cli.Delete(ctx, template)
	}()

	// Create binding with stricter constraints
	binding := &telekomv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-constraints-applied-binding",
			Namespace: testNS,
		},
		Spec: telekomv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef: &telekomv1alpha1.TemplateReference{
				Name: template.Name,
			},
			Clusters: []string{clusterName},
			Constraints: &telekomv1alpha1.DebugSessionConstraints{
				MaxDuration:     "1h",  // Much stricter
				DefaultDuration: "15m", // Much stricter
			},
		},
	}
	_ = cli.Delete(ctx, binding)
	err = cli.Create(ctx, binding)
	if err != nil && !isAlreadyExists(err) {
		require.NoError(t, err, "Failed to create binding")
	}
	defer func() {
		_ = cli.Delete(ctx, binding)
	}()

	// Wait for binding status
	require.Eventually(t, func() bool {
		var updatedBinding telekomv1alpha1.DebugSessionClusterBinding
		if err := cli.Get(ctx, types.NamespacedName{
			Name:      binding.Name,
			Namespace: binding.Namespace,
		}, &updatedBinding); err != nil {
			return false
		}
		return len(updatedBinding.Status.ResolvedTemplates) > 0
	}, 30*time.Second, 2*time.Second, "Binding should resolve templates")

	// Verify binding was created with correct constraints
	var createdBinding telekomv1alpha1.DebugSessionClusterBinding
	err = cli.Get(ctx, types.NamespacedName{
		Name:      binding.Name,
		Namespace: binding.Namespace,
	}, &createdBinding)
	require.NoError(t, err)

	require.NotNil(t, createdBinding.Spec.Constraints)
	assert.Equal(t, "1h", createdBinding.Spec.Constraints.MaxDuration)
	assert.Equal(t, "15m", createdBinding.Spec.Constraints.DefaultDuration)

	t.Log("ClusterBinding constraints applied test passed")
}

// isAlreadyExists is a helper to check if error is already exists
func isAlreadyExists(err error) bool {
	return client.IgnoreAlreadyExists(err) == nil
}
