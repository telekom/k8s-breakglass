// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestApprovedBindingSnapshotServerSideApplyThenActivation exercises real
// API-server SSA and CRD pruning before the controller renders the workload.
// The spoke client is injected; this does not claim kubelet execution.
func TestApprovedBindingSnapshotServerSideApplyThenActivation(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	testEnv := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true}
	cfg, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testEnv.Stop()) })
	apiClient, err := client.New(cfg, client.Options{Scheme: testScheme()})
	require.NoError(t, err)
	c, ds, template, target := newDeploymentFenceFixture(t)
	persisted := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: ds.Name, Namespace: ds.Namespace}, Spec: ds.Spec}
	require.NoError(t, apiClient.Create(t.Context(), persisted))
	template.Spec.PodOverridesTemplate = "nodeSelector:\n  approved: \"yes\"\n"
	template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "hidden", InputType: breakglassv1alpha1.InputTypeText, Disabled: true}}
	persisted.Status = breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending, ResolvedTemplate: template.Spec.DeepCopy(), ResolvedBindingSnapshotCaptured: true}
	require.NoError(t, ssa.ApplyDebugSessionStatus(t.Context(), apiClient, persisted))
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(persisted), persisted))
	require.Equal(t, template.Spec.PodOverridesTemplate, persisted.Status.ResolvedTemplate.PodOverridesTemplate)
	require.True(t, persisted.Status.ResolvedTemplate.ExtraDeployVariables[0].Disabled)
	// Resume the controller with exactly the status returned by the API server.
	ds.Status = persisted.Status
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	template.Spec.PodTemplateString = strings.ReplaceAll(template.Spec.PodTemplateString, "busybox", "unsafe")
	template.Spec.PodOverridesTemplate = "nodeSelector:\n  approved: \"no\"\n"
	require.NoError(t, c.client.Update(t.Context(), template))
	_, err = c.handlePending(t.Context(), ds)
	require.NoError(t, err)
	deployment := &appsv1.Deployment{}
	require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
	require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
	require.Equal(t, "yes", deployment.Spec.Template.Spec.NodeSelector["approved"])
	require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State)
}
