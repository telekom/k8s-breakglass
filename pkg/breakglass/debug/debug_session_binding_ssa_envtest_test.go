// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
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
	for name, hasVariables := range map[string]bool{"variables": true, "empty-policy": false} {
		t.Run(name, func(t *testing.T) {
			c, ds, template, target := newDeploymentFenceFixture(t)
			persisted := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: ds.Name + "-" + name, Namespace: ds.Namespace}, Spec: ds.Spec}
			require.NoError(t, apiClient.Create(t.Context(), persisted))
			template.Spec.PodOverridesTemplate = "nodeSelector:\n  approved: \"yes\"\n"
			if hasVariables {
				template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "hidden", InputType: breakglassv1alpha1.InputTypeText, Disabled: true}}
			}
			persisted.Status = breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending, ResolvedTemplate: template.Spec.DeepCopy(), ResolvedBindingSnapshotCaptured: true}
			require.NoError(t, ssa.ApplyDebugSessionStatus(t.Context(), apiClient, persisted))
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(persisted), persisted))
			require.Equal(t, template.Spec.PodOverridesTemplate, persisted.Status.ResolvedTemplate.PodOverridesTemplate)
			if hasVariables {
				require.True(t, persisted.Status.ResolvedTemplate.ExtraDeployVariables[0].Disabled)
			} else {
				require.Nil(t, persisted.Status.ResolvedTemplateVariablePolicy)
				require.True(t, persisted.Status.ResolvedBindingSnapshotCaptured)
			}
			// The normal controller helper must refresh its caller's resource version
			// so consecutive snapshot and activation writes need no intervening Get.
			previousVersion := persisted.ResourceVersion
			persisted.Status.Message = "approved snapshot persisted"
			require.NoError(t, breakglass.ApplyDebugSessionStatus(t.Context(), apiClient, persisted))
			require.NotEqual(t, previousVersion, persisted.ResourceVersion)
			persisted.Status.Message = "activation next"
			require.NoError(t, breakglass.ApplyDebugSessionStatus(t.Context(), apiClient, persisted))
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
		})
	}
}

// TestPendingApprovalSnapshotsOnRealAPIServer covers the normal status writer,
// including JSON-only runtime regex fields and canonical empty policy slices.
func TestPendingApprovalSnapshotsOnRealAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	testEnv := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true}
	cfg, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testEnv.Stop()) })
	hub, err := client.New(cfg, client.Options{Scheme: testScheme()})
	require.NoError(t, err)
	for _, scenario := range []string{"regex", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			c, _, template, target := newDeploymentFenceFixture(t)
			if scenario == "regex" {
				for _, obj := range []client.Object{&breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: "default"}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: "default"}}} {
					require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(obj), obj))
					obj.SetResourceVersion("")
					obj.SetUID("")
					require.NoError(t, hub.Create(t.Context(), obj))
				}
				cc := &breakglassv1alpha1.ClusterConfig{}
				require.NoError(t, hub.Get(t.Context(), client.ObjectKey{Name: "spoke", Namespace: "default"}, cc))
				cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Verified", LastTransitionTime: metav1.Now()}}
				require.NoError(t, hub.Status().Update(t.Context(), cc))
			}
			c.client = hub
			c.apiReader = hub
			c.reader = hub
			c.ccProvider = cluster.NewClientProvider(hub, zap.NewNop().Sugar())
			template.Name = "snapshot-" + scenario
			template.ResourceVersion = ""
			template.UID = ""
			template.Spec.Allowed = &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Users: []string{"tester"}}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: template.Name, Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{"spoke"}}}
			values := ""
			if scenario == "regex" {
				template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "value", InputType: breakglassv1alpha1.InputTypeText, Validation: &breakglassv1alpha1.VariableValidation{Pattern: "^safe-"}}}
				binding.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariableConstraint{{Name: "value", Validation: &breakglassv1alpha1.VariableValidation{Pattern: "-prod$"}}}
				template.Spec.PodOverridesTemplate = "nodeSelector:\n  approved: {{ .vars.value | yamlQuote }}\n"
				values = `,"extraDeployValues":{"value":"safe-prod"}`
			}
			require.NoError(t, hub.Create(t.Context(), template))
			require.NoError(t, hub.Create(t.Context(), binding))
			api := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil)
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("legacy_identity_allowed", true)
				ctx.Set("username", "tester")
				ctx.Next()
			})
			require.NoError(t, api.Register(router.Group("/api/v1/"+api.BasePath())))
			request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(`{"templateRef":"`+template.Name+`","cluster":"spoke","bindingRef":"default/`+binding.Name+`"`+values+`}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var detail DebugSessionDetailResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &detail))
			ds := &detail.DebugSession
			require.NoError(t, hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
			_, err = c.handlePending(t.Context(), ds)
			require.NoError(t, err)
			require.NoError(t, hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State, ds.Status.Message)
			deployment := &appsv1.Deployment{}
			require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: ds.Spec.TargetNamespace, Name: ds.Name}, deployment))
			if scenario == "regex" {
				require.Empty(t, ds.Status.ResolvedTemplate.ExtraDeployVariables[0].Validation.AdditionalPatterns)
				require.Equal(t, "safe-prod", deployment.Spec.Template.Spec.NodeSelector["approved"])
			} else {
				require.Nil(t, ds.Status.ResolvedTemplate.ExtraDeployVariables)
				require.Nil(t, ds.Status.ResolvedTemplateVariablePolicy)
			}
		})
	}
}
