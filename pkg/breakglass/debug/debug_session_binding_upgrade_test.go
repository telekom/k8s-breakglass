// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package debug

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestLegacyPendingUsesPersistedPolicyAfterLiveTemplateRotation(t *testing.T) {
	for _, constrained := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconstrained upgrade", true: "missing constrained provenance"}[constrained], func(t *testing.T) {
			ctx := context.Background()
			c, ds, template, target := newDeploymentFenceFixture(t)
			template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "hidden", InputType: breakglassv1alpha1.InputTypeText, Disabled: true}}
			ds.Status.State = breakglassv1alpha1.DebugSessionStatePending
			ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
			ds.Status.ResolvedBindingSnapshotCaptured = true
			if constrained {
				ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: []byte(`{"extraDeployVariables":[{"name":"hidden","disabled":true}]}`)}
			}
			// Exercise the native apply converter and JSON persistence before recovery.
			encoded, err := json.Marshal(ssa.DebugSessionStatusFrom(&ds.Status))
			require.NoError(t, err)
			ds.Status = breakglassv1alpha1.DebugSessionStatus{}
			require.NoError(t, json.Unmarshal(encoded, &ds.Status))
			require.True(t, ds.Status.ResolvedTemplate.ExtraDeployVariables[0].Disabled)
			require.NoError(t, c.client.Status().Update(ctx, ds))
			template.Spec.PodTemplateString = strings.ReplaceAll(template.Spec.PodTemplateString, "busybox", "unsafe")
			template.Spec.ExtraDeployVariables[0].Disabled = false
			require.NoError(t, c.client.Update(ctx, template))
			require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), ds))
			_, err = c.handlePending(ctx, ds)
			require.NoError(t, err)
			persisted := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, c.client.Get(ctx, client.ObjectKeyFromObject(ds), persisted))
			if constrained {
				require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, persisted.Status.State)
				require.Contains(t, persisted.Status.Message, "recreate")
				var deployments appsv1.DeploymentList
				require.NoError(t, target.List(ctx, &deployments))
				require.Empty(t, deployments.Items)
				return
			}
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, persisted.Status.State)
			require.True(t, persisted.Status.ResolvedTemplateVariablePolicy[0].Disabled)
			deployment := &appsv1.Deployment{}
			require.NoError(t, target.Get(ctx, client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
			require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
		})
	}
}

func TestBindingDefaultAdmissionDoesNotMaterializeHiddenTemplateDefaults(t *testing.T) {
	for _, provided := range []bool{false, true} {
		t.Run(map[bool]string{false: "binding default", true: "user value"}[provided], func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "default-policy"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Mode: breakglassv1alpha1.DebugSessionModeWorkload, Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Users: []string{"alice@example.com"}}, ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariable{
				{Name: "visible", InputType: breakglassv1alpha1.InputTypeText},
				{Name: "hidden", InputType: breakglassv1alpha1.InputTypeText, AllowedGroups: []string{"admins"}, Default: &apiextensionsv1.JSON{Raw: []byte(`"private-default"`)}},
			}}}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "defaults", Namespace: "breakglass"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{"production"}, ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariableConstraint{{Name: "visible", Default: &apiextensionsv1.JSON{Raw: []byte(`"binding-value"`)}}}}}
			cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "breakglass"}, Status: breakglassv1alpha1.ClusterConfigStatus{Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.ClusterConfigConditionReady), Status: metav1.ConditionTrue, Reason: "Verified"}}}}
			hub := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, binding, cluster).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			c := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil)
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("legacy_identity_allowed", true)
				ctx.Set("username", "alice@example.com")
				ctx.Next()
			})
			require.NoError(t, c.Register(router.Group("/api/v1/"+c.BasePath())))
			values := ""
			if provided {
				values = `,"extraDeployValues":{"visible":"user-value"}`
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(`{"templateRef":"default-policy","cluster":"production"`+values+`}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var sessions breakglassv1alpha1.DebugSessionList
			require.NoError(t, hub.List(context.Background(), &sessions))
			require.Len(t, sessions.Items, 1)
			require.NotContains(t, sessions.Items[0].Spec.ExtraDeployValues, "hidden")
			var value string
			require.NoError(t, json.Unmarshal(sessions.Items[0].Spec.ExtraDeployValues["visible"].Raw, &value))
			if provided {
				require.Equal(t, "user-value", value)
			} else {
				require.Equal(t, "binding-value", value)
			}
		})
	}
}

func TestPersistedBindingProvenanceFailsBeforeWorkloadCreation(t *testing.T) {
	for _, state := range []breakglassv1alpha1.DebugSessionState{breakglassv1alpha1.DebugSessionStatePending, breakglassv1alpha1.DebugSessionStatePendingApproval} {
		for _, raw := range []string{"missing", "null", "[]"} {
			t.Run(string(state)+"/"+raw, func(t *testing.T) {
				c, ds, template, target := newDeploymentFenceFixture(t)
				ds.Status.State = state
				ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
				ds.Status.ResolvedTemplate.ExtraDeployVariables = nil
				ds.Status.ResolvedBindingSnapshotCaptured = true
				ds.Status.ResolvedBinding = &breakglassv1alpha1.ResolvedBindingRef{Name: "approved-binding", Namespace: "breakglass"}
				if raw != "missing" {
					ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: []byte(raw)}
				}
				require.NoError(t, c.client.Status().Update(t.Context(), ds))
				var err error
				if state == breakglassv1alpha1.DebugSessionStatePending {
					_, err = c.handlePending(t.Context(), ds)
				} else {
					_, err = c.activateSession(t.Context(), ds, template, nil)
				}
				require.NoError(t, err)
				require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
				require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
				require.Contains(t, ds.Status.Message, "recreate")
				var deployments appsv1.DeploymentList
				require.NoError(t, target.List(t.Context(), &deployments))
				require.Empty(t, deployments.Items)
			})
		}
	}
}

func TestBindingDiscoverySkipsInvalidPolicy(t *testing.T) {
	c, _, template, _ := newDeploymentFenceFixture(t)
	template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "mode", InputType: breakglassv1alpha1.InputTypeSelect, Options: []breakglassv1alpha1.SelectOption{{Value: "safe"}}}}
	invalid := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "a-invalid", Namespace: "breakglass"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{"target"}, ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariableConstraint{{Name: "mode", AllowedValues: []string{"unknown"}}}}}
	valid := invalid.DeepCopy()
	valid.Name = "z-valid"
	valid.Spec.ExtraDeployVariables[0].AllowedValues = []string{"safe"}
	require.NoError(t, c.client.Create(t.Context(), invalid))
	require.NoError(t, c.client.Create(t.Context(), valid))
	binding, err := c.findBindingForSession(t.Context(), template, "target")
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, valid.Name, binding.Name)
	require.NoError(t, c.client.Delete(t.Context(), valid))
	_, err = c.findBindingForSession(t.Context(), template, "target")
	require.ErrorContains(t, err, "invalid variable policy")
}

func TestBindingRestrictedDefaultSurvivesAPIAndActivation(t *testing.T) {
	for _, restriction := range []string{"variable", "option"} {
		for _, provided := range []string{"", "busybox", "unsafe"} {
			t.Run(restriction+"/"+provided, func(t *testing.T) {
				c, prior, template, target := newDeploymentFenceFixture(t)
				require.NoError(t, c.client.Delete(t.Context(), prior))
				template.Spec.Allowed = &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"*"}, Users: []string{"alice@example.com"}}
				variable := breakglassv1alpha1.ExtraDeployVariable{Name: "image", InputType: breakglassv1alpha1.InputTypeSelect, Options: []breakglassv1alpha1.SelectOption{{Value: "busybox"}, {Value: "unsafe"}}}
				if restriction == "variable" {
					variable.AllowedGroups = []string{"admins"}
				} else {
					for i := range variable.Options {
						variable.Options[i].AllowedGroups = []string{"admins"}
					}
				}
				template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{variable}
				template.Spec.PodTemplateString = strings.ReplaceAll(template.Spec.PodTemplateString, "busybox", "{{ .vars.image | yamlQuote }}")
				require.NoError(t, c.client.Update(t.Context(), template))
				cluster := &breakglassv1alpha1.ClusterConfig{}
				require.NoError(t, c.client.Get(t.Context(), client.ObjectKey{Name: "spoke", Namespace: "default"}, cluster))
				cluster.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Verified"}}
				require.NoError(t, c.client.Update(t.Context(), cluster))
				binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{"spoke"}, ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariableConstraint{{Name: "image", Default: &apiextensionsv1.JSON{Raw: []byte(`"busybox"`)}}}}}
				require.NoError(t, c.client.Create(t.Context(), binding))
				api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
				router := gin.New()
				router.Use(func(ctx *gin.Context) {
					ctx.Set("legacy_identity_allowed", true)
					ctx.Set("username", "alice@example.com")
					ctx.Next()
				})
				require.NoError(t, api.Register(router.Group("/api/v1/"+api.BasePath())))
				values := ""
				if provided != "" {
					values = `,"extraDeployValues":{"image":"` + provided + `"}`
				}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(`{"templateRef":"template","cluster":"spoke"`+values+`}`))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if provided == "unsafe" {
					require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
					// Direct CR creation must enforce the same non-default group denial.
					prior.ResourceVersion = ""
					prior.Spec.Cluster = "spoke"
					prior.Spec.ExtraDeployValues = map[string]apiextensionsv1.JSON{"image": {Raw: []byte(`"unsafe"`)}}
					prior.Status = breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending}
					require.NoError(t, c.client.Create(t.Context(), prior))
					_, err := c.handlePending(t.Context(), prior)
					require.NoError(t, err)
					require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(prior), prior))
					require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, prior.Status.State)
					var deployments appsv1.DeploymentList
					require.NoError(t, target.List(t.Context(), &deployments))
					require.Empty(t, deployments.Items)
					return
				}
				require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
				var sessions breakglassv1alpha1.DebugSessionList
				require.NoError(t, c.client.List(t.Context(), &sessions))
				require.Len(t, sessions.Items, 1)
				ds := &sessions.Items[0]
				require.JSONEq(t, `"busybox"`, string(ds.Spec.ExtraDeployValues["image"].Raw))
				_, err := c.handlePending(t.Context(), ds)
				require.NoError(t, err)
				require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
				require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State, ds.Status.Message)
				deployment := &appsv1.Deployment{}
				require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
				require.Len(t, deployment.Spec.Template.Spec.Containers, 1)
				require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
			})
		}
	}
}
