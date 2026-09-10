// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package debug

import (
	"context"
	"encoding/json"
	"fmt"
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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestLegacyPendingUsesPersistedPolicyAfterLiveTemplateRotation(t *testing.T) {
	for _, constrained := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconstrained upgrade", true: "missing constrained provenance"}[constrained], func(t *testing.T) {
			ctx := context.Background()
			c, ds, template, target := newDeploymentFenceFixture(t)
			template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "hidden", InputType: breakglassv1alpha1.InputTypeText, Disabled: true}}
			template.Spec.PodOverridesTemplate = "nodeSelector:\n  approved: \"yes\"\n"
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
			template.Spec.PodOverridesTemplate = "nodeSelector:\n  approved: \"no\"\n"
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
			require.Equal(t, "yes", deployment.Spec.Template.Spec.NodeSelector["approved"])
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
		for _, raw := range []string{"missing", "null", "[]", "{}", `{"unknown":true}`, `{"templateRef":{},"clusters":[""]}`, `{"templateRef":{"name":" "},"clusters":["spoke"]}`, `{"templateRef":{"name":"template"},"clusters":[" "]}`, `{"templateRef":{"name":"template"},"clusters":["spoke"],"extraDeployVariables":[{"name":"absent","disabled":true}]}`} {
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

func TestAutoApprovalPersistsSnapshotBeforeActivationFailure(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	template.Spec.ExtraDeployVariables = []breakglassv1alpha1.ExtraDeployVariable{{Name: "value", InputType: breakglassv1alpha1.InputTypeText}}
	require.NoError(t, c.client.Update(t.Context(), template))
	ds.Status = breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending}
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	hub := c.client.(client.WithWatch)
	writes := 0
	c.client = interceptor.NewClient(hub, interceptor.Funcs{SubResourcePatch: func(ctx context.Context, cl client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
		if _, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
			writes++
			if writes == 2 {
				return fmt.Errorf("activation interrupted")
			}
		}
		return cl.Status().Patch(ctx, obj, patch, opts...)
	}})
	_, err := c.handlePending(t.Context(), ds)
	require.ErrorContains(t, err, "activation interrupted")
	require.NoError(t, hub.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	require.Equal(t, breakglassv1alpha1.DebugSessionStatePending, ds.Status.State)
	require.NotNil(t, ds.Status.ResolvedTemplate)
	require.True(t, ds.Status.ResolvedBindingSnapshotCaptured)
	require.NotNil(t, ds.Status.ResolvedTemplateVariablePolicy)
	require.Nil(t, ds.Status.ExpiresAt, "activation lease write failed after approval snapshot persistence")
	template.Spec.PodTemplateString = strings.ReplaceAll(template.Spec.PodTemplateString, "busybox", "unsafe")
	require.NoError(t, hub.Update(t.Context(), template))
	c.client = hub
	_, err = c.handlePending(t.Context(), ds)
	require.NoError(t, err)
	deployment := &appsv1.Deployment{}
	require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
	require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
}

func TestSessionDetailHidesRecoveryVariablePolicy(t *testing.T) {
	c, ds, _, _ := newDeploymentFenceFixture(t)
	ds.Status.ResolvedTemplateVariablePolicy = []breakglassv1alpha1.ExtraDeployVariable{{Name: "hidden", Default: &apiextensionsv1.JSON{Raw: []byte(`"private-policy-value"`)}}}
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
	router := gin.New()
	router.Use(func(ctx *gin.Context) {
		ctx.Set("legacy_identity_allowed", true)
		ctx.Set("username", ds.Spec.RequestedBy)
		ctx.Next()
	})
	require.NoError(t, api.Register(router.Group("/api/debugSessions")))
	request := httptest.NewRequest(http.MethodGet, "/api/debugSessions/"+ds.Name+"?namespace="+ds.Namespace, nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.NotContains(t, response.Body.String(), "private-policy-value")
	require.NotContains(t, response.Body.String(), "resolvedTemplateVariablePolicy")
	require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	require.Len(t, ds.Status.ResolvedTemplateVariablePolicy, 1)
	require.JSONEq(t, `"private-policy-value"`, string(ds.Status.ResolvedTemplateVariablePolicy[0].Default.Raw))
}

func TestActivationUsesApprovedPodReferenceBeforeLiveTemplate(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	ds.Status.State = breakglassv1alpha1.DebugSessionStatePending
	ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
	ds.Status.ResolvedBindingSnapshotCaptured = true
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	template.Spec.PodTemplateRef = &breakglassv1alpha1.DebugPodTemplateReference{Name: "unapproved-live-reference"}
	require.NoError(t, c.client.Update(t.Context(), template))
	_, err := c.activateSession(t.Context(), ds, template, nil)
	require.NoError(t, err)
	deployment := &appsv1.Deployment{}
	require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
	require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
}

func TestEmptyApprovedPolicyCannotSkipBindingConstraints(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	ds.Status.State = breakglassv1alpha1.DebugSessionStatePending
	ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
	ds.Status.ResolvedBindingSnapshotCaptured = true
	ds.Status.ResolvedBinding = &breakglassv1alpha1.ResolvedBindingRef{Name: "binding", Namespace: "default"}
	ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: []byte(`{"templateRef":{"name":"template"},"clusters":["spoke"],"extraDeployVariables":[{"name":"missing","disabled":true}]}`)}
	ds.Status.ResolvedTemplateVariablePolicy = []breakglassv1alpha1.ExtraDeployVariable{}
	require.NoError(t, c.client.Status().Update(t.Context(), ds))
	// Preserve the explicitly empty in-memory slice as well as persisted provenance.
	ds.Status.ResolvedTemplateVariablePolicy = []breakglassv1alpha1.ExtraDeployVariable{}
	_, err := c.activateSession(t.Context(), ds, template, nil)
	require.NoError(t, err)
	require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State)
	var deployments appsv1.DeploymentList
	require.NoError(t, target.List(t.Context(), &deployments))
	require.Empty(t, deployments.Items)
}

func TestNewNoVariableSessionAPIActivation(t *testing.T) {
	testNoVariableSessionAPIActivation(t, false)
}
func TestSelectorOnlyNoVariableSessionAPIActivation(t *testing.T) {
	testNoVariableSessionAPIActivation(t, true)
}

func testNoVariableSessionAPIActivation(t *testing.T, selectorOnly bool) {
	t.Helper()
	for _, mode := range []breakglassv1alpha1.DebugSessionTemplateMode{breakglassv1alpha1.DebugSessionModeWorkload, breakglassv1alpha1.DebugSessionModeKubectlDebug} {
		t.Run(string(mode), func(t *testing.T) {
			c, prior, template, target := newDeploymentFenceFixture(t)
			require.NoError(t, c.client.Delete(t.Context(), prior))
			template.Spec.Mode = mode
			template.Spec.Allowed = &breakglassv1alpha1.DebugSessionAllowed{ClusterSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"environment": "production"}}, Users: []string{"alice@example.com"}}
			if !selectorOnly {
				template.Spec.Allowed.ClusterSelector = nil
				template.Spec.Allowed.Clusters = []string{"*"}
			}
			if mode == breakglassv1alpha1.DebugSessionModeKubectlDebug {
				template.Spec.PodTemplateString = ""
				template.Spec.WorkloadType = ""
				template.Spec.KubectlDebug = &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}}}
			}
			require.NoError(t, c.client.Update(t.Context(), template))
			cc := &breakglassv1alpha1.ClusterConfig{}
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKey{Name: "spoke", Namespace: "default"}, cc))
			cc.Labels = map[string]string{"environment": "production"}
			cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Verified"}}
			require.NoError(t, c.client.Update(t.Context(), cc))
			// Invalid matching policy must not shadow this direct template grant.
			invalid := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: "invalid", Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{"spoke"}, ExtraDeployVariables: []breakglassv1alpha1.ExtraDeployVariableConstraint{{Name: "absent", Disabled: ptr.To(true)}}}}
			if mode == breakglassv1alpha1.DebugSessionModeWorkload {
				require.NoError(t, c.client.Create(t.Context(), invalid))
			}
			api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("legacy_identity_allowed", true)
				ctx.Set("username", "alice@example.com")
				ctx.Next()
			})
			require.NoError(t, api.Register(router.Group("/api/v1/"+api.BasePath())))
			if selectorOnly {
				// The same selector governs discovery, admission, and activation.
				discovery := httptest.NewRecorder()
				router.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates/template/clusters", nil))
				require.Equal(t, http.StatusOK, discovery.Code, discovery.Body.String())
				require.Contains(t, discovery.Body.String(), `"name":"spoke"`)
				cc.Labels["environment"] = "development"
				require.NoError(t, c.client.Update(t.Context(), cc))
				denied := httptest.NewRecorder()
				deniedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(`{"templateRef":"template","cluster":"spoke"}`))
				deniedRequest.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(denied, deniedRequest)
				require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
				cc.Labels["environment"] = "production"
				require.NoError(t, c.client.Update(t.Context(), cc))
			}

			request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(`{"templateRef":"template","cluster":"spoke"}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			sessions := &breakglassv1alpha1.DebugSessionList{}
			require.NoError(t, c.client.List(t.Context(), sessions))
			require.Len(t, sessions.Items, 1)
			ds := &sessions.Items[0]
			require.Empty(t, ds.Status.State)
			require.Nil(t, ds.Spec.BindingRef)
			_, err := c.handlePending(t.Context(), ds)
			require.NoError(t, err)
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
			require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State, ds.Status.Message)
			require.Nil(t, ds.Status.ResolvedBinding)
			// Binding activation publishes Active before the merged accounting
			// reconciler observes it; retries must retain exactly one active count.
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(template), template))
			require.EqualValues(t, 1, template.Status.ActiveSessionCount)
			require.NoError(t, c.reconcileActiveAccounting(t.Context(), ds, false))
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(template), template))
			require.EqualValues(t, 1, template.Status.ActiveSessionCount)

			if mode == breakglassv1alpha1.DebugSessionModeWorkload {
				deployment := &appsv1.Deployment{}
				require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
				require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
			}
		})
	}
}

func TestApprovedSnapshotActivationAfterTemplateDeletion(t *testing.T) {
	for _, scenario := range []string{"approved", "unapproved", "missing snapshot", "empty binding name", "invalid binding namespace"} {
		t.Run(scenario, func(t *testing.T) {
			c, ds, template, target := newDeploymentFenceFixture(t)
			ds.CreationTimestamp = metav1.Now()
			require.NoError(t, c.client.Update(t.Context(), ds))
			ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
			ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
			ds.Status.ResolvedBindingSnapshotCaptured = true
			ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: true}
			if scenario != "unapproved" {
				now := metav1.Now()
				ds.Status.Approval.ApprovedAt = &now
			}
			if scenario == "missing snapshot" {
				ds.Status.ResolvedTemplate = nil
			}
			if scenario == "empty binding name" || scenario == "invalid binding namespace" {
				ds.Status.ResolvedBinding = &breakglassv1alpha1.ResolvedBindingRef{Name: "binding", Namespace: "default"}
				if scenario == "empty binding name" {
					ds.Status.ResolvedBinding.Name = ""
				} else {
					ds.Status.ResolvedBinding.Namespace = "invalid/namespace"
				}
				ds.Status.ResolvedBindingSpec = &apiextensionsv1.JSON{Raw: []byte(`{"templateRef":{"name":"template"},"clusters":["spoke"]}`)}
			}
			require.NoError(t, c.client.Status().Update(t.Context(), ds))
			require.NoError(t, c.client.Delete(t.Context(), template))
			_, err := c.handlePendingApproval(t.Context(), ds)
			require.NoError(t, err)
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKeyFromObject(ds), ds))
			if scenario == "approved" {
				require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State, ds.Status.Message)
				deployment := &appsv1.Deployment{}
				require.NoError(t, target.Get(t.Context(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
				require.Equal(t, "busybox", deployment.Spec.Template.Spec.Containers[0].Image)
			} else {
				require.NotEqual(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State)
				deployments := &appsv1.DeploymentList{}
				require.NoError(t, target.List(t.Context(), deployments))
				require.Empty(t, deployments.Items)
			}
		})
	}
}

func TestExplicitVisibleBindingDoesNotSelectHiddenBinding(t *testing.T) {
	for _, selected := range []string{"z-visible", "a-hidden"} {
		t.Run(selected, func(t *testing.T) {
			c, prior, template, _ := newDeploymentFenceFixture(t)
			require.NoError(t, c.client.Delete(t.Context(), prior))
			template.Spec.Allowed = &breakglassv1alpha1.DebugSessionAllowed{Users: []string{"alice@example.com"}}
			require.NoError(t, c.client.Update(t.Context(), template))
			cc := &breakglassv1alpha1.ClusterConfig{}
			require.NoError(t, c.client.Get(t.Context(), client.ObjectKey{Name: "spoke", Namespace: "default"}, cc))
			cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Verified"}}
			require.NoError(t, c.client.Update(t.Context(), cc))
			for _, name := range []string{"a-hidden", "z-visible"} {
				binding := &breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"}, Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name}, Clusters: []string{"spoke"}, Hidden: name == "a-hidden"}}
				require.NoError(t, c.client.Create(t.Context(), binding))
			}
			api := NewDebugSessionAPIController(zap.NewNop().Sugar(), c.client, nil, nil)
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("legacy_identity_allowed", true)
				ctx.Set("username", "alice@example.com")
				ctx.Next()
			})
			require.NoError(t, api.Register(router.Group("/api/v1/"+api.BasePath())))
			discovery := httptest.NewRecorder()
			router.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/api/v1/debugSessions/templates/template/clusters", nil))
			require.Equal(t, http.StatusOK, discovery.Code, discovery.Body.String())
			require.Contains(t, discovery.Body.String(), "z-visible")
			require.NotContains(t, discovery.Body.String(), "a-hidden")
			request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(fmt.Sprintf(`{"templateRef":"template","cluster":"spoke","bindingRef":"default/%s"}`, selected)))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			sessions := &breakglassv1alpha1.DebugSessionList{}
			require.NoError(t, c.client.List(t.Context(), sessions))
			require.Len(t, sessions.Items, 1)
			require.NotNil(t, sessions.Items[0].Spec.BindingRef)
			require.Equal(t, selected, sessions.Items[0].Spec.BindingRef.Name)
		})
	}
}
