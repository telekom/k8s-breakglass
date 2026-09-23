// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCreateDebugSessionFencesAdmissionPolicy(t *testing.T) {
	for _, change := range []string{"unchanged", "template edited", "binding edited", "template replaced", "binding replaced", "no binding unchanged", "binding added", "template status", "no binding template status", "binding status", "template spec", "binding spec", "template annotation", "binding annotation"} {
		t.Run(change, func(t *testing.T) {
			template := &breakglassv1alpha1.DebugSessionTemplate{
				ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "original-template"},
				Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
					Mode:      breakglassv1alpha1.DebugSessionModeKubectlDebug,
					Approvers: &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
					Allowed:   &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"production"}},
				},
			}
			binding := &breakglassv1alpha1.DebugSessionClusterBinding{
				ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default", UID: "original-binding"},
				Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
					TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
					Clusters:    []string{"production"},
					Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
				},
			}
			cluster := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "production", Namespace: "default"}, Status: breakglassv1alpha1.ClusterConfigStatus{Conditions: []metav1.Condition{{Type: string(breakglassv1alpha1.ClusterConfigConditionReady), Status: metav1.ConditionTrue}}}}
			builder := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(template, cluster).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}, template, binding)
			noBinding := strings.HasPrefix(change, "no binding") || change == "binding added"
			if !noBinding {
				builder = builder.WithObjects(binding)
			}
			hub := builder.Build()
			api := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, nil, nil)
			router := gin.New()
			router.Use(func(ctx *gin.Context) {
				ctx.Set("legacy_identity_allowed", true)
				ctx.Set("username", "tester")
				ctx.Next()
			})
			require.NoError(t, api.Register(router.Group("/api/v1/"+api.BasePath())))
			body := `{"templateRef":"template","cluster":"production","bindingRef":"default/binding"}`
			if noBinding {
				body = `{"templateRef":"template","cluster":"production"}`
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			var detail DebugSessionDetailResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &detail))
			session := detail.DebugSession.DeepCopy()
			require.NoError(t, hub.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			require.NotEmpty(t, session.Annotations[breakglassv1alpha1.DebugSessionAdmissionPolicyAnnotation])
			require.Nil(t, session.Status.ResolvedTemplate)

			// Change policy after HTTP admission but before the first reconcile.
			var object client.Object = template
			if strings.HasPrefix(change, "binding") {
				object = binding
			}
			if change == "binding added" {
				require.NoError(t, hub.Create(t.Context(), binding))
			} else {
				require.NoError(t, hub.Get(t.Context(), client.ObjectKeyFromObject(object), object))
			}
			if strings.HasSuffix(change, "status") {
				previousVersion := object.GetResourceVersion()
				condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}
				switch typed := object.(type) {
				case *breakglassv1alpha1.DebugSessionTemplate:
					typed.Status.Conditions = []metav1.Condition{condition}
				case *breakglassv1alpha1.DebugSessionClusterBinding:
					typed.Status.Conditions = []metav1.Condition{condition}
				}
				require.NoError(t, hub.Status().Update(t.Context(), object))
				require.NotEqual(t, previousVersion, object.GetResourceVersion(), "status updates change resource versions without changing policy")
			} else if strings.HasSuffix(change, "spec") {
				switch typed := object.(type) {
				case *breakglassv1alpha1.DebugSessionTemplate:
					typed.Spec.Allowed.Clusters = append(typed.Spec.Allowed.Clusters, "another-cluster")
				case *breakglassv1alpha1.DebugSessionClusterBinding:
					typed.Spec.Clusters = append(typed.Spec.Clusters, "another-cluster")
				}
				require.NoError(t, hub.Update(t.Context(), object))
			} else if strings.HasSuffix(change, "annotation") {
				object.SetAnnotations(map[string]string{"changed": "after-admission"})
				require.NoError(t, hub.Update(t.Context(), object))
			} else if strings.HasSuffix(change, "edited") {
				object.SetLabels(map[string]string{"changed": "after-admission"})
				require.NoError(t, hub.Update(t.Context(), object))
			} else if strings.HasSuffix(change, "replaced") {
				require.NoError(t, hub.Delete(t.Context(), object))
				object.SetResourceVersion("")
				object.SetUID("replacement")
				require.NoError(t, hub.Create(t.Context(), object))
			}
			controller := NewDebugSessionController(zap.NewNop().Sugar(), hub, nil)
			_, err := controller.handlePending(t.Context(), session)
			require.NoError(t, err)
			require.NoError(t, hub.Get(t.Context(), client.ObjectKeyFromObject(session), session))
			if change == "unchanged" || change == "no binding unchanged" || strings.HasSuffix(change, "status") {
				require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, session.Status.State)
				require.NotNil(t, session.Status.ResolvedTemplate)
			} else {
				require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, session.Status.State)
				require.Contains(t, session.Status.Message, "changed after API admission")
				require.Nil(t, session.Status.ResolvedTemplate, "changed policy must not become an approved snapshot")
			}
		})
	}
}

func TestAdmissionPolicyVersionIncludesReferencedPodTemplate(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "template", UID: "template"}}
	pod := &breakglassv1alpha1.DebugPodTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", UID: "pod"},
		Spec:       breakglassv1alpha1.DebugPodTemplateSpec{TemplateString: "image: one"},
	}
	first, err := admissionPolicyVersion(template, nil, pod)
	require.NoError(t, err)
	pod.Spec.TemplateString = "image: two"
	second, err := admissionPolicyVersion(template, nil, pod)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
}
