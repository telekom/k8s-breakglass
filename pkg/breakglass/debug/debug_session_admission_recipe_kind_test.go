// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestAdmissionRecipeKind is a composed proof on a real Kind API server: HTTP
// request, independent approval, controller apply, real admission behaviour,
// drift, expiry and terminate reverts, and a controller restart in between.
// Run it with hack/admission-recipe-kind.sh.
func TestAdmissionRecipeKind(t *testing.T) {
	kubeconfig := os.Getenv("ADMISSION_RECIPE_KIND_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("run hack/admission-recipe-kind.sh for the disposable Kind proof")
	}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	ctx := t.Context()
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	scheme := testScheme()
	require.NoError(t, apiextensionsv1.AddToScheme(scheme))
	scheme.AddKnownTypeWithName(validatingPolicyGVK, &unstructured.Unstructured{})
	hub, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	// A minimal structural ValidatingPolicy CRD: enough for the real API server
	// to validate the field the recipe changes.
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "validatingpolicies.policies.kyverno.io"},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "policies.kyverno.io", Scope: apiextensionsv1.ClusterScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: "validatingpolicies", Singular: "validatingpolicy", Kind: "ValidatingPolicy", ListKind: "ValidatingPolicyList"},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{Name: "v1", Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
					Type: "object", Properties: map[string]apiextensionsv1.JSONSchemaProps{
						"spec": {Type: "object", Properties: map[string]apiextensionsv1.JSONSchemaProps{
							"validationActions": {Type: "array", Items: &apiextensionsv1.JSONSchemaPropsOrArray{Schema: &apiextensionsv1.JSONSchemaProps{
								Type: "string", Enum: []apiextensionsv1.JSON{{Raw: []byte(`"Deny"`)}, {Raw: []byte(`"Audit"`)}, {Raw: []byte(`"Warn"`)}}}}},
						}},
					}}}}},
		},
	}
	require.NoError(t, hub.Create(ctx, crd))
	require.Eventually(t, func() bool {
		live := &apiextensionsv1.CustomResourceDefinition{}
		if hub.Get(ctx, client.ObjectKeyFromObject(crd), live) != nil {
			return false
		}
		for _, condition := range live.Status.Conditions {
			if condition.Type == apiextensionsv1.Established && condition.Status == apiextensionsv1.ConditionTrue {
				return true
			}
		}
		return false
	}, time.Minute, time.Second)
	hub, err = client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	const namespace = "admission-recipe-proof"
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: map[string]string{"proof": "guarded"}}}))
	require.NoError(t, hub.Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "down-webhook", Namespace: namespace},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 443}}, Selector: map[string]string{"app": "absent"}}}))
	fail, none := admissionregistrationv1.Fail, admissionregistrationv1.SideEffectClassNone
	webhook := func(name string, labels map[string]string) admissionregistrationv1.ValidatingWebhook {
		return admissionregistrationv1.ValidatingWebhook{Name: name, FailurePolicy: &fail, SideEffects: &none,
			AdmissionReviewVersions: []string{"v1"}, TimeoutSeconds: ptr.To(int32(2)),
			ClientConfig:      admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: namespace, Name: "down-webhook"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: labels},
			Rules: []admissionregistrationv1.RuleWithOperations{{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
				Rule: admissionregistrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"configmaps"}}}},
		}
	}
	vwc := &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "proof-admission"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			webhook("guarded.proof.example.com", map[string]string{"proof": "guarded"}),
			webhook("decoy.proof.example.com", map[string]string{"proof": "decoy"}),
		}}
	require.NoError(t, hub.Create(ctx, vwc))
	createConfigMap := func(name string) error {
		return hub.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
	}
	require.Eventually(t, func() bool { return createConfigMap("before") != nil }, 30*time.Second, time.Second, "a down webhook with Fail blocks creates")

	for name, categories := range map[string]string{"require-labels": "platform-best-practices", "disallow-host-path": "critical_psa_platform-best-practices"} {
		require.NoError(t, hub.Create(ctx, recipePolicy(name, categories, "Deny")))
	}

	raw, err := os.ReadFile(kubeconfig)
	require.NoError(t, err)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: namespace}, Data: map[string][]byte{"value": raw}}
	require.NoError(t, hub.Create(ctx, secret))
	cc := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "recipe-spoke", Namespace: namespace},
		Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: secret.Name, Namespace: namespace}}}
	require.NoError(t, hub.Create(ctx, cc))
	cc.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "DisposableKindProof", LastTransitionTime: metav1.Now()}}
	cc.Status.ObservedGeneration = cc.Generation
	require.NoError(t, hub.Status().Update(ctx, cc))

	provider := cluster.NewClientProvider(hub, zap.NewNop().Sugar())
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 16, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	newController := func() *DebugSessionController {
		return NewDebugSessionController(zap.NewExample().Sugar(), hub, provider).WithAPIReader(hub).WithAuditManager(manager)
	}
	controller := newController()
	api := NewDebugSessionAPIController(zap.NewNop().Sugar(), hub, provider, nil).WithAPIReader(hub)
	router := gin.New()
	actor := "requester@example.com"
	router.Use(func(c *gin.Context) {
		c.Set("legacy_identity_allowed", true)
		c.Set("username", actor)
		c.Set("email", actor)
		c.Set("groups", []string{})
		c.Next()
	})
	require.NoError(t, api.Register(router.Group("/debugSessions")))
	call := func(as, method, path string, body []byte, expected int) []byte {
		t.Helper()
		actor = as
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		require.Equal(t, expected, response.Code, response.Body.String())
		return response.Body.Bytes()
	}
	reconcile := func(session *breakglassv1alpha1.DebugSession) {
		t.Helper()
		_, err := controller.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(session)})
		require.NoError(t, err)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
	}
	template := func(name string, recipe breakglassv1alpha1.DebugSessionAdmissionRecipe) {
		require.NoError(t, hub.Create(ctx, &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				Allowed:         &breakglassv1alpha1.DebugSessionAllowed{Users: []string{"requester@example.com"}, Clusters: []string{cc.Name}},
				Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver@example.com"}},
				Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "10m", DefaultDuration: "10m"},
				AdmissionRecipe: &recipe,
			}}))
	}
	request := func(templateName, duration string, targets []breakglassv1alpha1.AdmissionRecipeTarget, expected int) *breakglassv1alpha1.DebugSession {
		t.Helper()
		body, err := json.Marshal(CreateDebugSessionRequest{TemplateRef: templateName, Cluster: cc.Name, RequestedDuration: duration,
			Reason: "Disposable admission recipe proof", AdmissionRecipe: &breakglassv1alpha1.AdmissionRecipeRequest{Targets: targets}})
		require.NoError(t, err)
		response := call("requester@example.com", http.MethodPost, "/debugSessions", body, expected)
		if expected != http.StatusCreated {
			return nil
		}
		var created DebugSessionDetailResponse
		require.NoError(t, json.Unmarshal(response, &created))
		session := &created.DebugSession
		reconcile(session)
		require.Equal(t, breakglassv1alpha1.DebugSessionStatePendingApproval, session.Status.State, session.Status.Message)
		call("requester@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/approve?namespace="+session.Namespace, nil, http.StatusForbidden)
		call("approver@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/approve?namespace="+session.Namespace, nil, http.StatusOK)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
		reconcile(session)
		require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, session.Status.State, session.Status.Message)
		return session
	}

	t.Run("webhook fail-open until terminate", func(t *testing.T) {
		target := breakglassv1alpha1.AdmissionRecipeTarget{Kind: "ValidatingWebhookConfiguration", Name: "proof-admission", Webhook: "guarded.proof.example.com"}
		template("proof-webhook-fail-open", breakglassv1alpha1.DebugSessionAdmissionRecipe{Action: breakglassv1alpha1.AdmissionRecipeWebhookFailOpen,
			AllowedTargets: []breakglassv1alpha1.AdmissionRecipeTarget{target}})
		decoy := target
		decoy.Webhook = "decoy.proof.example.com"
		request("proof-webhook-fail-open", "10m", []breakglassv1alpha1.AdmissionRecipeTarget{decoy}, http.StatusBadRequest)
		session := request("proof-webhook-fail-open", "10m", []breakglassv1alpha1.AdmissionRecipeTarget{target}, http.StatusCreated)
		require.Eventually(t, func() bool { return createConfigMap("during") == nil }, 30*time.Second, time.Second, "fail-open admits creates")
		live := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(vwc), live))
		require.Equal(t, admissionregistrationv1.Fail, *live.Webhooks[1].FailurePolicy, "decoy webhook unchanged")
		call("requester@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/renew?namespace="+session.Namespace, []byte(`{"extendBy":"5m"}`), http.StatusBadRequest)

		controller = newController() // controller restart between apply and revert
		call("requester@example.com", http.MethodPost, "/debugSessions/"+session.Name+"/terminate?namespace="+session.Namespace, nil, http.StatusOK)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(session), session))
		reconcile(session)
		require.True(t, session.Status.AdmissionRecipe.Reverted, session.Status.Message)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(vwc), live))
		require.Equal(t, admissionregistrationv1.Fail, *live.Webhooks[0].FailurePolicy)
		require.NotContains(t, live.Annotations, breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
		require.Eventually(t, func() bool { return createConfigMap("after") != nil }, 30*time.Second, time.Second, "revert blocks creates again")
	})

	t.Run("policy audit refuses critical targets and reverts at expiry", func(t *testing.T) {
		allowed, critical := policyTarget("require-labels"), policyTarget("disallow-host-path")
		template("proof-policy-audit", breakglassv1alpha1.DebugSessionAdmissionRecipe{Action: breakglassv1alpha1.AdmissionRecipePolicyAudit, Flux: true,
			AllowedTargets:     []breakglassv1alpha1.AdmissionRecipeTarget{allowed, critical},
			DeniedTargetLabels: []breakglassv1alpha1.AdmissionRecipeDeniedLabel{{Key: "categories", ValuePattern: criticalCategoryPattern}}})
		request("proof-policy-audit", "1m", []breakglassv1alpha1.AdmissionRecipeTarget{critical}, http.StatusBadRequest)
		session := request("proof-policy-audit", "1m", []breakglassv1alpha1.AdmissionRecipeTarget{allowed}, http.StatusCreated)
		policy := &unstructured.Unstructured{}
		policy.SetGroupVersionKind(validatingPolicyGVK)
		require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: "require-labels"}, policy))
		require.Equal(t, []string{"Audit"}, policyActions(t, policy))
		require.Equal(t, "disabled", policy.GetAnnotations()[breakglassv1alpha1.FluxKustomizeReconcileAnnotation])
		require.Eventually(t, func() bool {
			reconcile(session)
			return session.Status.State != breakglassv1alpha1.DebugSessionStateActive
		}, 2*time.Minute, 5*time.Second, "the hard deadline expires the session")
		require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, session.Status.State)
		controller = newController()
		reconcile(session)
		require.True(t, session.Status.AdmissionRecipe.Reverted, session.Status.Message)
		require.NoError(t, hub.Get(ctx, client.ObjectKey{Name: "require-labels"}, policy))
		require.Equal(t, []string{"Deny"}, policyActions(t, policy))
		require.Empty(t, policy.GetAnnotations())
		types := map[audit.EventType]int{}
		for _, event := range sink.Events() {
			if event.Details["sessionUID"] == string(session.UID) {
				types[event.Type]++
			}
		}
		require.Equal(t, 1, types[audit.EventDebugSessionAdmissionRecipeApplied])
		require.Equal(t, 1, types[audit.EventDebugSessionAdmissionRecipeReverted])
	})
}
