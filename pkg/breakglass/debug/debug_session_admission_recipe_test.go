// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var validatingPolicyGVK = schema.GroupVersionKind{Group: "policies.kyverno.io", Version: "v1", Kind: "ValidatingPolicy"}

const criticalCategoryPattern = `(.+_)?(platform-)?critical(_.+)?`

func recipePolicy(name, categories string, actions ...string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(validatingPolicyGVK)
	obj.SetName(name)
	obj.SetLabels(map[string]string{"categories": categories})
	values := make([]interface{}, 0, len(actions))
	for _, action := range actions {
		values = append(values, action)
	}
	obj.Object["spec"] = map[string]interface{}{"validationActions": values}
	return obj
}

func recipeWebhookConfiguration() *admissionregistrationv1.ValidatingWebhookConfiguration {
	fail := admissionregistrationv1.Fail
	none := admissionregistrationv1.SideEffectClassNone
	webhook := func(name string) admissionregistrationv1.ValidatingWebhook {
		return admissionregistrationv1.ValidatingWebhook{Name: name, FailurePolicy: &fail, SideEffects: &none,
			AdmissionReviewVersions: []string{"v1"}, ClientConfig: admissionregistrationv1.WebhookClientConfig{URL: ptr.To("https://webhook.invalid")}}
	}
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "ingress-nginx-admission"},
		Webhooks:   []admissionregistrationv1.ValidatingWebhook{webhook("validate.nginx.ingress.kubernetes.io"), webhook("other.example.com")},
	}
}

type recipeFixture struct {
	c     *DebugSessionController
	ds    *breakglassv1alpha1.DebugSession
	spoke client.Client
	sink  *maintenanceAuditCaptureSink
}

func newRecipeFixture(t *testing.T, recipe breakglassv1alpha1.DebugSessionAdmissionRecipe, request []breakglassv1alpha1.AdmissionRecipeTarget, objects ...client.Object) *recipeFixture {
	t.Helper()
	controller, ds, _, _ := newDeploymentFenceFixture(t)
	ds.Spec.AdmissionRecipe = &breakglassv1alpha1.AdmissionRecipeRequest{Targets: request}
	require.NoError(t, controller.client.Update(t.Context(), ds))
	spec := breakglassv1alpha1.DebugSessionTemplateSpec{
		Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
		Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "30m"},
		AdmissionRecipe: &recipe,
	}
	now := metav1.Now()
	ds.Status.ResolvedTemplate = &spec
	ds.Status.ResolvedTemplateIdentityCaptured = true
	ds.Status.AuthenticatedUserGroupsCaptured = true
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: true, ApprovedBy: "approver", ApprovedByIdentityProvider: "keycloak", ApprovedAt: &now}
	require.NoError(t, controller.client.Status().Update(t.Context(), ds))
	scheme := testScheme()
	scheme.AddKnownTypeWithName(validatingPolicyGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(validatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"), &unstructured.UnstructuredList{})
	spoke := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	controller.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return spoke, nil }
	sink := &maintenanceAuditCaptureSink{}
	manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	controller.WithAuditManager(manager)
	return &recipeFixture{c: controller, ds: ds, spoke: spoke, sink: sink}
}

func policyTarget(name string) breakglassv1alpha1.AdmissionRecipeTarget {
	return breakglassv1alpha1.AdmissionRecipeTarget{Kind: "ValidatingPolicy", APIVersion: "policies.kyverno.io/v1", Name: name}
}

func policyRecipe(flux bool, targets ...breakglassv1alpha1.AdmissionRecipeTarget) breakglassv1alpha1.DebugSessionAdmissionRecipe {
	return breakglassv1alpha1.DebugSessionAdmissionRecipe{
		Action: breakglassv1alpha1.AdmissionRecipePolicyAudit, AllowedTargets: targets, Flux: flux,
		DeniedTargetLabels: []breakglassv1alpha1.AdmissionRecipeDeniedLabel{{Key: "categories", ValuePattern: criticalCategoryPattern}},
	}
}

func getPolicy(t *testing.T, spoke client.Client, name string) *unstructured.Unstructured {
	t.Helper()
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(validatingPolicyGVK)
	require.NoError(t, spoke.Get(t.Context(), client.ObjectKey{Name: name}, obj))
	return obj
}

func policyActions(t *testing.T, obj *unstructured.Unstructured) []string {
	t.Helper()
	actions, _, err := unstructured.NestedStringSlice(obj.Object, "spec", "validationActions")
	require.NoError(t, err)
	return actions
}

func TestAdmissionRecipePolicyAuditAppliesAndReverts(t *testing.T) {
	target := policyTarget("require-pod-probes")
	policy := recipePolicy("require-pod-probes", "platform-best-practices", "Deny")
	policy.SetAnnotations(map[string]string{breakglassv1alpha1.FluxHelmDriftDetectionAnnotation: "warn"})
	f := newRecipeFixture(t, policyRecipe(true, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, policy)

	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	require.True(t, hasAdmissionRecipeFinalizer(f.ds))
	live := getPolicy(t, f.spoke, "require-pod-probes")
	require.Equal(t, []string{"Audit"}, policyActions(t, live))
	require.Equal(t, string(f.ds.UID), live.GetAnnotations()[breakglassv1alpha1.AdmissionRecipeSessionAnnotation])
	require.Equal(t, "disabled", live.GetAnnotations()[breakglassv1alpha1.FluxHelmDriftDetectionAnnotation])
	require.Equal(t, "disabled", live.GetAnnotations()[breakglassv1alpha1.FluxKustomizeReconcileAnnotation])
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.Equal(t, `["Deny"]`, f.ds.Status.AdmissionRecipe.Targets[0].Original)
	require.Len(t, f.sink.Events(), 1)
	require.Equal(t, audit.EventDebugSessionAdmissionRecipeApplied, f.sink.Events()[0].Type)

	// A second reconcile must not write again or emit another intent.
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	require.Len(t, f.sink.Events(), 1)
	require.NoError(t, f.c.detectAdmissionRecipeDrift(t.Context(), f.ds))
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)

	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
	live = getPolicy(t, f.spoke, "require-pod-probes")
	require.Equal(t, []string{"Deny"}, policyActions(t, live))
	require.NotContains(t, live.GetAnnotations(), breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
	require.NotContains(t, live.GetAnnotations(), breakglassv1alpha1.FluxKustomizeReconcileAnnotation)
	require.Equal(t, "warn", live.GetAnnotations()[breakglassv1alpha1.FluxHelmDriftDetectionAnnotation], "pre-existing Flux annotation is restored")
	require.True(t, f.ds.Status.AdmissionRecipe.Reverted)
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetReverted, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.Len(t, f.sink.Events(), 2)
	require.Equal(t, audit.EventDebugSessionAdmissionRecipeReverted, f.sink.Events()[1].Type)
	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds), "revert is idempotent")
	require.Len(t, f.sink.Events(), 2)
}

func TestAdmissionRecipeWebhookFailOpenChangesOnlyTheNamedWebhook(t *testing.T) {
	target := breakglassv1alpha1.AdmissionRecipeTarget{Kind: "ValidatingWebhookConfiguration", Name: "ingress-nginx-admission", Webhook: "validate.nginx.ingress.kubernetes.io"}
	recipe := breakglassv1alpha1.DebugSessionAdmissionRecipe{Action: breakglassv1alpha1.AdmissionRecipeWebhookFailOpen, AllowedTargets: []breakglassv1alpha1.AdmissionRecipeTarget{target}}
	f := newRecipeFixture(t, recipe, []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipeWebhookConfiguration())

	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	live := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "ingress-nginx-admission"}, live))
	require.Equal(t, admissionregistrationv1.Ignore, *live.Webhooks[0].FailurePolicy)
	require.Equal(t, admissionregistrationv1.Fail, *live.Webhooks[1].FailurePolicy)
	require.NotContains(t, live.Annotations, breakglassv1alpha1.FluxHelmDriftDetectionAnnotation, "flux disabled")

	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "ingress-nginx-admission"}, live))
	require.Equal(t, admissionregistrationv1.Fail, *live.Webhooks[0].FailurePolicy)
	require.Empty(t, live.Annotations)
}

func TestAdmissionRecipeRefusesDeniedForeignAndUnexpectedTargets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy *unstructured.Unstructured
		want   string
	}{
		{"critical folder", recipePolicy("disallow-host-path", "critical_psa_platform-best-practices", "Deny"), "denied by label"},
		{"platform-critical", recipePolicy("disallow-host-path", "platform-critical", "Deny"), "denied by label"},
		{"critical last token", recipePolicy("disallow-host-path", "psa_platform-best-practices_critical", "Deny"), "denied by label"},
		{"already audit", recipePolicy("disallow-host-path", "psa", "Audit"), "expected starting value"},
		{"foreign session", func() *unstructured.Unstructured {
			p := recipePolicy("disallow-host-path", "psa", "Deny")
			p.SetAnnotations(map[string]string{breakglassv1alpha1.AdmissionRecipeSessionAnnotation: "other-session"})
			return p
		}(), "another session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := policyTarget("disallow-host-path")
			f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, tc.policy)
			require.ErrorContains(t, f.c.validateAdmissionRecipePending(t.Context(), f.ds, &breakglassv1alpha1.DebugSessionTemplate{Spec: *f.ds.Status.ResolvedTemplate}, nil), tc.want)
			require.ErrorContains(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), tc.want)
			live := getPolicy(t, f.spoke, "disallow-host-path")
			require.Equal(t, tc.policy.Object["spec"], live.Object["spec"], "a refused target is never written")
			require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetNotApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)
			require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
			require.True(t, f.ds.Status.AdmissionRecipe.Reverted)
		})
	}
}

func TestAdmissionRecipeDriftIsReportedAndNotOverwritten(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "platform-best-practices", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	live := getPolicy(t, f.spoke, "require-labels")
	require.NoError(t, unstructured.SetNestedStringSlice(live.Object, []string{"Deny", "Audit"}, "spec", "validationActions"))
	require.NoError(t, f.spoke.Update(t.Context(), live))

	require.NoError(t, f.c.detectAdmissionRecipeDrift(t.Context(), f.ds))
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetDrifted, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.Equal(t, audit.EventDebugSessionAdmissionRecipeDrift, f.sink.Events()[1].Type)
	require.Equal(t, []string{"Deny", "Audit"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")), "drift is never overwritten")

	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
	live = getPolicy(t, f.spoke, "require-labels")
	require.Equal(t, []string{"Deny", "Audit"}, policyActions(t, live), "a value someone else set is left as is")
	require.NotContains(t, live.GetAnnotations(), breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, f.ds.Status.AdmissionRecipe.Targets[0].State)
}

func TestAdmissionRecipeDriftReceiptPrecedesTheStateChange(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "platform-best-practices", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	live := getPolicy(t, f.spoke, "require-labels")
	require.NoError(t, unstructured.SetNestedStringSlice(live.Object, []string{"Deny", "Audit"}, "spec", "validationActions"))
	require.NoError(t, f.spoke.Update(t.Context(), live))

	manager := f.c.currentAuditManager()
	f.c.WithAuditManager(nil)
	require.ErrorContains(t, f.c.detectAdmissionRecipeDrift(t.Context(), f.ds), "durable audit")
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplied, f.ds.Status.AdmissionRecipe.Targets[0].State, "no state change without a receipt")
	f.c.WithAuditManager(manager)
	require.NoError(t, f.c.detectAdmissionRecipeDrift(t.Context(), f.ds))
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetDrifted, f.ds.Status.AdmissionRecipe.Targets[0].State)
	events := f.sink.Events()
	require.Equal(t, audit.EventDebugSessionAdmissionRecipeDrift, events[len(events)-1].Type)
}

func TestAdmissionRecipeRevertsWhenOnlyTheSessionAnnotationWasStripped(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	live := getPolicy(t, f.spoke, "require-labels")
	annotations := live.GetAnnotations()
	delete(annotations, breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
	live.SetAnnotations(annotations)
	require.NoError(t, f.spoke.Update(t.Context(), live))
	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")), "the value this session wrote is restored")
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetReverted, f.ds.Status.AdmissionRecipe.Targets[0].State)
}

func TestAdmissionRecipeRevertRetryAfterAnUnrecordedRevert(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	// The first revert restored the target, then its status write failed.
	live := getPolicy(t, f.spoke, "require-labels")
	annotations := live.GetAnnotations()
	delete(annotations, breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
	delete(annotations, breakglassv1alpha1.AdmissionRecipeExpiresAnnotation)
	live.SetAnnotations(annotations)
	require.NoError(t, unstructured.SetNestedStringSlice(live.Object, []string{"Deny"}, "spec", "validationActions"))
	require.NoError(t, f.spoke.Update(t.Context(), live))
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetReverted, f.ds.Status.AdmissionRecipe.Targets[0].State,
		"a restored field is not a change by another writer")
	require.Empty(t, f.ds.Status.AdmissionRecipe.Targets[0].Message)
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipeDeletingAnExpiredActiveSessionReverts(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	past := metav1.NewTime(time.Now().Add(-time.Minute))
	f.ds.Status.ExpiresAt = &past
	require.NoError(t, f.c.client.Status().Update(t.Context(), f.ds))
	require.NoError(t, f.c.client.Delete(t.Context(), f.ds))
	_, err := f.c.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.ds)})
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(f.c.client.Get(t.Context(), client.ObjectKeyFromObject(f.ds), &breakglassv1alpha1.DebugSession{})))
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipeRecoversInterruptedWrites(t *testing.T) {
	target := policyTarget("require-labels")
	t.Run("write happened, status lost", func(t *testing.T) {
		policy := recipePolicy("require-labels", "psa", "Deny")
		f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, policy)
		writes := 0
		// Fail the status patch that records "applied" once, after the target write.
		require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
		require.NoError(t, f.c.setAdmissionRecipeTargetState(t.Context(), f.ds, 0, breakglassv1alpha1.AdmissionRecipeTargetApplying, ""))
		f.spoke = interceptor.NewClient(f.spoke.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			writes++
			return cl.Update(ctx, obj, opts...)
		}})
		f.c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return f.spoke, nil }
		require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
		require.Zero(t, writes, "an already written target is not written again")
		require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)
	})
	t.Run("intent recorded, write never happened", func(t *testing.T) {
		policy := recipePolicy("require-labels", "psa", "Deny")
		f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, policy)
		failing := interceptor.NewClient(f.spoke.(client.WithWatch), interceptor.Funcs{Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			return errors.New("connection reset")
		}})
		f.c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return failing, nil }
		require.ErrorContains(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), "connection reset")
		require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplying, f.ds.Status.AdmissionRecipe.Targets[0].State)
		f.c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return f.spoke, nil }
		require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
		require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetNotApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)
		require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
	})
}

func TestAdmissionRecipeRequiresIndependentLiveApproval(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	f.ds.Status.Approval.ApprovedBy = f.ds.Spec.RequestedBy
	require.ErrorContains(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), "independently approved")
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipeDeletionRevertsBeforeReleasingTheSession(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	require.NoError(t, f.c.client.Delete(t.Context(), f.ds))
	_, err := f.c.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(f.ds)})
	require.NoError(t, err)
	require.True(t, apierrors.IsNotFound(f.c.client.Get(t.Context(), client.ObjectKeyFromObject(f.ds), &breakglassv1alpha1.DebugSession{})))
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipeExpiryRevertsThroughCleanup(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	require.True(t, hasTrackedSpokeResources(f.ds))
	past := metav1.NewTime(time.Now().Add(-time.Minute))
	f.ds.Status.ExpiresAt = &past
	require.NoError(t, f.c.client.Status().Update(t.Context(), f.ds))
	_, err := f.c.handleAdmissionRecipeActive(t.Context(), f.ds)
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateExpired, f.ds.Status.State)
	require.NoError(t, f.c.cleanupResources(t.Context(), f.ds))
	require.True(t, f.ds.Status.AdmissionRecipe.Reverted)
	require.False(t, hasTrackedSpokeResources(f.ds))
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipeAuditFailureBlocksEveryWrite(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	f.c.WithAuditManager(nil)
	require.ErrorContains(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), "durable audit")
	require.Nil(t, f.ds.Status.AdmissionRecipe, "no inventory without an intent receipt")
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
	require.ErrorContains(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), "durable audit", "a retry still needs the receipt")
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipePartialApplyIsRevertedOnFailure(t *testing.T) {
	first, second := policyTarget("require-labels"), policyTarget("require-pod-probes")
	f := newRecipeFixture(t, policyRecipe(false, first, second), []breakglassv1alpha1.AdmissionRecipeTarget{first, second},
		recipePolicy("require-labels", "psa", "Deny"), recipePolicy("require-pod-probes", "critical_psa", "Deny"))
	require.ErrorContains(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), "denied by label")
	require.Equal(t, []string{"Audit"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
	require.True(t, hasTrackedSpokeResources(f.ds))
	_, err := f.c.failSession(t.Context(), f.ds, "invalid admission recipe target")
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, f.ds.Status.State)
	require.True(t, f.ds.Status.AdmissionRecipe.Reverted)
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-pod-probes")))
}

func TestAdmissionRecipeConcurrentWriterConflictRetries(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	conflicted := false
	racing := interceptor.NewClient(f.spoke.(client.WithWatch), interceptor.Funcs{Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
		if !conflicted {
			conflicted = true
			return apierrors.NewConflict(schema.GroupResource{Group: "policies.kyverno.io", Resource: "validatingpolicies"}, obj.GetName(), errors.New("modified"))
		}
		return cl.Update(ctx, obj, opts...)
	}})
	f.c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return racing, nil }
	err := f.c.applyAdmissionRecipe(t.Context(), f.ds)
	require.True(t, isDebugSessionDeploymentConflict(err), "a conflict requeues activation instead of failing the session: %v", err)
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplying, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds), "the next reconcile re-reads and writes once")
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetApplied, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.Equal(t, []string{"Audit"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}

func TestAdmissionRecipeRevertSurvivesRemovedWebhookEntry(t *testing.T) {
	target := breakglassv1alpha1.AdmissionRecipeTarget{Kind: "ValidatingWebhookConfiguration", Name: "ingress-nginx-admission", Webhook: "validate.nginx.ingress.kubernetes.io"}
	recipe := breakglassv1alpha1.DebugSessionAdmissionRecipe{Action: breakglassv1alpha1.AdmissionRecipeWebhookFailOpen, AllowedTargets: []breakglassv1alpha1.AdmissionRecipeTarget{target}}
	f := newRecipeFixture(t, recipe, []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipeWebhookConfiguration())
	require.NoError(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	live := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "ingress-nginx-admission"}, live))
	live.Webhooks = live.Webhooks[1:]
	require.NoError(t, f.spoke.Update(t.Context(), live))
	require.NoError(t, f.c.revertAdmissionRecipe(t.Context(), f.ds))
	require.True(t, f.ds.Status.AdmissionRecipe.Reverted)
	require.Equal(t, breakglassv1alpha1.AdmissionRecipeTargetRevertSkipped, f.ds.Status.AdmissionRecipe.Targets[0].State)
	require.NoError(t, f.spoke.Get(t.Context(), client.ObjectKey{Name: "ingress-nginx-admission"}, live))
	require.NotContains(t, live.Annotations, breakglassv1alpha1.AdmissionRecipeSessionAnnotation)
}

func TestAdmissionRecipeBindingCannotEnableRenewal(t *testing.T) {
	template := &breakglassv1alpha1.DebugSessionTemplate{Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		Approvers:       &breakglassv1alpha1.DebugSessionApprovers{Users: []string{"approver"}},
		Constraints:     &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "30m"},
		AdmissionRecipe: &breakglassv1alpha1.DebugSessionAdmissionRecipe{Action: breakglassv1alpha1.AdmissionRecipePolicyAudit, AllowedTargets: []breakglassv1alpha1.AdmissionRecipeTarget{policyTarget("require-labels")}},
	}}
	require.NoError(t, admissionRecipeApprovers(template, nil))
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
		Constraints: &breakglassv1alpha1.DebugSessionConstraints{AllowRenewal: ptr.To(true)},
	}}
	require.ErrorContains(t, admissionRecipeApprovers(template, binding), "renewal")
}

func TestAdmissionRecipePendingSeparatesTargetOutage(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	f.c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return nil, errors.New("dial tcp: i/o timeout") }
	err := f.c.validateAdmissionRecipePending(t.Context(), f.ds, &breakglassv1alpha1.DebugSessionTemplate{Spec: *f.ds.Status.ResolvedTemplate}, nil)
	require.ErrorIs(t, err, errMaintenanceTargetUnavailable)
}

type failingRecipeAuditSink struct{ maintenanceAuditCaptureSink }

func (s *failingRecipeAuditSink) Write(context.Context, *audit.Event) error {
	return errors.New("sink unavailable")
}

func TestAdmissionRecipeFailingSinkBlocksEveryWrite(t *testing.T) {
	target := policyTarget("require-labels")
	f := newRecipeFixture(t, policyRecipe(false, target), []breakglassv1alpha1.AdmissionRecipeTarget{target}, recipePolicy("require-labels", "psa", "Deny"))
	manager := audit.NewManager(&failingRecipeAuditSink{}, audit.ManagerConfig{QueueSize: 8, WorkerCount: 1}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	f.c.WithAuditManager(manager)
	require.Error(t, f.c.applyAdmissionRecipe(t.Context(), f.ds))
	require.Nil(t, f.ds.Status.AdmissionRecipe)
	require.Equal(t, []string{"Deny"}, policyActions(t, getPolicy(t, f.spoke, "require-labels")))
}
