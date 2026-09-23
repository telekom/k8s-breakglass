// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestPolicyExceptionAuxiliaryLifecycle(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	gvk := schema.GroupVersionKind{Group: "kyverno.io", Version: "v2", Kind: "PolicyException"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	target := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, cfg runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			payload, err := json.Marshal(cfg)
			require.NoError(t, err)
			var object map[string]interface{}
			require.NoError(t, json.Unmarshal(payload, &object))
			metadata, _ := object["metadata"].(map[string]interface{})
			metadata["uid"] = "exception-uid"
			desired := &unstructured.Unstructured{Object: object}
			current := &unstructured.Unstructured{}
			current.SetGroupVersionKind(desired.GroupVersionKind())
			if err := c.Get(ctx, client.ObjectKeyFromObject(desired), current); err == nil {
				desired.SetUID(current.GetUID())
				desired.SetResourceVersion(current.GetResourceVersion())
				return c.Update(ctx, desired)
			}
			return c.Create(ctx, desired)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			obj.SetUID("exception-uid")
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
	mgr := newTestAuxiliaryResourceManager()
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "reviewed-session", Namespace: "breakglass", UID: "session-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "target"},
	}
	template := &breakglassv1alpha1.DebugSessionTemplateSpec{
		RequiredAuxiliaryResourceCategories: []string{"policy-exception"},
		AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{
			Name: "reviewed-policy", Category: "policy-exception", CreateBefore: true, DeleteAfter: true,
			FailurePolicy: breakglassv1alpha1.AuxiliaryResourceFailurePolicyFail,
			TemplateString: `apiVersion: kyverno.io/v2
kind: PolicyException
metadata:
  name: "debug-{{ .session.name }}"
  namespace: "{{ .target.namespace }}"
spec:
  exceptions:
  - policyName: reviewed-hostpath-policy
    ruleNames: [reviewed-hostpath-rule]
  match:
    any:
    - resources:
        kinds: [Pod]
        namespaces: ["{{ .target.namespace }}"]
        selector:
          matchLabels:
            breakglass.telekom.com/debug-session: "{{ .session.name }}"
`,
		}},
	}
	// Cleanup must use the policy persisted with the resolved session template,
	// rather than falling back to the current/default resource policy.
	session.Status.ResolvedTemplate = template.DeepCopy()
	// A binding cannot switch off a required admission prerequisite.
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
		AuxiliaryResourceOverrides: map[string]bool{"policy-exception": false},
	}}
	statuses, err := mgr.DeployAuxiliaryResourcesForPhase(ctx, session, template, binding, target, "debug-target", false)
	require.NoError(t, err)
	require.Empty(t, statuses)
	statuses, err = mgr.DeployAuxiliaryResourcesForPhase(ctx, session, template, binding, target, "debug-target", true)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.True(t, statuses[0].Created)
	require.Equal(t, "exception-uid", statuses[0].UID)
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	key := client.ObjectKey{Name: "debug-reviewed-session", Namespace: "debug-target"}
	require.NoError(t, target.Get(ctx, key, obj))
	match, found, err := unstructured.NestedSlice(obj.Object, "spec", "match", "any")
	require.NoError(t, err)
	require.True(t, found)
	resources := match[0].(map[string]interface{})["resources"].(map[string]interface{})
	require.Equal(t, []interface{}{"debug-target"}, resources["namespaces"])
	selector := resources["selector"].(map[string]interface{})["matchLabels"].(map[string]interface{})
	require.Equal(t, session.Name, selector[DebugSessionLabelKey])
	require.NoError(t, unstructured.SetNestedSlice(obj.Object, []interface{}{map[string]interface{}{
		"policyName": "second-reviewed-policy", "ruleNames": []interface{}{"second-rule"},
	}}, "spec", "exceptions"))
	obj.SetUID("")
	obj.SetResourceVersion("")
	require.NoError(t, applyOrRecoverAuxiliaryResource(ctx, target, obj, session))
	updated := &unstructured.Unstructured{}
	updated.SetGroupVersionKind(gvk)
	require.NoError(t, target.Get(ctx, key, updated))
	exceptions, found, err := unstructured.NestedSlice(updated.Object, "spec", "exceptions")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "second-reviewed-policy", exceptions[0].(map[string]interface{})["policyName"])
	// The generic controller inventory removes the exception at session cleanup.
	session.Status.AuxiliaryResourceStatuses = statuses
	template.AuxiliaryResources[0].DeleteAfter = false
	require.NoError(t, mgr.CleanupAuxiliaryResources(ctx, session, target))
	require.True(t, session.Status.AuxiliaryResourceStatuses[0].Deleted)
	require.True(t, apierrors.IsNotFound(target.Get(ctx, key, obj)))
	require.NoError(t, mgr.CleanupAuxiliaryResources(ctx, session, target))

	// A cluster binding can require the category even when the template does
	// not. Its requirement also cannot be disabled by an override.
	template.RequiredAuxiliaryResourceCategories = nil
	binding.Spec.RequiredAuxiliaryResourceCategories = []string{"policy-exception"}
	session.Status.AuxiliaryResourceStatuses = nil
	statuses, err = mgr.DeployAuxiliaryResourcesForPhase(ctx, session, template, binding, target, "debug-target", false)
	require.NoError(t, err)
	require.Empty(t, statuses)
	statuses, err = mgr.DeployAuxiliaryResourcesForPhase(ctx, session, template, binding, target, "debug-target", true)
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.True(t, statuses[0].Created)
}

func TestAuxiliaryCreateDoesNotAdoptConcurrentForeignResource(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	gvk := schema.GroupVersionKind{Group: "example.telekom.com", Version: "v1", Kind: "ExternalResource"}
	scheme.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{UID: "owner-session"}}
	foreign := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": gvk.GroupVersion().String(), "kind": gvk.Kind,
		"metadata": map[string]interface{}{"name": "concurrent", "namespace": "target", "annotations": map[string]interface{}{
			sourceSessionUIDAnnotation: "foreign-session", createOperationIDAnnotation: "operation",
		}},
	}}
	target := fake.NewClientBuilder().WithScheme(scheme).WithObjects(foreign).Build()
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": gvk.GroupVersion().String(), "kind": gvk.Kind,
		"metadata": map[string]interface{}{"name": "concurrent", "namespace": "target", "annotations": map[string]interface{}{
			sourceSessionUIDAnnotation: string(session.UID), createOperationIDAnnotation: "operation",
		}},
	}}
	err := recoverTrackedCreateResult(ctx, target, obj, session, apierrors.NewAlreadyExists(schema.GroupResource{Group: gvk.Group, Resource: "externalresources"}, obj.GetName()))
	require.ErrorContains(t, err, "owned by another session")
}
