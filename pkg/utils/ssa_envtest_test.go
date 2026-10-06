// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestTypedApplyDecisions(t *testing.T) {
	apiClient := ssatest.Start(t)
	for _, tc := range []struct {
		name   string
		object client.Object
		mutate func(client.Object)
		repeat PatchApplyResult
	}{
		{
			name: "secret",
			object: &corev1.Secret{
				TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
				ObjectMeta: metav1.ObjectMeta{Name: "typed-secret", Namespace: "default"},
				Type:       corev1.SecretTypeOpaque, Data: map[string][]byte{"rotated": []byte("first")},
			},
			mutate: func(obj client.Object) { obj.(*corev1.Secret).Data["rotated"] = []byte("second") },
			repeat: PatchApplyResultSkipped,
		},
		{
			name: "cluster-config",
			object: &breakglassv1alpha1.ClusterConfig{
				TypeMeta:   metav1.TypeMeta{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "ClusterConfig"},
				ObjectMeta: metav1.ObjectMeta{Name: "typed-cluster", Namespace: "default"},
				Spec: breakglassv1alpha1.ClusterConfigSpec{
					KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "kubeconfig", Namespace: "default"},
				},
			},
			mutate: func(obj client.Object) {
				obj.(*breakglassv1alpha1.ClusterConfig).Spec.KubeconfigSecretRef.Name = "other"
			},
			repeat: PatchApplyResultPatched,
		},
		{
			name: "breakglass-session",
			object: &breakglassv1alpha1.BreakglassSession{
				TypeMeta:   metav1.TypeMeta{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "BreakglassSession"},
				ObjectMeta: metav1.ObjectMeta{Name: "typed-session", Namespace: "default"},
				Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "spoke", User: "user@example.com", GrantedGroup: "admins"},
			},
			mutate: func(obj client.Object) { obj.(*breakglassv1alpha1.BreakglassSession).Spec.User = "second@example.com" },
			repeat: PatchApplyResultPatched,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &ssatest.CountingClient{Client: apiClient}
			result, err := PatchApplyObject(t.Context(), c, tc.object)
			require.NoError(t, err)
			require.Equal(t, PatchApplyResultCreated, result)
			require.EqualValues(t, 1, c.Applies.Load())
			result, err = PatchApplyObject(t.Context(), c, tc.object)
			require.NoError(t, err)
			// CRD conversion currently includes server metadata in equality, so a
			// fresh desired manifest is reapplied even when spec is unchanged.
			require.Equal(t, tc.repeat, result)
			afterRepeat := c.Applies.Load()
			tc.mutate(tc.object)
			result, err = PatchApplyObject(t.Context(), c, tc.object)
			require.NoError(t, err)
			require.Equal(t, PatchApplyResultPatched, result)
			require.Equal(t, afterRepeat+1, c.Applies.Load())
			require.NoError(t, ApplyObject(t.Context(), c, tc.object))
			expected := afterRepeat + 1
			if tc.repeat == PatchApplyResultPatched {
				expected++
			}
			require.Equal(t, expected, c.Applies.Load())
			live := tc.object.DeepCopyObject().(client.Object)
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(tc.object), live))
			require.NotEmpty(t, live.GetManagedFields())
			competing := tc.object.DeepCopyObject().(client.Object)
			competing.SetLabels(map[string]string{"foreign": "preserve"})
			switch obj := competing.(type) {
			case *corev1.Secret:
				obj.Data["rotated"] = []byte("foreign")
			case *breakglassv1alpha1.ClusterConfig:
				obj.Spec.KubeconfigSecretRef.Name = "foreign"
			case *breakglassv1alpha1.BreakglassSession:
				obj.Spec.User = "foreign@example.com"
			}
			foreignConfig, err := ToApplyConfiguration(competing)
			require.NoError(t, err)
			require.NoError(t, apiClient.Apply(t.Context(), foreignConfig, client.FieldOwner("competitor"), client.ForceOwnership))
			result, err = PatchApplyObject(t.Context(), c, tc.object)
			require.NoError(t, err)
			require.Equal(t, PatchApplyResultPatched, result)
			require.Equal(t, expected+1, c.Applies.Load())
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(tc.object), live))
			require.Equal(t, "preserve", live.GetLabels()["foreign"])
			switch obj := live.(type) {
			case *corev1.Secret:
				require.Equal(t, tc.object.(*corev1.Secret).Data["rotated"], obj.Data["rotated"])
			case *breakglassv1alpha1.ClusterConfig:
				require.Equal(t, tc.object.(*breakglassv1alpha1.ClusterConfig).Spec.KubeconfigSecretRef.Name, obj.Spec.KubeconfigSecretRef.Name)
			case *breakglassv1alpha1.BreakglassSession:
				require.Equal(t, tc.object.(*breakglassv1alpha1.BreakglassSession).Spec.User, obj.Spec.User)
			}
		})
	}
}

func TestSSAEnvtestCompetingFieldManager(t *testing.T) {
	apiClient := ssatest.Start(t)
	c := &ssatest.CountingClient{Client: apiClient}
	desired := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "ownership", Namespace: "default"},
		Type:       corev1.SecretTypeOpaque, Data: map[string][]byte{"rotated": []byte("first")},
	}
	require.NoError(t, ApplyObject(t.Context(), c, desired))
	competitor := corev1ac.Secret(desired.Name, desired.Namespace).
		WithData(map[string][]byte{"rotated": []byte("foreign"), "external": []byte("preserve")}).
		WithLabels(map[string]string{"external": "preserve"})
	require.NoError(t, apiClient.Apply(t.Context(), competitor, client.FieldOwner("competitor"), client.ForceOwnership))
	result, err := PatchApplyObject(t.Context(), c, desired)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.EqualValues(t, 2, c.Applies.Load())
	live := &corev1.Secret{}
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(desired), live))
	require.Equal(t, []byte("first"), live.Data["rotated"])
	require.Equal(t, []byte("preserve"), live.Data["external"])
	require.Equal(t, "preserve", live.Labels["external"])
	// The typed gate compares the full converted metadata/data, including
	// foreign keys, so the foreign label/data also force another apply.
	competitor = corev1ac.Secret(desired.Name, desired.Namespace).WithData(map[string][]byte{"rotated": []byte("first"), "external": []byte("preserve")}).WithLabels(map[string]string{"external": "preserve"})
	require.NoError(t, apiClient.Apply(t.Context(), competitor, client.FieldOwner("competitor"), client.ForceOwnership))
	result, err = PatchApplyObject(t.Context(), c, desired)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.EqualValues(t, 3, c.Applies.Load())
}

func TestSSAEnvtestUnstructuredAuxiliary(t *testing.T) {
	apiClient := ssatest.Start(t)
	c := &ssatest.CountingClient{Client: apiClient}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]interface{}{"name": "auxiliary", "namespace": "default"},
		"data":     map[string]interface{}{"owned": "first"},
	}}
	result, err := PatchApplyUnstructured(t.Context(), c, obj)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultCreated, result)
	require.NoError(t, ApplyUnstructured(t.Context(), c, obj))
	require.EqualValues(t, 1, c.Applies.Load())
	require.NoError(t, apiClient.Apply(t.Context(), corev1ac.ConfigMap("auxiliary", "default").
		WithData(map[string]string{"owned": "foreign", "external": "preserve"}),
		client.FieldOwner("competitor"), client.ForceOwnership))
	obj.SetResourceVersion("")
	obj.SetUID("")
	result, err = PatchApplyUnstructured(t.Context(), c, obj)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	live := &corev1.ConfigMap{}
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKey{Name: "auxiliary", Namespace: "default"}, live))
	require.Equal(t, "first", live.Data["owned"])
	require.Equal(t, "preserve", live.Data["external"])
	require.EqualValues(t, 2, c.Applies.Load())
}
