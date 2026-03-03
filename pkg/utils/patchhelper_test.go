package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newPatchHelperTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

// ---------------------------------------------------------------------------
// PatchApplyObject
// ---------------------------------------------------------------------------

func TestPatchApplyObject_Creates(t *testing.T) {
	ctx := context.Background()
	scheme := newPatchHelperTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	session := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "new-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster: "cluster-a",
			User:    "user@example.com",
		},
	}

	result, err := PatchApplyObject(ctx, c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultCreated, result)

	// Verify
	var created breakglassv1alpha1.BreakglassSession
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: "new-session", Namespace: "default"}, &created))
	assert.Equal(t, "cluster-a", created.Spec.Cluster)
}

func TestPatchApplyObject_Skipped(t *testing.T) {
	ctx := context.Background()
	scheme := newPatchHelperTestScheme()

	session := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "cluster-a",
			User:         "user@example.com",
			GrantedGroup: "group-a",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create via first apply.
	result, err := PatchApplyObject(ctx, c, session)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultCreated, result)

	// Re-fetch so the object matches cache.
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: "existing-session", Namespace: "default"}, &fetched))
	fetched.TypeMeta = session.TypeMeta

	// Apply same state — should skip.
	result, err = PatchApplyObject(ctx, c, &fetched)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultSkipped, result)
}

func TestPatchApplyObject_Patched(t *testing.T) {
	ctx := context.Background()
	scheme := newPatchHelperTestScheme()

	session := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "cluster-a",
			User:         "user@example.com",
			GrantedGroup: "group-a",
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create via first apply.
	_, err := PatchApplyObject(ctx, c, session)
	require.NoError(t, err)

	// Re-fetch and modify.
	var fetched breakglassv1alpha1.BreakglassSession
	require.NoError(t, c.Get(ctx, types.NamespacedName{Name: "existing-session", Namespace: "default"}, &fetched))
	fetched.TypeMeta = session.TypeMeta
	fetched.Spec.GrantedGroup = "group-b" // Changed.

	result, err := PatchApplyObject(ctx, c, &fetched)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultPatched, result)
}

// ---------------------------------------------------------------------------
// PatchApplyUnstructured
// ---------------------------------------------------------------------------

func TestPatchApplyUnstructured_Creates(t *testing.T) {
	ctx := context.Background()
	scheme := newPatchHelperTestScheme()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
			"data": map[string]interface{}{
				"key": "value",
			},
		},
	}

	result, err := PatchApplyUnstructured(ctx, c, obj)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultCreated, result)
}

func TestPatchApplyUnstructured_Skipped(t *testing.T) {
	ctx := context.Background()
	scheme := newPatchHelperTestScheme()

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
		Data: map[string]string{"key": "value"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
				"labels":    map[string]interface{}{"app": "test"},
			},
			"data": map[string]interface{}{
				"key": "value",
			},
		},
	}

	result, err := PatchApplyUnstructured(ctx, c, obj)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultSkipped, result)
}

func TestPatchApplyUnstructured_Patched(t *testing.T) {
	ctx := context.Background()
	scheme := newPatchHelperTestScheme()

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cm",
			Namespace: "default",
		},
		Data: map[string]string{"key": "old-value"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
			"data": map[string]interface{}{
				"key": "new-value",
			},
		},
	}

	result, err := PatchApplyUnstructured(ctx, c, obj)
	require.NoError(t, err)
	assert.Equal(t, PatchApplyResultPatched, result)
}

// ---------------------------------------------------------------------------
// PatchApplyResult.String
// ---------------------------------------------------------------------------

func TestPatchApplyResult_String(t *testing.T) {
	assert.Equal(t, "skipped", PatchApplyResultSkipped.String())
	assert.Equal(t, "created", PatchApplyResultCreated.String())
	assert.Equal(t, "patched", PatchApplyResultPatched.String())
	assert.Equal(t, "unknown", PatchApplyResult(42).String())
}

// ---------------------------------------------------------------------------
// applyConfigsEqual
// ---------------------------------------------------------------------------

func TestApplyConfigsEqual_SameContent(t *testing.T) {
	session := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "ns"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1"},
	}

	ac1, err := ToApplyConfiguration(session)
	require.NoError(t, err)
	ac2, err := ToApplyConfiguration(session)
	require.NoError(t, err)

	assert.True(t, applyConfigsEqual(ac1, ac2))
}

func TestApplyConfigsEqual_DifferentSpec(t *testing.T) {
	s1 := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "ns"},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1"},
	}
	s2 := s1.DeepCopy()
	s2.Spec.Cluster = "c2"

	ac1, err := ToApplyConfiguration(s1)
	require.NoError(t, err)
	ac2, err := ToApplyConfiguration(s2)
	require.NoError(t, err)

	assert.False(t, applyConfigsEqual(ac1, ac2))
}

// ---------------------------------------------------------------------------
// unstructuredSpecEqual
// ---------------------------------------------------------------------------

func TestUnstructuredSpecEqual_Same(t *testing.T) {
	a := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "test"},
		},
	}}
	b := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "test"},
		},
	}}
	assert.True(t, unstructuredSpecEqual(a, b))
}

func TestUnstructuredSpecEqual_DifferentSpec(t *testing.T) {
	a := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
	}}
	b := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(5)},
	}}
	assert.False(t, unstructuredSpecEqual(a, b))
}

func TestUnstructuredSpecEqual_DifferentData(t *testing.T) {
	a := &unstructured.Unstructured{Object: map[string]interface{}{
		"data": map[string]interface{}{"key": "v1"},
	}}
	b := &unstructured.Unstructured{Object: map[string]interface{}{
		"data": map[string]interface{}{"key": "v2"},
	}}
	assert.False(t, unstructuredSpecEqual(a, b))
}

// TestUnstructuredSpecEqual_ClusterRoleRules ensures that kinds that use
// top-level fields other than spec/data (e.g. ClusterRole.rules) are compared
// correctly — regression test for the generic subset comparison.
func TestUnstructuredSpecEqual_ClusterRoleRules(t *testing.T) {
	rules := []interface{}{
		map[string]interface{}{
			"apiGroups": []interface{}{""},
			"resources": []interface{}{"pods"},
			"verbs":     []interface{}{"get", "list"},
		},
	}
	desired := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]interface{}{"name": "test-role"},
		"rules":      rules,
	}}
	current := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata": map[string]interface{}{
			"name":            "test-role",
			"resourceVersion": "12345",
			"uid":             "abc-def",
		},
		"rules": rules,
	}}
	assert.True(t, unstructuredSpecEqual(desired, current), "identical rules should match")

	// Mutate rules in current — should detect the diff.
	changedRules := []interface{}{
		map[string]interface{}{
			"apiGroups": []interface{}{""},
			"resources": []interface{}{"pods"},
			"verbs":     []interface{}{"get", "list", "watch"},
		},
	}
	currentChanged := current.DeepCopy()
	currentChanged.Object["rules"] = changedRules
	assert.False(t, unstructuredSpecEqual(desired, currentChanged), "different rules should not match")
}

// TestUnstructuredSpecEqual_ServiceAccount tests a kind with top-level fields
// other than spec (automountServiceAccountToken, secrets, imagePullSecrets).
func TestUnstructuredSpecEqual_ServiceAccount(t *testing.T) {
	desired := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion":                   "v1",
		"kind":                         "ServiceAccount",
		"metadata":                     map[string]interface{}{"name": "test-sa", "namespace": "default"},
		"automountServiceAccountToken": true,
	}}
	current := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion":                   "v1",
		"kind":                         "ServiceAccount",
		"metadata":                     map[string]interface{}{"name": "test-sa", "namespace": "default", "resourceVersion": "999"},
		"automountServiceAccountToken": true,
	}}
	assert.True(t, unstructuredSpecEqual(desired, current))

	currentDiff := current.DeepCopy()
	currentDiff.Object["automountServiceAccountToken"] = false
	assert.False(t, unstructuredSpecEqual(desired, currentDiff))
}

func TestUnstructuredSpecEqual_ExtraLabelsInCurrent(t *testing.T) {
	desired := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "test"},
		},
	}}
	current := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
		"metadata": map[string]interface{}{
			"labels": map[string]interface{}{"app": "test", "extra": "label"},
		},
	}}
	// Desired labels are a subset of current — should match.
	assert.True(t, unstructuredSpecEqual(desired, current))
}

// ---------------------------------------------------------------------------
// mapSubsetMatch
// ---------------------------------------------------------------------------

func TestMapSubsetMatch_EmptyDesired(t *testing.T) {
	assert.True(t, mapSubsetMatch(map[string]string{"a": "1"}, nil))
	assert.True(t, mapSubsetMatch(map[string]string{"a": "1"}, map[string]string{}))
}

func TestMapSubsetMatch_Subset(t *testing.T) {
	existing := map[string]string{"a": "1", "b": "2", "c": "3"}
	desired := map[string]string{"a": "1", "c": "3"}
	assert.True(t, mapSubsetMatch(existing, desired))
}

func TestMapSubsetMatch_MissingKey(t *testing.T) {
	existing := map[string]string{"a": "1"}
	desired := map[string]string{"a": "1", "b": "2"}
	assert.False(t, mapSubsetMatch(existing, desired))
}

func TestMapSubsetMatch_DifferentValue(t *testing.T) {
	existing := map[string]string{"a": "1"}
	desired := map[string]string{"a": "2"}
	assert.False(t, mapSubsetMatch(existing, desired))
}

// ---------------------------------------------------------------------------
// jsonFieldSubsetEqual / jsonSubsetEqual / jsonValueSubsetEqual
// ---------------------------------------------------------------------------

func TestJsonFieldSubsetEqual_BothMissing(t *testing.T) {
	a := map[string]interface{}{"other": "value"}
	b := map[string]interface{}{"other": "value"}
	assert.True(t, jsonFieldSubsetEqual(a, b, "spec"))
}

func TestJsonFieldSubsetEqual_OneMissing(t *testing.T) {
	a := map[string]interface{}{"spec": map[string]interface{}{"x": 1}}
	b := map[string]interface{}{}
	assert.False(t, jsonFieldSubsetEqual(a, b, "spec"))
}

func TestJsonFieldSubsetEqual_Equal(t *testing.T) {
	a := map[string]interface{}{"spec": map[string]interface{}{"x": float64(1)}}
	b := map[string]interface{}{"spec": map[string]interface{}{"x": float64(1)}}
	assert.True(t, jsonFieldSubsetEqual(a, b, "spec"))
}

func TestJsonFieldSubsetEqual_Different(t *testing.T) {
	a := map[string]interface{}{"spec": map[string]interface{}{"x": float64(1)}}
	b := map[string]interface{}{"spec": map[string]interface{}{"x": float64(2)}}
	assert.False(t, jsonFieldSubsetEqual(a, b, "spec"))
}

func TestJsonSubsetEqual_SubsetMatch(t *testing.T) {
	desired := map[string]interface{}{"x": float64(1)}
	current := map[string]interface{}{"x": float64(1), "y": float64(2)}
	assert.True(t, jsonSubsetEqual(desired, current))
}

func TestJsonSubsetEqual_NestedSubsetMatch(t *testing.T) {
	desired := map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
	}
	current := map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3), "selector": "default"},
	}
	assert.True(t, jsonSubsetEqual(desired, current))
}

func TestJsonSubsetEqual_NestedDifference(t *testing.T) {
	desired := map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(3)},
	}
	current := map[string]interface{}{
		"spec": map[string]interface{}{"replicas": float64(5), "selector": "default"},
	}
	assert.False(t, jsonSubsetEqual(desired, current))
}

func TestJsonSubsetEqual_MissingInCurrent(t *testing.T) {
	desired := map[string]interface{}{"x": float64(1), "y": float64(2)}
	current := map[string]interface{}{"x": float64(1)}
	assert.False(t, jsonSubsetEqual(desired, current))
}

func TestJsonValueSubsetEqual_ScalarEqual(t *testing.T) {
	assert.True(t, jsonValueSubsetEqual(float64(1), float64(1)))
	assert.True(t, jsonValueSubsetEqual("hello", "hello"))
	assert.True(t, jsonValueSubsetEqual(true, true))
}

func TestJsonValueSubsetEqual_ScalarDifferent(t *testing.T) {
	assert.False(t, jsonValueSubsetEqual(float64(1), float64(2)))
	assert.False(t, jsonValueSubsetEqual("hello", "world"))
}

func TestJsonValueSubsetEqual_SliceEqual(t *testing.T) {
	a := []interface{}{float64(1), float64(2)}
	b := []interface{}{float64(1), float64(2)}
	assert.True(t, jsonValueSubsetEqual(a, b))
}

func TestJsonValueSubsetEqual_SliceDifferent(t *testing.T) {
	a := []interface{}{float64(1), float64(2)}
	b := []interface{}{float64(1), float64(3)}
	assert.False(t, jsonValueSubsetEqual(a, b))
}
