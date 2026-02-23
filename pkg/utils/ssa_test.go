package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newSSATestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	return scheme
}

func TestApplyObject_BreakglassSession(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	// Create a fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	session := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test@example.com",
			GrantedGroup: "test-group",
		},
	}

	// Apply should create the object
	err := ApplyObject(ctx, fakeClient, session)
	require.NoError(t, err)

	// Verify object was created
	var created breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-session", Namespace: "default"}, &created)
	require.NoError(t, err)
	assert.Equal(t, "test-cluster", created.Spec.Cluster)
	assert.Equal(t, "test@example.com", created.Spec.User)
}

func TestApplyObject_Secret(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test",
			},
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
		Type: corev1.SecretTypeOpaque,
	}

	err := ApplyObject(ctx, fakeClient, secret)
	require.NoError(t, err)

	var created corev1.Secret
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-secret", Namespace: "default"}, &created)
	require.NoError(t, err)
	assert.Equal(t, "test", created.Labels["app"])
	assert.Equal(t, []byte("value"), created.Data["key"])
}

func TestApplyObject_Update(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	// Pre-create an object
	existing := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "old-cluster",
			User:         "old@example.com",
			GrantedGroup: "old-group",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existing).
		Build()

	// Apply with updated values
	updated := &breakglassv1alpha1.BreakglassSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "new-cluster",
			User:         "new@example.com",
			GrantedGroup: "new-group",
		},
	}

	err := ApplyObject(ctx, fakeClient, updated)
	require.NoError(t, err)

	var result breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-session", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "new-cluster", result.Spec.Cluster)
	assert.Equal(t, "new@example.com", result.Spec.User)
}

func TestApplyStatus_BreakglassSession(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	// Pre-create an object (status updates require existing object)
	existing := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test@example.com",
			GrantedGroup: "test-group",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStatePending,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existing).
		WithStatusSubresource(&breakglassv1alpha1.BreakglassSession{}).
		Build()

	// Update status
	updated := existing.DeepCopy()
	updated.TypeMeta = metav1.TypeMeta{
		APIVersion: breakglassv1alpha1.GroupVersion.String(),
		Kind:       "BreakglassSession",
	}
	updated.Status.State = breakglassv1alpha1.SessionStateApproved

	err := ApplyStatus(ctx, fakeClient, updated)
	require.NoError(t, err)

	var result breakglassv1alpha1.BreakglassSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-session", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, result.Status.State)
}

func TestToApplyConfiguration_UnsupportedType(t *testing.T) {
	// Test with an unsupported type
	unsupported := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, err := ToApplyConfiguration(unsupported)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestToStatusApplyConfiguration_UnsupportedType(t *testing.T) {
	// Test with an unsupported type for status
	unsupported := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
	}

	_, err := ToStatusApplyConfiguration(unsupported)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestApplyObject_ClusterConfig(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	config := &breakglassv1alpha1.ClusterConfig{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "ClusterConfig",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			ClusterID: "cluster-123",
			AuthType:  breakglassv1alpha1.ClusterAuthTypeKubeconfig,
		},
	}

	err := ApplyObject(ctx, fakeClient, config)
	require.NoError(t, err)

	var created breakglassv1alpha1.ClusterConfig
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cluster", Namespace: "default"}, &created)
	require.NoError(t, err)
	assert.Equal(t, "cluster-123", created.Spec.ClusterID)
}

func TestApplyObject_DebugSession(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	session := &breakglassv1alpha1.DebugSession{
		TypeMeta: metav1.TypeMeta{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "DebugSession",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-debug",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
	}

	err := ApplyObject(ctx, fakeClient, session)
	require.NoError(t, err)

	var created breakglassv1alpha1.DebugSession
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-debug", Namespace: "default"}, &created)
	require.NoError(t, err)
	assert.Equal(t, "test-cluster", created.Spec.Cluster)
}

func TestApplyUnstructured_ConfigMap(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create an unstructured ConfigMap
	cm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
			"data": map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	err := ApplyUnstructured(ctx, fakeClient, cm)
	require.NoError(t, err)

	// Verify the ConfigMap was created
	var result unstructured.Unstructured
	result.SetAPIVersion("v1")
	result.SetKind("ConfigMap")
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cm", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "test-cm", result.GetName())
	data, found, err := unstructured.NestedStringMap(result.Object, "data")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "value1", data["key1"])
	assert.Equal(t, "value2", data["key2"])
}

func TestApplyUnstructured_Update(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	// Pre-create an unstructured ConfigMap
	existing := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
			"data": map[string]interface{}{
				"key1": "old-value",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existing).
		Build()

	// Apply with updated values
	updated := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
			"data": map[string]interface{}{
				"key1": "new-value",
				"key2": "added-value",
			},
		},
	}

	err := ApplyUnstructured(ctx, fakeClient, updated)
	require.NoError(t, err)

	// Verify the ConfigMap was updated
	var result unstructured.Unstructured
	result.SetAPIVersion("v1")
	result.SetKind("ConfigMap")
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-cm", Namespace: "default"}, &result)
	require.NoError(t, err)
	data, found, err := unstructured.NestedStringMap(result.Object, "data")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "new-value", data["key1"])
	assert.Equal(t, "added-value", data["key2"])
}

func TestApplyUnstructured_Deployment(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// Create an unstructured Deployment (arbitrary auxiliary resource)
	deployment := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "debug-deployment",
				"namespace": "default",
				"labels": map[string]interface{}{
					"app": "debug-session",
				},
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "debug-session",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "debug-session",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "debug",
								"image": "busybox:latest",
							},
						},
					},
				},
			},
		},
	}

	err := ApplyUnstructured(ctx, fakeClient, deployment)
	require.NoError(t, err)

	// Verify the Deployment was created
	var result unstructured.Unstructured
	result.SetAPIVersion("apps/v1")
	result.SetKind("Deployment")
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "debug-deployment", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "debug-deployment", result.GetName())

	labels := result.GetLabels()
	assert.Equal(t, "debug-session", labels["app"])
}

func TestApplyTypedObject_WithTypeMeta(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// ConfigMap with TypeMeta explicitly set
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "typed-cm",
			Namespace: "default",
		},
		Data: map[string]string{"key": "value"},
	}

	err := ApplyTypedObject(ctx, fakeClient, cm, scheme)
	require.NoError(t, err)

	// Verify the ConfigMap was created
	var result corev1.ConfigMap
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "typed-cm", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "typed-cm", result.Name)
	assert.Equal(t, "value", result.Data["key"])
}

func TestApplyTypedObject_GVKFromScheme(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	// ConfigMap WITHOUT TypeMeta — GVK should be resolved from the scheme
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "schemeless-cm",
			Namespace: "default",
		},
		Data: map[string]string{"foo": "bar"},
	}

	err := ApplyTypedObject(ctx, fakeClient, cm, scheme)
	require.NoError(t, err)

	var result corev1.ConfigMap
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "schemeless-cm", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "bar", result.Data["foo"])
}

func TestApplyTypedObject_NoGVK_ReturnsError(t *testing.T) {
	ctx := context.Background()

	fakeClient := fake.NewClientBuilder().
		WithScheme(runtime.NewScheme()). // empty scheme — no GVK resolution
		Build()

	// ConfigMap with no TypeMeta and no scheme registration → cannot determine GVK
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unknown-cm",
			Namespace: "default",
		},
	}

	err := ApplyTypedObject(ctx, fakeClient, cm, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot apply object without GVK")
}

func TestApplyTypedObject_Update(t *testing.T) {
	ctx := context.Background()
	scheme := newSSATestScheme()

	// Pre-create a ConfigMap
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "update-cm",
			Namespace: "default",
		},
		Data: map[string]string{"key": "old"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(existing).
		Build()

	// Apply an update via ApplyTypedObject
	updated := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "update-cm",
			Namespace: "default",
		},
		Data: map[string]string{"key": "new"},
	}

	err := ApplyTypedObject(ctx, fakeClient, updated, scheme)
	require.NoError(t, err)

	var result corev1.ConfigMap
	err = fakeClient.Get(ctx, types.NamespacedName{Name: "update-cm", Namespace: "default"}, &result)
	require.NoError(t, err)
	assert.Equal(t, "new", result.Data["key"])
}
