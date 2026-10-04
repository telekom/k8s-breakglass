// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newSSATestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
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

func TestToApplyConfiguration_Job(t *testing.T) {
	job := &batchv1.Job{TypeMeta: metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: metav1.ObjectMeta{Name: "debug-job", Namespace: "default"}}
	cfg, err := ToApplyConfiguration(job)
	require.NoError(t, err)
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.JSONEq(t, `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"debug-job","namespace":"default"},"spec":{"template":{"metadata":{},"spec":{}}}}`, string(data))
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

func TestApplyConfigurationFrom_DropsStatusAndUsesSeedTypeMeta(t *testing.T) {
	// Objects read through a client have no TypeMeta; the seed supplies it.
	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "ns", Labels: map[string]string{"a": "b"}},
		Spec:       breakglassv1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1"},
		Status:     breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved},
	}
	cfg, err := ApplyConfigurationFrom(ac.BreakglassSession(session.Name, session.Namespace), session)
	require.NoError(t, err)
	assert.Nil(t, cfg.Status)
	require.NotNil(t, cfg.Spec)
	assert.Equal(t, "c1", *cfg.Spec.Cluster)
	assert.Equal(t, "BreakglassSession", *cfg.Kind)
	assert.Equal(t, breakglassv1alpha1.GroupVersion.String(), *cfg.APIVersion)
	assert.Equal(t, "ns", *cfg.GetNamespace())
	assert.Equal(t, map[string]string{"a": "b"}, cfg.Labels)
	assert.Equal(t, breakglassv1alpha1.SessionStateApproved, session.Status.State, "input must not be mutated")
}

func TestApplyConfigurationFrom_ClusterScopedSeedDropsNamespace(t *testing.T) {
	idp := &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: "idp", Namespace: "stray"}}
	cfg, err := ApplyConfigurationFrom(ac.IdentityProvider(idp.Name), idp)
	require.NoError(t, err)
	assert.Nil(t, cfg.GetNamespace())
	assert.Equal(t, "idp", *cfg.GetName())
}

func TestApplyConfigurationFrom_PreservesLargeIntegers(t *testing.T) {
	const generation = int64(1<<62 + 1) // not representable as float64
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns", Generation: generation}}
	cfg, err := ApplyConfigurationFrom(corev1ac.Pod(pod.Name, pod.Namespace), pod)
	require.NoError(t, err)
	assert.Equal(t, generation, *cfg.Generation)
}

func TestApplyConfigurationFrom_MarshalErrorReturnsZero(t *testing.T) {
	cfg, err := ApplyConfigurationFrom(ac.DenyPolicy("p"), map[string]any{"bad": make(chan int)})
	require.Error(t, err)
	assert.Nil(t, cfg)
}

func TestToApplyConfiguration_AllSupportedTypesOmitStatus(t *testing.T) {
	meta := metav1.ObjectMeta{Name: "obj", Namespace: "ns"}
	for _, tc := range []struct {
		obj        client.Object
		kind       string
		namespaced bool
	}{
		{&breakglassv1alpha1.BreakglassSession{ObjectMeta: meta, Status: breakglassv1alpha1.BreakglassSessionStatus{State: breakglassv1alpha1.SessionStateApproved}}, "BreakglassSession", true},
		{&breakglassv1alpha1.ClusterConfig{ObjectMeta: meta, Status: breakglassv1alpha1.ClusterConfigStatus{ObservedGeneration: 1}}, "ClusterConfig", true},
		{&breakglassv1alpha1.DebugSession{ObjectMeta: meta, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive}}, "DebugSession", true},
		{&breakglassv1alpha1.BreakglassEscalation{ObjectMeta: meta, Status: breakglassv1alpha1.BreakglassEscalationStatus{ObservedGeneration: 1}}, "BreakglassEscalation", true},
		{&breakglassv1alpha1.IdentityProvider{ObjectMeta: meta, Status: breakglassv1alpha1.IdentityProviderStatus{ObservedGeneration: 1}}, "IdentityProvider", false},
		{&breakglassv1alpha1.MailProvider{ObjectMeta: meta, Status: breakglassv1alpha1.MailProviderStatus{ObservedGeneration: 1}}, "MailProvider", false},
		{&breakglassv1alpha1.DenyPolicy{ObjectMeta: meta, Status: breakglassv1alpha1.DenyPolicyStatus{ObservedGeneration: 1}}, "DenyPolicy", false},
		{&breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: meta, Status: breakglassv1alpha1.DebugSessionTemplateStatus{ObservedGeneration: 1}}, "DebugSessionTemplate", false},
		{&breakglassv1alpha1.DebugPodTemplate{ObjectMeta: meta, Status: breakglassv1alpha1.DebugPodTemplateStatus{ObservedGeneration: 1}}, "DebugPodTemplate", false},
		{&breakglassv1alpha1.DebugSessionClusterBinding{ObjectMeta: meta, Status: breakglassv1alpha1.DebugSessionClusterBindingStatus{ObservedGeneration: 1}}, "DebugSessionClusterBinding", true},
		{&corev1.Secret{ObjectMeta: meta}, "Secret", true},
		{&corev1.Pod{ObjectMeta: meta, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, "Pod", true},
		{&corev1.ResourceQuota{ObjectMeta: meta, Status: corev1.ResourceQuotaStatus{Hard: corev1.ResourceList{}}}, "ResourceQuota", true},
		{&policyv1.PodDisruptionBudget{ObjectMeta: meta, Status: policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1}}, "PodDisruptionBudget", true},
		{&appsv1.DaemonSet{ObjectMeta: meta, Status: appsv1.DaemonSetStatus{ObservedGeneration: 1}}, "DaemonSet", true},
		{&appsv1.Deployment{ObjectMeta: meta, Status: appsv1.DeploymentStatus{ObservedGeneration: 1}}, "Deployment", true},
		{&batchv1.Job{ObjectMeta: meta, Status: batchv1.JobStatus{Active: 1}}, "Job", true},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			cfg, err := ToApplyConfiguration(tc.obj)
			require.NoError(t, err)
			data, err := json.Marshal(cfg)
			require.NoError(t, err)
			var fields map[string]any
			require.NoError(t, json.Unmarshal(data, &fields))
			assert.Equal(t, tc.kind, fields["kind"])
			assert.NotEmpty(t, fields["apiVersion"])
			assert.NotContains(t, fields, "status")
			metadata, ok := fields["metadata"].(map[string]any)
			require.True(t, ok)
			assert.Equal(t, "obj", metadata["name"])
			if tc.namespaced {
				assert.Equal(t, "ns", metadata["namespace"])
			} else {
				assert.NotContains(t, metadata, "namespace")
			}
		})
	}
}
