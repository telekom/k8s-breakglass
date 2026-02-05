/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/cli-utils/pkg/kstatus/status"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newKstatusTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	return scheme
}

func newTestLogger() *zap.SugaredLogger {
	logger, _ := zap.NewDevelopment()
	return logger.Sugar()
}

func TestCheckReadiness_ConfigMap_Current(t *testing.T) {
	// ConfigMaps are always "Current" since they have no status
	cm := &unstructured.Unstructured{
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

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(cm)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
	assert.NoError(t, result.Error)
}

func TestCheckReadiness_Deployment_InProgress(t *testing.T) {
	// Deployment with no status set should be InProgress
	deploy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":       "test-deploy",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"replicas": int64(3),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(deploy)

	// Without status, deployment is in progress
	assert.False(t, result.Ready)
	assert.Equal(t, status.InProgressStatus, result.Status)
}

func TestCheckReadiness_Deployment_Ready(t *testing.T) {
	// Deployment with matching replicas should be Current
	deploy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":       "test-deploy",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"replicas": int64(3),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
			"status": map[string]interface{}{
				"observedGeneration":  int64(1),
				"replicas":            int64(3),
				"readyReplicas":       int64(3),
				"updatedReplicas":     int64(3),
				"availableReplicas":   int64(3),
				"unavailableReplicas": int64(0),
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Available",
						"status": "True",
					},
					map[string]interface{}{
						"type":   "Progressing",
						"status": "True",
						"reason": "NewReplicaSetAvailable",
					},
				},
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(deploy)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}

func TestCheckResourceReadiness_NotFound(t *testing.T) {
	ctx := context.Background()
	scheme := newKstatusTestScheme()

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckResourceReadiness(ctx, fakeClient,
		schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		"nonexistent", "default")

	assert.False(t, result.Ready)
	assert.Equal(t, status.NotFoundStatus, result.Status)
	assert.Error(t, result.Error)
}

func TestCheckResourceReadiness_Found(t *testing.T) {
	ctx := context.Background()
	scheme := newKstatusTestScheme()

	cm := &unstructured.Unstructured{
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

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckResourceReadiness(ctx, fakeClient,
		schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		"test-cm", "default")

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
	assert.NoError(t, result.Error)
}

func TestWaitForReadiness_AlreadyReady(t *testing.T) {
	ctx := context.Background()
	scheme := newKstatusTestScheme()

	cm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm).
		Build()

	checker := NewReadinessChecker(newTestLogger())
	result := checker.WaitForReadiness(ctx, fakeClient,
		schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
		"test-cm", "default",
		5*time.Second,
		100*time.Millisecond)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}

func TestWaitForReadiness_Timeout(t *testing.T) {
	ctx := context.Background()
	scheme := newKstatusTestScheme()

	// Create a deployment that won't be ready (no status)
	deploy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":       "test-deploy",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(deploy).
		Build()

	checker := NewReadinessChecker(newTestLogger())
	result := checker.WaitForReadiness(ctx, fakeClient,
		schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
		"test-deploy", "default",
		200*time.Millisecond,
		50*time.Millisecond)

	assert.False(t, result.Ready)
	assert.Error(t, result.Error)
	assert.Contains(t, result.Message, "timeout")
}

func TestWaitForReadiness_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	scheme := newKstatusTestScheme()

	deploy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":       "test-deploy",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"replicas": int64(1),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(deploy).
		Build()

	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	checker := NewReadinessChecker(newTestLogger())
	result := checker.WaitForReadiness(ctx, fakeClient,
		schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
		"test-deploy", "default",
		5*time.Second,
		100*time.Millisecond)

	assert.False(t, result.Ready)
	assert.Error(t, result.Error)
	assert.Contains(t, result.Message, "cancelled")
}

func TestCheckMultipleResourceReadiness(t *testing.T) {
	ctx := context.Background()
	scheme := newKstatusTestScheme()

	cm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      "test-cm",
				"namespace": "default",
			},
		},
	}

	secret := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      "test-secret",
				"namespace": "default",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cm, secret).
		Build()

	resources := []ResourceRef{
		{GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}, Name: "test-cm", Namespace: "default"},
		{GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, Name: "test-secret", Namespace: "default"},
		{GVK: schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}, Name: "missing", Namespace: "default"},
	}

	checker := NewReadinessChecker(newTestLogger())
	results := checker.CheckMultipleResourceReadiness(ctx, fakeClient, resources)

	assert.Len(t, results, 3)

	// ConfigMap should be ready
	cmKey := "ConfigMap/default/test-cm"
	assert.True(t, results[cmKey].Ready)

	// Secret should be ready
	secretKey := "Secret/default/test-secret"
	assert.True(t, results[secretKey].Ready)

	// Missing should not be found
	missingKey := "ConfigMap/default/missing"
	assert.False(t, results[missingKey].Ready)
	assert.Equal(t, status.NotFoundStatus, results[missingKey].Status)
}

func TestAllReady(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]ResourceReadiness
		expected bool
	}{
		{
			name:     "empty map",
			input:    map[string]ResourceReadiness{},
			expected: true,
		},
		{
			name: "all ready",
			input: map[string]ResourceReadiness{
				"a": {Ready: true, Status: status.CurrentStatus},
				"b": {Ready: true, Status: status.CurrentStatus},
			},
			expected: true,
		},
		{
			name: "one not ready",
			input: map[string]ResourceReadiness{
				"a": {Ready: true, Status: status.CurrentStatus},
				"b": {Ready: false, Status: status.InProgressStatus},
			},
			expected: false,
		},
		{
			name: "none ready",
			input: map[string]ResourceReadiness{
				"a": {Ready: false, Status: status.InProgressStatus},
				"b": {Ready: false, Status: status.FailedStatus},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AllReady(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAnyFailed(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]ResourceReadiness
		expected bool
	}{
		{
			name:     "empty map",
			input:    map[string]ResourceReadiness{},
			expected: false,
		},
		{
			name: "all current",
			input: map[string]ResourceReadiness{
				"a": {Ready: true, Status: status.CurrentStatus},
				"b": {Ready: true, Status: status.CurrentStatus},
			},
			expected: false,
		},
		{
			name: "one failed",
			input: map[string]ResourceReadiness{
				"a": {Ready: true, Status: status.CurrentStatus},
				"b": {Ready: false, Status: status.FailedStatus},
			},
			expected: true,
		},
		{
			name: "in progress only",
			input: map[string]ResourceReadiness{
				"a": {Ready: false, Status: status.InProgressStatus},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnyFailed(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceRef_Key(t *testing.T) {
	tests := []struct {
		name     string
		ref      ResourceRef
		expected string
	}{
		{
			name: "namespaced resource",
			ref: ResourceRef{
				GVK:       schema.GroupVersionKind{Kind: "ConfigMap"},
				Name:      "test-cm",
				Namespace: "default",
			},
			expected: "ConfigMap/default/test-cm",
		},
		{
			name: "cluster-scoped resource",
			ref: ResourceRef{
				GVK:  schema.GroupVersionKind{Kind: "ClusterRole"},
				Name: "admin",
			},
			expected: "ClusterRole/admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ref.Key()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceRefFromUnstructured(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      "my-deploy",
				"namespace": "my-namespace",
			},
		},
	}

	ref := ResourceRefFromUnstructured(obj)

	assert.Equal(t, "Deployment", ref.GVK.Kind)
	assert.Equal(t, "apps", ref.GVK.Group)
	assert.Equal(t, "v1", ref.GVK.Version)
	assert.Equal(t, "my-deploy", ref.Name)
	assert.Equal(t, "my-namespace", ref.Namespace)
}

func TestSummarizeReadiness(t *testing.T) {
	input := map[string]ResourceReadiness{
		"a": {Ready: true, Status: status.CurrentStatus},
		"b": {Ready: true, Status: status.CurrentStatus},
		"c": {Ready: false, Status: status.InProgressStatus},
		"d": {Ready: false, Status: status.FailedStatus},
	}

	summary := SummarizeReadiness(input)
	assert.Equal(t, "2/4 ready, 1 failed, 1 in-progress", summary)
}

func TestResourceReadiness_Helpers(t *testing.T) {
	tests := []struct {
		name          string
		readiness     ResourceReadiness
		wantReady     bool
		wantFailed    bool
		wantProgress  bool
		wantTerminate bool
	}{
		{
			name:      "current status",
			readiness: ResourceReadiness{Ready: true, Status: status.CurrentStatus},
			wantReady: true,
		},
		{
			name:       "failed status",
			readiness:  ResourceReadiness{Ready: false, Status: status.FailedStatus},
			wantFailed: true,
		},
		{
			name:         "in progress status",
			readiness:    ResourceReadiness{Ready: false, Status: status.InProgressStatus},
			wantProgress: true,
		},
		{
			name:          "terminating status",
			readiness:     ResourceReadiness{Ready: false, Status: status.TerminatingStatus},
			wantTerminate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantReady, tt.readiness.IsReady())
			assert.Equal(t, tt.wantFailed, tt.readiness.IsFailed())
			assert.Equal(t, tt.wantProgress, tt.readiness.IsInProgress())
			assert.Equal(t, tt.wantTerminate, tt.readiness.IsTerminating())
		})
	}
}

func TestCheckReadiness_PodRunning(t *testing.T) {
	pod := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "test-pod",
				"namespace": "default",
			},
			"status": map[string]interface{}{
				"phase": "Running",
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Ready",
						"status": "True",
					},
				},
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(pod)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}

func TestCheckReadiness_PodPending(t *testing.T) {
	pod := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "test-pod",
				"namespace": "default",
			},
			"status": map[string]interface{}{
				"phase": "Pending",
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(pod)

	assert.False(t, result.Ready)
	assert.Equal(t, status.InProgressStatus, result.Status)
}

func TestCheckReadiness_Job_Complete(t *testing.T) {
	job := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "batch/v1",
			"kind":       "Job",
			"metadata": map[string]interface{}{
				"name":      "test-job",
				"namespace": "default",
			},
			"status": map[string]interface{}{
				"succeeded": int64(1),
				"conditions": []interface{}{
					map[string]interface{}{
						"type":   "Complete",
						"status": "True",
					},
				},
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(job)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}

func TestCheckReadiness_StatefulSet_Ready(t *testing.T) {
	sts := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"metadata": map[string]interface{}{
				"name":       "test-sts",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"replicas": int64(3),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
			"status": map[string]interface{}{
				"observedGeneration": int64(1),
				"replicas":           int64(3),
				"readyReplicas":      int64(3),
				"currentReplicas":    int64(3),
				"updatedReplicas":    int64(3),
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(sts)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}

func TestCheckReadiness_Service(t *testing.T) {
	// Services are always current (no rollout status)
	svc := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Service",
			"metadata": map[string]interface{}{
				"name":      "test-svc",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"app": "test",
				},
				"ports": []interface{}{
					map[string]interface{}{
						"port":       int64(80),
						"targetPort": int64(8080),
					},
				},
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(svc)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}

func TestCheckReadiness_Terminating(t *testing.T) {
	now := metav1.Now()
	deploy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":              "test-deploy",
				"namespace":         "default",
				"deletionTimestamp": now.Format(time.RFC3339),
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(deploy)

	assert.False(t, result.Ready)
	assert.Equal(t, status.TerminatingStatus, result.Status)
	assert.True(t, result.IsTerminating())
}

func TestCheckReadiness_DaemonSet_Ready(t *testing.T) {
	ds := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "DaemonSet",
			"metadata": map[string]interface{}{
				"name":       "test-ds",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
			"status": map[string]interface{}{
				"observedGeneration":     int64(1),
				"desiredNumberScheduled": int64(3),
				"numberReady":            int64(3),
				"numberAvailable":        int64(3),
				"currentNumberScheduled": int64(3),
				"updatedNumberScheduled": int64(3),
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(ds)

	// DaemonSet should be current when all desired pods are ready
	require.Equal(t, status.CurrentStatus, result.Status)
	assert.True(t, result.Ready)
}

func TestCheckReadiness_ReplicaSet_Ready(t *testing.T) {
	rs := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "ReplicaSet",
			"metadata": map[string]interface{}{
				"name":       "test-rs",
				"namespace":  "default",
				"generation": int64(1),
			},
			"spec": map[string]interface{}{
				"replicas": int64(2),
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test",
					},
				},
				"template": map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app": "test",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "test",
								"image": "nginx",
							},
						},
					},
				},
			},
			"status": map[string]interface{}{
				"observedGeneration":   int64(1),
				"replicas":             int64(2),
				"readyReplicas":        int64(2),
				"availableReplicas":    int64(2),
				"fullyLabeledReplicas": int64(2),
			},
		},
	}

	checker := NewReadinessChecker(newTestLogger())
	result := checker.CheckReadiness(rs)

	assert.True(t, result.Ready)
	assert.Equal(t, status.CurrentStatus, result.Status)
}
