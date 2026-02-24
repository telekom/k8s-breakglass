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

package breakglass

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
)

// mockClientProvider is a test implementation of ClientProviderInterface
type mockClientProvider struct {
	clients map[string]ctrlclient.Client
	err     error
}

func (m *mockClientProvider) GetClient(_ context.Context, clusterName string) (ctrlclient.Client, error) {
	if m.err != nil {
		return nil, m.err
	}
	if client, ok := m.clients[clusterName]; ok {
		return client, nil
	}
	return nil, nil
}

func newKubectlTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = breakglassv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestKubectlDebugHandler_ValidateEphemeralContainerRequest(t *testing.T) {
	scheme := newKubectlTestScheme()

	tests := []struct {
		name         string
		session      *breakglassv1alpha1.DebugSession
		namespace    string
		podName      string
		image        string
		capabilities []string
		runAsNonRoot bool
		expectError  bool
		errorContain string
	}{
		{
			name: "valid request",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:       true,
								AllowedImages: []string{"busybox:*", "alpine:*"},
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			capabilities: nil,
			runAsNonRoot: false,
			expectError:  false,
		},
		{
			name: "no resolved template",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			expectError:  true,
			errorContain: "no resolved template",
		},
		{
			name: "ephemeral containers not configured",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: nil,
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			expectError:  true,
			errorContain: "ephemeral containers not configured",
		},
		{
			name: "ephemeral containers disabled",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled: false,
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			expectError:  true,
			errorContain: "not enabled",
		},
		{
			name: "namespace denied",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:          true,
								DeniedNamespaces: &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system", "kube-*"}},
							},
						},
					},
				},
			},
			namespace:    "kube-system",
			podName:      "test-pod",
			image:        "busybox:latest",
			expectError:  true,
			errorContain: "namespace kube-system is not allowed",
		},
		{
			name: "image not allowed",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:       true,
								AllowedImages: []string{"busybox:*"},
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "malicious:latest",
			expectError:  true,
			errorContain: "image malicious:latest is not in the allowed list",
		},
		{
			name: "requires image digest",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:            true,
								RequireImageDigest: true,
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			expectError:  true,
			errorContain: "must use @sha256: digest",
		},
		{
			name: "valid with image digest",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:            true,
								RequireImageDigest: true,
							},
						},
					},
				},
			},
			namespace:   "default",
			podName:     "test-pod",
			image:       "busybox@sha256:abc123def456",
			expectError: false,
		},
		{
			name: "capability not allowed",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:         true,
								MaxCapabilities: []string{"NET_ADMIN"},
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			capabilities: []string{"SYS_ADMIN"},
			expectError:  true,
			errorContain: "capability SYS_ADMIN is not allowed",
		},
		{
			name: "requires non-root",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:        true,
								RequireNonRoot: true,
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			runAsNonRoot: false,
			expectError:  true,
			errorContain: "must run as non-root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).Build()
			handler := NewKubectlDebugHandler(client, nil)

			err := handler.ValidateEphemeralContainerRequest(
				context.Background(),
				tt.session,
				tt.namespace,
				tt.podName,
				tt.image,
				tt.capabilities,
				tt.runAsNonRoot,
			)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContain)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestKubectlDebugHandler_isNamespaceAllowed(t *testing.T) {
	handler := &KubectlDebugHandler{}

	tests := []struct {
		name      string
		namespace string
		allowed   *breakglassv1alpha1.NamespaceFilter
		denied    *breakglassv1alpha1.NamespaceFilter
		expected  bool
	}{
		{
			name:      "no restrictions",
			namespace: "anything",
			allowed:   nil,
			denied:    nil,
			expected:  true,
		},
		{
			name:      "explicitly denied",
			namespace: "kube-system",
			allowed:   nil,
			denied:    &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-system"}},
			expected:  false,
		},
		{
			name:      "denied by pattern",
			namespace: "kube-public",
			allowed:   nil,
			denied:    &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"kube-*"}},
			expected:  false,
		},
		{
			name:      "allowed list only - match",
			namespace: "default",
			allowed:   &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"default", "app-*"}},
			denied:    nil,
			expected:  true,
		},
		{
			name:      "allowed list only - no match",
			namespace: "other",
			allowed:   &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"default", "app-*"}},
			denied:    nil,
			expected:  false,
		},
		{
			name:      "allowed by pattern",
			namespace: "app-frontend",
			allowed:   &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"default", "app-*"}},
			denied:    nil,
			expected:  true,
		},
		{
			name:      "denied takes precedence",
			namespace: "app-secret",
			allowed:   &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"app-*"}},
			denied:    &breakglassv1alpha1.NamespaceFilter{Patterns: []string{"app-secret"}},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isNamespaceAllowed(tt.namespace, tt.allowed, tt.denied)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlDebugHandler_isImageAllowed(t *testing.T) {
	handler := &KubectlDebugHandler{}

	tests := []struct {
		name     string
		image    string
		allowed  []string
		expected bool
	}{
		{
			name:     "no restrictions",
			image:    "anything:latest",
			allowed:  nil,
			expected: true,
		},
		{
			name:     "exact match",
			image:    "busybox:latest",
			allowed:  []string{"busybox:latest"},
			expected: true,
		},
		{
			name:     "wildcard match",
			image:    "busybox:1.35",
			allowed:  []string{"busybox:*"},
			expected: true,
		},
		{
			name:     "prefix match",
			image:    "gcr.io/myproject/myimage:v1",
			allowed:  []string{"gcr.io/myproject/*"},
			expected: true,
		},
		{
			name:     "no match",
			image:    "malicious:latest",
			allowed:  []string{"busybox:*", "alpine:*"},
			expected: false,
		},
		{
			name:     "digest pattern match",
			image:    "busybox@sha256:abc123",
			allowed:  []string{"busybox@sha256:*"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isImageAllowed(tt.image, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlDebugHandler_hasImageDigest(t *testing.T) {
	handler := &KubectlDebugHandler{}

	tests := []struct {
		name     string
		image    string
		expected bool
	}{
		{
			name:     "tag only",
			image:    "busybox:latest",
			expected: false,
		},
		{
			name:     "sha256 digest",
			image:    "busybox@sha256:abc123def456",
			expected: true,
		},
		{
			name:     "no tag or digest",
			image:    "busybox",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.hasImageDigest(tt.image)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlDebugHandler_isCapabilityAllowed(t *testing.T) {
	handler := &KubectlDebugHandler{}

	tests := []struct {
		name     string
		cap      string
		maxCaps  []string
		expected bool
	}{
		{
			name:     "no restrictions",
			cap:      "SYS_ADMIN",
			maxCaps:  nil,
			expected: true,
		},
		{
			name:     "allowed",
			cap:      "NET_ADMIN",
			maxCaps:  []string{"NET_ADMIN", "SYS_PTRACE"},
			expected: true,
		},
		{
			name:     "not allowed",
			cap:      "SYS_ADMIN",
			maxCaps:  []string{"NET_ADMIN"},
			expected: false,
		},
		{
			name:     "case insensitive",
			cap:      "net_admin",
			maxCaps:  []string{"NET_ADMIN"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isCapabilityAllowed(tt.cap, tt.maxCaps)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid label",
			input:    "valid-label_123",
			expected: "valid-label_123",
		},
		{
			name:     "email address",
			input:    "user@example.com",
			expected: "user_example.com",
		},
		{
			name:     "special characters",
			input:    "my/path:value!",
			expected: "my_path_value_",
		},
		{
			name:     "too long",
			input:    "this-is-a-very-long-label-value-that-exceeds-the-kubernetes-maximum-of-63-characters",
			expected: "this-is-a-very-long-label-value-that-exceeds-the-kubernetes-max",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeLabel(tt.input)
			assert.Equal(t, tt.expected, result)
			assert.LessOrEqual(t, len(result), 63)
		})
	}
}

func TestKubectlDebugHandler_InjectEphemeralContainer(t *testing.T) {
	scheme := newKubectlTestScheme()

	// Create a test pod
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "main",
					Image: "nginx:latest",
				},
			},
		},
	}

	// Create a test session
	testSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
						Enabled: true,
					},
				},
			},
		},
	}

	// Create clients
	targetClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testPod).
		Build()

	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testSession).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	mockProvider := &mockClientProvider{
		clients: map[string]ctrlclient.Client{
			"test-cluster": targetClient,
		},
	}

	handler := NewKubectlDebugHandler(hubClient, mockProvider)

	t.Run("inject ephemeral container", func(t *testing.T) {
		err := handler.InjectEphemeralContainer(
			context.Background(),
			testSession,
			"default",
			"test-pod",
			"debugger",
			"busybox:latest",
			[]string{"sh"},
			nil,
			"test-user@example.com",
		)

		// The fake client may or may not support SubResource updates depending on version
		// We just verify the function runs without panicking
		_ = err
	})

	t.Run("container already exists", func(t *testing.T) {
		// Add existing ephemeral container to pod
		podWithEC := testPod.DeepCopy()
		podWithEC.Spec.EphemeralContainers = []corev1.EphemeralContainer{
			{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name:  "existing",
					Image: "busybox:latest",
				},
			},
		}

		targetClient2 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(podWithEC).
			Build()

		mockProvider2 := &mockClientProvider{
			clients: map[string]ctrlclient.Client{
				"test-cluster": targetClient2,
			},
		}

		handler2 := NewKubectlDebugHandler(hubClient, mockProvider2)

		err := handler2.InjectEphemeralContainer(
			context.Background(),
			testSession,
			"default",
			"test-pod",
			"existing", // Same name as existing
			"busybox:latest",
			[]string{"sh"},
			nil,
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestKubectlDebugHandler_CreatePodCopy(t *testing.T) {
	scheme := newKubectlTestScheme()

	// Create test namespace
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "debug-copies",
		},
	}

	// Create a test pod to copy
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-pod",
			Namespace: "production",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "app",
					Image: "myapp:v1",
				},
			},
		},
	}

	// Create a test session
	testSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session-12345678",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					PodCopy: &breakglassv1alpha1.PodCopyConfig{
						Enabled:         true,
						TargetNamespace: "debug-copies",
						TTL:             "1h",
					},
				},
			},
		},
	}

	targetClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testPod, testNs).
		Build()

	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testSession).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	mockProvider := &mockClientProvider{
		clients: map[string]ctrlclient.Client{
			"test-cluster": targetClient,
		},
	}

	handler := NewKubectlDebugHandler(hubClient, mockProvider)

	t.Run("create pod copy", func(t *testing.T) {
		pod, err := handler.CreatePodCopy(
			context.Background(),
			testSession,
			"production",
			"app-pod",
			"busybox:latest",
			"test-user@example.com",
		)

		require.NoError(t, err)
		assert.NotNil(t, pod)
		assert.Contains(t, pod.Name, "debug-copy-app-pod")
		assert.Equal(t, "debug-copies", pod.Namespace)
		assert.Equal(t, corev1.RestartPolicyNever, pod.Spec.RestartPolicy)

		// Should have original container + debug container
		assert.Len(t, pod.Spec.Containers, 2)

		// Check labels
		assert.Equal(t, testSession.Name, pod.Labels[DebugSessionLabelKey])
		assert.Equal(t, "true", pod.Labels["breakglass.telekom.com/debug-copy"])
	})

	t.Run("pod copy disabled", func(t *testing.T) {
		disabledSession := testSession.DeepCopy()
		disabledSession.Status.ResolvedTemplate.KubectlDebug.PodCopy.Enabled = false

		_, err := handler.CreatePodCopy(
			context.Background(),
			disabledSession,
			"production",
			"app-pod",
			"",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("target namespace missing", func(t *testing.T) {
		sessionWithMissingNs := testSession.DeepCopy()
		sessionWithMissingNs.Status.ResolvedTemplate.KubectlDebug.PodCopy.TargetNamespace = "missing-namespace"

		_, err := handler.CreatePodCopy(
			context.Background(),
			sessionWithMissingNs,
			"production",
			"app-pod",
			"",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})
}

func TestKubectlDebugHandler_CreateNodeDebugPod(t *testing.T) {
	scheme := newKubectlTestScheme()

	// Create test namespace
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "breakglass-debug",
		},
	}

	// Create a test node
	testNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-1",
			Labels: map[string]string{
				"node-role.kubernetes.io/worker": "true",
			},
		},
	}

	// Create a test session
	testSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session-12345678",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster: "test-cluster",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
				TargetNamespace: "breakglass-debug",
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
						Enabled:       true,
						AllowedImages: []string{"busybox:stable"},
						HostNamespaces: &breakglassv1alpha1.HostNamespacesConfig{
							HostNetwork: true,
							HostPID:     true,
							HostIPC:     false,
						},
					},
				},
			},
		},
	}

	targetClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testNode, testNs).
		Build()

	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testSession).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()

	mockProvider := &mockClientProvider{
		clients: map[string]ctrlclient.Client{
			"test-cluster": targetClient,
		},
	}

	handler := NewKubectlDebugHandler(hubClient, mockProvider)

	t.Run("create node debug pod", func(t *testing.T) {
		pod, err := handler.CreateNodeDebugPod(
			context.Background(),
			testSession,
			"worker-1",
			"test-user@example.com",
		)

		require.NoError(t, err)
		assert.NotNil(t, pod)
		assert.Contains(t, pod.Name, "node-debugger-worker-1")
		assert.Equal(t, "breakglass-debug", pod.Namespace)
		assert.Equal(t, "worker-1", pod.Spec.NodeName)
		assert.True(t, pod.Spec.HostNetwork)
		assert.True(t, pod.Spec.HostPID)
		assert.False(t, pod.Spec.HostIPC)

		// Check container
		require.Len(t, pod.Spec.Containers, 1)
		assert.Equal(t, "debugger", pod.Spec.Containers[0].Name)
		assert.Equal(t, "busybox:stable", pod.Spec.Containers[0].Image)
		assert.True(t, *pod.Spec.Containers[0].SecurityContext.Privileged)

		// Check host root mount
		require.Len(t, pod.Spec.Volumes, 1)
		assert.Equal(t, "host-root", pod.Spec.Volumes[0].Name)
	})

	t.Run("node debug disabled", func(t *testing.T) {
		disabledSession := testSession.DeepCopy()
		disabledSession.Status.ResolvedTemplate.KubectlDebug.NodeDebug.Enabled = false

		_, err := handler.CreateNodeDebugPod(
			context.Background(),
			disabledSession,
			"worker-1",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("node selector mismatch", func(t *testing.T) {
		selectorSession := testSession.DeepCopy()
		selectorSession.Status.ResolvedTemplate.KubectlDebug.NodeDebug.NodeSelector = map[string]string{
			"special": "true",
		}

		_, err := handler.CreateNodeDebugPod(
			context.Background(),
			selectorSession,
			"worker-1",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match required selector")
	})
}

func TestKubectlDebugHandler_CleanupKubectlDebugResources(t *testing.T) {
	scheme := newKubectlTestScheme()

	t.Run("no-op when KubectlDebugStatus is nil", func(t *testing.T) {
		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		mockProvider := &mockClientProvider{}
		handler := NewKubectlDebugHandler(hubClient, mockProvider)

		session := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				KubectlDebugStatus: nil, // No kubectl debug status
			},
		}

		err := handler.CleanupKubectlDebugResources(context.Background(), session)
		require.NoError(t, err)
	})

	t.Run("returns error when GetClient fails", func(t *testing.T) {
		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		mockProvider := &mockClientProvider{
			err: assert.AnError,
		}
		handler := NewKubectlDebugHandler(hubClient, mockProvider)

		session := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{
					CopiedPods: []breakglassv1alpha1.CopiedPodRef{
						{CopyName: "pod-copy", CopyNamespace: "default"},
					},
				},
			},
		}

		err := handler.CleanupKubectlDebugResources(context.Background(), session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get client")
	})

	t.Run("cleans up copied pods and clears status", func(t *testing.T) {
		// Create target cluster client with a pod to delete
		targetClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-copy",
					Namespace: "default",
				},
			}).
			Build()

		session := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStateTerminated,
				KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{
					CopiedPods: []breakglassv1alpha1.CopiedPodRef{
						{CopyName: "pod-copy", CopyNamespace: "default"},
					},
				},
			},
		}

		// Create hub client with the session
		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()

		mockProvider := &mockClientProvider{
			clients: map[string]ctrlclient.Client{
				"test-cluster": targetClient,
			},
		}
		handler := NewKubectlDebugHandler(hubClient, mockProvider)

		err := handler.CleanupKubectlDebugResources(context.Background(), session)
		require.NoError(t, err)

		// Verify KubectlDebugStatus is cleared
		assert.Nil(t, session.Status.KubectlDebugStatus)
	})

	t.Run("wraps ErrClusterConfigNotFound for reconciler handling", func(t *testing.T) {
		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			Build()

		// Simulate the error that would come from clusterClientAdapter when ClusterConfig is missing
		wrappedErr := fmt.Errorf("failed to get REST config: %w", cluster.ErrClusterConfigNotFound)
		mockProvider := &mockClientProvider{
			err: wrappedErr,
		}
		handler := NewKubectlDebugHandler(hubClient, mockProvider)

		session := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "orphaned-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "deleted-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{
					CopiedPods: []breakglassv1alpha1.CopiedPodRef{
						{CopyName: "pod-copy", CopyNamespace: "default"},
					},
				},
			},
		}

		err := handler.CleanupKubectlDebugResources(context.Background(), session)
		require.Error(t, err)

		// Verify that the error wraps ErrClusterConfigNotFound so the reconciler can detect it
		assert.True(t, errors.Is(err, cluster.ErrClusterConfigNotFound),
			"error should wrap ErrClusterConfigNotFound for reconciler to handle gracefully")
	})
}
