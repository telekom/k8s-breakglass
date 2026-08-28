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

package debug

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
)

// mockClientProvider is a test implementation of ClientProviderInterface
type mockClientProvider struct {
	clients       map[string]ctrlclient.Client
	err           error
	configured    *breakglassv1alpha1.ClusterConfig
	events        *[]string
	validateCalls int
	validateErrAt int
	validateErr   error
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

func (m *mockClientProvider) GetClientForPrivilegedOperation(ctx context.Context, clusterName string) (ctrlclient.Client, *breakglassv1alpha1.ClusterConfig, error) {
	targetClient, err := m.GetClient(ctx, clusterName)
	if err != nil {
		return nil, nil, err
	}
	configured := m.configured
	if configured == nil {
		configured = &breakglassv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: "default", UID: types.UID(clusterName + "-uid")},
		}
	}
	return targetClient, configured.DeepCopy(), nil
}

func (m *mockClientProvider) ValidatePrivilegedOperationClusterConfig(_ context.Context, _ *breakglassv1alpha1.ClusterConfig) error {
	m.validateCalls++
	if m.events != nil {
		*m.events = append(*m.events, "validate-cluster-config")
	}
	if m.validateErr != nil && (m.validateErrAt == 0 || m.validateCalls == m.validateErrAt) {
		return m.validateErr
	}
	return nil
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
		privileged   bool
		expectError  bool
		errorContain string
		wantHTTP     int
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
			wantHTTP:     http.StatusBadRequest,
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
			wantHTTP:     http.StatusBadRequest,
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
			wantHTTP:     http.StatusBadRequest,
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
			wantHTTP:     http.StatusForbidden,
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
			wantHTTP:     http.StatusForbidden,
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
			wantHTTP:     http.StatusForbidden,
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
			wantHTTP:     http.StatusForbidden,
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
			wantHTTP:     http.StatusForbidden,
		},
		{
			name: "privileged denied unless explicitly allowed",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:         true,
								AllowPrivileged: false,
							},
						},
					},
				},
			},
			namespace:    "default",
			podName:      "test-pod",
			image:        "busybox:latest",
			privileged:   true,
			expectError:  true,
			errorContain: "privileged ephemeral containers are not allowed",
			wantHTTP:     http.StatusForbidden,
		},
		{
			name: "privileged allowed when configured",
			session: &breakglassv1alpha1.DebugSession{
				Status: breakglassv1alpha1.DebugSessionStatus{
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
							EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
								Enabled:         true,
								AllowPrivileged: true,
							},
						},
					},
				},
			},
			namespace:   "default",
			podName:     "test-pod",
			image:       "busybox:latest",
			privileged:  true,
			expectError: false,
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
				tt.privileged,
			)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContain)
				assert.Equal(t, tt.wantHTTP, kubectlDebugOperationHTTPStatus(err))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestKubectlDebugHandler_ValidateEphemeralContainerRequestNamespaceSelectors(t *testing.T) {
	scheme := newKubectlTestScheme()

	session := &breakglassv1alpha1.DebugSession{
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
						Enabled: true,
					},
				},
			},
		},
	}
	prodNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "production",
			Labels: map[string]string{"env": "prod"},
		},
	}

	tests := []struct {
		name             string
		allowed          *breakglassv1alpha1.NamespaceFilter
		denied           *breakglassv1alpha1.NamespaceFilter
		targetObjects    []ctrlclient.Object
		expectError      bool
		expectedErrorMsg string
		wantHTTP         int
	}{
		{
			name: "allowed selector matches namespace labels",
			allowed: &breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			targetObjects: []ctrlclient.Object{prodNamespace},
		},
		{
			name: "allowed selector blocks non matching namespace labels",
			allowed: &breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "staging"}},
				},
			},
			targetObjects:    []ctrlclient.Object{prodNamespace},
			expectError:      true,
			expectedErrorMsg: "namespace production is not allowed",
			wantHTTP:         http.StatusForbidden,
		},
		{
			name: "denied selector blocks matching namespace labels",
			denied: &breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			targetObjects:    []ctrlclient.Object{prodNamespace},
			expectError:      true,
			expectedErrorMsg: "namespace production is not allowed",
			wantHTTP:         http.StatusForbidden,
		},
		{
			name: "selector lookup treats missing namespace as request error",
			allowed: &breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
					{MatchLabels: map[string]string{"env": "prod"}},
				},
			},
			expectError:      true,
			expectedErrorMsg: "namespace production not found",
			wantHTTP:         http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSession := session.DeepCopy()
			testSession.Status.ResolvedTemplate.KubectlDebug.EphemeralContainers.AllowedNamespaces = tt.allowed
			testSession.Status.ResolvedTemplate.KubectlDebug.EphemeralContainers.DeniedNamespaces = tt.denied

			targetClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.targetObjects...).
				Build()
			hubClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
				clients: map[string]ctrlclient.Client{"test-cluster": targetClient},
			})

			err := handler.ValidateEphemeralContainerRequest(
				context.Background(),
				testSession,
				"production",
				"test-pod",
				"busybox:latest",
				nil,
				false,
				false,
			)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrorMsg)
				assert.Equal(t, tt.wantHTTP, kubectlDebugOperationHTTPStatus(err))
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("selector lookup uses handler client when provider is nil", func(t *testing.T) {
		testSession := session.DeepCopy()
		testSession.Status.ResolvedTemplate.KubectlDebug.EphemeralContainers.AllowedNamespaces = &breakglassv1alpha1.NamespaceFilter{
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{MatchLabels: map[string]string{"env": "prod"}},
			},
		}

		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(prodNamespace).
			Build()
		handler := NewKubectlDebugHandler(hubClient, nil)

		err := handler.ValidateEphemeralContainerRequest(
			context.Background(),
			testSession,
			"production",
			"test-pod",
			"busybox:latest",
			nil,
			false,
			false,
		)

		require.NoError(t, err)
	})
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
			name:     "exact entry does not allow longer prefix",
			image:    "registry.example.com/debug:1.0.0-backdoored",
			allowed:  []string{"registry.example.com/debug:1.0.0"},
			expected: false,
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
			UID:       "pod-test-uid",
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
			UID:       "session-test-uid",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: func() *metav1.Time {
				at := metav1.NewTime(time.Now().UTC().Add(time.Hour))
				return &at
			}(),
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
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, subResourceName string, obj ctrlclient.Object, _ ...ctrlclient.SubResourceUpdateOption) error {
				if subResourceName == "ephemeralcontainers" {
					return cl.Update(ctx, obj)
				}
				return cl.SubResource(subResourceName).Update(ctx, obj)
			},
		}).
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

		require.NoError(t, err)
		storedPod := &corev1.Pod{}
		require.NoError(t, targetClient.Get(context.Background(), ctrlclient.ObjectKey{Name: "test-pod", Namespace: "default"}, storedPod))
		require.Len(t, storedPod.Spec.EphemeralContainers, 1)
		assert.Equal(t, "debugger", storedPod.Spec.EphemeralContainers[0].Name)
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

func newEphemeralOperationTestSession() *breakglassv1alpha1.DebugSession {
	expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	return &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "operation-session",
			Namespace: "default",
			UID:       "operation-session-uid",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAt,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true},
				},
			},
		},
	}
}

func TestKubectlDebugHandler_EphemeralOperationIntentPrecedesTargetMutation(t *testing.T) {
	scheme := newKubectlTestScheme()
	statusErr := errors.New("simulated durable intent write failure")
	updates := 0
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}},
	}
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
				if name == "ephemeralcontainers" {
					updates++
				}
				return cl.SubResource(name).Update(ctx, obj, opts...)
			},
		}).Build()
	hubClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(newEphemeralOperationTestSession()).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ ctrlclient.Client, name string, _ ctrlclient.Object, _ ctrlclient.Patch, _ ...ctrlclient.SubResourcePatchOption) error {
				if name == "status" {
					return statusErr
				}
				return nil
			},
		}).Build()
	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	err := handler.InjectEphemeralContainer(context.Background(), newEphemeralOperationTestSession(), "default", "target", "debugger", "busybox:latest", []string{"sh"}, nil, "test-user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist ephemeral-container operation intent")
	assert.Zero(t, updates, "target mutation must not be attempted when durable intent cannot be written")

	storedPod := &corev1.Pod{}
	require.NoError(t, targetClient.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "default", Name: "target"}, storedPod))
	assert.Empty(t, storedPod.Spec.EphemeralContainers)
}

func TestKubectlDebugHandler_EphemeralOperationRecoversAfterOutcomeWriteFailure(t *testing.T) {
	scheme := newKubectlTestScheme()
	statusPatches := 0
	targetUpdates := 0
	statusErr := errors.New("simulated outcome write failure")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "target-uid"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}},
	}
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
				if name == "ephemeralcontainers" {
					targetUpdates++
					return cl.Update(ctx, obj)
				}
				return cl.SubResource(name).Update(ctx, obj, opts...)
			},
		}).Build()
	hubClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(newEphemeralOperationTestSession()).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, cl ctrlclient.Client, name string, obj ctrlclient.Object, patch ctrlclient.Patch, opts ...ctrlclient.SubResourcePatchOption) error {
				if name == "status" {
					statusPatches++
					if statusPatches == 2 {
						return statusErr
					}
				}
				return cl.SubResource(name).Patch(ctx, obj, patch, opts...)
			},
		}).Build()
	provider := &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}}
	handler := NewKubectlDebugHandler(hubClient, provider)
	session := newEphemeralOperationTestSession()

	err := handler.InjectEphemeralContainer(context.Background(), session, "default", "target", "debugger", "busybox:latest", []string{"sh"}, nil, "test-user@example.com")
	require.Error(t, err, "the interrupted outcome write must be reported")

	var afterFailure breakglassv1alpha1.DebugSession
	require.NoError(t, hubClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &afterFailure))
	require.NotNil(t, afterFailure.Status.KubectlDebugStatus)
	require.Len(t, afterFailure.Status.KubectlDebugStatus.Operations, 1)
	assert.Equal(t, breakglassv1alpha1.KubectlDebugOperationPrepared, afterFailure.Status.KubectlDebugStatus.Operations[0].State)
	var changedPod corev1.Pod
	require.NoError(t, targetClient.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "default", Name: "target"}, &changedPod))
	require.Len(t, changedPod.Spec.EphemeralContainers, 1, "the target mutation must remain observable for recovery")

	// A fresh handler models a controller restart. Once the status writer is
	// healthy again, recovery inspects the exact Pod UID and container request,
	// then commits the existing operation without re-applying the mutation.
	statusPatches = 2
	restarted := NewKubectlDebugHandler(hubClient, provider)
	require.NoError(t, restarted.RecoverPendingKubectlDebugOperations(context.Background(), &afterFailure))

	var recovered breakglassv1alpha1.DebugSession
	require.NoError(t, hubClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &recovered))
	require.Len(t, recovered.Status.KubectlDebugStatus.Operations, 1)
	assert.Equal(t, breakglassv1alpha1.KubectlDebugOperationCompleted, recovered.Status.KubectlDebugStatus.Operations[0].State)
	require.Len(t, recovered.Status.KubectlDebugStatus.EphemeralContainersInjected, 1)
	assert.Equal(t, "debugger", recovered.Status.KubectlDebugStatus.EphemeralContainersInjected[0].ContainerName)
	assert.Len(t, changedPod.Spec.EphemeralContainers, 1, "recovery must not duplicate the target mutation")

	// Retrying the original API operation after recovery must be an idempotent
	// success, not an "already exists" error or a second subresource update.
	require.NoError(t, restarted.InjectEphemeralContainer(context.Background(), &recovered,
		"default", "target", "debugger", "busybox:latest", []string{"sh"}, nil,
		"test-user@example.com"))
	assert.Equal(t, 1, targetUpdates, "an idempotent retry must not update the target twice")
}

func TestKubectlDebugHandler_EphemeralOperationAmbiguousTargetIsNotGuessed(t *testing.T) {
	scheme := newKubectlTestScheme()
	prepared := newEphemeralOperationTestSession()
	desired := breakglassv1alpha1.KubectlDebugEphemeralContainerIntent{Name: "debugger", Image: "busybox:latest", Command: []string{"sh"}, SecurityContextDigest: securityContextDigest(nil), TTY: true, Stdin: true}
	prepared.Status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{Operations: []breakglassv1alpha1.KubectlDebugOperation{{
		ID: "ambiguous-operation", Kind: kubectlDebugOperationKindEphemeralContainer, State: breakglassv1alpha1.KubectlDebugOperationPrepared,
		TargetPod:          breakglassv1alpha1.KubectlDebugOperationTargetPod{Namespace: "default", Name: "target", UID: "original-uid"},
		EphemeralContainer: desired, RequestedBy: "test-user@example.com", PreparedAt: metav1.Now(),
	}}}
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "default", UID: "replacement-uid"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}},
	}).Build()
	hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(prepared).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	require.NoError(t, handler.RecoverPendingKubectlDebugOperations(context.Background(), prepared))
	var recovered breakglassv1alpha1.DebugSession
	require.NoError(t, hubClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(prepared), &recovered))
	require.Len(t, recovered.Status.KubectlDebugStatus.Operations, 1)
	assert.Equal(t, breakglassv1alpha1.KubectlDebugOperationUnknown, recovered.Status.KubectlDebugStatus.Operations[0].State)
	assert.Empty(t, recovered.Status.KubectlDebugStatus.EphemeralContainersInjected, "an identity mismatch must not be recorded as success")
}

func TestKubectlDebugHandler_InjectEphemeralContainerPreservesLiveStatusFromStaleSession(t *testing.T) {
	scheme := newKubectlTestScheme()
	ctx := context.Background()
	oldExpiry := metav1.NewTime(time.Now().UTC().Add(15 * time.Minute))
	renewedExpiry := metav1.NewTime(time.Now().UTC().Add(45 * time.Minute))

	targetClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "app-pod",
				Namespace: "production",
				UID:       "pod-app-uid",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app", Image: "myapp:v1"}},
			},
		}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, subResourceName string, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
				if subResourceName == "ephemeralcontainers" {
					return nil
				}
				return cl.SubResource(subResourceName).Update(ctx, obj, opts...)
			},
		}).
		Build()

	liveSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-session-12345678",
			Namespace:       "default",
			UID:             "session-live-uid",
			ResourceVersion: "2",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:        breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt:    &renewedExpiry,
			RenewalCount: 1,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{{
				User:     "active@example.com",
				Role:     breakglassv1alpha1.ParticipantRoleParticipant,
				JoinedAt: metav1.Now(),
			}},
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
	staleSession := liveSession.DeepCopy()
	staleSession.ResourceVersion = "1"
	staleSession.Status.ExpiresAt = &oldExpiry
	staleSession.Status.RenewalCount = 0
	staleSession.Status.Participants = nil

	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(liveSession).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
		clients: map[string]ctrlclient.Client{"test-cluster": targetClient},
	})

	err := handler.InjectEphemeralContainer(
		ctx,
		staleSession,
		"production",
		"app-pod",
		"debugger",
		"busybox:latest",
		[]string{"sh"},
		nil,
		"active@example.com",
	)
	require.NoError(t, err)

	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hubClient.Get(ctx, ctrlclient.ObjectKey{Name: liveSession.Name, Namespace: liveSession.Namespace}, stored))
	require.NotNil(t, stored.Status.ExpiresAt)
	assert.WithinDuration(t, renewedExpiry.Time, stored.Status.ExpiresAt.Time, time.Second)
	assert.Equal(t, int32(1), stored.Status.RenewalCount)
	require.Len(t, stored.Status.Participants, 1)
	assert.Equal(t, "active@example.com", stored.Status.Participants[0].User)
	require.NotNil(t, stored.Status.KubectlDebugStatus)
	require.Len(t, stored.Status.KubectlDebugStatus.EphemeralContainersInjected, 1)
	assert.Equal(t, "debugger", stored.Status.KubectlDebugStatus.EphemeralContainersInjected[0].ContainerName)
	assert.Contains(t, stored.Status.AllowedPods, breakglassv1alpha1.AllowedPodRef{
		Namespace: "production",
		Name:      "app-pod",
		Ready:     true,
	})
}

func TestKubectlDebugHandler_InjectEphemeralContainerFinalSessionFence(t *testing.T) {
	scheme := newKubectlTestScheme()
	expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	liveSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "fenced-session", Namespace: "default", UID: "session-fenced-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "operator@example.com"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:     breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: &expiresAt,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode:         breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true}},
			},
		},
	}

	tests := []struct {
		name          string
		mutateSession func(*breakglassv1alpha1.DebugSession)
		mutatePod     func(*corev1.Pod)
	}{
		{name: "missing expiry", mutateSession: func(ds *breakglassv1alpha1.DebugSession) { ds.Status.ExpiresAt = nil }},
		{name: "equal expiry", mutateSession: func(ds *breakglassv1alpha1.DebugSession) { at := metav1.Now(); ds.Status.ExpiresAt = &at }},
		{name: "past expiry", mutateSession: func(ds *breakglassv1alpha1.DebugSession) {
			at := metav1.NewTime(time.Now().UTC().Add(-time.Hour))
			ds.Status.ExpiresAt = &at
		}},
		{name: "replaced", mutateSession: func(ds *breakglassv1alpha1.DebugSession) { ds.UID = "replacement-uid" }},
		{name: "changed template", mutateSession: func(ds *breakglassv1alpha1.DebugSession) { ds.Status.ResolvedTemplate = nil }},
		{name: "replaced pod", mutatePod: func(pod *corev1.Pod) { pod.UID = "replacement-pod-uid" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "production", UID: "pod-original-uid"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:v1"}}}}
			targetGets := 0
			targetUpdates := 0
			targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					targetGets++
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if targetGets > 1 && tt.mutatePod != nil {
						tt.mutatePod(obj.(*corev1.Pod))
					}
					return nil
				},
				SubResourceUpdate: func(context.Context, ctrlclient.Client, string, ctrlclient.Object, ...ctrlclient.SubResourceUpdateOption) error {
					targetUpdates++
					return nil
				},
			}).Build()

			hubObject := liveSession.DeepCopy()
			hubObject.Status.ExpiresAt = &expiresAt
			hubGets := 0
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(hubObject).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					hubGets++
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if hubGets > 1 && tt.mutateSession != nil {
						tt.mutateSession(obj.(*breakglassv1alpha1.DebugSession))
					}
					return nil
				},
			}).Build()

			handler := NewKubectlDebugHandlerWithReader(hubClient, hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})
			err := handler.InjectEphemeralContainer(context.Background(), liveSession.DeepCopy(), "production", "target", "debug", "busybox:latest", nil, nil, "operator@example.com")
			require.Error(t, err)
			assert.Zero(t, targetUpdates, "denied mutation must not update target Pod")
		})
	}
}

func TestKubectlDebugHandler_InjectEphemeralContainerRepeatsNamespacePolicyAtMutation(t *testing.T) {
	scheme := newKubectlTestScheme()
	expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "namespace-fence", Namespace: "default", UID: "namespace-fence-uid"},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "operator@example.com"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiresAt,
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
					Enabled: true,
					AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{{
						MatchLabels: map[string]string{"debug": "allowed"},
					}}},
				}},
			},
		},
	}
	hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
	namespaceReads := 0
	updates := 0
	targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production", Labels: map[string]string{"debug": "allowed"}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "production", UID: "pod-uid"}},
	).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			if err := cl.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if ns, ok := obj.(*corev1.Namespace); ok {
				namespaceReads++
				if namespaceReads > 1 {
					ns.Labels = map[string]string{"debug": "denied"}
				}
			}
			return nil
		},
		SubResourceUpdate: func(context.Context, ctrlclient.Client, string, ctrlclient.Object, ...ctrlclient.SubResourceUpdateOption) error {
			updates++
			return nil
		},
	}).Build()
	handler := NewKubectlDebugHandlerWithReader(hubClient, hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

	require.NoError(t, handler.ValidateEphemeralContainerRequest(context.Background(), session, "production", "app", "busybox:stable", nil, false, false))
	err := handler.InjectEphemeralContainer(context.Background(), session, "production", "app", "debugger", "busybox:stable", nil, nil, "operator@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer allowed")
	assert.Zero(t, updates, "namespace policy revoked before the privileged boundary must prevent the target update")
}

func TestKubectlDebugHandler_PrivilegedWritesFenceClusterConfig(t *testing.T) {
	tests := []struct {
		name      string
		operation func(context.Context, *KubectlDebugHandler, *breakglassv1alpha1.DebugSession) error
		objects   []ctrlclient.Object
	}{
		{
			name: "ephemeral update",
			objects: []ctrlclient.Object{
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "production", UID: "pod-uid"}},
			},
			operation: func(ctx context.Context, handler *KubectlDebugHandler, session *breakglassv1alpha1.DebugSession) error {
				return handler.InjectEphemeralContainer(ctx, session, "production", "app", "debugger", "busybox:stable", nil, nil, "operator@example.com")
			},
		},
		{
			name: "pod copy create",
			objects: []ctrlclient.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production", UID: "production-uid"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}},
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "production", UID: "pod-uid"}},
			},
			operation: func(ctx context.Context, handler *KubectlDebugHandler, session *breakglassv1alpha1.DebugSession) error {
				_, err := handler.CreatePodCopy(ctx, session, "production", "app", "", "operator@example.com")
				return err
			},
		},
		{
			name: "node debug create",
			objects: []ctrlclient.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "debug-namespace-uid"}},
				&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-uid"}},
			},
			operation: func(ctx context.Context, handler *KubectlDebugHandler, session *breakglassv1alpha1.DebugSession) error {
				_, err := handler.CreateNodeDebugPod(ctx, session, "worker-1", "operator@example.com")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, outcome := range []struct {
				name        string
				validateErr error
				wantEvents  []string
			}{
				{name: "unchanged", wantEvents: []string{"validate-cluster-config", "target-write"}},
				{name: "changed", validateErr: errors.New("ClusterConfig default/test-cluster spec changed"), wantEvents: []string{"validate-cluster-config"}},
			} {
				t.Run(outcome.name, func(t *testing.T) {
					scheme := newKubectlTestScheme()
					expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
					session := &breakglassv1alpha1.DebugSession{
						ObjectMeta: metav1.ObjectMeta{Name: "cluster-fence-session", Namespace: "default", UID: "session-uid"},
						Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "operator@example.com"},
						Status: breakglassv1alpha1.DebugSessionStatus{
							State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiresAt,
							ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
								Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug, TargetNamespace: "breakglass-debug",
								KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
									EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true},
									PodCopy:             &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "debug-copies"},
									NodeDebug:           &breakglassv1alpha1.NodeDebugConfig{Enabled: true},
								},
							},
						},
					}
					events := []string{}
					targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.objects...).WithInterceptorFuncs(interceptor.Funcs{
						Create: func(context.Context, ctrlclient.WithWatch, ctrlclient.Object, ...ctrlclient.CreateOption) error {
							events = append(events, "target-write")
							return nil
						},
						SubResourceUpdate: func(context.Context, ctrlclient.Client, string, ctrlclient.Object, ...ctrlclient.SubResourceUpdateOption) error {
							events = append(events, "target-write")
							return nil
						},
					}).Build()
					hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
					provider := &mockClientProvider{
						clients:     map[string]ctrlclient.Client{"test-cluster": targetClient},
						events:      &events,
						validateErr: outcome.validateErr,
					}
					handler := NewKubectlDebugHandlerWithReader(hubClient, hubClient, provider)

					err := tt.operation(context.Background(), handler, session.DeepCopy())
					if outcome.validateErr != nil {
						require.Error(t, err)
						assert.Contains(t, err.Error(), "target cluster configuration changed")
					} else {
						require.NoError(t, err)
					}
					assert.Equal(t, 1, provider.validateCalls, "the ClusterConfig must be read at the final write fence")
					assert.Equal(t, outcome.wantEvents, events, "the final live ClusterConfig read must be immediately before the target write")
				})
			}
		})
	}
}

func TestKubectlDebugHandler_CreatePodCopy(t *testing.T) {
	scheme := newKubectlTestScheme()

	// Create test namespace
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "debug-copies",
			UID:  "debug-copies-uid",
		},
	}

	productionNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "production",
		},
	}

	// Create a test pod to copy
	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-pod",
			Namespace: "production",
			UID:       "pod-app-uid",
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
			UID:       "session-copy-uid",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: func() *metav1.Time {
				at := metav1.NewTime(time.Now().UTC().Add(time.Hour))
				return &at
			}(),
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
		WithObjects(testPod, testNs, productionNs).
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
		assert.Equal(t, "debugger", pod.Spec.Containers[1].Name)
		assert.Equal(t, "busybox:latest", pod.Spec.Containers[1].Image)
		assert.Empty(t, pod.Spec.Containers[1].ImagePullPolicy)

		// Check labels
		assert.Equal(t, testSession.Name, pod.Labels[DebugSessionLabelKey])
		assert.Equal(t, "true", pod.Labels["breakglass.telekom.com/debug-copy"])
	})

	t.Run("pod copy disabled", func(t *testing.T) {
		disabledSession := testSession.DeepCopy()
		disabledSession.Status.ResolvedTemplate.KubectlDebug.PodCopy.Enabled = false
		disabledHub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabledSession).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
		disabledHandler := NewKubectlDebugHandler(disabledHub, mockProvider)

		_, err := disabledHandler.CreatePodCopy(
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
		missingNsHub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sessionWithMissingNs).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
		missingNsHandler := NewKubectlDebugHandler(missingNsHub, mockProvider)

		_, err := missingNsHandler.CreatePodCopy(
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

	t.Run("namespace allowed passes validation", func(t *testing.T) {
		sessionWithAllowed := testSession.DeepCopy()
		sessionWithAllowed.Status.ResolvedTemplate.KubectlDebug.PodCopy.AllowedNamespaces = &breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"production", "staging"},
		}

		targetClient2 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(testPod, testNs, productionNs).
			Build()
		hubClient2 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(sessionWithAllowed).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
			Build()
		handler2 := NewKubectlDebugHandler(hubClient2, &mockClientProvider{
			clients: map[string]ctrlclient.Client{"test-cluster": targetClient2},
		})

		pod, err := handler2.CreatePodCopy(
			context.Background(),
			sessionWithAllowed,
			"production",
			"app-pod",
			"",
			"test-user@example.com",
		)

		require.NoError(t, err)
		assert.NotNil(t, pod)
	})

	t.Run("namespace denied is blocked", func(t *testing.T) {
		sessionWithDenied := testSession.DeepCopy()
		sessionWithDenied.Status.ResolvedTemplate.KubectlDebug.PodCopy.DeniedNamespaces = &breakglassv1alpha1.NamespaceFilter{
			Patterns: []string{"production", "kube-*"},
		}
		deniedHub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sessionWithDenied).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
		deniedHandler := NewKubectlDebugHandler(deniedHub, mockProvider)

		_, err := deniedHandler.CreatePodCopy(
			context.Background(),
			sessionWithDenied,
			"production",
			"app-pod",
			"",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace production is not allowed for pod copy")
	})

	t.Run("no namespace filter configured passes", func(t *testing.T) {
		sessionNoFilter := testSession.DeepCopy()
		sessionNoFilter.Status.ResolvedTemplate.KubectlDebug.PodCopy.AllowedNamespaces = nil
		sessionNoFilter.Status.ResolvedTemplate.KubectlDebug.PodCopy.DeniedNamespaces = nil

		targetClient3 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(testPod, testNs, productionNs).
			Build()
		handler3 := NewKubectlDebugHandler(hubClient, &mockClientProvider{
			clients: map[string]ctrlclient.Client{"test-cluster": targetClient3},
		})

		pod, err := handler3.CreatePodCopy(
			context.Background(),
			sessionNoFilter,
			"production",
			"app-pod",
			"busybox:latest",
			"test-user@example.com",
		)

		require.NoError(t, err)
		assert.NotNil(t, pod)
	})

	t.Run("label selector allows matching namespace", func(t *testing.T) {
		labeledNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "production",
				Labels: map[string]string{"env": "prod"},
			},
		}
		sessionWithSelector := testSession.DeepCopy()
		sessionWithSelector.Status.ResolvedTemplate.KubectlDebug.PodCopy.AllowedNamespaces = &breakglassv1alpha1.NamespaceFilter{
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{MatchLabels: map[string]string{"env": "prod"}},
			},
		}

		targetClient4 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(testPod, testNs, labeledNs).
			Build()
		hubClient4 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(sessionWithSelector).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
			Build()
		handler4 := NewKubectlDebugHandler(hubClient4, &mockClientProvider{
			clients: map[string]ctrlclient.Client{"test-cluster": targetClient4},
		})

		pod, err := handler4.CreatePodCopy(
			context.Background(),
			sessionWithSelector,
			"production",
			"app-pod",
			"",
			"test-user@example.com",
		)

		require.NoError(t, err)
		assert.NotNil(t, pod)
	})

	t.Run("label selector blocks non-matching namespace", func(t *testing.T) {
		sessionWithSelector := testSession.DeepCopy()
		sessionWithSelector.Status.ResolvedTemplate.KubectlDebug.PodCopy.AllowedNamespaces = &breakglassv1alpha1.NamespaceFilter{
			SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{
				{MatchLabels: map[string]string{"env": "staging"}},
			},
		}

		targetClient5 := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(testPod, testNs, productionNs).
			Build()
		handler5 := NewKubectlDebugHandler(fake.NewClientBuilder().WithScheme(scheme).WithObjects(sessionWithSelector).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build(), &mockClientProvider{
			clients: map[string]ctrlclient.Client{"test-cluster": targetClient5},
		})

		_, err := handler5.CreatePodCopy(
			context.Background(),
			sessionWithSelector,
			"production",
			"app-pod",
			"",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace production is not allowed for pod copy")
	})
}

func TestKubectlDebugHandler_CreatePodCopyPreservesLiveStatusFromStaleSession(t *testing.T) {
	scheme := newKubectlTestScheme()
	ctx := context.Background()
	oldExpiry := metav1.NewTime(time.Now().UTC().Add(15 * time.Minute))
	renewedExpiry := metav1.NewTime(time.Now().UTC().Add(45 * time.Minute))

	targetClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
			&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "app-pod",
					Namespace: "production",
					UID:       "pod-copy-source-uid",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "myapp:v1"}},
				},
			},
		).
		Build()

	liveSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-session-12345678",
			Namespace:       "default",
			UID:             "session-live-uid",
			ResourceVersion: "2",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:        breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt:    &renewedExpiry,
			RenewalCount: 1,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{{
				User:     "active@example.com",
				Role:     breakglassv1alpha1.ParticipantRoleParticipant,
				JoinedAt: metav1.Now(),
			}},
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
	staleSession := liveSession.DeepCopy()
	staleSession.ResourceVersion = "1"
	staleSession.Status.ExpiresAt = &oldExpiry
	staleSession.Status.RenewalCount = 0
	staleSession.Status.Participants = nil

	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(liveSession).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
		clients: map[string]ctrlclient.Client{"test-cluster": targetClient},
	})

	pod, err := handler.CreatePodCopy(ctx, staleSession, "production", "app-pod", "busybox:latest", "test-user@example.com")
	require.NoError(t, err)

	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hubClient.Get(ctx, ctrlclient.ObjectKey{Name: liveSession.Name, Namespace: liveSession.Namespace}, stored))
	require.NotNil(t, stored.Status.ExpiresAt)
	assert.WithinDuration(t, renewedExpiry.Time, stored.Status.ExpiresAt.Time, time.Second)
	assert.Equal(t, int32(1), stored.Status.RenewalCount)
	require.Len(t, stored.Status.Participants, 1)
	assert.Equal(t, "active@example.com", stored.Status.Participants[0].User)
	require.NotNil(t, stored.Status.KubectlDebugStatus)
	require.Len(t, stored.Status.KubectlDebugStatus.CopiedPods, 1)
	assert.Equal(t, pod.Name, stored.Status.KubectlDebugStatus.CopiedPods[0].CopyName)
	assert.Contains(t, stored.Status.AllowedPods, breakglassv1alpha1.AllowedPodRef{
		Namespace: "debug-copies",
		Name:      pod.Name,
		Ready:     false,
	})
}

func TestKubectlDebugHandler_CreatePodCopyFailsClosedOnDestinationNamespaceUID(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		initialUID types.UID
		freshUID   types.UID
		want       string
	}{
		{name: "initial UID empty", initialUID: "", freshUID: "", want: "has no UID"},
		{name: "fresh UID empty", initialUID: "debug-copies-uid", freshUID: "", want: "changed during copy authorization"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "copy-uid-session", Namespace: "default", UID: "copy-uid-session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "operator@example.com"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:     breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt: &expiresAt,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Mode:         breakglassv1alpha1.DebugSessionModeKubectlDebug,
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{PodCopy: &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "debug-copies"}},
					},
				},
			}
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			destinationReads := 0
			creates := 0
			targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production", UID: "production-uid"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: scenario.initialUID}},
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "production", UID: "source-pod-uid"}},
			).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if ns, ok := obj.(*corev1.Namespace); ok && key.Name == "debug-copies" {
						destinationReads++
						if destinationReads > 1 {
							ns.UID = scenario.freshUID
						}
					}
					return nil
				},
				Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
					creates++
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
			handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

			pod, err := handler.CreatePodCopy(context.Background(), session, "production", "app", "", "operator@example.com")
			require.Error(t, err)
			assert.Nil(t, pod)
			assert.Contains(t, err.Error(), scenario.want)
			assert.Zero(t, creates)
		})
	}
}

func TestKubectlDebugHandler_CreateNodeDebugPod(t *testing.T) {
	scheme := newKubectlTestScheme()

	// Create test namespace
	testNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "breakglass-debug",
			UID:  "breakglass-debug-uid",
		},
	}

	// Create a test node
	testNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "worker-1",
			UID:  "node-debug-uid",
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
			UID:       "session-node-uid",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: func() *metav1.Time {
				at := metav1.NewTime(time.Now().UTC().Add(time.Hour))
				return &at
			}(),
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

	t.Run("uses resolved session target namespace before template namespace", func(t *testing.T) {
		tenantNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "tenant-debug",
				UID:  "tenant-debug-uid",
			},
		}
		targetClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(testNode, tenantNs).
			Build()
		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(func() *breakglassv1alpha1.DebugSession {
				hubSession := testSession.DeepCopy()
				hubSession.Spec.TargetNamespace = "tenant-debug"
				return hubSession
			}()).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
			Build()
		handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
			clients: map[string]ctrlclient.Client{
				"test-cluster": targetClient,
			},
		})

		session := testSession.DeepCopy()
		session.Spec.TargetNamespace = "tenant-debug"
		session.Status.ResolvedTemplate.TargetNamespace = "breakglass-debug"

		pod, err := handler.CreateNodeDebugPod(
			context.Background(),
			session,
			"worker-1",
			"test-user@example.com",
		)

		require.NoError(t, err)
		assert.Equal(t, "tenant-debug", pod.Namespace)
	})

	t.Run("node debug disabled", func(t *testing.T) {
		disabledSession := testSession.DeepCopy()
		disabledSession.Status.ResolvedTemplate.KubectlDebug.NodeDebug.Enabled = false
		disabledHub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabledSession).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
		disabledHandler := NewKubectlDebugHandler(disabledHub, mockProvider)

		_, err := disabledHandler.CreateNodeDebugPod(
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
		selectorHub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(selectorSession).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
		selectorHandler := NewKubectlDebugHandler(selectorHub, mockProvider)

		_, err := selectorHandler.CreateNodeDebugPod(
			context.Background(),
			selectorSession,
			"worker-1",
			"test-user@example.com",
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match required selector")
	})
}

func TestKubectlDebugHandler_CreateNodeDebugPodFencesLiveNamespace(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(*corev1.Namespace)
		want   string
	}{
		{
			name: "namespace deletion and recreation",
			mutate: func(ns *corev1.Namespace) {
				ns.UID = "recreated-namespace-uid"
			},
			want: "changed during pod authorization",
		},
		{
			name: "namespace allow label removed",
			mutate: func(ns *corev1.Namespace) {
				ns.Labels = map[string]string{"debug": "denied"}
			},
			want: "no longer allowed",
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "node-namespace-session", Namespace: "default", UID: "node-namespace-session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "operator@example.com"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:     breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt: &expiresAt,
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
						TargetNamespace: "breakglass-debug",
						NamespaceConstraints: &breakglassv1alpha1.NamespaceConstraints{
							AllowedNamespaces: &breakglassv1alpha1.NamespaceFilter{SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{{MatchLabels: map[string]string{"debug": "allowed"}}}},
						},
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true}},
					},
				},
			}
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).Build()
			namespaceReads := 0
			creates := 0
			targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "namespace-uid", Labels: map[string]string{"debug": "allowed"}}},
				&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-uid"}},
			).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if ns, ok := obj.(*corev1.Namespace); ok && key.Name == "breakglass-debug" {
						namespaceReads++
						if namespaceReads > 1 {
							scenario.mutate(ns)
						}
					}
					return nil
				},
				Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
					creates++
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
			handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

			pod, err := handler.CreateNodeDebugPod(context.Background(), session, "worker-1", "operator@example.com")
			require.Error(t, err)
			assert.Nil(t, pod)
			assert.Contains(t, err.Error(), scenario.want)
			assert.Zero(t, creates, "namespace change must prevent privileged Pod creation")
		})
	}
}

func TestKubectlDebugHandler_CreateNodeDebugPodPreservesLiveStatusFromStaleSession(t *testing.T) {
	scheme := newKubectlTestScheme()
	ctx := context.Background()
	oldExpiry := metav1.NewTime(time.Now().UTC().Add(15 * time.Minute))
	renewedExpiry := metav1.NewTime(time.Now().UTC().Add(45 * time.Minute))

	targetClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "breakglass-debug-uid"}},
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-live-uid"}},
		).
		Build()

	liveSession := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-session-12345678",
			Namespace:       "default",
			UID:             "session-live-uid",
			ResourceVersion: "2",
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "test-user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State:        breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt:    &renewedExpiry,
			RenewalCount: 1,
			Participants: []breakglassv1alpha1.DebugSessionParticipant{{
				User:     "active@example.com",
				Role:     breakglassv1alpha1.ParticipantRoleParticipant,
				JoinedAt: metav1.Now(),
			}},
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
				TargetNamespace: "breakglass-debug",
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
						Enabled:       true,
						AllowedImages: []string{"busybox:stable"},
					},
				},
			},
		},
	}
	staleSession := liveSession.DeepCopy()
	staleSession.ResourceVersion = "1"
	staleSession.Status.ExpiresAt = &oldExpiry
	staleSession.Status.RenewalCount = 0
	staleSession.Status.Participants = nil

	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(liveSession).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
		clients: map[string]ctrlclient.Client{"test-cluster": targetClient},
	})

	pod, err := handler.CreateNodeDebugPod(ctx, staleSession, "worker-1", "test-user@example.com")
	require.NoError(t, err)

	stored := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, hubClient.Get(ctx, ctrlclient.ObjectKey{Name: liveSession.Name, Namespace: liveSession.Namespace}, stored))
	require.NotNil(t, stored.Status.ExpiresAt)
	assert.WithinDuration(t, renewedExpiry.Time, stored.Status.ExpiresAt.Time, time.Second)
	assert.Equal(t, int32(1), stored.Status.RenewalCount)
	require.Len(t, stored.Status.Participants, 1)
	assert.Equal(t, "active@example.com", stored.Status.Participants[0].User)
	assert.Contains(t, stored.Status.AllowedPods, breakglassv1alpha1.AllowedPodRef{
		Namespace: "breakglass-debug",
		Name:      pod.Name,
		NodeName:  "worker-1",
		Ready:     false,
	})
	assert.Contains(t, stored.Status.DeployedResources, breakglassv1alpha1.DeployedResourceRef{
		APIVersion: "v1",
		Kind:       "Pod",
		Name:       pod.Name,
		Namespace:  "breakglass-debug",
	})
}

func TestKubectlDebugHandler_FinalMutationFencePreventsPrivilegedCreates(t *testing.T) {
	scenarios := []struct {
		name   string
		mutate func(*breakglassv1alpha1.DebugSession)
	}{
		{
			name: "expiry equality",
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				expired := metav1.Now()
				ds.Status.ExpiresAt = &expired
			},
		},
		{
			name: "revocation",
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
			},
		},
		{
			name: "participant removal",
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				ds.Status.Participants = nil
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run("pod copy/"+scenario.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "copy-fence-session", Namespace: "default", UID: "copy-fence-session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "owner@example.com"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:        breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt:    &expiresAt,
					Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "debugger@example.com", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Mode:         breakglassv1alpha1.DebugSessionModeKubectlDebug,
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{PodCopy: &breakglassv1alpha1.PodCopyConfig{Enabled: true, TargetNamespace: "debug-copies"}},
					},
				},
			}
			hubObject := session.DeepCopy()
			mutateHub := false
			mutationApplied := false
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(hubObject).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
						if err := cl.Get(ctx, key, obj, opts...); err != nil {
							return err
						}
						if mutateHub && !mutationApplied {
							scenario.mutate(obj.(*breakglassv1alpha1.DebugSession))
							mutationApplied = true
						}
						return nil
					},
				}).Build()
			creates := 0
			podReads := 0
			targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}},
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "production", UID: "source-pod-uid"}},
			).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if _, ok := obj.(*corev1.Pod); ok && key.Name == "app" {
						podReads++
						if podReads == 2 {
							mutateHub = true
						}
					}
					return nil
				},
				Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
					creates++
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
			handler := NewKubectlDebugHandlerWithReader(hubClient, hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

			copyPod, err := handler.CreatePodCopy(context.Background(), session.DeepCopy(), "production", "app", "busybox:stable", "debugger@example.com")
			assert.Error(t, err)
			assert.Nil(t, copyPod)
			assert.Zero(t, creates, "a revoked or expired session must not create a Pod copy")
		})

		t.Run("node debug/"+scenario.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "node-fence-session", Namespace: "default", UID: "node-fence-session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "owner@example.com"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:        breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt:    &expiresAt,
					Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "debugger@example.com", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Mode:            breakglassv1alpha1.DebugSessionModeKubectlDebug,
						TargetNamespace: "breakglass-debug",
						KubectlDebug:    &breakglassv1alpha1.KubectlDebugConfig{NodeDebug: &breakglassv1alpha1.NodeDebugConfig{Enabled: true, AllowedImages: []string{"busybox:stable"}}},
					},
				},
			}
			hubObject := session.DeepCopy()
			mutateHub := false
			mutationApplied := false
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(hubObject).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
						if err := cl.Get(ctx, key, obj, opts...); err != nil {
							return err
						}
						if mutateHub && !mutationApplied {
							scenario.mutate(obj.(*breakglassv1alpha1.DebugSession))
							mutationApplied = true
						}
						return nil
					},
				}).Build()
			creates := 0
			nodeReads := 0
			targetClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug", UID: "breakglass-debug-uid"}},
				&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "worker-1", UID: "node-fence-uid"}},
			).WithInterceptorFuncs(interceptor.Funcs{
				Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
					if err := cl.Get(ctx, key, obj, opts...); err != nil {
						return err
					}
					if _, ok := obj.(*corev1.Node); ok && key.Name == "worker-1" {
						nodeReads++
						if nodeReads == 2 {
							mutateHub = true
						}
					}
					return nil
				},
				Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
					creates++
					return cl.Create(ctx, obj, opts...)
				},
			}).Build()
			handler := NewKubectlDebugHandlerWithReader(hubClient, hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

			debugPod, err := handler.CreateNodeDebugPod(context.Background(), session.DeepCopy(), "worker-1", "debugger@example.com")
			assert.Error(t, err)
			assert.Nil(t, debugPod)
			assert.Zero(t, creates, "a revoked or expired session must not create a privileged Node debug Pod")
		})
	}
}

func TestKubectlDebugHandler_FinalMutationFencePreventsEphemeralUpdate(t *testing.T) {
	scenarios := []struct {
		name   string
		mutate func(*breakglassv1alpha1.DebugSession)
	}{
		{
			name: "expiry equality",
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				expired := metav1.Now()
				ds.Status.ExpiresAt = &expired
			},
		},
		{
			name: "revocation",
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
			},
		},
		{
			name: "participant removal",
			mutate: func(ds *breakglassv1alpha1.DebugSession) {
				ds.Status.Participants = nil
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			scheme := newKubectlTestScheme()
			expiresAt := metav1.NewTime(time.Now().UTC().Add(time.Hour))
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "ephemeral-fence-session", Namespace: "default", UID: "ephemeral-fence-session-uid"},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster", RequestedBy: "owner@example.com"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:        breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt:    &expiresAt,
					Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "debugger@example.com", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
						Mode:         breakglassv1alpha1.DebugSessionModeKubectlDebug,
						KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}}},
					},
				},
			}
			hubObject := session.DeepCopy()
			mutateHub := false
			mutationApplied := false
			hubClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(hubObject).
				WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
						if err := cl.Get(ctx, key, obj, opts...); err != nil {
							return err
						}
						if mutateHub && !mutationApplied {
							scenario.mutate(obj.(*breakglassv1alpha1.DebugSession))
							mutationApplied = true
						}
						return nil
					},
				}).Build()
			podReads := 0
			updates := 0
			targetClient := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "production", UID: "target-pod-uid"}}).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, cl ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
						if err := cl.Get(ctx, key, obj, opts...); err != nil {
							return err
						}
						if _, ok := obj.(*corev1.Pod); ok && key.Name == "app" {
							podReads++
							if podReads == 2 {
								mutateHub = true
							}
						}
						return nil
					},
					SubResourceUpdate: func(ctx context.Context, cl ctrlclient.Client, subResourceName string, obj ctrlclient.Object, opts ...ctrlclient.SubResourceUpdateOption) error {
						updates++
						return cl.Update(ctx, obj)
					},
				}).Build()
			handler := NewKubectlDebugHandlerWithReader(hubClient, hubClient, &mockClientProvider{clients: map[string]ctrlclient.Client{"test-cluster": targetClient}})

			err := handler.InjectEphemeralContainer(context.Background(), session.DeepCopy(), "production", "app", "debugger", "busybox:stable", nil, nil, "debugger@example.com")
			assert.Error(t, err)
			assert.Zero(t, updates, "a revoked or expired session must not update the target Pod")
		})
	}
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

	t.Run("clears empty status without spoke client", func(t *testing.T) {
		session := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ephemeral-only-session",
				Namespace: "breakglass",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State: breakglassv1alpha1.DebugSessionStateTerminated,
				KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{
					EphemeralContainersInjected: []breakglassv1alpha1.EphemeralContainerRef{
						{
							PodName:       "app-pod",
							Namespace:     "default",
							ContainerName: "debugger",
						},
					},
				},
			},
		}
		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(session).
			WithStatusSubresource(session).
			Build()
		handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{err: assert.AnError})

		err := handler.CleanupKubectlDebugResources(context.Background(), session)
		require.NoError(t, err)

		var stored breakglassv1alpha1.DebugSession
		require.NoError(t, hubClient.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "breakglass", Name: "ephemeral-only-session"}, &stored))
		assert.Nil(t, stored.Status.KubectlDebugStatus)
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

	t.Run("cleanup preserves live status from stale session", func(t *testing.T) {
		oldExpiry := metav1.NewTime(time.Now().UTC().Add(15 * time.Minute))
		renewedExpiry := metav1.NewTime(time.Now().UTC().Add(45 * time.Minute))
		ctx := context.Background()

		targetClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-copy",
					Namespace: "default",
				},
			}).
			Build()

		liveSession := &breakglassv1alpha1.DebugSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-session",
				Namespace:       "breakglass",
				ResourceVersion: "2",
			},
			Spec: breakglassv1alpha1.DebugSessionSpec{
				Cluster: "test-cluster",
			},
			Status: breakglassv1alpha1.DebugSessionStatus{
				State:        breakglassv1alpha1.DebugSessionStateTerminated,
				ExpiresAt:    &renewedExpiry,
				RenewalCount: 1,
				Participants: []breakglassv1alpha1.DebugSessionParticipant{{
					User:     "active@example.com",
					Role:     breakglassv1alpha1.ParticipantRoleParticipant,
					JoinedAt: metav1.Now(),
				}},
				KubectlDebugStatus: &breakglassv1alpha1.KubectlDebugStatus{
					CopiedPods: []breakglassv1alpha1.CopiedPodRef{
						{CopyName: "pod-copy", CopyNamespace: "default"},
					},
				},
			},
		}
		staleSession := liveSession.DeepCopy()
		staleSession.ResourceVersion = "1"
		staleSession.Status.ExpiresAt = &oldExpiry
		staleSession.Status.RenewalCount = 0
		staleSession.Status.Participants = nil

		hubClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(liveSession).
			WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
			Build()
		handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
			clients: map[string]ctrlclient.Client{
				"test-cluster": targetClient,
			},
		})

		err := handler.CleanupKubectlDebugResources(ctx, staleSession)
		require.NoError(t, err)

		stored := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, hubClient.Get(ctx, ctrlclient.ObjectKey{Name: liveSession.Name, Namespace: liveSession.Namespace}, stored))
		require.NotNil(t, stored.Status.ExpiresAt)
		assert.WithinDuration(t, renewedExpiry.Time, stored.Status.ExpiresAt.Time, time.Second)
		assert.Equal(t, int32(1), stored.Status.RenewalCount)
		require.Len(t, stored.Status.Participants, 1)
		assert.Equal(t, "active@example.com", stored.Status.Participants[0].User)
		assert.Nil(t, stored.Status.KubectlDebugStatus)
	})

	t.Run("preserves copied pods when deletion fails", func(t *testing.T) {
		targetClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(&corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-copy",
					Namespace: "default",
				},
			}).
			WithInterceptorFuncs(interceptor.Funcs{
				Delete: func(_ context.Context, _ ctrlclient.WithWatch, _ ctrlclient.Object, _ ...ctrlclient.DeleteOption) error {
					return errors.New("delete denied")
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
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete copied pod")

		var updated breakglassv1alpha1.DebugSession
		require.NoError(t, hubClient.Get(context.Background(), ctrlclient.ObjectKey{Namespace: "breakglass", Name: "test-session"}, &updated))
		require.NotNil(t, updated.Status.KubectlDebugStatus)
		require.Len(t, updated.Status.KubectlDebugStatus.CopiedPods, 1)
		assert.Equal(t, "pod-copy", updated.Status.KubectlDebugStatus.CopiedPods[0].CopyName)
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

// TestCreateNodeDebugPod_StatusFailureDeletesOrphan is the regression test for
// #096. CreateNodeDebugPod creates a PRIVILEGED pod with hostPath "/" mounted
// read-write on the spoke cluster and then records it in the DebugSession status.
// If the status patch fails, the pod is absent from the very status lists that
// CleanupKubectlDebugResources / cleanupResources iterate, so nothing ever deletes
// it and it outlives its session indefinitely.
func TestCreateNodeDebugPod_StatusFailureDeletesOrphan(t *testing.T) {
	scheme := testScheme()

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-node-session", Namespace: "default", UID: "orphan-node-session-uid"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:         "test-cluster",
			RequestedBy:     "user@example.com",
			TargetNamespace: "breakglass-debug",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: func() *metav1.Time {
				at := metav1.NewTime(time.Now().UTC().Add(time.Hour))
				return &at
			}(),
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
						Enabled:       true,
						AllowedImages: []string{"busybox:stable"},
					},
				},
			},
		},
	}

	targetClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1", UID: "node-orphan-uid"}}).
		Build()

	// Hub client whose status patch always fails, simulating a lost lease, a
	// conflict storm, or a transient apiserver error at exactly the wrong moment.
	statusErr := errors.New("simulated status patch failure")
	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ ctrlclient.Client, _ string, _ ctrlclient.Object, _ ctrlclient.Patch, _ ...ctrlclient.SubResourcePatchOption) error {
				return statusErr
			},
		}).
		Build()

	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
		clients: map[string]ctrlclient.Client{"test-cluster": targetClient},
	})

	pod, err := handler.CreateNodeDebugPod(context.Background(), session, "node-1", "user@example.com")
	require.Error(t, err, "the status failure must be reported to the caller")
	assert.Nil(t, pod)

	// No privileged hostPath pod may be left behind on the spoke cluster.
	var pods corev1.PodList
	require.NoError(t, targetClient.List(context.Background(), &pods))
	assert.Empty(t, pods.Items,
		"a privileged hostPath:/ pod was orphaned on the spoke cluster: it is untracked "+
			"in the session status, so no cleanup path will ever delete it")
}

// TestCreatePodCopy_StatusFailureDeletesOrphan is the regression test for #095:
// the same create-then-status-patch ordering in the pod-copy path.
func TestCreatePodCopy_StatusFailureDeletesOrphan(t *testing.T) {
	scheme := testScheme()

	originalPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "default", UID: "orphan-copy-source-uid"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx:latest"}},
		},
	}

	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "orphan-copy-session", Namespace: "default", UID: "orphan-copy-session-uid"},
		Spec: breakglassv1alpha1.DebugSessionSpec{
			Cluster:     "test-cluster",
			RequestedBy: "user@example.com",
		},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive,
			ExpiresAt: func() *metav1.Time {
				at := metav1.NewTime(time.Now().UTC().Add(time.Hour))
				return &at
			}(),
			ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
				Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
				KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
					PodCopy: &breakglassv1alpha1.PodCopyConfig{
						Enabled: true,
						TTL:     "1h",
					},
				},
			},
		},
	}

	// The pod-copy path resolves namespace labels and requires the target
	// namespace to exist, so both namespaces must be seeded for the test to reach
	// the create at all.
	sourceNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	copiesNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "debug-copies", UID: "debug-copies-uid"}}
	targetClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(originalPod, sourceNS, copiesNS).Build()

	statusErr := errors.New("simulated status patch failure")
	hubClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(session).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ ctrlclient.Client, _ string, _ ctrlclient.Object, _ ctrlclient.Patch, _ ...ctrlclient.SubResourcePatchOption) error {
				return statusErr
			},
		}).
		Build()

	handler := NewKubectlDebugHandler(hubClient, &mockClientProvider{
		clients: map[string]ctrlclient.Client{"test-cluster": targetClient},
	})

	copyPod, err := handler.CreatePodCopy(context.Background(), session, "default", "app-pod", "busybox:latest", "user@example.com")
	require.Error(t, err)
	assert.Nil(t, copyPod)

	var pods corev1.PodList
	require.NoError(t, targetClient.List(context.Background(), &pods))
	// Only the original pod may remain.
	require.Len(t, pods.Items, 1, "the pod copy must not be orphaned on the spoke cluster")
	assert.Equal(t, "app-pod", pods.Items[0].Name)
}
