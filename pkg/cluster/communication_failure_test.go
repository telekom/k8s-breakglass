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

package cluster

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// TestConnectionRefused tests handling of connection refused errors.
func TestConnectionRefused(t *testing.T) {
	// This test verifies the error classification for connection refused
	connErr := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &net.AddrError{Err: "connection refused"},
	}

	assert.True(t, isTemporaryNetworkError(connErr), "connection refused should be classified as temporary")
}

// TestDialTimeout tests handling of dial timeout errors.
func TestDialTimeout(t *testing.T) {
	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for timeout
	<-ctx.Done()

	assert.Equal(t, context.DeadlineExceeded, ctx.Err())
}

// TestTLSHandshakeFailure tests handling of TLS errors.
func TestTLSHandshakeFailure(t *testing.T) {
	// Verify TLS errors are properly classified
	tlsErr := errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority")
	assert.True(t, isTLSError(tlsErr), "TLS verification error should be classified as TLS error")
}

// TestAuthenticationFailure tests handling of authentication errors.
func TestAuthenticationFailure(t *testing.T) {
	authErr := errors.New("Unauthorized")
	assert.True(t, isAuthError(authErr), "Unauthorized should be classified as auth error")
}

// Helper functions for error classification
func isTemporaryNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || isConnectionRefused(err)
	}
	return isConnectionRefused(err)
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsStr(errStr, "connection refused") ||
		containsStr(errStr, "no route to host") ||
		containsStr(errStr, "network is unreachable")
}

func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsStr(errStr, "tls:") ||
		containsStr(errStr, "x509:") ||
		containsStr(errStr, "certificate")
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsStr(errStr, "Unauthorized") ||
		containsStr(errStr, "Forbidden") ||
		containsStr(errStr, "authentication") ||
		containsStr(errStr, "token expired")
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// MockClusterClientProvider is a mock implementation for testing.
type MockClusterClientProvider struct {
	configs     map[string]*rest.Config
	errors      map[string]error
	getCalled   int
	invalidated []string
}

// NewMockClusterClientProvider creates a new mock client provider.
func NewMockClusterClientProvider() *MockClusterClientProvider {
	return &MockClusterClientProvider{
		configs: make(map[string]*rest.Config),
		errors:  make(map[string]error),
	}
}

// GetRESTConfig returns the configured REST config or error for the cluster.
func (m *MockClusterClientProvider) GetRESTConfig(_ context.Context, cluster string) (*rest.Config, error) {
	m.getCalled++
	if err, ok := m.errors[cluster]; ok {
		return nil, err
	}
	if cfg, ok := m.configs[cluster]; ok {
		return cfg, nil
	}
	return nil, ErrClusterConfigNotFound
}

// InvalidateCache records a cache invalidation request.
func (m *MockClusterClientProvider) InvalidateCache(key string) {
	m.invalidated = append(m.invalidated, key)
}

// SetConfig sets the REST config for a cluster.
func (m *MockClusterClientProvider) SetConfig(cluster string, cfg *rest.Config) {
	m.configs[cluster] = cfg
}

// SetError sets an error to return for a cluster.
func (m *MockClusterClientProvider) SetError(cluster string, err error) {
	m.errors[cluster] = err
}

// GetClient returns a mock client (not implemented).
func (m *MockClusterClientProvider) GetClient(_ context.Context, _ string) (client.Client, error) {
	return nil, errors.New("not implemented in mock")
}

// GetCallCount returns how many times GetRESTConfig was called.
func (m *MockClusterClientProvider) GetCallCount() int {
	return m.getCalled
}

// GetInvalidatedKeys returns the list of keys that were invalidated.
func (m *MockClusterClientProvider) GetInvalidatedKeys() []string {
	return m.invalidated
}

// TestMockClusterClientProvider_ErrorInjection tests that errors are properly propagated.
func TestMockClusterClientProvider_ErrorInjection(t *testing.T) {
	mock := NewMockClusterClientProvider()
	mock.SetError("failing-cluster", errors.New("simulated network failure"))

	_, err := mock.GetRESTConfig(context.Background(), "failing-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated network failure")
}

// TestMockClusterClientProvider_ConfigInjection tests that configs are properly returned.
func TestMockClusterClientProvider_ConfigInjection(t *testing.T) {
	mock := NewMockClusterClientProvider()
	expectedCfg := &rest.Config{Host: "https://test.example.com:6443"}
	mock.SetConfig("test-cluster", expectedCfg)

	cfg, err := mock.GetRESTConfig(context.Background(), "test-cluster")
	require.NoError(t, err)
	assert.Equal(t, expectedCfg.Host, cfg.Host)
}

// TestMockClusterClientProvider_NotFound tests error when cluster not found.
func TestMockClusterClientProvider_NotFound(t *testing.T) {
	mock := NewMockClusterClientProvider()

	_, err := mock.GetRESTConfig(context.Background(), "missing-cluster")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrClusterConfigNotFound))
}

// TestMockClusterClientProvider_CacheInvalidation tests cache invalidation tracking.
func TestMockClusterClientProvider_CacheInvalidation(t *testing.T) {
	mock := NewMockClusterClientProvider()
	mock.InvalidateCache("ns/cluster1")
	mock.InvalidateCache("ns/cluster2")

	assert.Len(t, mock.GetInvalidatedKeys(), 2)
	assert.Contains(t, mock.GetInvalidatedKeys(), "ns/cluster1")
	assert.Contains(t, mock.GetInvalidatedKeys(), "ns/cluster2")
}

// TestMockClusterClientProvider_CallCounting tests call counting.
func TestMockClusterClientProvider_CallCounting(t *testing.T) {
	mock := NewMockClusterClientProvider()
	mock.SetConfig("cluster-a", &rest.Config{Host: "https://a.example.com"})

	assert.Equal(t, 0, mock.GetCallCount())

	_, _ = mock.GetRESTConfig(context.Background(), "cluster-a")
	assert.Equal(t, 1, mock.GetCallCount())

	_, _ = mock.GetRESTConfig(context.Background(), "cluster-a")
	_, _ = mock.GetRESTConfig(context.Background(), "cluster-b")
	assert.Equal(t, 3, mock.GetCallCount())
}

// testScheme creates a scheme with necessary types for testing
func testScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = telekomv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}

// TestClientProvider_ClusterConfigNotFound tests error when ClusterConfig doesn't exist.
func TestClientProvider_ClusterConfigNotFound(t *testing.T) {
	scheme := testScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	_, err := provider.GetRESTConfig(context.Background(), "nonexistent-cluster")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrClusterConfigNotFound), "should return ErrClusterConfigNotFound")
}

// TestClientProvider_SecretNotFound tests error when kubeconfig secret doesn't exist.
func TestClientProvider_SecretNotFound(t *testing.T) {
	scheme := testScheme()

	// Create a ClusterConfig that references a non-existent secret
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "missing-secret",
				Namespace: "breakglass-system",
				Key:       "kubeconfig",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	_, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fetch kubeconfig secret")
}

// TestClientProvider_SecretKeyMissing tests error when secret doesn't have the expected key.
func TestClientProvider_SecretKeyMissing(t *testing.T) {
	scheme := testScheme()

	// Create a secret without the expected key
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "breakglass-system",
		},
		Data: map[string][]byte{
			"wrong-key": []byte("some data"),
		},
	}

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "test-secret",
				Namespace: "breakglass-system",
				Key:       "kubeconfig",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc, secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	_, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing key")
}

// TestClientProvider_InvalidKubeconfig tests error when kubeconfig is malformed.
func TestClientProvider_InvalidKubeconfig(t *testing.T) {
	scheme := testScheme()

	// Create a secret with invalid kubeconfig data
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "breakglass-system",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte("this is not valid kubeconfig yaml"),
		},
	}

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "test-secret",
				Namespace: "breakglass-system",
				Key:       "kubeconfig",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc, secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	_, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse kubeconfig")
}

// TestClientProvider_NoAuthMethodConfigured tests error when no auth method is set.
func TestClientProvider_NoAuthMethodConfigured(t *testing.T) {
	scheme := testScheme()

	// Create a ClusterConfig with no auth method
	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			// No AuthType, no KubeconfigSecretRef, no OIDCAuth
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	_, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication method configured")
}

// TestClientProvider_ValidKubeconfig tests successful kubeconfig loading.
func TestClientProvider_ValidKubeconfig(t *testing.T) {
	scheme := testScheme()

	// Create a valid kubeconfig
	validKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-cluster.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJkakNDQVIyZ0F3SUJBZ0lCQURBS0JnZ3Foa2pPUFFRREFqQWpNU0V3SHdZRFZRUUREQmhyTTNNdGMyVnkKZG1WeUxXTmhRREUzTVRBeE16a3hPVEV3SGhjTk1qUXdNekV3TVRjd05UVXhXaGNOTXpRd016QTRNVGN3TlRVeApXakFqTVNFd0h3WURWUVFEREJock0zTXRjMlZ5ZG1WeUxXTmhRREUzTVRBeE16a3hPVEV3V1RBVEJnY3Foa2pPClBRSUJCZ2dxaGtqT1BRTUJCd05DQUFUdDdDNWEzTHVITWVUZWFoSXVGM2ZhclVtTEZDWHZVaE9yVVpVZnlxclQKSUxIUFMwbmdYRmNRWjlSUUFYZmMzZnJGZWtXU2xOSCt2QmpsUGpPNWFITUpvMEl3UURBT0JnTlZIUThCQWY4RQpCQU1DQXFRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVUNQcUxnK2JiRXhMTHlYelJOekdVCnlBazhRT0l3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnWVEvbktXanpjRWJGUUt6R3pPdkVQNFJkTTRYL1E0MW4KYkJJa0xkMGdOeGdDSUhQdXZYWjZJcFVtSDFGdFlQNDUwcExHZk1pUTl6alp4MVdEY1h5aWxTRkoKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "breakglass-system",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(validKubeconfig),
		},
	}

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "test-secret",
				Namespace: "breakglass-system",
				Key:       "kubeconfig",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc, secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	cfg, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	assert.Contains(t, cfg.Host, "test-cluster.example.com")
}

// TestClientProvider_CacheInvalidation tests that cache invalidation works correctly.
func TestClientProvider_CacheInvalidation(t *testing.T) {
	scheme := testScheme()

	// Create a valid kubeconfig
	validKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-cluster.example.com:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "breakglass-system",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(validKubeconfig),
		},
	}

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "test-secret",
				Namespace: "breakglass-system",
				Key:       "kubeconfig",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc, secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	// First call should cache the config
	cfg1, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.NoError(t, err)
	require.NotNil(t, cfg1)

	// Invalidate the cache
	provider.Invalidate("breakglass-system", "test-cluster")

	// Next call should re-fetch (but we can't easily verify this without counting API calls)
	cfg2, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.NoError(t, err)
	require.NotNil(t, cfg2)
}

// TestClientProvider_SecretInvalidation tests that secret invalidation works correctly.
func TestClientProvider_SecretInvalidation(t *testing.T) {
	scheme := testScheme()

	validKubeconfig := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-cluster.example.com:6443
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
`

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "shared-secret",
			Namespace: "breakglass-system",
		},
		Data: map[string][]byte{
			"kubeconfig": []byte(validKubeconfig),
		},
	}

	cc := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "breakglass-system",
		},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			AuthType: telekomv1alpha1.ClusterAuthTypeKubeconfig,
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
				Name:      "shared-secret",
				Namespace: "breakglass-system",
				Key:       "kubeconfig",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cc, secret).
		Build()
	log := zap.NewNop().Sugar()

	provider := NewClientProvider(fakeClient, log)

	// Load config to populate cache
	_, err := provider.GetRESTConfig(context.Background(), "breakglass-system/test-cluster")
	require.NoError(t, err)

	// Verify secret is tracked
	assert.True(t, provider.IsSecretTracked("breakglass-system", "shared-secret"))

	// Invalidate by secret
	provider.InvalidateSecret("breakglass-system", "shared-secret")

	// Secret should no longer be tracked after invalidation
	assert.False(t, provider.IsSecretTracked("breakglass-system", "shared-secret"))
}

// TestNetworkErrorClassification tests the network error classification helpers.
func TestNetworkErrorClassification(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		isTemporary bool
		isTLS       bool
		isAuth      bool
	}{
		{
			name:        "connection refused",
			err:         errors.New("dial tcp 10.0.0.1:6443: connection refused"),
			isTemporary: true,
			isTLS:       false,
			isAuth:      false,
		},
		{
			name:        "no route to host",
			err:         errors.New("dial tcp 10.0.0.1:6443: no route to host"),
			isTemporary: true,
			isTLS:       false,
			isAuth:      false,
		},
		{
			name:        "network unreachable",
			err:         errors.New("dial tcp 10.0.0.1:6443: network is unreachable"),
			isTemporary: true,
			isTLS:       false,
			isAuth:      false,
		},
		{
			name:        "TLS certificate error",
			err:         errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"),
			isTemporary: false,
			isTLS:       true,
			isAuth:      false,
		},
		{
			name:        "x509 certificate expired",
			err:         errors.New("x509: certificate has expired or is not yet valid"),
			isTemporary: false,
			isTLS:       true,
			isAuth:      false,
		},
		{
			name:        "unauthorized",
			err:         errors.New("Unauthorized"),
			isTemporary: false,
			isTLS:       false,
			isAuth:      true,
		},
		{
			name:        "forbidden",
			err:         errors.New("Forbidden: User not authorized"),
			isTemporary: false,
			isTLS:       false,
			isAuth:      true,
		},
		{
			name:        "token expired",
			err:         errors.New("token expired at 2024-01-01"),
			isTemporary: false,
			isTLS:       false,
			isAuth:      true,
		},
		{
			name:        "nil error",
			err:         nil,
			isTemporary: false,
			isTLS:       false,
			isAuth:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isTemporary, isConnectionRefused(tt.err), "isConnectionRefused mismatch")
			assert.Equal(t, tt.isTLS, isTLSError(tt.err), "isTLSError mismatch")
			assert.Equal(t, tt.isAuth, isAuthError(tt.err), "isAuthError mismatch")
		})
	}
}

// TestAPIErrorWrapping tests that Kubernetes API errors are properly handled.
func TestAPIErrorWrapping(t *testing.T) {
	t.Run("NotFound error", func(t *testing.T) {
		err := apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "secrets"}, "test-secret")
		assert.True(t, apierrors.IsNotFound(err))
		// NotFound errors should not be classified as auth errors
		assert.False(t, apierrors.IsUnauthorized(err))
	})

	t.Run("Forbidden error", func(t *testing.T) {
		err := apierrors.NewForbidden(schema.GroupResource{Group: "", Resource: "secrets"}, "test-secret", errors.New("access denied"))
		assert.True(t, apierrors.IsForbidden(err))
		// Verify the error message contains "forbidden" (case-insensitive)
		assert.Contains(t, err.Error(), "forbidden")
	})

	t.Run("Unauthorized error", func(t *testing.T) {
		err := apierrors.NewUnauthorized("invalid token")
		assert.True(t, apierrors.IsUnauthorized(err))
		// Verify we can detect unauthorized via the API errors package
		assert.False(t, apierrors.IsNotFound(err))
	})

	t.Run("ServiceUnavailable error", func(t *testing.T) {
		err := apierrors.NewServiceUnavailable("cluster unreachable")
		assert.True(t, apierrors.IsServiceUnavailable(err))
	})

	t.Run("Timeout error", func(t *testing.T) {
		err := apierrors.NewTimeoutError("request timed out", 30)
		assert.True(t, apierrors.IsTimeout(err))
	})
}
