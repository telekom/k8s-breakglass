package cluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientcache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestExtractClusterConfigHandlesDeletedFinalState(t *testing.T) {
	cfg := &telekomv1alpha1.ClusterConfig{}
	wrapped := clientcache.DeletedFinalStateUnknown{Obj: cfg}

	assert.Same(t, cfg, extractClusterConfig(wrapped))
}

func TestExtractClusterConfigReturnsNilForUnknownTypes(t *testing.T) {
	assert.Nil(t, extractClusterConfig("not-a-cluster"))
}

func TestExtractSecretHandlesDeletedFinalState(t *testing.T) {
	sec := &corev1.Secret{}
	wrapped := clientcache.DeletedFinalStateUnknown{Obj: sec}

	assert.Same(t, sec, extractSecret(wrapped))
}

func TestExtractSecretReturnsNilForUnknownTypes(t *testing.T) {
	assert.Nil(t, extractSecret(v1.Now()))
}

func TestExtractClusterConfig_DirectObject(t *testing.T) {
	cfg := &telekomv1alpha1.ClusterConfig{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
	}

	result := extractClusterConfig(cfg)
	assert.Same(t, cfg, result)
}

func TestExtractClusterConfig_DeletedFinalStateUnknown_WrongType(t *testing.T) {
	// Test with DeletedFinalStateUnknown wrapping a non-ClusterConfig object
	wrapped := clientcache.DeletedFinalStateUnknown{Obj: &corev1.Secret{}}

	result := extractClusterConfig(wrapped)
	assert.Nil(t, result)
}

func TestExtractSecret_DirectObject(t *testing.T) {
	sec := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
	}

	result := extractSecret(sec)
	assert.Same(t, sec, result)
}

func TestExtractSecret_DeletedFinalStateUnknown_WrongType(t *testing.T) {
	// Test with DeletedFinalStateUnknown wrapping a non-Secret object
	wrapped := clientcache.DeletedFinalStateUnknown{Obj: &telekomv1alpha1.ClusterConfig{}}

	result := extractSecret(wrapped)
	assert.Nil(t, result)
}

func TestRegisterInvalidationHandlers_NilProvider(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	err := RegisterInvalidationHandlers(context.Background(), nil, nil, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client provider is nil")
}

func TestRegisterInvalidationHandlers_NilManager(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	scheme := runtime.NewScheme()
	_ = telekomv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	provider := NewClientProvider(fakeClient, logger)

	err := RegisterInvalidationHandlers(context.Background(), nil, provider, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "manager is nil")
}

func newTestClientProviderScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = telekomv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func newTestClientProviderClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newTestClientProviderScheme()).
		WithObjects(objs...).
		Build()
}

func TestClientProvider_Invalidate(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	cli := newTestClientProviderClient()
	provider := NewClientProvider(cli, logger)

	// Invalidate should not panic even if the cluster doesn't exist
	provider.Invalidate("nonexistent-cluster")
}

func TestClientProvider_IsSecretTracked_NotTracked(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	cli := newTestClientProviderClient()
	provider := NewClientProvider(cli, logger)

	// Initially not tracked
	assert.False(t, provider.IsSecretTracked("default", "unknown-secret"))
}
