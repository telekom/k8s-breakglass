package cluster

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/stretchr/testify/assert"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewClientProvider(t *testing.T) {
	logger := zaptest.NewLogger(t)
	fakeClient := fake.NewClientBuilder().Build()

	provider := NewClientProvider(fakeClient, logger.Sugar())

	assert.NotNil(t, provider)
	assert.NotNil(t, provider.k8s)
	assert.NotNil(t, provider.log)
	assert.NotNil(t, provider.data)
	assert.NotNil(t, provider.rest)
	assert.Empty(t, provider.data)
	assert.Empty(t, provider.rest)
}

// Note: More comprehensive tests require adding the API types to the scheme
// so the fake client can store/retrieve ClusterConfig objects. The tests below
// exercise REST config parsing, loopback host rewriting and caching behavior.

func mustBuildKubeconfigYAML(host string) []byte {
	// Build a minimal kubeconfig using the typed clientcmd API and marshal it
	cfg := clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{"test": {Server: host}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"user": {}},
		Contexts:       map[string]*clientcmdapi.Context{"ctx": {Cluster: "test", AuthInfo: "user"}},
		CurrentContext: "ctx",
	}

	b, err := clientcmd.Write(cfg)
	if err != nil {
		panic(err)
	}
	return b
}

func TestGetRESTConfig_RewritesLoopbackHostAndCaches(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://127.0.0.1:6443")

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "kube-secret", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	cfg, err := provider.GetRESTConfig(context.Background(), "my-cluster")
	assert.NoError(t, err)
	// loopback should be rewritten to cluster DNS
	assert.Equal(t, "https://kubernetes.default.svc", cfg.Host)

	// second call should return cached pointer
	cfg2, err2 := provider.GetRESTConfig(context.Background(), "my-cluster")
	assert.NoError(t, err2)
	assert.Same(t, cfg, cfg2)
}

func TestGetRESTConfig_MissingSecretKey(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// secret contains default key, but ClusterConfig points to a different key
	kubeYAML := mustBuildKubeconfigYAML("https://example.com:6443")
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "c2", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "kube-secret-2", Namespace: "default", Key: "nonexistent"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret-2", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	_, err := provider.GetRESTConfig(context.Background(), "c2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing key")
}

func TestGet_CachingAndNotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "c1", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	first, err := provider.GetInNamespace(ctx, "default", "c1")
	assert.NoError(t, err)
	assert.Equal(t, "c1", first.Name)

	second, err2 := provider.GetInNamespace(ctx, "default", "c1")
	assert.NoError(t, err2)
	// Should return the same cached pointer
	assert.Same(t, first, second)

	// Non-existent cluster should return an error
	_, err3 := provider.GetInNamespace(ctx, "default", "does-not-exist")
	assert.Error(t, err3)
}

func TestInvalidate_ClearsCache(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ci1", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	first, err := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err)
	// cache hit
	second, err2 := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err2)
	assert.Same(t, first, second)

	// Invalidate and ensure subsequent Get produces a different pointer
	provider.Invalidate("ci1")
	third, err3 := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err3)
	if first == third {
		t.Fatalf("expected different pointer after Invalidate, got same")
	}
}
