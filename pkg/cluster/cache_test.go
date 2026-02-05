package cluster

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/stretchr/testify/assert"
	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name       string
		envKey     string
		envValue   string
		defaultVal time.Duration
		expected   time.Duration
	}{
		{
			name:       "valid duration 10m",
			envKey:     "TEST_DURATION_10M",
			envValue:   "10m",
			defaultVal: 5 * time.Minute,
			expected:   10 * time.Minute,
		},
		{
			name:       "valid duration 300s",
			envKey:     "TEST_DURATION_300S",
			envValue:   "300s",
			defaultVal: 5 * time.Minute,
			expected:   300 * time.Second,
		},
		{
			name:       "valid duration 1h30m",
			envKey:     "TEST_DURATION_1H30M",
			envValue:   "1h30m",
			defaultVal: time.Hour,
			expected:   90 * time.Minute,
		},
		{
			name:       "env not set returns default",
			envKey:     "TEST_DURATION_NOT_SET",
			envValue:   "", // not set
			defaultVal: 15 * time.Minute,
			expected:   15 * time.Minute,
		},
		{
			name:       "invalid duration returns default",
			envKey:     "TEST_DURATION_INVALID",
			envValue:   "not-a-duration",
			defaultVal: 5 * time.Minute,
			expected:   5 * time.Minute,
		},
		{
			name:       "empty string returns default",
			envKey:     "TEST_DURATION_EMPTY",
			envValue:   "",
			defaultVal: 10 * time.Minute,
			expected:   10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set or unset the env variable
			if tt.envValue != "" {
				os.Setenv(tt.envKey, tt.envValue)
				defer os.Unsetenv(tt.envKey)
			} else {
				os.Unsetenv(tt.envKey)
			}

			result := getEnvDuration(tt.envKey, tt.defaultVal)
			assert.Equal(t, tt.expected, result, "getEnvDuration should return expected duration")
		})
	}
}

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
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "kube-secret", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	cfg, err := provider.GetRESTConfig(context.Background(), "default/my-cluster")
	assert.NoError(t, err)
	// loopback should be rewritten to cluster DNS
	assert.Equal(t, "https://kubernetes.default.svc", cfg.Host)

	// second call should return cached pointer
	cfg2, err2 := provider.GetRESTConfig(context.Background(), "default/my-cluster")
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
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "kube-secret-2", Namespace: "default", Key: "nonexistent"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-secret-2", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	_, err := provider.GetRESTConfig(context.Background(), "default/c2")
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
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
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
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
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
	provider.Invalidate("default", "ci1")
	third, err3 := provider.GetInNamespace(ctx, "default", "ci1")
	assert.NoError(t, err3)
	if first == third {
		t.Fatalf("expected different pointer after Invalidate, got same")
	}
}

func TestInvalidateSecret_EvictsTrackedEntries(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	kubeYAML := mustBuildKubeconfigYAML("https://kind-control-plane:6443")
	cc := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "kind", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "kind-kube", Namespace: "default"},
		},
	}
	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kind-kube", Namespace: "default"},
		Data:       map[string][]byte{"value": kubeYAML},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&cc, &secret).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()
	firstCfg, err := provider.GetRESTConfig(ctx, "default/kind")
	assert.NoError(t, err)
	assert.True(t, provider.IsSecretTracked("default", "kind-kube"))

	provider.InvalidateSecret("default", "kind-kube")
	assert.False(t, provider.IsSecretTracked("default", "kind-kube"))

	secondCfg, err := provider.GetRESTConfig(ctx, "default/kind")
	assert.NoError(t, err)
	assert.NotSame(t, firstCfg, secondCfg, "expected rest config to be rebuilt after secret invalidation")
}

func TestIsSecretTracked_FalseForUnknownSecret(t *testing.T) {
	provider := NewClientProvider(fake.NewClientBuilder().Build(), zaptest.NewLogger(t).Sugar())
	assert.False(t, provider.IsSecretTracked("default", "missing"))
}

func TestGetAcrossAllNamespaces_DoesNotMatchSimilarNames(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = telekomv1alpha1.AddToScheme(scheme)

	// Create clusters with similar names
	ccProd := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "prod", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}
	ccMyProd := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-prod", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}
	ccTestProd := telekomv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-prod", Namespace: "default"},
		Spec: telekomv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{Name: "s", Namespace: "default"},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&ccProd, &ccMyProd, &ccTestProd).Build()
	provider := NewClientProvider(fakeClient, zaptest.NewLogger(t).Sugar())

	ctx := context.Background()

	// Fetch "my-prod" to cache it
	result, err := provider.GetAcrossAllNamespaces(ctx, "my-prod")
	assert.NoError(t, err)
	assert.Equal(t, "my-prod", result.Name, "should return exact match")

	// Now fetch "prod" - should NOT return "my-prod" from cache
	resultProd, err := provider.GetAcrossAllNamespaces(ctx, "prod")
	assert.NoError(t, err)
	assert.Equal(t, "prod", resultProd.Name, "should return exact match for 'prod', not 'my-prod'")

	// Fetch "test-prod" - should NOT return "prod" or "my-prod"
	resultTestProd, err := provider.GetAcrossAllNamespaces(ctx, "test-prod")
	assert.NoError(t, err)
	assert.Equal(t, "test-prod", resultTestProd.Name, "should return exact match for 'test-prod'")
}
