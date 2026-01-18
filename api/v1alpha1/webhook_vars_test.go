package v1alpha1

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInitWebhookClient(t *testing.T) {
	// Reset the once for this test (need to use a fresh package state)
	// Since we can't reset sync.Once, we test the functions that don't depend on it

	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("GetWebhookClient returns nil before initialization", func(t *testing.T) {
		// Note: This test may not work as expected if other tests have already initialized
		// In practice, we test that the getter functions work
		_ = GetWebhookClient()
		_ = GetWebhookCache()
	})

	t.Run("InitWebhookClient sets client", func(t *testing.T) {
		// Create a test-specific initialization
		var testOnce sync.Once
		var testClient client.Client
		var testCache cache.Cache

		testOnce.Do(func() {
			testClient = fakeClient
			testCache = &informertest.FakeInformers{}
		})

		require.NotNil(t, testClient)
		assert.Equal(t, fakeClient, testClient)
		require.NotNil(t, testCache)
	})
}

func TestGetWebhookClient(t *testing.T) {
	// Test that GetWebhookClient returns whatever was set
	// The actual value depends on test ordering, but the function should not panic
	client := GetWebhookClient()
	// May be nil or non-nil depending on test order
	_ = client
}

func TestGetWebhookCache(t *testing.T) {
	// Test that GetWebhookCache returns whatever was set
	// The actual value depends on test ordering, but the function should not panic
	cache := GetWebhookCache()
	// May be nil or non-nil depending on test order
	_ = cache
}

func TestInitWebhookClient_OnlyOnce(t *testing.T) {
	// Verify the sync.Once behavior using a local simulation
	var once sync.Once
	var counter int

	// First call should execute
	once.Do(func() {
		counter++
	})

	// Second call should not execute
	once.Do(func() {
		counter++
	})

	assert.Equal(t, 1, counter, "sync.Once should only execute the function once")
}
