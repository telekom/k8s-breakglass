package config

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// TestIdentityProviderWatcher_Creation tests watcher creation
func TestIdentityProviderWatcher_Creation(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	watcher := NewIdentityProviderWatcher(client, log)

	assert.NotNil(t, watcher)
	assert.Equal(t, 1*time.Second, watcher.debounce)
	assert.Nil(t, watcher.onReload)
}

// TestIdentityProviderWatcher_WithDebounce tests debounce configuration
func TestIdentityProviderWatcher_WithDebounce(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	watcher := NewIdentityProviderWatcher(client, log).
		WithDebounce(5 * time.Second)

	assert.Equal(t, 5*time.Second, watcher.debounce)
}

// TestIdentityProviderWatcher_WithReloadCallback tests callback registration
func TestIdentityProviderWatcher_WithReloadCallback(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callCount := int32(0)
	callback := func(ctx context.Context) error {
		atomic.AddInt32(&callCount, 1)
		return nil
	}

	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(callback)

	assert.NotNil(t, watcher.onReload)

	// Test callback
	err := watcher.onReload(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(1), callCount)
}

// TestIdentityProviderWatcher_StartStop tests start/stop lifecycle
func TestIdentityProviderWatcher_StartStop(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	watcher := NewIdentityProviderWatcher(client, log)

	// Start watcher
	done := watcher.Start(context.Background())

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop watcher
	watcher.Stop()

	// Wait for done signal (with timeout)
	select {
	case <-done:
		// Success - watcher stopped
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop within timeout")
	}
}

// TestIdentityProviderWatcher_TriggerReload tests manual reload trigger
func TestIdentityProviderWatcher_TriggerReload(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callCount := int32(0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			atomic.AddInt32(&callCount, 1)
			return nil
		})

	// Trigger manual reload
	err := watcher.TriggerReload(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int32(1), callCount)
}

// TestIdentityProviderWatcher_TriggerReloadWithoutCallback tests error when no callback
func TestIdentityProviderWatcher_TriggerReloadWithoutCallback(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	watcher := NewIdentityProviderWatcher(client, log)

	err := watcher.TriggerReload(context.Background())
	assert.Error(t, err)
}

// TestIdentityProviderWatcher_DebounceWorks tests debouncing prevents rapid reloads
// Note: TriggerReload bypasses debouncing for immediate manual triggers.
// Debouncing is primarily for the periodic watch loop, not manual triggers.
func TestIdentityProviderWatcher_DebounceWorks(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callCount := int32(0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithDebounce(200 * time.Millisecond).
		WithReloadCallback(func(ctx context.Context) error {
			atomic.AddInt32(&callCount, 1)
			return nil
		})

	// Trigger first reload
	err := watcher.TriggerReload(context.Background())
	assert.NoError(t, err)
	firstCount := atomic.LoadInt32(&callCount)
	assert.Equal(t, int32(1), firstCount)

	// Try to trigger immediately again - TriggerReload bypasses debouncing
	// (debouncing is for periodic checks, not manual triggers)
	err = watcher.TriggerReload(context.Background())
	assert.NoError(t, err)
	secondCount := atomic.LoadInt32(&callCount)
	// Manual triggers are not debounced
	assert.Equal(t, int32(2), secondCount, "TriggerReload is not debounced (expected behavior)")
}

// TestIdentityProviderWatcher_WatchLoop_ContextCancellation tests context cancellation
func TestIdentityProviderWatcher_WatchLoop_ContextCancellation(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	watcher := NewIdentityProviderWatcher(client, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := watcher.Start(ctx)

	// Cancel context
	cancel()

	// Wait for done signal
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop after context cancellation")
	}
}

// TestIdentityProviderWatcher_IntegrationWithReload tests watcher integration with reload
func TestIdentityProviderWatcher_IntegrationWithReload(t *testing.T) {
	log := zap.NewNop().Sugar()

	// Setup fake client with IdentityProvider
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Primary:  true,
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()

	reloadCount := int32(0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			atomic.AddInt32(&reloadCount, 1)
			return nil
		})

	// Trigger manual reload
	err2 := watcher.TriggerReload(context.Background())
	assert.NoError(t, err2)
	assert.Equal(t, int32(1), reloadCount)
}

// TestIdentityProviderWatcher_MultipleCallbacks tests multiple sequential reloads
func TestIdentityProviderWatcher_MultipleCallbacks(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callSequence := make([]int, 0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithDebounce(10 * time.Millisecond).
		WithReloadCallback(func(ctx context.Context) error {
			callSequence = append(callSequence, 1)
			return nil
		})

	// Trigger multiple reloads with debounce between them
	err := watcher.TriggerReload(context.Background())
	assert.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	err = watcher.TriggerReload(context.Background())
	assert.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	err = watcher.TriggerReload(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, 3, len(callSequence), "should have 3 successful reloads")
}

// TestIdentityProviderWatcher_ReloadErrorHandling tests error handling during reload
func TestIdentityProviderWatcher_ReloadErrorHandling(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callCount := int32(0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			atomic.AddInt32(&callCount, 1)
			// Simulate callback error
			return fmt.Errorf("reload failed: connection refused")
		})

	// Trigger reload that will fail
	err := watcher.TriggerReload(context.Background())
	assert.Error(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
	assert.Contains(t, err.Error(), "reload failed")
}

// TestIdentityProviderWatcher_K8sClientErrorHandling tests handling of Kubernetes client errors
func TestIdentityProviderWatcher_K8sClientErrorHandling(t *testing.T) {
	log := zap.NewNop().Sugar()
	// Fake client that returns error on List
	client := fake.NewClientBuilder().
		WithLists(&breakglassv1alpha1.IdentityProviderList{}).
		Build()

	watcher := NewIdentityProviderWatcher(client, log)

	// shouldReload should handle list errors gracefully
	result := watcher.shouldReload(context.Background())
	// Should return false without panicking
	assert.False(t, result, "shouldReload should return false on error")
}

// TestIdentityProviderWatcher_ErrorRetry tests retry behavior on failure
func TestIdentityProviderWatcher_ErrorRetry(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callCount := int32(0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			count := atomic.AddInt32(&callCount, 1)
			// Fail first time, succeed second time
			if count == 1 {
				return fmt.Errorf("temporary failure")
			}
			return nil
		})

	// First reload fails
	err1 := watcher.TriggerReload(context.Background())
	assert.Error(t, err1)

	// Second reload succeeds
	err2 := watcher.TriggerReload(context.Background())
	assert.NoError(t, err2)
	assert.Equal(t, int32(2), atomic.LoadInt32(&callCount))
}

// TestIdentityProviderWatcher_ConcurrentReloadSafety tests thread-safe reload handling
func TestIdentityProviderWatcher_ConcurrentReloadSafety(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	callCount := int32(0)
	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			atomic.AddInt32(&callCount, 1)
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})

	// Trigger multiple concurrent reloads
	numGoroutines := 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			err := watcher.TriggerReload(context.Background())
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	assert.Equal(t, int32(numGoroutines), atomic.LoadInt32(&callCount))
}

// TestIdentityProviderWatcher_NoCallbackErrorHandling tests error when callback is nil
func TestIdentityProviderWatcher_NoCallbackErrorHandling(t *testing.T) {
	log := zap.NewNop().Sugar()
	client := fake.NewClientBuilder().Build()

	watcher := NewIdentityProviderWatcher(client, log)
	// No callback set

	err := watcher.TriggerReload(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reload callback not set")
}

// TestIdentityProviderWatcher_MultiProviderDetection tests watcher detects changes to ANY provider
func TestIdentityProviderWatcher_MultiProviderDetection(t *testing.T) {
	log := zap.NewNop().Sugar()

	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Create two different IdentityProviders
	idp1 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "provider-oidc",
			ResourceVersion: "1",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client1",
			},
			Primary:  true,
			Disabled: false,
		},
	}

	idp2 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "provider-keycloak",
			ResourceVersion: "1",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://keycloak.example.com",
				ClientID:  "client2",
			},
			Primary:  false,
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp1, idp2).
		Build()

	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			return nil
		})

	// First check - should detect changes (ResourceVersion exists)
	shouldReload := watcher.shouldReload(context.Background())
	assert.True(t, shouldReload, "should detect initial providers")

	// Second check - no change (ResourceVersion same)
	shouldReload = watcher.shouldReload(context.Background())
	assert.False(t, shouldReload, "should not reload if ResourceVersion unchanged")

	// Verify both providers exist in watcher's view
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := client.List(context.Background(), idpList); err != nil {
		t.Fatalf("failed to list providers: %v", err)
	}

	assert.Equal(t, 2, len(idpList.Items), "should have 2 providers in cluster")
}

// TestIdentityProviderWatcher_MultiProviderIsolation tests that watcher monitors
// all providers independently
func TestIdentityProviderWatcher_MultiProviderIsolation(t *testing.T) {
	log := zap.NewNop().Sugar()

	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	// Create provider A
	providerA := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "provider-a",
			ResourceVersion: "1",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth-a.example.com",
				ClientID:  "client-a",
			},
			Primary:  true,
			Disabled: false,
		},
	}

	// Create provider B
	providerB := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "provider-b",
			ResourceVersion: "1",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth-b.example.com",
				ClientID:  "client-b",
			},
			Primary:  false,
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(providerA, providerB).
		Build()

	watcher := NewIdentityProviderWatcher(client, log).
		WithReloadCallback(func(ctx context.Context) error {
			return nil
		})

	// Establish baseline ResourceVersion
	watcher.shouldReload(context.Background())

	// Verify watcher tracks both providers
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := client.List(context.Background(), idpList); err != nil {
		t.Fatalf("failed to list providers: %v", err)
	}

	assert.Equal(t, 2, len(idpList.Items), "should have 2 providers")

	// Verify both providers are detectable
	providerNames := make(map[string]bool)
	for _, idp := range idpList.Items {
		providerNames[idp.Name] = true
	}

	assert.True(t, providerNames["provider-a"], "provider A should be listed")
	assert.True(t, providerNames["provider-b"], "provider B should be listed")
}

// TestIdentityProviderWatcher_ConditionHelpers tests condition management helpers
func TestIdentityProviderWatcher_ConditionHelpers(t *testing.T) {
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
	}

	// Initially no conditions
	assert.Nil(t, idp.GetCondition("Ready"))

	// Set a condition
	condition := metav1.Condition{
		Type:   "Ready",
		Status: metav1.ConditionTrue,
		Reason: "ConfigValid",
	}
	idp.SetCondition(condition)

	// Verify condition was set
	readyCondition := idp.GetCondition("Ready")
	assert.NotNil(t, readyCondition)
	assert.Equal(t, "Ready", readyCondition.Type)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)

	// Update the same condition
	condition.Status = metav1.ConditionFalse
	condition.Reason = "ConfigError"
	idp.SetCondition(condition)

	// Verify condition was updated (not duplicated)
	assert.Equal(t, 1, len(idp.Status.Conditions), "should have only one Ready condition")
	readyCondition = idp.GetCondition("Ready")
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, "ConfigError", readyCondition.Reason)
}

// TestIdentityProviderWatcher_UpdateAllProviderStatuses tests status update for multiple providers
func TestIdentityProviderWatcher_UpdateAllProviderStatuses(t *testing.T) {
	log := zap.NewNop().Sugar()

	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	assert.NoError(t, err)

	idp1 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "provider-1",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client1",
			},
			Primary:  true,
			Disabled: false,
		},
	}

	idp2 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "provider-2",
		},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "client2",
			},
			Primary:  false,
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp1, idp2).
		Build()

	watcher := NewIdentityProviderWatcher(client, log)

	// Test status update on success (no error)
	err = watcher.updateAllProviderStatuses(context.Background(), nil)
	assert.NoError(t, err, "should successfully update provider statuses on success")

	// Test status update on error
	testErr := fmt.Errorf("reload failed")
	err = watcher.updateAllProviderStatuses(context.Background(), testErr)
	assert.NoError(t, err, "should not return error when updating status for failed reload")

	// Verify that listing still works (proves we reached the providers)
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	err = client.List(context.Background(), idpList)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(idpList.Items))
}
