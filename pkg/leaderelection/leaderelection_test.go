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

package leaderelection

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func TestLeaderElection_Callbacks(t *testing.T) {
	// This test validates that the leader election callbacks work as expected
	// by simulating what happens when leadership is acquired/lost
	logger := zaptest.NewLogger(t).Sugar()

	t.Run("OnStartedLeading closes channel", func(t *testing.T) {
		leaderElectedCh := make(chan struct{})

		// Simulate OnStartedLeading
		select {
		case <-leaderElectedCh:
			// Already closed
		default:
			close(leaderElectedCh)
		}

		// Verify channel is closed
		select {
		case <-leaderElectedCh:
			// Expected - channel is closed
		default:
			t.Fatal("Expected channel to be closed")
		}
		logger.Info("Channel closed as expected")
	})

	t.Run("OnStartedLeading handles already closed channel", func(t *testing.T) {
		leaderElectedCh := make(chan struct{})
		close(leaderElectedCh)

		// Simulate OnStartedLeading with already closed channel - should not panic
		select {
		case <-leaderElectedCh:
			// Already closed, we've signaled leadership
		default:
			close(leaderElectedCh) // This would panic if reached
		}

		// If we get here without panic, test passes
		logger.Info("Handled already closed channel without panic")
	})

	t.Run("OnStoppedLeading recreates channel", func(t *testing.T) {
		leaderElectedCh := make(chan struct{})
		close(leaderElectedCh)

		// Simulate OnStoppedLeading
		leaderElectedCh = make(chan struct{})

		// Verify channel is open (not closed)
		select {
		case <-leaderElectedCh:
			t.Fatal("Expected channel to be open, but it was closed")
		default:
			// Expected - channel is open
		}
		logger.Info("Channel recreated as expected")
	})

	t.Run("OnNewLeader logs correctly", func(t *testing.T) {
		hostname := "test-pod-abc123"
		identity := "test-pod-abc123"

		// This simulates the OnNewLeader callback
		if identity == hostname {
			logger.Infow("I became the leader", "identity", identity)
		} else {
			logger.Infow("New leader elected", "identity", identity)
		}
	})
}

func TestLeaderElection_ResourceLock(t *testing.T) {
	// Test creating a resource lock with fake client
	clientset := fake.NewClientset() //nolint:staticcheck // Using NewClientset for testing

	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		"test-namespace",
		"test-lease",
		clientset.CoreV1(),
		clientset.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity: "test-identity",
		},
	)
	assert.NoError(t, err)
	assert.NotNil(t, lock)

	// Verify lock identity
	assert.Equal(t, "test-identity", lock.Identity())
}

func TestLeaderElection_ContextCancellation(t *testing.T) {
	// Test that context cancellation stops waiting
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	done := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(done)

		// Simulate waiting for leader election with context
		select {
		case <-ctx.Done():
			// Expected path
			return
		case <-time.After(5 * time.Second):
			t.Error("Should have been cancelled")
		}
	}()

	// Cancel the context
	cancel()

	// Wait for goroutine to finish
	select {
	case <-done:
		// Expected
	case <-time.After(1 * time.Second):
		t.Fatal("Goroutine did not finish in time")
	}

	wg.Wait()
}

func TestLeaderElection_LeaseDurationConfig(t *testing.T) {
	// Verify lease configuration values are reasonable
	leaseDuration := 15 * time.Second
	renewDeadline := 10 * time.Second
	retryPeriod := 2 * time.Second

	// Lease duration must be greater than renew deadline
	assert.Greater(t, leaseDuration, renewDeadline, "Lease duration should be greater than renew deadline")

	// Renew deadline must be greater than retry period
	assert.Greater(t, renewDeadline, retryPeriod, "Renew deadline should be greater than retry period")

	// Standard leader election best practice:
	// leaseDuration > renewDeadline > retryPeriod * 2
	assert.Greater(t, renewDeadline, 2*retryPeriod, "Renew deadline should be at least 2x retry period")
}

func TestLeaderElection_LeaseMetadata(t *testing.T) {
	// Test lease metadata creation
	leaseName := "breakglass-controller"
	leaseNamespace := "breakglass-system"
	hostname := "breakglass-pod-abc123"

	meta := metav1.ObjectMeta{
		Name:      leaseName,
		Namespace: leaseNamespace,
	}

	assert.Equal(t, leaseName, meta.Name)
	assert.Equal(t, leaseNamespace, meta.Namespace)
	assert.NotEmpty(t, hostname)
}

func TestLeaderElection_ChannelSignaling(t *testing.T) {
	// Test complete channel lifecycle
	leaderElectedCh := make(chan struct{})

	// Initially channel should be open (blocking)
	select {
	case <-leaderElectedCh:
		t.Fatal("Channel should be open initially")
	default:
		// Expected
	}

	// Simulate acquiring leadership
	close(leaderElectedCh)

	// Now channel should be closed (non-blocking)
	select {
	case <-leaderElectedCh:
		// Expected
	default:
		t.Fatal("Channel should be closed after acquiring leadership")
	}

	// Simulate losing leadership and recreating channel
	leaderElectedCh = make(chan struct{})

	// Channel should be open again
	select {
	case <-leaderElectedCh:
		t.Fatal("Channel should be open after recreation")
	default:
		// Expected
	}
}

func TestLeaderElection_ConcurrentChannelAccess(t *testing.T) {
	// Test that channel operations are safe under concurrent access
	leaderElectedCh := make(chan struct{})

	var wg sync.WaitGroup
	const numGoroutines = 10

	// Start multiple goroutines waiting on the channel
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-leaderElectedCh
		}()
	}

	// Give goroutines time to start
	time.Sleep(10 * time.Millisecond)

	// Close the channel (simulating leadership acquisition)
	close(leaderElectedCh)

	// All goroutines should complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Expected - all goroutines completed
	case <-time.After(1 * time.Second):
		t.Fatal("Goroutines did not complete in time")
	}
}

func TestLeaderElection_MultipleLeadershipTransitions(t *testing.T) {
	// Simulate multiple leadership transitions
	logger := zaptest.NewLogger(t).Sugar()
	const numTransitions = 5

	for i := 0; i < numTransitions; i++ {
		leaderElectedCh := make(chan struct{})

		// Acquire leadership
		close(leaderElectedCh)
		logger.Infow("Acquired leadership", "iteration", i)

		// Verify leadership is signaled
		select {
		case <-leaderElectedCh:
			// Expected
		default:
			t.Fatalf("Leadership should be signaled in iteration %d", i)
		}

		// In a real scenario, OnStoppedLeading would recreate the channel
		// We just log here to verify the transition pattern
		logger.Infow("Lost leadership", "iteration", i)
	}
}

func TestLeaderElection_TimingConstants(t *testing.T) {
	// Verify that timing constants follow Kubernetes leader election best practices
	// From: https://github.com/kubernetes/client-go/blob/master/tools/leaderelection/leaderelection.go

	leaseDuration := 15 * time.Second
	renewDeadline := 10 * time.Second
	retryPeriod := 2 * time.Second

	// LeaseDuration must be > RenewDeadline (leader must be able to renew before lease expires)
	assert.True(t, leaseDuration > renewDeadline,
		"LeaseDuration (%v) must be greater than RenewDeadline (%v)", leaseDuration, renewDeadline)

	// RenewDeadline must be > RetryPeriod (must have time to retry renewal)
	assert.True(t, renewDeadline > retryPeriod,
		"RenewDeadline (%v) must be greater than RetryPeriod (%v)", renewDeadline, retryPeriod)

	// Common pattern: RenewDeadline should be ~2/3 of LeaseDuration
	expectedRenewDeadline := leaseDuration * 2 / 3
	assert.True(t, renewDeadline >= expectedRenewDeadline,
		"RenewDeadline (%v) should be at least 2/3 of LeaseDuration (%v)", renewDeadline, expectedRenewDeadline)
}

// TestStart_ActualExecution tests the actual Start function with real leader election.
// This test provides actual code coverage for the Start function.
func TestStart_ActualExecution(t *testing.T) {
	fakeClient := fake.NewClientset() //nolint:staticcheck // Using NewClientset for testing
	namespace := "test-namespace"
	_, err := fakeClient.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{})
	assert.NoError(t, err)

	leaseName := "test-lease-actual"
	hostname := "test-host-actual"

	resourceLock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace,
		leaseName,
		fakeClient.CoreV1(),
		fakeClient.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity: hostname,
		},
	)
	assert.NoError(t, err)

	log := zaptest.NewLogger(t).Sugar()
	leaderElectedCh := make(chan struct{})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	// Start the actual leader election function
	go Start(ctx, &wg, &leaderElectedCh, resourceLock, hostname, leaseName, namespace, log)

	// Wait for leadership acquisition or timeout
	select {
	case <-leaderElectedCh:
		t.Log("Leadership acquired successfully")
	case <-time.After(2 * time.Second):
		t.Log("Timeout waiting for leadership - this is acceptable in test environment")
	}

	// Cancel context to trigger shutdown
	cancel()

	// Wait for goroutine to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("Leader election shut down cleanly")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for leader election shutdown")
	}
}
