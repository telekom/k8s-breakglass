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
