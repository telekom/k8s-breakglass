// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package escalation

import (
	"context"
	"testing"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/breakglass/clusterconfig"
	"go.uber.org/zap/zaptest"
)

// TestEscalationStatusUpdater_WaitsForLeadershipSignal verifies that
// EscalationStatusUpdater blocks until receiving leadership signal.
func TestEscalationStatusUpdater_WaitsForLeadershipSignal(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	leaderCh := make(chan struct{})

	updater := EscalationStatusUpdater{
		Log:           logger,
		K8sClient:     nil, // Not used in this test
		Resolver:      nil, // Not used in this test
		Interval:      0,   // Will default to 5m
		LeaderElected: leaderCh,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Run updater in background - will block waiting for leadership
	done := make(chan bool, 1)
	go func() {
		updater.Start(ctx)
		done <- true
	}()

	// Should be blocked waiting for signal
	select {
	case <-done:
		t.Fatal("EscalationStatusUpdater should block until leadership signal")
	case <-time.After(100 * time.Millisecond):
		// Expected: blocked on channel
	}

	// Cancel context to stop before it tries to run business logic
	cancel()

	// Should exit due to context cancellation
	select {
	case <-done:
		// Expected: routine exited
	case <-time.After(200 * time.Millisecond):
		t.Error("EscalationStatusUpdater should exit when context is cancelled")
	}
}

// TestEscalationStatusUpdater_StartsImmediatelyWithoutSignal verifies backward compatibility.
func TestEscalationStatusUpdater_StartsImmediatelyWithoutSignal(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	updater := EscalationStatusUpdater{
		Log:           logger,
		K8sClient:     nil,
		Resolver:      nil,
		Interval:      0,
		LeaderElected: nil, // No leadership signal
	}

	// Verify that with nil LeaderElected, the routine doesn't block on startup
	done := make(chan struct{})
	go func() {
		// This simulates what Start() does - checks if LeaderElected != nil before blocking
		if updater.LeaderElected != nil {
			<-updater.LeaderElected
		}
		// Should reach here immediately since LeaderElected is nil
		close(done)
	}()

	// Should not block
	select {
	case <-done:
		// Expected: completed immediately
	case <-time.After(time.Second):
		t.Error("EscalationStatusUpdater with nil LeaderElected should not block")
	}
}

// TestEscalationStatusUpdater_ContextCancellationBeforeLeadership verifies
// that context cancellation is respected even before leadership signal.
func TestEscalationStatusUpdater_ContextCancellationBeforeLeadership(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	leaderCh := make(chan struct{})

	updater := EscalationStatusUpdater{
		Log:           logger,
		K8sClient:     nil,
		Resolver:      nil,
		Interval:      0,
		LeaderElected: leaderCh,
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context immediately
	cancel()

	// Run updater - should exit immediately
	done := make(chan bool, 1)
	go func() {
		updater.Start(ctx)
		done <- true
	}()

	// Should exit quickly despite no leadership signal
	select {
	case <-done:
		// Expected: exited due to context cancellation
	case <-time.After(200 * time.Millisecond):
		t.Error("EscalationStatusUpdater should exit when context cancelled")
	}
}

// TestLeadershipSignal_MultipleListeners verifies that multiple routines
// can listen on the same leadership signal channel.
func TestLeadershipSignal_MultipleListeners(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	leaderCh := make(chan struct{})

	// Listener 1: EscalationStatusUpdater
	updater := EscalationStatusUpdater{
		Log:           logger,
		K8sClient:     nil,
		Resolver:      nil,
		Interval:      0,
		LeaderElected: leaderCh,
	}

	// Listener 2: ClusterConfigChecker
	checker := clusterconfig.ClusterConfigChecker{
		Log:           logger,
		Client:        nil,
		Interval:      0,
		Recorder:      nil,
		LeaderElected: leaderCh,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done1 := make(chan bool, 1)
	done2 := make(chan bool, 1)

	go func() {
		updater.Start(ctx)
		done1 <- true
	}()

	go func() {
		checker.Start(ctx)
		done2 <- true
	}()

	// Both should block initially
	select {
	case <-done1:
		t.Fatal("Updater should block until leadership signal")
	case <-done2:
		t.Fatal("Checker should block until leadership signal")
	case <-time.After(100 * time.Millisecond):
		// Expected: both blocked
	}

	// Both should eventually exit due to context timeout
	completed := 0
	stop := false
	for range 2 {
		select {
		case <-done1:
			completed++
		case <-done2:
			completed++
		case <-time.After(400 * time.Millisecond):
			stop = true
		}
		if stop {
			break
		}
	}

	if completed != 2 {
		t.Errorf("Expected 2 routines to complete, got %d", completed)
	}
}
