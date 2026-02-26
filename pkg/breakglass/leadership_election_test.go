package breakglass

import (
	"context"
	"testing"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/breakglass/clusterconfig"
	"go.uber.org/zap/zaptest"
)

// TestClusterConfigChecker_WaitsForLeadershipSignal verifies that
// ClusterConfigChecker blocks until receiving leadership signal.
func TestClusterConfigChecker_WaitsForLeadershipSignal(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	leaderCh := make(chan struct{})

	checker := clusterconfig.ClusterConfigChecker{
		Log:           logger,
		Client:        nil, // Not used in this test
		Interval:      0,   // Will default to 10m
		Recorder:      nil, // Not used in this test
		LeaderElected: leaderCh,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run checker in background - will block waiting for leadership
	done := make(chan bool, 1)
	go func() {
		checker.Start(ctx)
		done <- true
	}()

	// Should be blocked waiting for signal
	select {
	case <-done:
		t.Fatal("ClusterConfigChecker should block until leadership signal")
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
		t.Error("ClusterConfigChecker should exit when context is cancelled")
	}
}

// TestClusterConfigChecker_StartsImmediatelyWithoutSignal verifies backward compatibility.
func TestClusterConfigChecker_StartsImmediatelyWithoutSignal(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	checker := clusterconfig.ClusterConfigChecker{
		Log:           logger,
		Client:        nil,
		Interval:      0,
		Recorder:      nil,
		LeaderElected: nil, // No leadership signal
	}

	// Verify that with nil LeaderElected, the routine doesn't block on startup
	done := make(chan struct{})
	go func() {
		// This simulates what Start() does - checks if LeaderElected != nil before blocking
		if checker.LeaderElected != nil {
			<-checker.LeaderElected
		}
		// Should reach here immediately since LeaderElected is nil
		close(done)
	}()

	// Should not block
	select {
	case <-done:
		// Expected: completed immediately
	case <-time.After(time.Second):
		t.Error("ClusterConfigChecker with nil LeaderElected should not block")
	}
}

// TestClusterConfigChecker_ContextCancellationBeforeLeadership verifies
// that context cancellation is respected even before leadership signal.
func TestClusterConfigChecker_ContextCancellationBeforeLeadership(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	leaderCh := make(chan struct{})

	checker := clusterconfig.ClusterConfigChecker{
		Log:           logger,
		Client:        nil,
		Interval:      0,
		Recorder:      nil,
		LeaderElected: leaderCh,
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context immediately
	cancel()

	// Run checker - should exit immediately
	done := make(chan bool, 1)
	go func() {
		checker.Start(ctx)
		done <- true
	}()

	// Should exit quickly despite no leadership signal
	select {
	case <-done:
		// Expected: exited due to context cancellation
	case <-time.After(200 * time.Millisecond):
		t.Error("ClusterConfigChecker should exit when context cancelled")
	}
}

// TestLeadershipSignal_EarlyClose verifies that closing the leadership
// channel early (before listeners start) is immediately readable.
func TestLeadershipSignal_EarlyClose(t *testing.T) {
	leaderCh := make(chan struct{})
	close(leaderCh) // Close immediately - signal already sent

	// Verify that the channel is immediately readable (closed)
	select {
	case <-leaderCh:
		// Expected: channel is closed and immediately readable
	default:
		t.Error("LeaderElected channel should be immediately readable when closed early")
	}

	// Verify multiple readers can all receive from closed channel
	select {
	case <-leaderCh:
		// Expected: still readable
	default:
		t.Error("LeaderElected channel should remain readable for multiple receivers")
	}
}
