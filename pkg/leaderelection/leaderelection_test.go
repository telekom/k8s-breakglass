package leaderelection

import (
	"context"
	"testing"
	"time"
)

func TestTracker(t *testing.T) {
	tracker := NewTracker()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracker.SetLeaderCtx(ctx)

	lCtx, err := tracker.AwaitLeadership(context.Background())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if lCtx != ctx {
		t.Fatalf("expected lCtx == ctx")
	}

	cancel()

	// Wait should fail if we cancel the outer context
	outerCtx, outerCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer outerCancel()

	_, err = tracker.AwaitLeadership(outerCtx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}
