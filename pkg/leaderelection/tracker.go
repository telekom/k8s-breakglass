package leaderelection

import (
	"context"
	"sync/atomic"
	"time"
)

type Tracker struct {
	val atomic.Value
}

func NewTracker() *Tracker {
	return &Tracker{}
}

func (t *Tracker) SetLeaderCtx(ctx context.Context) {
	if ctx == nil {
		t.val.Store((*context.Context)(nil))
	} else {
		t.val.Store(&ctx)
	}
}

func (t *Tracker) AwaitLeadership(ctx context.Context) (context.Context, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		val := t.val.Load()
		if val != nil {
			if lCtxPtr, ok := val.(*context.Context); ok && lCtxPtr != nil {
				lCtx := *lCtxPtr
				if lCtx.Err() == nil {
					return lCtx, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
