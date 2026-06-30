package main

import (
	
	"io/ioutil"
	"strings"
)

func main() {
	f, _ := ioutil.ReadFile("pkg/breakglass/cleanup_task.go")
	s := string(f)
	oldStr := `func (cr CleanupRoutine) CleanupRoutine(ctx context.Context) {
	// Wait for leadership signal if provided (enables multi-replica scaling with leader election)
	if cr.LeaderTracker != nil {
		cr.Log.Info("Cleanup routine waiting for leadership signal before starting...")
		select {
		case <-ctx.Done():
			cr.Log.Infow("Cert-controller's manager stopping before acquiring leadership (context cancelled)")
			return
		case <-cr.LeaderTracker:
			cr.Log.Info("Leadership acquired - starting cleanup routine")
		}
	}

	// run initial cleanup
	cr.clean(ctx)

	// Use time.NewTicker instead of time.Tick to avoid memory leak.
	// time.Tick creates a ticker that is never garbage collected.
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cr.clean(ctx)
		}
	}
}`
	newStr := `func (cr CleanupRoutine) CleanupRoutine(ctx context.Context) {
	for {
		var leaderCtx context.Context
		if cr.LeaderTracker != nil {
			cr.Log.Info("Cleanup routine waiting for leadership signal before starting...")
			var err error
			leaderCtx, err = cr.LeaderTracker.AwaitLeadership(ctx)
			if err != nil {
				return
			}
			cr.Log.Info("Leadership acquired - starting cleanup routine")
		} else {
			leaderCtx = ctx
		}

		cr.runLoop(leaderCtx)

		if cr.LeaderTracker == nil || ctx.Err() != nil {
			return
		}
	}
}

func (cr CleanupRoutine) runLoop(ctx context.Context) {
	// run initial cleanup
	cr.clean(ctx)

	// Use time.NewTicker instead of time.Tick to avoid memory leak.
	// time.Tick creates a ticker that is never garbage collected.
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cr.clean(ctx)
		}
	}
}`
	s = strings.Replace(s, oldStr, newStr, 1)
	ioutil.WriteFile("pkg/breakglass/cleanup_task.go", []byte(s), 0644)
}
