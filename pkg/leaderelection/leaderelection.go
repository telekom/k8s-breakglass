package leaderelection

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

func Start(ctx context.Context, wg *sync.WaitGroup, leaderElectedCh *chan struct{}, resourceLock resourcelock.Interface,
	hostname, leaseName, leaseNamespace string, log *zap.SugaredLogger) {
	defer wg.Done()
	// Create callbacks for leader election
	leaderCallbacks := leaderelection.LeaderCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			log.Infow("This replica acquired leadership, signaling background loops")
			// Signal background loops that we're the leader
			select {
			case <-*leaderElectedCh:
				// Already closed, we've signaled leadership
			default:
				close(*leaderElectedCh)
			}
		},
		OnStoppedLeading: func() {
			log.Infow("Lost leadership")
			// Recreate the channel for the next leader to use
			*leaderElectedCh = make(chan struct{})
		},
		OnNewLeader: func(identity string) {
			if identity == hostname {
				log.Infow("I became the leader", "identity", identity)
			} else {
				log.Infow("New leader elected", "identity", identity)
			}
		},
	}

	// Create the LeaderElector which handles the full lifecycle of leader election:
	// - Acquires the lock when becoming leader (creates/updates the lease)
	// - Renews the lock at the specified interval to maintain leadership
	// - Releases the lock when context is cancelled
	// - Detects when leadership is lost and calls OnStoppedLeading
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:          resourceLock,
		LeaseDuration: 15 * time.Second, // Time the lease is held by leader
		RenewDeadline: 10 * time.Second, // Deadline for renewing the lease before losing it
		RetryPeriod:   2 * time.Second,  // Duration to wait between leader election tries
		Callbacks:     leaderCallbacks,
		WatchDog:      nil,
		Name:          "breakglass-controller",
	})
	if err != nil {
		log.Errorw("Failed to create LeaderElector", "error", err)
		// Don't call Fatalf in library code - let the caller decide how to handle
		// In cmd/main.go, the failure is already handled by error checking
		return
	}

	log.Infow("Starting leader election", "id", leaseName, "namespace", leaseNamespace, "identity", hostname)

	// Run the leader election - this will block until context is cancelled
	// It continuously tries to acquire the lease and renews it if successful
	elector.Run(ctx)
}
