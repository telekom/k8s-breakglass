package leaderelection

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	leaseDuration = 15 * time.Second
	renewDeadline = 10 * time.Second
	retryPeriod   = 2 * time.Second
)

type leaderElectorRunner interface {
	Run(context.Context)
}

type leaderElectorFactory func(leaderelection.LeaderCallbacks) (leaderElectorRunner, error)

func Start(ctx context.Context, wg *sync.WaitGroup, leaderElectedCh *chan struct{}, resourceLock resourcelock.Interface,
	hostname, leaseName, leaseNamespace string, log *zap.SugaredLogger, onStarted func(context.Context)) {
	defer wg.Done()

	callbacks := newLeaderCallbacks(leaderElectedCh, hostname, log, onStarted)
	factory := func(callbacks leaderelection.LeaderCallbacks) (leaderElectorRunner, error) {
		return leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock:          resourceLock,
			LeaseDuration: leaseDuration,
			RenewDeadline: renewDeadline,
			RetryPeriod:   retryPeriod,
			Callbacks:     callbacks,
			WatchDog:      nil,
			Name:          "breakglass-controller",
		})
	}

	runLoop(ctx, leaseName, leaseNamespace, hostname, log, callbacks, factory)
}

func newLeaderCallbacks(leaderElectedCh *chan struct{}, hostname string, log *zap.SugaredLogger,
	onStarted func(context.Context),
) leaderelection.LeaderCallbacks {
	// Protect concurrent access to *leaderElectedCh from OnStartedLeading
	// and OnStoppedLeading callbacks, which may run on different goroutines.
	var chMu sync.Mutex
	return leaderelection.LeaderCallbacks{
		OnStartedLeading: func(ctx context.Context) {
			log.Infow("This replica acquired leadership, signaling background loops")
			chMu.Lock()
			defer chMu.Unlock()
			// If leadership was already lost (context cancelled) while this
			// callback was dispatched, avoid closing a channel that
			// OnStoppedLeading may have already replaced.
			select {
			case <-ctx.Done():
				// Leadership no longer held; do not signal.
				return
			default:
			}
			if onStarted != nil {
				onStarted(ctx)
			}
			select {
			case <-*leaderElectedCh:
				// Already closed — leadership was previously signaled.
			default:
				close(*leaderElectedCh)
			}
		},
		OnStoppedLeading: func() {
			log.Infow("Lost leadership")
			// Replace the channel so a future re-acquisition can signal again.
			// Goroutines that captured the old (closed) channel value will continue
			// to see it as closed — they will not observe this new channel.
			chMu.Lock()
			defer chMu.Unlock()
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
}

func runLoop(ctx context.Context, leaseName, leaseNamespace, hostname string, log *zap.SugaredLogger,
	callbacks leaderelection.LeaderCallbacks, factory leaderElectorFactory,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Create the LeaderElector which handles one leadership epoch:
		// - Acquires the lock when becoming leader (creates/updates the lease)
		// - Renews the lock at the specified interval to maintain leadership
		// - Releases the lock when context is cancelled
		// - Detects when leadership is lost and calls OnStoppedLeading
		elector, err := factory(callbacks)
		if err != nil {
			log.Errorw("Failed to create LeaderElector", "error", err)
			// Don't call Fatalf in library code - let the caller decide how to handle
			// In cmd/main.go, the failure is already handled by error checking
			return
		}

		log.Infow("Starting leader election", "id", leaseName, "namespace", leaseNamespace, "identity", hostname)

		// Run blocks until the process context is cancelled or this process loses
		// the lease. Losing the lease must not permanently stop this replica from
		// becoming leader again, so retry until the parent context shuts down.
		elector.Run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryPeriod):
			log.Infow("Leader election stopped; retrying leadership acquisition",
				"id", leaseName, "namespace", leaseNamespace, "identity", hostname)
		}
	}
}
