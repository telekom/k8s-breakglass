// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package leaderelection

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientleaderelection "k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type partitionedTransport struct {
	base    http.RoundTripper
	blocked *atomic.Bool
}

func (p partitionedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if p.blocked.Load() {
		return nil, errors.New("characterization: elector disconnected from API server")
	}
	return p.base.RoundTrip(req)
}

func TestPlatformLeaderEpochsEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	environment := &envtest.Environment{}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	apiClient, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	ctx := context.Background()
	_, err = apiClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "leader-platform"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	var partition atomic.Bool
	firstConfig := rest.CopyConfig(cfg)
	firstConfig.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		return partitionedTransport{base: base, blocked: &partition}
	}
	firstClient, err := kubernetes.NewForConfig(firstConfig)
	require.NoError(t, err)
	newLock := func(identity string, cli kubernetes.Interface) resourcelock.Interface {
		t.Helper()
		lock, lockErr := resourcelock.New(resourcelock.LeasesResourceLock, "leader-platform", "epochs",
			cli.CoreV1(), cli.CoordinationV1(), resourcelock.ResourceLockConfig{Identity: identity})
		require.NoError(t, lockErr)
		return lock
	}
	epochSignals := []chan struct{}{make(chan struct{}), make(chan struct{})}
	started := []chan context.Context{make(chan context.Context, 4), make(chan context.Context, 4)}
	stopped := []chan struct{}{make(chan struct{}, 4), make(chan struct{}, 4)}
	locks := []resourcelock.Interface{newLock("first", firstClient), newLock("second", apiClient)}
	contexts := make([]context.Context, 2)
	cancels := make([]context.CancelFunc, 2)
	var wg sync.WaitGroup
	launch := func(index int) {
		contexts[index], cancels[index] = context.WithCancel(ctx)
		callbacks := newLeaderCallbacks(&epochSignals[index], "replica", zap.NewNop().Sugar(),
			func(leaderCtx context.Context) { started[index] <- leaderCtx })
		originalStopped := callbacks.OnStoppedLeading
		callbacks.OnStoppedLeading = func() {
			originalStopped()
			stopped[index] <- struct{}{}
		}
		factory := func(cb clientleaderelection.LeaderCallbacks) (leaderElectorRunner, error) {
			return clientleaderelection.NewLeaderElector(clientleaderelection.LeaderElectionConfig{
				Lock: locks[index], LeaseDuration: 3 * time.Second,
				RenewDeadline: 2 * time.Second, RetryPeriod: 200 * time.Millisecond,
				Callbacks: cb,
			})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			runLoop(contexts[index], "epochs", "leader-platform", "replica", zap.NewNop().Sugar(), callbacks, factory)
		}()
	}
	t.Cleanup(func() {
		for _, cancel := range cancels {
			if cancel != nil {
				cancel()
			}
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("electors did not stop")
		}
	})
	awaitEpoch := func(index int, signal <-chan struct{}) context.Context {
		t.Helper()
		var leaderCtx context.Context
		select {
		case leaderCtx = <-started[index]:
		case <-time.After(20 * time.Second):
			t.Fatal("leadership not acquired")
		}
		select {
		case <-signal:
		case <-time.After(5 * time.Second):
			t.Fatal("background-work signal not closed")
		}
		lease, getErr := apiClient.CoordinationV1().Leases("leader-platform").Get(ctx, "epochs", metav1.GetOptions{})
		require.NoError(t, getErr)
		require.Equal(t, []string{"first", "second"}[index], *lease.Spec.HolderIdentity)
		return leaderCtx
	}
	firstSignal := epochSignals[0]
	launch(0)
	firstEpoch := awaitEpoch(0, firstSignal)
	secondSignal := epochSignals[1]
	launch(1)
	select {
	case <-started[1]:
		t.Fatal("competing elector acquired a held lease")
	case <-time.After(500 * time.Millisecond):
	}
	partition.Store(true)
	select {
	case <-stopped[0]:
	case <-time.After(10 * time.Second):
		t.Fatal("partitioned leader did not stop")
	}
	require.ErrorIs(t, firstEpoch.Err(), context.Canceled, "background work must stop when leadership is lost")
	// The stopped event synchronizes access after the production callback
	// replaces the channel; the partition prevents another acquisition.
	nextFirstSignal := epochSignals[0]
	require.NotEqual(t, firstSignal, nextFirstSignal)
	select {
	case <-nextFirstSignal:
		t.Fatal("new epoch signaled before reacquisition")
	default:
	}
	secondEpoch := awaitEpoch(1, secondSignal)
	cancels[1]()
	select {
	case <-stopped[1]:
	case <-time.After(10 * time.Second):
		t.Fatal("second leader did not stop")
	}
	require.ErrorIs(t, secondEpoch.Err(), context.Canceled)
	partition.Store(false)
	reacquired := awaitEpoch(0, nextFirstSignal)
	require.NoError(t, reacquired.Err(), "original runLoop reacquires without restarting the process")
}
