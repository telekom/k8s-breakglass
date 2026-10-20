// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// The authorization webhook emits audit events and reads the audit state for
// every SubjectAccessReview. These tests pin that a stalled AuditConfig reload
// (a secret get that never returns, a sink that never closes) cannot delay it.
const decisionBudget = time.Second

func requireFast(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(decisionBudget):
		t.Fatalf("%s blocked for more than %s while audit I/O stalled", what, decisionBudget)
	}
	t.Logf("%s returned after %s", what, time.Since(start))
}

func logAuditConfig(name string) *breakglassv1alpha1.AuditConfig {
	return &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{Name: name, Type: breakglassv1alpha1.AuditSinkTypeLog}}},
	}
}

func kafkaTLSAuditConfig(name string) *breakglassv1alpha1.AuditConfig {
	return &breakglassv1alpha1.AuditConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: breakglassv1alpha1.AuditConfigSpec{Enabled: true,
			Sinks: []breakglassv1alpha1.AuditSinkConfig{{Name: name, Type: breakglassv1alpha1.AuditSinkTypeKafka,
				Kafka: &breakglassv1alpha1.KafkaSinkSpec{Brokers: []string{"kafka.invalid:9093"}, Topic: "audit",
					TLS: &breakglassv1alpha1.KafkaTLSSpec{Enabled: true,
						CASecretRef: &breakglassv1alpha1.SecretKeySelector{Name: "kafka-client"}}}}}},
	}
}

// stalledSecretClient blocks every Get until the request context ends,
// like an API server that does not answer.
func stalledSecretClient(t *testing.T, entered chan<- struct{}) ctrlclient.Client {
	var once sync.Once
	return fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, _ ctrlclient.WithWatch, _ ctrlclient.ObjectKey, _ ctrlclient.Object, _ ...ctrlclient.GetOption) error {
			once.Do(func() { close(entered) })
			<-ctx.Done()
			return ctx.Err()
		},
	}).Build()
}

func TestReloadStalledOnSecretDoesNotBlockDecisions(t *testing.T) {
	saved := reloadBuildTimeout
	reloadBuildTimeout = 2 * time.Second
	t.Cleanup(func() { reloadBuildTimeout = saved })
	entered := make(chan struct{})
	svc := NewService(stalledSecretClient(t, entered), nil, zap.NewNop(), "test-namespace")
	require.NoError(t, svc.Reload(context.Background(), logAuditConfig("old")))
	// Bounded, so a regression fails the test instead of hanging it.
	t.Cleanup(func() {
		closed := make(chan struct{})
		go func() { _ = svc.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(15 * time.Second):
			t.Error("Close waited for the stalled reload")
		}
	})

	kept := testutil.ToFloat64(metrics.AuditConfigReloads.WithLabelValues("kept_previous"))
	reloaded := make(chan error, 1)
	// The running config is unchanged; a new config's Secret read stalls.
	go func() {
		reloaded <- svc.ReloadMultiple(context.Background(), []*breakglassv1alpha1.AuditConfig{logAuditConfig("old"), kafkaTLSAuditConfig("new")})
	}()
	<-entered

	requireFast(t, "Emit", func() { svc.Emit(context.Background(), &Event{Type: EventAccessDenied}) })
	requireFast(t, "IsEnabled", func() { assert.True(t, svc.IsEnabled()) })
	requireFast(t, "IsConfigured", func() { assert.True(t, svc.IsConfigured()) })
	requireFast(t, "EmitSync", func() { _ = svc.EmitSync(context.Background(), &Event{Type: EventSessionRevoked}) })

	// The reload is bounded and keeps the working pipeline when it fails.
	select {
	case err := <-reloaded:
		require.ErrorContains(t, err, "context deadline exceeded")
		require.ErrorIs(t, err, ErrKeptPreviousPipeline)
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled secret get kept the reload running past its timeout")
	}
	assert.True(t, svc.IsEnabled())
	assert.Equal(t, ConfigurationReady, svc.ConfigurationState())
	assert.InDelta(t, kept+1, testutil.ToFloat64(metrics.AuditConfigReloads.WithLabelValues("kept_previous")), 0)
}

// closeBlockingSink never finishes Close, like a Kafka writer that cannot
// flush to a stopped broker.
type closeBlockingSink struct {
	closing chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *closeBlockingSink) Write(context.Context, *Event) error { return nil }
func (s *closeBlockingSink) Name() string                        { return "close-blocking" }
func (s *closeBlockingSink) Close() error {
	s.once.Do(func() { close(s.closing) })
	<-s.release
	return nil
}

func TestReloadDoesNotWaitForOldSinksUnderTheLock(t *testing.T) {
	svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
	old := &closeBlockingSink{closing: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(old.release); _ = svc.Close() })
	svc.mu.Lock()
	svc.manager = NewManager(old, DefaultManagerConfig(), zap.NewNop())
	svc.sinks = []Sink{old}
	svc.enabled, svc.configurationState = true, ConfigurationReady
	svc.mu.Unlock()

	reloaded := make(chan error, 1)
	go func() { reloaded <- svc.Reload(context.Background(), logAuditConfig("new")) }()
	select {
	case err := <-reloaded:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("reload waited for the old sink to close")
	}
	<-old.closing
	requireFast(t, "Emit", func() { svc.Emit(context.Background(), &Event{Type: EventAccessDenied}) })
	requireFast(t, "IsEnabled", func() { assert.True(t, svc.IsEnabled()) })
}

// writeBlockingSink blocks every write until its context ends, like a Kafka
// broker that is down.
type writeBlockingSink struct{}

func (writeBlockingSink) Write(ctx context.Context, _ *Event) error {
	<-ctx.Done()
	return ctx.Err()
}
func (writeBlockingSink) Close() error                      { return nil }
func (writeBlockingSink) Name() string                      { return "write-blocking" }
func (writeBlockingSink) SupportsSynchronousDelivery() bool { return true }

// Emit runs on the authorization path. With a stalled sink and a full queue it
// must drop a sensitive event at once instead of writing it synchronously
// while the SubjectAccessReview waits.
func TestFullQueueEmitNeverWritesSynchronously(t *testing.T) {
	sink := writeBlockingSink{}
	manager := NewManager(sink, ManagerConfig{QueueSize: 1, WorkerCount: 1, DropOnFull: true,
		WriteTimeout: 3 * time.Second, DirectSinks: []Sink{sink}}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	// The worker blocks on the first event and the second fills the queue.
	manager.Emit(context.Background(), &Event{Type: EventAccessGranted})
	require.Eventually(t, func() bool { return len(manager.asyncQueue) == 0 }, time.Second, 5*time.Millisecond)
	manager.Emit(context.Background(), &Event{Type: EventAccessGranted})
	require.Len(t, manager.asyncQueue, 1)
	// No caller deadline: only Emit itself can keep the decision fast.
	for range 3 {
		requireFast(t, "Emit of a sensitive event on a full queue", func() {
			assert.True(t, manager.Emit(context.Background(), &Event{Type: EventAccessDenied}))
		})
	}
	assert.Equal(t, int64(3), manager.droppedEvents.Load(), "every overflow is counted as dropped")
	assert.Zero(t, manager.sensitiveEventsSyncWritten.Load(), "Emit must not write synchronously")
}

// With dropOnFull false, Emit waits for queue capacity, but never longer than
// the caller's deadline, so a short SubjectAccessReview deadline still bounds
// the authorization path.
func TestFullQueueEmitWithoutDropOnFullEndsAtTheCallerDeadline(t *testing.T) {
	sink := writeBlockingSink{}
	manager := NewManager(sink, ManagerConfig{QueueSize: 1, WorkerCount: 1, DropOnFull: false,
		WriteTimeout: 3 * time.Second, DirectSinks: []Sink{sink}}, zap.NewNop())
	t.Cleanup(func() { _ = manager.Close() })
	manager.Emit(context.Background(), &Event{Type: EventAccessGranted})
	require.Eventually(t, func() bool { return len(manager.asyncQueue) == 0 }, time.Second, 5*time.Millisecond)
	manager.Emit(context.Background(), &Event{Type: EventAccessGranted})
	require.Len(t, manager.asyncQueue, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	assert.True(t, manager.Emit(ctx, &Event{Type: EventAccessDenied}))
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "Emit must wait for queue capacity until the caller deadline")
	assert.Less(t, elapsed, time.Second, "Emit must end at the caller deadline, not at WriteTimeout")
	assert.Equal(t, int64(1), manager.droppedEvents.Load(), "the timed-out event is counted as dropped")
	assert.Zero(t, manager.sensitiveEventsSyncWritten.Load(), "Emit must not write synchronously")
}

// A failed reload must never keep a sink that the admin removed or changed:
// the previous pipeline stays only while its configs are unchanged.
func TestFailedReloadNeverKeepsARemovedOrChangedSink(t *testing.T) {
	newSvc := func() *Service {
		svc := NewService(fake.NewClientBuilder().WithScheme(newServiceTestScheme(t)).Build(), nil, zap.NewNop(), "test-namespace")
		t.Cleanup(func() { _ = svc.Close() })
		running := logAuditConfig("cfg")
		running.Spec.Sinks = append(running.Spec.Sinks, breakglassv1alpha1.AuditSinkConfig{Name: "second", Type: breakglassv1alpha1.AuditSinkTypeLog})
		require.NoError(t, svc.Reload(context.Background(), running))
		require.True(t, svc.IsEnabled())
		return svc
	}
	failing := kafkaTLSAuditConfig("cfg") // same name, sinks replaced by one whose Secret is missing

	t.Run("sink removed and another changed", func(t *testing.T) {
		svc := newSvc()
		err := svc.Reload(context.Background(), failing)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrKeptPreviousPipeline)
		assert.False(t, svc.IsEnabled(), "the old sinks must stop")
		assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
		assert.Error(t, svc.EmitSync(context.Background(), &Event{Type: EventSessionTerminationIntent}), "sensitive events fail closed")
	})
	t.Run("config rejected", func(t *testing.T) {
		svc := newSvc()
		require.Error(t, svc.ReloadMultipleWithAvailability(context.Background(), nil, true))
		assert.False(t, svc.IsEnabled())
		assert.Equal(t, ConfigurationUnavailable, svc.ConfigurationState())
	})
	t.Run("config disabled while another is rejected", func(t *testing.T) {
		svc := newSvc()
		disabled := logAuditConfig("cfg")
		disabled.Spec.Enabled = false
		require.Error(t, svc.ReloadMultipleWithAvailability(context.Background(), []*breakglassv1alpha1.AuditConfig{disabled}, true))
		assert.False(t, svc.IsEnabled())
	})
	t.Run("unchanged config kept while another is rejected", func(t *testing.T) {
		svc := newSvc()
		running := logAuditConfig("cfg")
		running.Spec.Sinks = append(running.Spec.Sinks, breakglassv1alpha1.AuditSinkConfig{Name: "second", Type: breakglassv1alpha1.AuditSinkTypeLog})
		err := svc.ReloadMultipleWithAvailability(context.Background(), []*breakglassv1alpha1.AuditConfig{running}, true)
		require.ErrorIs(t, err, ErrKeptPreviousPipeline)
		assert.True(t, svc.IsEnabled())
		assert.Equal(t, ConfigurationReady, svc.ConfigurationState())
	})
}
