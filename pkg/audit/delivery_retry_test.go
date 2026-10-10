// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
)

type retryBatchSink struct {
	mu       sync.Mutex
	failures int
	calls    [][]string
	times    []time.Time
}

func (s *retryBatchSink) Name() string { return "retry-test" }
func (s *retryBatchSink) Close() error { return nil }
func (s *retryBatchSink) Write(ctx context.Context, event *Event) error {
	return s.WriteBatch(ctx, []*Event{event})
}
func (s *retryBatchSink) WriteBatch(_ context.Context, events []*Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, len(events))
	for i := range events {
		ids[i] = events[i].ID
	}
	s.calls = append(s.calls, ids)
	s.times = append(s.times, time.Now())
	if len(s.calls) <= s.failures {
		return errors.New("broker unavailable")
	}
	return nil
}

func retryTestConfig() QueuedSinkConfig {
	cfg := DefaultQueuedSinkConfig()
	cfg.WorkerCount, cfg.BatchSize = 1, 2
	cfg.BatchTimeout = time.Hour
	cfg.RetryAttempts = 4
	cfg.RetryInitialBackoff = 5 * time.Millisecond
	cfg.RetryMaxBackoff = 20 * time.Millisecond
	cfg.RetryTimeout = time.Second
	return cfg
}

func TestQueuedBatchRetainsIdentityAcrossRetry(t *testing.T) {
	sink := &retryBatchSink{failures: 2}
	qs := NewQueuedSink(sink, retryTestConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	require.NoError(t, qs.WriteBatch(context.Background(), []*Event{{ID: "one"}, {ID: "two"}}))
	require.Eventually(t, func() bool { return qs.Health().ProcessedEvents == 2 }, time.Second, time.Millisecond)
	health := qs.Health()
	require.Equal(t, int64(4), health.FailedEvents)
	require.Zero(t, health.DroppedEvents)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.calls, 3)
	for _, ids := range sink.calls {
		require.Equal(t, []string{"one", "two"}, ids)
	}
	require.GreaterOrEqual(t, sink.times[1].Sub(sink.times[0]), 5*time.Millisecond)
	require.GreaterOrEqual(t, sink.times[2].Sub(sink.times[1]), 10*time.Millisecond)
}

func TestQueuedBatchExhaustionCountsEveryLostEvent(t *testing.T) {
	sink := &retryBatchSink{failures: 1000}
	before := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "retry_exhausted"))
	qs := NewQueuedSink(sink, retryTestConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	require.NoError(t, qs.WriteBatch(context.Background(), []*Event{{ID: "one"}, {ID: "two"}}))
	require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 2 }, time.Second, time.Millisecond)
	require.Equal(t, int64(8), qs.Health().FailedEvents)
	require.Zero(t, qs.Health().ProcessedEvents)
	require.Equal(t, before+2, testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "retry_exhausted")))
}

func TestQueuedRetryShutdownInterruptsBackoff(t *testing.T) {
	sink := &retryBatchSink{failures: 1000}
	cfg := retryTestConfig()
	cfg.RetryInitialBackoff, cfg.RetryMaxBackoff = time.Hour, time.Hour
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	require.NoError(t, qs.WriteBatch(context.Background(), []*Event{{ID: "one"}, {ID: "two"}}))
	require.Eventually(t, func() bool { return qs.Health().FailedEvents == 2 }, time.Second, time.Millisecond)
	start := time.Now()
	require.NoError(t, qs.Close())
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, int64(2), qs.Health().DroppedEvents)
}

func TestQueuedRetryDeadlineBoundsBackoff(t *testing.T) {
	sink := &retryBatchSink{failures: 1000}
	cfg := retryTestConfig()
	cfg.RetryInitialBackoff, cfg.RetryMaxBackoff = time.Second, time.Second
	cfg.RetryTimeout = 10 * time.Millisecond
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	require.NoError(t, qs.WriteBatch(context.Background(), []*Event{{ID: "one"}, {ID: "two"}}))
	require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 2 }, time.Second, time.Millisecond)
	require.Equal(t, int64(2), qs.Health().FailedEvents)
}

func TestQueuedBlockingEnqueueHonorsCallerDeadline(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{})
	sink := newQueuedMockSink("blocking")
	sink.blockFirst, sink.firstStarted = block, started
	cfg := retryTestConfig()
	cfg.QueueSize, cfg.DropOnFull = 1, false
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	t.Cleanup(func() { close(block); require.NoError(t, qs.Close()) })
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "first"}))
	<-started
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "second"}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, qs.Write(ctx, &Event{ID: "third"}), context.DeadlineExceeded)
	require.Equal(t, int64(1), qs.Health().DroppedEvents)
}

func TestPerSinkDeliveryConfiguration(t *testing.T) {
	first := queuedConfig(nil)
	second := queuedConfig(&breakglassv1alpha1.AuditQueueConfig{
		Size: 1000, Workers: 1, DropOnFull: false, RetryAttempts: 3,
		RetryInitialBackoffMillis: 5, RetryMaxBackoffMillis: 10, RetryTimeoutSeconds: 2,
	})
	require.Equal(t, 8, first.RetryAttempts)
	require.Equal(t, 3, second.RetryAttempts)
	require.Equal(t, 5*time.Millisecond, second.RetryInitialBackoff)
	require.Equal(t, 10*time.Millisecond, second.RetryMaxBackoff)
	require.Equal(t, 2*time.Second, second.RetryTimeout)
	ims := NewIsolatedMultiSink([]Sink{newQueuedMockSink("first"), newQueuedMockSink("second")},
		DefaultQueuedSinkConfig(), zap.NewNop(), first, second)
	t.Cleanup(func() { require.NoError(t, ims.Close()) })
	require.Equal(t, first, ims.sinks[0].config)
	require.Equal(t, second, ims.sinks[1].config)
}

func TestKafkaBatchSerializationFailureIsNotSuccessfulDelivery(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Brokers: []string{"localhost:1"}, Topic: "test"}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close()) })
	err = sink.WriteBatch(context.Background(), []*Event{
		{ID: "valid"}, {ID: "invalid", Details: map[string]interface{}{"unsupported": make(chan int)}},
	})
	require.ErrorContains(t, err, "marshal audit batch")
	written, failed, _ := sink.MessageStats()
	require.Zero(t, written)
	require.Equal(t, int64(2), failed)
}

func TestKafkaAsyncFailuresAreObservable(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "async-failure-test", Brokers: []string{"localhost:1"}, Topic: "test", Async: true}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close()) })
	before := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "async_write"))
	sink.writer.Completion([]kafka.Message{{Key: []byte("first")}, {Key: []byte("second")}}, errors.New("delivery failed"))
	_, failed, _ := sink.MessageStats()
	require.Equal(t, int64(2), failed)
	require.False(t, sink.IsConnected())
	require.Equal(t, before+2, testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "async_write")))
	sink.writer.Completion([]kafka.Message{{Key: []byte("third")}}, context.DeadlineExceeded)
	_, lastErr := sink.LastError()
	require.ErrorIs(t, lastErr, context.DeadlineExceeded)
}

func TestTypedQueueConfigPreservesExplicitFalse(t *testing.T) {
	data, err := json.Marshal(breakglassv1alpha1.AuditQueueConfig{DropOnFull: false})
	require.NoError(t, err)
	require.Contains(t, string(data), `"dropOnFull":false`)
}

func TestIsolatedFanoutDoesNotDelayHealthySink(t *testing.T) {
	block, started := make(chan struct{}), make(chan struct{})
	unhealthy, healthy := newQueuedMockSink("backpressure"), newQueuedMockSink("healthy")
	unhealthy.blockFirst, unhealthy.firstStarted = block, started
	cfg := retryTestConfig()
	cfg.QueueSize, cfg.DropOnFull = 1, false
	ims := NewIsolatedMultiSink([]Sink{unhealthy, healthy}, cfg, zap.NewNop())
	t.Cleanup(func() { close(block); require.NoError(t, ims.Close()) })
	require.NoError(t, ims.sinks[0].Write(context.Background(), &Event{ID: "first"}))
	<-started
	require.NoError(t, ims.sinks[0].Write(context.Background(), &Event{ID: "second"}))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = ims.Write(ctx, &Event{ID: "fanout"})
		close(done)
	}()
	require.Eventually(t, func() bool { return healthy.writtenCount.Load() == 1 }, 100*time.Millisecond, time.Millisecond)
	<-done
}

type contextBlockedSink struct{}

func (contextBlockedSink) Name() string { return "context-blocked" }
func (contextBlockedSink) Close() error { return nil }
func (contextBlockedSink) Write(ctx context.Context, _ *Event) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestManagerShutdownBoundsIngressDrain(t *testing.T) {
	cfg := DefaultManagerConfig()
	cfg.QueueSize, cfg.WorkerCount, cfg.WriteTimeout = 100, 1, time.Minute
	manager := NewManager(contextBlockedSink{}, cfg, zap.NewNop())
	for i := range 100 {
		manager.Emit(context.Background(), &Event{ID: fmt.Sprint(i), Type: EventSessionRequested})
	}
	start := time.Now()
	require.NoError(t, manager.Close())
	require.Less(t, time.Since(start), 6*time.Second)
	require.Positive(t, manager.Stats().DroppedEvents)
}
