// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	"k8s.io/utils/ptr"
)

type retryBatchSink struct {
	mu            sync.Mutex
	failures      int
	panicFailures bool
	calls         [][]string
	times         []time.Time
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
		if s.panicFailures {
			panic("broker panic")
		}
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

func TestQueuedFiltersExcludedEventsBeforeLossAccounting(t *testing.T) {
	sink := &retryBatchSink{failures: 1000}
	filtered := NewFilteredSink(NewFilteredSink(sink, EventFilterConfig{
		IncludeEventTypes: []string{string(EventSessionRequested)},
	}), EventFilterConfig{ExcludeUsers: []string{"excluded"}})
	cfg := retryTestConfig()
	cfg.BatchSize = 1
	cfg.RetryAttempts = 1
	qs := NewQueuedSink(filtered, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	for i := 0; i < 99; i++ {
		require.NoError(t, qs.Write(context.Background(), &Event{ID: fmt.Sprint(i),
			Type: EventSessionRequested, Actor: Actor{User: "excluded"}}))
	}
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "excluded-type", Type: EventAccessGranted}))
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "allowed", Type: EventSessionRequested}))
	require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 1 }, time.Second, time.Millisecond)
	require.Equal(t, int64(1), qs.Health().FailedEvents)
	require.Zero(t, qs.Health().ProcessedEvents)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Equal(t, [][]string{{"allowed"}}, sink.calls)
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

func TestQueuedSinkPanicsRetainIdentityAndAccountLoss(t *testing.T) {
	for _, batchSize := range []int{1, 2} {
		for _, failures := range []int{2, 1000} {
			t.Run(fmt.Sprintf("batch-%d/failures-%d", batchSize, failures), func(t *testing.T) {
				sink := &retryBatchSink{failures: failures, panicFailures: true}
				cfg := retryTestConfig()
				cfg.BatchSize = batchSize
				qs := NewQueuedSink(sink, cfg, zap.NewNop())
				t.Cleanup(func() { require.NoError(t, qs.Close()) })
				events := []*Event{{ID: "one"}}
				if batchSize == 2 {
					events = append(events, &Event{ID: "two"})
				}
				before := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "retry_exhausted"))
				require.NoError(t, qs.WriteBatch(context.Background(), events))
				count := int64(len(events))
				if failures < cfg.RetryAttempts {
					require.Eventually(t, func() bool { return qs.Health().ProcessedEvents == count }, time.Second, time.Millisecond)
					require.Zero(t, qs.Health().DroppedEvents)
					require.Equal(t, int64(failures)*count, qs.Health().FailedEvents)
				} else {
					require.Eventually(t, func() bool { return qs.Health().DroppedEvents == count }, time.Second, time.Millisecond)
					require.Equal(t, before+float64(count), testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "retry_exhausted")))
					require.Equal(t, int64(cfg.RetryAttempts)*count, qs.Health().FailedEvents)
				}
				sink.mu.Lock()
				defer sink.mu.Unlock()
				for _, ids := range sink.calls {
					require.Equal(t, len(events), len(ids))
					require.Equal(t, "one", ids[0])
					if len(events) == 2 {
						require.Equal(t, "two", ids[1])
					}
				}
			})
		}
	}
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

func TestQueuedHealthUsesWrappedCircuitStateDuringRetries(t *testing.T) {
	sink := &retryBatchSink{failures: 1000}
	breakerConfig := DefaultCircuitBreakerConfig()
	breakerConfig.FailureThreshold = 2
	breakerConfig.OpenTimeout = time.Hour
	breaker := NewCircuitBreakerSink(sink, breakerConfig, zap.NewNop())
	qs := NewQueuedSink(NewFilteredSink(breaker, EventFilterConfig{}), retryTestConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	require.NoError(t, qs.WriteBatch(context.Background(), []*Event{{ID: "one"}, {ID: "two"}}))
	require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 2 }, time.Second, time.Millisecond)
	require.Equal(t, "open", qs.Health().CircuitState)
	require.True(t, qs.Health().CircuitOpen)
	require.False(t, qs.Health().Healthy)
	require.Equal(t, int(breaker.Stats().ConsecutiveFails), qs.Health().ConsecutiveFails)
	service := &Service{isolatedMultiSink: &IsolatedMultiSink{sinks: []*QueuedSink{qs}}}
	require.Equal(t, "open", service.GetSinkHealth()[0].CircuitState)
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
	require.ErrorIs(t, qs.WriteBatch(ctx, []*Event{{ID: "third"}, {ID: "fourth"}}), context.DeadlineExceeded)
	require.Equal(t, int64(2), qs.Health().DroppedEvents)
}

func TestIsolatedBlockingEnqueuePropagatesOrdinaryDeadline(t *testing.T) {
	block, started := make(chan struct{}), make(chan struct{})
	sink := newQueuedMockSink("isolated-blocking")
	sink.blockFirst, sink.firstStarted = block, started
	cfg := retryTestConfig()
	cfg.QueueSize, cfg.DropOnFull, cfg.BatchSize = 1, false, 1
	isolated := NewIsolatedMultiSink([]Sink{sink}, cfg, zap.NewNop())
	t.Cleanup(func() { close(block); require.NoError(t, isolated.Close()) })
	require.NoError(t, isolated.Write(context.Background(), &Event{ID: "first", Type: EventResourceGet}))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sink worker did not start")
	}
	require.NoError(t, isolated.Write(context.Background(), &Event{ID: "second", Type: EventResourceGet}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, isolated.WriteBatch(ctx, []*Event{{ID: "third", Type: EventResourceGet}}), context.DeadlineExceeded)
	require.Equal(t, int64(1), isolated.Health()[0].DroppedEvents)
}

func TestBlockingEnqueueShutdownCountsAbandonedEvent(t *testing.T) {
	block, started := make(chan struct{}), make(chan struct{})
	sink := newQueuedMockSink("shutdown-enqueue")
	sink.blockFirst, sink.firstStarted = block, started
	cfg := retryTestConfig()
	cfg.QueueSize, cfg.DropOnFull, cfg.BatchSize = 1, false, 1
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "first"}))
	select {
	case <-started:
	case <-time.After(time.Second):
		close(block)
		t.Fatal("sink worker did not start")
	}
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "second"}))
	result := make(chan error, 1)
	go func() { result <- qs.Write(context.Background(), &Event{ID: "abandoned"}) }()
	require.Eventually(t, func() bool {
		if qs.sendMu.TryLock() {
			qs.sendMu.Unlock()
			return false
		}
		return true
	}, time.Second, time.Millisecond)
	closed := make(chan error, 1)
	go func() { closed <- qs.Close() }()
	select {
	case err := <-result:
		require.ErrorContains(t, err, "is closed")
	case <-time.After(time.Second):
		close(block)
		t.Fatal("shutdown did not interrupt blocked enqueue")
	}
	require.Equal(t, int64(1), qs.Health().DroppedEvents)
	close(block)
	require.NoError(t, <-closed)
}

func TestPerSinkDeliveryConfiguration(t *testing.T) {
	first := queuedConfig(nil)
	second := queuedConfig(&breakglassv1alpha1.AuditQueueConfig{
		Size: 1000, Workers: 1, DropOnFull: ptr.To(false), RetryAttempts: 3,
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
	require.ErrorIs(t, err, ErrSerialization)
	written, failed, _ := sink.MessageStats()
	require.Zero(t, written)
	require.Equal(t, int64(2), failed)
}

func TestQueuedSerializationFailureDoesNotRetryOrTripCircuitBreakers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	kafkaSink, err := NewKafkaSink(KafkaSinkConfig{Name: "serialization-kafka", Brokers: []string{"localhost:1"}, Topic: "test"}, zap.NewNop())
	require.NoError(t, err)
	webhook := NewWebhookSink(WebhookSinkConfig{Name: "serialization-webhook", URL: server.URL}, zap.NewNop())
	for _, sink := range []Sink{kafkaSink, webhook} {
		t.Run(sink.Name(), func(t *testing.T) {
			cbCfg := DefaultCircuitBreakerConfig()
			cbCfg.FailureThreshold = 1
			cb := NewCircuitBreakerSink(sink, cbCfg, zap.NewNop())
			cfg := retryTestConfig()
			cfg.CircuitBreakerThreshold = 1
			qs := NewQueuedSink(cb, cfg, zap.NewNop())
			t.Cleanup(func() { require.NoError(t, qs.Close()) })
			before := testutil.ToFloat64(metrics.AuditSinkErrors.WithLabelValues(sink.Name(), "retry"))
			require.NoError(t, qs.WriteBatch(context.Background(), []*Event{
				{ID: "valid"}, {ID: "invalid", Details: map[string]interface{}{"unsupported": make(chan int)}},
			}))
			require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 2 }, time.Second, time.Millisecond)
			require.Equal(t, int64(2), qs.Health().FailedEvents, "serialization is attempted only once")
			require.False(t, qs.circuitOpen.Load())
			require.Zero(t, qs.consecutiveFails.Load())
			require.Equal(t, CircuitClosed, cb.Stats().State)
			require.Zero(t, cb.Stats().TotalFailures)
			require.Zero(t, cb.Stats().ConsecutiveFails)
			require.Equal(t, before, testutil.ToFloat64(metrics.AuditSinkErrors.WithLabelValues(sink.Name(), "retry")))
			droppedBefore := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "serialization"))
			fallbackBefore := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "sync_fallback"))
			require.ErrorIs(t, qs.syncFallback(context.Background(), &Event{
				ID: "invalid-fallback", Details: map[string]interface{}{"unsupported": make(chan int)},
			}), ErrSerialization)
			require.Equal(t, droppedBefore+1, testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "serialization")))
			require.Equal(t, fallbackBefore, testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "sync_fallback")))
			if sink == webhook {
				require.NoError(t, qs.WriteBatch(context.Background(), []*Event{{ID: "next"}, {ID: "healthy"}}))
				require.Eventually(t, func() bool { return qs.Health().ProcessedEvents == 2 }, time.Second, time.Millisecond)
			}
		})
	}
}

func TestKafkaAsyncFailuresAreObservable(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "async-failure-test", Brokers: []string{"localhost:1"}, Topic: "test", Async: true}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sink.Close()) })
	before := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "async_write"))
	processedBefore := testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(sink.Name()))
	qs := NewQueuedSink(NewFilteredSink(NewCircuitBreakerSink(sink, DefaultCircuitBreakerConfig(), zap.NewNop()), EventFilterConfig{}),
		retryTestConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	qs.deliver(2, "batch_write", func(context.Context) error { return nil })
	require.Zero(t, qs.Health().ProcessedEvents, "asynchronous submission is not successful delivery")
	require.Equal(t, processedBefore, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(sink.Name())))
	sink.writer.Completion([]kafka.Message{{Key: []byte("first")}, {Key: []byte("second")}}, errors.New("delivery failed"))
	_, failed, _ := sink.MessageStats()
	require.Equal(t, int64(2), failed)
	require.Zero(t, qs.Health().ProcessedEvents)
	require.Equal(t, int64(2), qs.Health().DroppedEvents)
	require.Equal(t, int64(2), qs.Health().FailedEvents)
	require.False(t, qs.Health().Healthy)
	require.Equal(t, "delivery failed", qs.Health().LastError)
	require.False(t, sink.IsConnected())
	require.Equal(t, before+2, testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "async_write")))
	sink.writer.Completion([]kafka.Message{{Key: []byte("third")}}, context.DeadlineExceeded)
	_, lastErr := sink.LastError()
	require.ErrorIs(t, lastErr, context.DeadlineExceeded)
	sink.writer.Completion([]kafka.Message{{Key: []byte("recovered")}}, nil)
	require.True(t, sink.IsConnected())
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.AuditSinkConnected.WithLabelValues(sink.Name())))
	written, _, _ := sink.MessageStats()
	require.Equal(t, int64(1), written, "only successful completion counts delivery")
	require.Equal(t, int64(1), qs.Health().ProcessedEvents)
	require.True(t, qs.Health().Healthy)
	require.False(t, qs.Health().LastSuccessTime.IsZero())
	require.Equal(t, processedBefore+1, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(sink.Name())))
	sink.writer.Completion([]kafka.Message{{Key: []byte("failed-after-success")}}, errors.New("broker unavailable"))
	require.False(t, qs.Health().Healthy, "an earlier recent success cannot hide a later completion failure")
	require.Equal(t, "broker unavailable", qs.Health().LastError)
	sink.writer.Completion([]kafka.Message{{Key: []byte("recovered-again")}}, nil)
	require.True(t, qs.Health().Healthy)
	require.NoError(t, sink.Close())
	require.False(t, sink.IsConnected())
	require.Zero(t, testutil.ToFloat64(metrics.AuditSinkConnected.WithLabelValues(sink.Name())))
}

func TestKafkaErrorHealthSnapshotIsConsistent(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{
		Name: "concurrent-error-health", Brokers: []string{"localhost:1"}, Topic: "test", Async: true,
	}, zap.NewNop())
	require.NoError(t, err)
	qs := NewQueuedSink(sink, retryTestConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := int64(1); i <= 1000; i++ {
			sink.lastError.Store(kafkaSinkError{
				err: fmt.Errorf("failure-%d", i), at: time.Unix(0, i),
			})
		}
	}()
	for i := 0; i < 1000; i++ {
		at, err := sink.LastError()
		if at.IsZero() {
			require.NoError(t, err)
		} else {
			require.EqualError(t, err, fmt.Sprintf("failure-%d", at.UnixNano()))
		}
		_ = qs.Health()
	}
	<-done
}

func TestManagerIsolatedKafkaHandoffDoesNotCountDelivery(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{
		Name: "manager-async-handoff", Brokers: []string{"localhost:1"}, Topic: "test", Async: true,
	}, zap.NewNop())
	require.NoError(t, err)
	cfg := retryTestConfig()
	cfg.BatchSize = 1
	isolated := NewIsolatedMultiSink([]Sink{sink}, cfg, zap.NewNop())
	manager := NewManager(isolated, ManagerConfig{
		WorkerCount: 1, BatchSize: 1, StatsInterval: -1,
	}, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	aggregateBefore := testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(isolated.Name()))
	deliveredBefore := testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(sink.Name()))
	manager.Emit(context.Background(), &Event{
		ID: "invalid", Type: EventConfigChanged,
		Details: map[string]interface{}{"unsupported": make(chan int)},
	})
	require.Eventually(t, func() bool {
		return manager.Stats().ProcessedEvents == 1 && isolated.Health()[0].DroppedEvents == 1
	}, time.Second, time.Millisecond)
	require.Zero(t, isolated.Health()[0].ProcessedEvents)
	require.Equal(t, aggregateBefore, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(isolated.Name())))
	require.Equal(t, deliveredBefore, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(sink.Name())))
	sink.writer.Completion([]kafka.Message{{Key: []byte("failed")}}, errors.New("broker unavailable"))
	require.Zero(t, isolated.Health()[0].ProcessedEvents)
	require.Equal(t, aggregateBefore, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(isolated.Name())))
	sink.writer.Completion([]kafka.Message{{Key: []byte("completed")}}, nil)
	require.Equal(t, int64(1), isolated.Health()[0].ProcessedEvents)
	require.Equal(t, deliveredBefore+1, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(sink.Name())))
	require.Equal(t, aggregateBefore, testutil.ToFloat64(metrics.AuditEventsProcessed.WithLabelValues(isolated.Name())))
}

func TestTypedQueueConfigPreservesExplicitFalse(t *testing.T) {
	data, err := json.Marshal(breakglassv1alpha1.AuditQueueConfig{DropOnFull: ptr.To(false)})
	require.NoError(t, err)
	require.Contains(t, string(data), `"dropOnFull":false`)
	data, err = json.Marshal(breakglassv1alpha1.AuditQueueConfig{Size: 10000})
	require.NoError(t, err)
	require.NotContains(t, string(data), `"dropOnFull"`)
	require.True(t, queuedConfig(&breakglassv1alpha1.AuditQueueConfig{Size: 10000}).DropOnFull)
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

func TestFilteredAndSampledEventsSkipResourceEnrichment(t *testing.T) {
	for _, filtered := range []bool{true, false} {
		cfg := DefaultManagerConfig()
		cfg.Enrich = func(context.Context, *Event) { t.Error("discarded event must not perform resource reads") }
		if filtered {
			cfg.ExcludeEventTypes = []string{string(EventResourceList)}
		} else {
			cfg.SampleRate, cfg.sampleRateConfigured = 0, true
			cfg.HighVolumeEventTypes = []EventType{EventResourceList}
		}

		manager := NewManager(newQueuedMockSink("filtered"), cfg, zap.NewNop())
		manager.Emit(context.Background(), &Event{Type: EventResourceList})
		require.NoError(t, manager.Close())
	}
}

func TestExpiredShutdownDoesNotInvokeSinkForBacklog(t *testing.T) {
	sink := newQueuedMockSink("expired-shutdown")
	qs := &QueuedSink{sink: sink, logger: zap.NewNop(), config: retryTestConfig(), queue: make(chan *Event, 100)}
	for i := range 100 {
		qs.queue <- &Event{ID: fmt.Sprint(i)}
	}
	close(qs.queue)
	qs.shutdownDeadline.Store(time.Now().Add(-time.Second).UnixNano())
	require.True(t, qs.dropShutdownBacklog(0))
	require.Equal(t, int64(100), qs.droppedEvents.Load())
	qs.deliver(1, "write", func(context.Context) error { t.Error("expired shutdown must not call sink"); return nil })
	require.Zero(t, sink.writeCount.Load())
	require.Equal(t, int64(101), qs.droppedEvents.Load())
}
