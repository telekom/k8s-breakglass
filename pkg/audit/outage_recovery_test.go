// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	"k8s.io/utils/ptr"
)

// TCAAS-1614: one panic during a half-open probe must not leave the breaker
// half-open with its only probe slot taken, rejecting every later write.
func TestCircuitBreakerRecoversAfterPanickingHalfOpenProbe(t *testing.T) {
	cb := NewCircuitBreaker("panic-probe", CircuitBreakerConfig{
		FailureThreshold: 1, SuccessThreshold: 2, OpenTimeout: 20 * time.Millisecond, HalfOpenMaxRequests: 1,
	}, zap.NewNop())
	require.Error(t, cb.Execute(context.Background(), func(context.Context) error { return errors.New("down") }))
	require.Equal(t, CircuitOpen, cb.State())
	time.Sleep(30 * time.Millisecond)
	require.PanicsWithValue(t, "kafka-go", func() {
		_ = cb.Execute(context.Background(), func(context.Context) error { panic("kafka-go") })
	})
	// The panic counts as a failed probe and reopens the breaker.
	require.Equal(t, CircuitOpen, cb.State())
	require.Eventually(t, func() bool {
		return cb.Execute(context.Background(), func(context.Context) error { return nil }) == nil &&
			cb.State() == CircuitClosed
	}, time.Second, 25*time.Millisecond)
}

// flakySink fails while down is set and records the IDs it delivered.
type flakySink struct {
	down      atomic.Bool
	delivered atomic.Int64
}

func (s *flakySink) Name() string { return "flaky-outage" }
func (s *flakySink) Close() error { return nil }
func (s *flakySink) Write(ctx context.Context, e *Event) error {
	return s.WriteBatch(ctx, []*Event{e})
}
func (s *flakySink) WriteBatch(_ context.Context, events []*Event) error {
	if s.down.Load() {
		return errors.New("broker unavailable")
	}
	s.delivered.Add(int64(len(events)))
	return nil
}

func outageConfig() QueuedSinkConfig {
	cfg := retryTestConfig()
	cfg.BatchSize = 1
	cfg.BatchTimeout = 10 * time.Millisecond
	cfg.RetryAttempts = 2
	cfg.RetryTimeout = 50 * time.Millisecond
	cfg.CircuitBreakerThreshold = 1
	cfg.DropAfterRetryWindow = false
	return cfg
}

func TestQueuedRetainsEventsBeyondRetryWindowAndRecovers(t *testing.T) {
	sink := &flakySink{}
	sink.down.Store(true)
	cb := NewCircuitBreakerSink(sink, CircuitBreakerConfig{
		FailureThreshold: 2, SuccessThreshold: 2, OpenTimeout: 30 * time.Millisecond, HalfOpenMaxRequests: 1,
	}, zap.NewNop())
	qs := NewQueuedSink(cb, outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	retained := metrics.AuditEventsRetained.WithLabelValues(sink.Name())
	before := testutil.ToFloat64(retained)

	for _, id := range []string{"a", "b", "c"} {
		require.NoError(t, qs.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
	}
	// The outage outlasts the retry window several times over and opens the
	// circuit breaker; nothing is dropped.
	require.Eventually(t, func() bool { return testutil.ToFloat64(retained)-before >= 1 }, time.Second, 5*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, CircuitOpen, cb.Stats().State)
	health := qs.Health()
	require.Zero(t, health.DroppedEvents)
	require.False(t, health.Healthy)
	require.False(t, qs.circuitOpen.Load(), "retention must not open the queue's drop-on-write circuit")
	// A non-sensitive event during the outage is queued, not dropped.
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "d", Type: EventConfigChanged}))

	sink.down.Store(false)
	require.Eventually(t, func() bool { return sink.delivered.Load() == 4 }, 2*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return testutil.ToFloat64(retained) == before }, time.Second, 5*time.Millisecond)
	require.Zero(t, qs.Health().DroppedEvents)
	require.Equal(t, int64(4), qs.Health().ProcessedEvents)
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "e", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return cb.Stats().State == CircuitClosed && qs.Health().Healthy },
		time.Second, 5*time.Millisecond)
}

func TestQueuedDropAfterRetryWindowOptOut(t *testing.T) {
	sink := &flakySink{}
	sink.down.Store(true)
	cfg := outageConfig()
	cfg.DropAfterRetryWindow = true
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	exhausted := metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "retry_exhausted")
	before := testutil.ToFloat64(exhausted)

	require.NoError(t, qs.Write(context.Background(), &Event{ID: "lost", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, before+1, testutil.ToFloat64(exhausted))
	sink.down.Store(false)
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, sink.delivered.Load())
}

func TestQueuedRetentionShutdownCountsRetainedEvents(t *testing.T) {
	sink := &flakySink{}
	sink.down.Store(true)
	qs := NewQueuedSink(sink, outageConfig(), zap.NewNop())
	shutdown := metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "shutdown")
	before := testutil.ToFloat64(shutdown)
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "held", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(sink.Name())) >= 1 },
		time.Second, 5*time.Millisecond)
	start := time.Now()
	require.NoError(t, qs.Close())
	require.Less(t, time.Since(start), time.Second)
	require.Equal(t, before+1, testutil.ToFloat64(shutdown))
	require.Equal(t, int64(1), qs.Health().DroppedEvents)
}

func TestQueuedConfigMapsDropAfterRetryWindow(t *testing.T) {
	require.False(t, queuedConfig(&breakglassv1alpha1.AuditQueueConfig{}).DropAfterRetryWindow)
	require.True(t, queuedConfig(&breakglassv1alpha1.AuditQueueConfig{DropAfterRetryWindow: ptr.To(true)}).DropAfterRetryWindow)
}

// metadataWithoutPartitions answers kafka-go metadata requests with the topic
// but no partitions, which makes kafka-go's LeastBytes balancer panic.
type metadataWithoutPartitions struct{}

func (metadataWithoutPartitions) RoundTrip(_ context.Context, _ net.Addr, req kafka.Request) (protocol.Message, error) {
	md, ok := req.(*metadataAPI.Request)
	if !ok {
		return nil, errors.New("unexpected request")
	}
	return &metadataAPI.Response{Topics: []metadataAPI.ResponseTopic{{Name: md.TopicNames[0]}}}, nil
}

func TestKafkaSinkTurnsWriterPanicIntoError(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "panic", Brokers: []string{"127.0.0.1:1"}, Topic: "audit"}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = metadataWithoutPartitions{}
	t.Cleanup(func() { _ = sink.Close() })
	err = sink.WriteBatch(context.Background(), []*Event{{ID: "x", Type: EventConfigChanged}})
	require.ErrorContains(t, err, "kafka writer panic")
	require.ErrorContains(t, sink.Write(context.Background(), &Event{ID: "y", Type: EventConfigChanged}), "kafka writer panic")
}
