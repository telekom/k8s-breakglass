// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/protocol"
	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
	produceAPI "github.com/segmentio/kafka-go/protocol/produce"
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
	// A panic is excluded from the breaker's counts: it neither closes nor
	// reopens the breaker, and the probe slot is free for the next write.
	require.Equal(t, CircuitHalfOpen, cb.State())
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
	// Retained retries count only as error_type="retry".
	failedBefore := qs.Health().FailedEvents
	retries := metrics.AuditSinkErrors.WithLabelValues(sink.Name(), "retry")
	retriesBefore := testutil.ToFloat64(retries)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, failedBefore, qs.Health().FailedEvents)
	require.Greater(t, testutil.ToFloat64(retries), retriesBefore)
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
	require.NotErrorIs(t, err, errSinkPanic, "the balancer panic stays retryable")
	require.ErrorContains(t, sink.Write(context.Background(), &Event{ID: "y", Type: EventConfigChanged}), "kafka writer panic")
}

// A payload the endpoint rejects (HTTP 413) must not be retained forever and
// block later events: it is dropped as "rejected" without tripping the breaker.
func TestQueuedRejectedPayloadDoesNotBlockLaterEvents(t *testing.T) {
	var delivered atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "too-big") {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		delivered.Add(1)
	}))
	t.Cleanup(server.Close)
	webhook := NewWebhookSink(WebhookSinkConfig{Name: "rejecting", URL: server.URL}, zap.NewNop())
	cb := NewCircuitBreakerSink(webhook, CircuitBreakerConfig{FailureThreshold: 1, OpenTimeout: time.Hour}, zap.NewNop())
	qs := NewQueuedSink(cb, outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	rejected := metrics.AuditEventsDropped.WithLabelValues("rejecting", "rejected")
	before := testutil.ToFloat64(rejected)

	require.NoError(t, qs.Write(context.Background(), &Event{ID: "too-big", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return qs.Health().DroppedEvents == 1 }, time.Second, 5*time.Millisecond)
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "fine", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return delivered.Load() == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, before+1, testutil.ToFloat64(rejected))
	require.Equal(t, CircuitClosed, cb.Stats().State)
}

func TestKafkaRejectedClassification(t *testing.T) {
	require.False(t, kafkaRejected(nil))
	require.False(t, kafkaRejected(errors.New("connection refused")))
	require.True(t, kafkaRejected(kafka.MessageTooLargeError{}))
	require.True(t, kafkaRejected(kafka.WriteErrors{nil, kafka.MessageSizeTooLarge}))
	require.False(t, kafkaRejected(kafka.WriteErrors{kafka.MessageSizeTooLarge, kafka.LeaderNotAvailable}))
	require.False(t, kafkaRejected(kafka.WriteErrors{nil}))
	require.True(t, kafkaRejected(kafka.InvalidRecord))
	require.False(t, kafkaRejected(kafka.InvalidMessage))
	require.False(t, kafkaRejected(kafka.WriteErrors{kafka.InvalidMessage}))
}

// batchLimitSink rejects batches above limit (like HTTP 413 or Kafka
// MESSAGE_TOO_LARGE), rejects "too-big" on its own, and panics on "boom".
type batchLimitSink struct {
	limit     int
	rejectErr error
	mu        sync.Mutex
	delivered []string
}

func (s *batchLimitSink) Name() string { return "batch-limit" }
func (s *batchLimitSink) Close() error { return nil }
func (s *batchLimitSink) Write(ctx context.Context, e *Event) error {
	return s.WriteBatch(ctx, []*Event{e})
}
func (s *batchLimitSink) WriteBatch(_ context.Context, events []*Event) error {
	for _, e := range events {
		if e.ID == "boom" {
			panic("deterministic sink bug")
		}
	}
	if len(events) > s.limit || slices.ContainsFunc(events, func(e *Event) bool { return e.ID == "too-big" }) {
		return s.rejectErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		s.delivered = append(s.delivered, e.ID)
	}
	return nil
}

func (s *batchLimitSink) ids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.delivered)
}

func splitConfig(batch int) QueuedSinkConfig {
	cfg := outageConfig()
	cfg.BatchSize = batch
	cfg.BatchTimeout = time.Hour
	return cfg
}

// A batch-size rejection (HTTP 413, Kafka MESSAGE_TOO_LARGE or a writer-side
// MessageTooLargeError) halves the batch until it fits; only an event that is
// rejected on its own is dropped.
func TestQueuedSplitsRejectedBatches(t *testing.T) {
	for name, rejectErr := range map[string]error{
		"webhook-413":       webhookStatusError("http://collector", http.StatusRequestEntityTooLarge),
		"kafka-writer":      fmt.Errorf("%w: %w", ErrRejected, kafka.MessageTooLargeError{}),
		"kafka-broker":      fmt.Errorf("%w: %w", ErrRejected, kafka.WriteErrors{kafka.MessageSizeTooLarge}),
		"kafka-record-list": fmt.Errorf("%w: %w", ErrRejected, kafka.RecordListTooLarge),
	} {
		t.Run(name, func(t *testing.T) {
			sink := &batchLimitSink{limit: 2, rejectErr: rejectErr}
			qs := NewQueuedSink(sink, splitConfig(5), zap.NewNop())
			t.Cleanup(func() { require.NoError(t, qs.Close()) })
			ids := []string{"a", "b", "too-big", "c", "d"}
			for _, id := range ids {
				require.NoError(t, qs.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
			}
			require.Eventually(t, func() bool { return len(sink.ids()) == 4 && qs.Health().DroppedEvents == 1 },
				time.Second, 5*time.Millisecond)
			require.ElementsMatch(t, []string{"a", "b", "c", "d"}, sink.ids())
		})
	}
}

// A deterministic panic is retried within the window, then treated as
// permanent: the batch is split, the panicking event dropped as "panic" and
// the others delivered, even in the default retention mode.
func TestQueuedDeterministicPanicIsNotRetainedForever(t *testing.T) {
	sink := &batchLimitSink{limit: 10}
	qs := NewQueuedSink(sink, splitConfig(3), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	panics := metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "panic")
	before := testutil.ToFloat64(panics)
	for _, id := range []string{"a", "boom", "b"} {
		require.NoError(t, qs.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
	}
	require.Eventually(t, func() bool { return len(sink.ids()) == 2 && qs.Health().DroppedEvents == 1 },
		2*time.Second, 5*time.Millisecond)
	require.ElementsMatch(t, []string{"a", "b"}, sink.ids())
	require.Equal(t, before+1, testutil.ToFloat64(panics))
	require.Zero(t, testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(sink.Name())))
}

func TestWebhookStatusClassification(t *testing.T) {
	for status, rejected := range map[int]bool{
		http.StatusBadRequest: false, http.StatusUnauthorized: false, http.StatusNotFound: false,
		http.StatusRequestEntityTooLarge: true, http.StatusUnprocessableEntity: true,
		http.StatusTooManyRequests: false, http.StatusServiceUnavailable: false,
	} {
		require.Equal(t, rejected, errors.Is(webhookStatusError("http://collector", status), ErrRejected), "status %d", status)
	}
}

func TestKafkaWriterPrecheckRejectsOversizedRecord(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "oversized", Brokers: []string{"127.0.0.1:1"}, Topic: "audit"}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })
	sink.writer.BatchBytes = 512
	err = sink.WriteBatch(context.Background(), []*Event{
		{ID: "small", Type: EventConfigChanged},
		{ID: "big", Type: EventConfigChanged, Details: map[string]interface{}{"blob": strings.Repeat("x", 1024)}},
	})
	require.ErrorIs(t, err, ErrRejected)
	var tooLarge kafka.MessageTooLargeError
	require.ErrorAs(t, err, &tooLarge)
}

// runtime.Goexit inside a write (t.FailNow in a fake sink) must release the
// probe slot without panicking with a nil value.
func TestCircuitBreakerHandlesGoexitInHalfOpenProbe(t *testing.T) {
	cb := NewCircuitBreaker("goexit-probe", CircuitBreakerConfig{
		FailureThreshold: 1, SuccessThreshold: 1, OpenTimeout: 20 * time.Millisecond, HalfOpenMaxRequests: 1,
	}, zap.NewNop())
	require.Error(t, cb.Execute(context.Background(), func(context.Context) error { return errors.New("down") }))
	time.Sleep(30 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cb.Execute(context.Background(), func(context.Context) error { runtime.Goexit(); return nil })
	}()
	<-done
	require.Equal(t, CircuitOpen, cb.State())
	require.Eventually(t, func() bool {
		return cb.Execute(context.Background(), func(context.Context) error { return nil }) == nil &&
			cb.State() == CircuitClosed
	}, time.Second, 25*time.Millisecond)
}

// A reload during an outage hands the events the old pipeline holds to the
// same-named sink of the new pipeline instead of dropping them.
func TestReloadHandsHeldEventsToTheReplacementPipeline(t *testing.T) {
	down := &flakySink{}
	down.down.Store(true)
	old := NewIsolatedMultiSink([]Sink{down}, outageConfig(), zap.NewNop())
	for _, id := range []string{"a", "b", "c"} {
		require.NoError(t, old.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
	}
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(down.Name())) >= 1
	}, time.Second, 5*time.Millisecond)

	up := &flakySink{}
	next := NewIsolatedMultiSink([]Sink{up}, outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	old.handOver(next)
	require.NoError(t, old.Close())
	require.Zero(t, old.sinks[0].Health().DroppedEvents)
	require.Eventually(t, func() bool { return up.delivered.Load() == 3 }, time.Second, 5*time.Millisecond)
}

// funcSink delegates batch writes to a replaceable function.
type funcSink struct {
	name string
	fn   atomic.Pointer[func([]*Event) error]
}

func newFuncSink(name string, fn func([]*Event) error) *funcSink {
	s := &funcSink{name: name}
	s.fn.Store(&fn)
	return s
}
func (s *funcSink) set(fn func([]*Event) error) { s.fn.Store(&fn) }
func (s *funcSink) Name() string                { return s.name }
func (s *funcSink) Close() error                { return nil }
func (s *funcSink) Write(ctx context.Context, e *Event) error {
	return s.WriteBatch(ctx, []*Event{e})
}
func (s *funcSink) WriteBatch(_ context.Context, events []*Event) error {
	return (*s.fn.Load())(events)
}

// A retained batch that is split counts only its still undelivered halves.
func TestRetainedGaugeCountsOnlyUndeliveredHalvesAfterSplit(t *testing.T) {
	sink := newFuncSink("retained-split", func([]*Event) error { return errors.New("broker unavailable") })
	qs := NewQueuedSink(sink, splitConfig(4), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	retained := metrics.AuditEventsRetained.WithLabelValues(sink.Name())
	before := testutil.ToFloat64(retained)
	for _, id := range []string{"a", "b", "c", "d"} {
		require.NoError(t, qs.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
	}
	require.Eventually(t, func() bool { return testutil.ToFloat64(retained) == before+4 }, time.Second, 5*time.Millisecond)
	// The broker is back but rejects batches above two records, and the
	// partition of c and d is still unavailable.
	sink.set(func(events []*Event) error {
		if len(events) > 2 {
			return fmt.Errorf("%w: %w", ErrRejected, kafka.RecordListTooLarge)
		}
		if events[0].ID == "c" {
			return kafka.LeaderNotAvailable
		}
		return nil
	})
	require.Eventually(t, func() bool { return qs.Health().ProcessedEvents == 2 }, time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return testutil.ToFloat64(retained) == before+2 }, time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, before+2, testutil.ToFloat64(retained))
	require.Zero(t, qs.Health().DroppedEvents)
}

// Reloads A -> B -> C where the idle B closes while A still holds events:
// A's events reach C through B instead of being dropped by the closed B.
func TestHandOverFollowsReloadChain(t *testing.T) {
	down := &flakySink{}
	down.down.Store(true)
	a := NewIsolatedMultiSink([]Sink{down}, outageConfig(), zap.NewNop())
	require.NoError(t, a.Write(context.Background(), &Event{ID: "held", Type: EventConfigChanged}))
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(down.Name())) >= 1
	}, time.Second, 5*time.Millisecond)
	b := NewIsolatedMultiSink([]Sink{&flakySink{}}, outageConfig(), zap.NewNop())
	up := &flakySink{}
	c := NewIsolatedMultiSink([]Sink{up}, outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	a.handOver(b)
	b.handOver(c)
	require.NoError(t, b.Close())
	require.NoError(t, a.Close())
	require.Zero(t, a.sinks[0].Health().DroppedEvents)
	require.Zero(t, b.sinks[0].Health().DroppedEvents)
	require.Eventually(t, func() bool { return up.delivered.Load() == 1 }, time.Second, 5*time.Millisecond)
}

// Sink names are unique only within one AuditConfig: each backlog goes to
// the replacement with the same AuditConfig and sink name.
func TestHandOverMatchesAuditConfigAndSinkName(t *testing.T) {
	failing := func([]*Event) error { return errors.New("broker unavailable") }
	var toA, toB atomic.Int64
	oldA, oldB := newFuncSink("events", failing), newFuncSink("events", failing)
	old := NewIsolatedMultiSink([]Sink{oldA, oldB}, outageConfig(), zap.NewNop())
	old.sinks[0].owner, old.sinks[1].owner = "config-a/kafka", "config-b/kafka"
	require.NoError(t, old.sinks[0].Write(context.Background(), &Event{ID: "for-a", Type: EventConfigChanged}))
	require.NoError(t, old.sinks[1].Write(context.Background(), &Event{ID: "for-b", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return old.sinks[0].Health().FailedEvents > 0 && old.sinks[1].Health().FailedEvents > 0 },
		time.Second, 5*time.Millisecond)

	newB := newFuncSink("events", func(events []*Event) error {
		for _, e := range events {
			if e.ID != "for-b" {
				t.Errorf("event %s reached the sink of config-b", e.ID)
			}
			toB.Add(1)
		}
		return nil
	})
	newA := newFuncSink("events", func(events []*Event) error {
		for _, e := range events {
			if e.ID != "for-a" {
				t.Errorf("event %s reached the sink of config-a", e.ID)
			}
			toA.Add(1)
		}
		return nil
	})
	next := NewIsolatedMultiSink([]Sink{newB, newA}, outageConfig(), zap.NewNop())
	next.sinks[0].owner, next.sinks[1].owner = "config-b/kafka", "config-a/kafka"
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	old.handOver(next)
	require.NoError(t, old.Close())
	require.Eventually(t, func() bool { return toA.Load() == 1 && toB.Load() == 1 }, time.Second, 5*time.Millisecond)
}

// While the first half of a split retained batch is retained again, the
// second half waiting for its turn still counts as retained.
func TestRetainedGaugeKeepsPendingSiblingCounted(t *testing.T) {
	sink := newFuncSink("retained-sibling", func([]*Event) error { return errors.New("broker unavailable") })
	qs := NewQueuedSink(sink, splitConfig(4), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	retained := metrics.AuditEventsRetained.WithLabelValues(sink.Name())
	before := testutil.ToFloat64(retained)
	for _, id := range []string{"a", "b", "c", "d"} {
		require.NoError(t, qs.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
	}
	require.Eventually(t, func() bool { return testutil.ToFloat64(retained) == before+4 }, time.Second, 5*time.Millisecond)
	// Batches above two records are rejected and a and b stay unavailable.
	unavailable := func(events []*Event) error {
		if len(events) > 2 {
			return fmt.Errorf("%w: %w", ErrRejected, kafka.RecordListTooLarge)
		}
		if events[0].ID == "a" {
			return kafka.LeaderNotAvailable
		}
		return nil
	}
	sink.set(unavailable)
	require.Eventually(t, func() bool { return qs.Health().FailedEvents >= 3 }, time.Second, 5*time.Millisecond)
	time.Sleep(150 * time.Millisecond) // the first half is retained again
	require.Equal(t, before+4, testutil.ToFloat64(retained), "c and d still wait behind a and b")
	sink.set(func([]*Event) error { return nil })
	require.Eventually(t, func() bool {
		return qs.Health().ProcessedEvents == 4 && testutil.ToFloat64(retained) == before
	}, 2*time.Second, 5*time.Millisecond)
	require.Zero(t, qs.Health().DroppedEvents)
}

// stalledProduce answers metadata at once but holds every Produce request
// until release is closed, like a broker whose partition leader hangs.
type stalledProduce struct {
	produced atomic.Int64
	release  chan struct{}
}

func (s *stalledProduce) RoundTrip(ctx context.Context, _ net.Addr, req kafka.Request) (protocol.Message, error) {
	switch r := req.(type) {
	case *metadataAPI.Request:
		return &metadataAPI.Response{
			Brokers: []metadataAPI.ResponseBroker{{NodeID: 1, Host: "127.0.0.1", Port: 1}},
			Topics: []metadataAPI.ResponseTopic{{Name: r.TopicNames[0],
				Partitions: []metadataAPI.ResponsePartition{{PartitionIndex: 0, LeaderID: 1}}}},
		}, nil
	case *produceAPI.Request:
		s.produced.Add(1)
		select {
		case <-s.release:
			return &produceAPI.Response{Topics: []produceAPI.ResponseTopic{{Topic: r.Topics[0].Topic,
				Partitions: []produceAPI.ResponsePartition{{Partition: 0}}}}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("unexpected request")
}

// A write cancelled by its context leaves its records inside kafka-go until
// the writer's own produce attempt completes. Retries during that time must
// not submit more copies: the sink refuses them until the records complete.
func TestKafkaSinkBoundsRecordsPendingInTheWriter(t *testing.T) {
	transport := &stalledProduce{release: make(chan struct{})}
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "stalled", Brokers: []string{"127.0.0.1:1"}, Topic: "audit", BatchSize: 1}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = transport
	t.Cleanup(func() { close(transport.release); _ = sink.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	require.ErrorIs(t, sink.WriteBatch(ctx, []*Event{{ID: "a", Type: EventConfigChanged}}), context.DeadlineExceeded)
	cancel()
	require.Equal(t, int64(1), sink.pending.Load())
	for range 20 {
		retryCtx, retryCancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		require.ErrorIs(t, sink.Write(retryCtx, &Event{ID: "a", Type: EventConfigChanged}), errKafkaWriterBusy)
		retryCancel()
	}
	require.Eventually(t, func() bool { return transport.produced.Load() >= 1 }, time.Second, 5*time.Millisecond)
	require.LessOrEqual(t, transport.produced.Load(), int64(1), "no copies submitted while the first write is pending")
}

// Concurrent writers that all time out while the broker stalls still leave
// at most one batch inside kafka-go: the slot is reserved atomically.
func TestKafkaSinkAdmitsOneWriteAtATime(t *testing.T) {
	transport := &stalledProduce{release: make(chan struct{})}
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "stalled-concurrent", Brokers: []string{"127.0.0.1:1"}, Topic: "audit", BatchSize: 1}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = transport
	t.Cleanup(func() { close(transport.release); _ = sink.Close() })
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_ = sink.Write(ctx, &Event{ID: fmt.Sprint(i), Type: EventConfigChanged})
		}()
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int64(1), transport.produced.Load())
	require.Equal(t, int64(1), sink.pending.Load())
}

// A write that overlaps a healthy write in progress waits for it within its
// own deadline instead of failing at once, so EmitSync gets its receipt.
func TestKafkaSinkWaitsForAHealthyWriteInProgress(t *testing.T) {
	transport := &stalledProduce{release: make(chan struct{})}
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "healthy-overlap", Brokers: []string{"127.0.0.1:1"}, Topic: "audit", BatchSize: 1}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = transport
	t.Cleanup(func() { _ = sink.Close() })
	first := make(chan error, 1)
	go func() { first <- sink.Write(context.Background(), &Event{ID: "background", Type: EventConfigChanged}) }()
	require.Eventually(t, func() bool { return transport.produced.Load() == 1 }, time.Second, 5*time.Millisecond)
	second := make(chan error, 1)
	go func() { second <- sink.Write(context.Background(), &Event{ID: "receipt", Type: EventAccessDenied}) }()
	time.Sleep(20 * time.Millisecond)
	close(transport.release) // the broker answers
	require.NoError(t, <-first)
	require.NoError(t, <-second)
	require.Zero(t, sink.pending.Load())
}

// Records kafka-go never submitted (here: a metadata error before
// balancing) are not counted as pending.
func TestKafkaSinkReleasesRecordsThatWereNeverSubmitted(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "unsubmitted", Brokers: []string{"127.0.0.1:1"}, Topic: "audit"}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = metadataWithoutPartitions{}
	t.Cleanup(func() { _ = sink.Close() })
	require.Error(t, sink.Write(context.Background(), &Event{ID: "x", Type: EventConfigChanged}))
	require.Zero(t, sink.pending.Load())
	require.Empty(t, sink.slot, "the write slot is free again")
}

// failingTransport fails every request, like an unreachable broker.
type failingTransport struct{}

func (failingTransport) RoundTrip(context.Context, net.Addr, kafka.Request) (protocol.Message, error) {
	return nil, errors.New("connection refused")
}

// Retained retries reaching the Kafka writer count only as
// error_type="retry", not again under the sink's classified error type.
func TestRetainedKafkaRetriesCountOnlyAsRetry(t *testing.T) {
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "retained-kafka", Brokers: []string{"127.0.0.1:1"}, Topic: "audit"}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = failingTransport{}
	qs := NewQueuedSink(sink, outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "held", Type: EventConfigChanged}))
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(sink.Name())) == 1
	}, time.Second, 5*time.Millisecond)
	classified := func() float64 {
		return testutil.ToFloat64(metrics.AuditSinkErrors.WithLabelValues(sink.Name(), "other")) +
			testutil.ToFloat64(metrics.AuditSinkErrors.WithLabelValues(sink.Name(), "network"))
	}
	retries := metrics.AuditSinkErrors.WithLabelValues(sink.Name(), "retry")
	classifiedBefore, retriesBefore := classified(), testutil.ToFloat64(retries)
	require.Eventually(t, func() bool { return testutil.ToFloat64(retries) >= retriesBefore+3 }, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, classifiedBefore, classified())
}

// A reload that keeps a sink's name but changes its type (Kafka to log)
// must not move the Kafka backlog into the log sink.
func TestHandOverNeverCrossesSinkTypes(t *testing.T) {
	failing := newFuncSink("events", func([]*Event) error { return errors.New("broker unavailable") })
	old := NewIsolatedMultiSink([]Sink{failing}, outageConfig(), zap.NewNop())
	old.sinks[0].owner = "config/kafka"
	require.NoError(t, old.Write(context.Background(), &Event{ID: "kafka-only", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return old.sinks[0].Health().FailedEvents > 0 }, time.Second, 5*time.Millisecond)
	var received atomic.Int64
	next := NewIsolatedMultiSink([]Sink{newFuncSink("events", func(events []*Event) error {
		received.Add(int64(len(events)))
		return nil
	})}, outageConfig(), zap.NewNop())
	next.sinks[0].owner = "config/log"
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	old.handOver(next)
	require.NoError(t, old.Close())
	time.Sleep(50 * time.Millisecond)
	require.Zero(t, received.Load())
	require.Equal(t, int64(1), old.sinks[0].Health().DroppedEvents)
}

// All hand-overs of one retiring sink share a single deadline, so several
// worker or retained batches cannot each wait a full write timeout for a
// replacement whose queue stays full.
func TestQueuedHandOverSharesOneDeadline(t *testing.T) {
	cfg := outageConfig()
	cfg.WriteTimeout = 200 * time.Millisecond
	old := NewQueuedSink(&flakySink{}, cfg, zap.NewNop())
	full := outageConfig()
	full.QueueSize, full.WorkerCount, full.DropOnFull = 1, 1, false
	full.WriteTimeout = time.Minute
	blocked := newFuncSink("handover-full", func([]*Event) error { select {} })
	next := NewQueuedSink(blocked, full, zap.NewNop())
	old.HandOver(next)
	start := time.Now()
	for i := range 5 {
		old.shutdownDrop([]*Event{{ID: fmt.Sprint(i), Type: EventConfigChanged}, {ID: fmt.Sprint(i, "b"), Type: EventConfigChanged}})
	}
	require.Less(t, time.Since(start), time.Second, "one handover budget, not one write timeout per batch")
	require.Positive(t, next.Health().DroppedEvents, "what did not fit is counted by the replacement")
}

func kafkaSinkConfig(brokers []string, topic, secret string) breakglassv1alpha1.AuditSinkConfig {
	return breakglassv1alpha1.AuditSinkConfig{Name: "events", Type: breakglassv1alpha1.AuditSinkTypeKafka,
		Kafka: &breakglassv1alpha1.KafkaSinkSpec{Brokers: brokers, Topic: topic,
			TLS: &breakglassv1alpha1.KafkaTLSSpec{Enabled: true,
				CASecretRef: &breakglassv1alpha1.SecretKeySelector{Name: secret, Namespace: "breakglass-system"}}}}
}

// The handover key includes the destination: a retargeted sink gets a new
// key, while a rotated Secret (same reference) or reordered brokers keep it.
func TestHandOverKeyFollowsTheDestination(t *testing.T) {
	base := handOverKey("config", kafkaSinkConfig([]string{"a:9093", "b:9093"}, "audit", "kafka-ca"))
	require.Equal(t, base, handOverKey("config", kafkaSinkConfig([]string{"b:9093", "a:9093"}, "audit", "kafka-ca")))
	for name, other := range map[string]string{
		"brokers": handOverKey("config", kafkaSinkConfig([]string{"c:9093"}, "audit", "kafka-ca")),
		"topic":   handOverKey("config", kafkaSinkConfig([]string{"a:9093", "b:9093"}, "audit-v2", "kafka-ca")),
		"secret":  handOverKey("config", kafkaSinkConfig([]string{"a:9093", "b:9093"}, "audit", "other-ca")),
		"config":  handOverKey("other", kafkaSinkConfig([]string{"a:9093", "b:9093"}, "audit", "kafka-ca")),
	} {
		require.NotEqual(t, base, other, name)
	}
	// An unused block of another type does not decide the destination.
	withUnusedKafka := func(url string) string {
		return handOverKey("config", breakglassv1alpha1.AuditSinkConfig{Name: "events", Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: url},
			Kafka:   &breakglassv1alpha1.KafkaSinkSpec{Brokers: []string{"a:9093"}, Topic: "audit"}})
	}
	require.NotEqual(t, withUnusedKafka("https://a/events"), withUnusedKafka("https://b/events"))
	webhook := func(url, batchURL string) string {
		return handOverKey("config", breakglassv1alpha1.AuditSinkConfig{Name: "events", Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: url, BatchURL: batchURL}})
	}
	require.Equal(t, webhook("https://a/events", ""), webhook("https://a/events", ""))
	require.NotEqual(t, webhook("https://a/events", ""), webhook("https://b/events", ""))
	require.NotEqual(t, webhook("https://a/events", ""), webhook("https://a/events", "https://a/batch"))
	withHeaders := func(headers map[string]string) string {
		return handOverKey("config", breakglassv1alpha1.AuditSinkConfig{Name: "events", Type: breakglassv1alpha1.AuditSinkTypeWebhook,
			Webhook: &breakglassv1alpha1.WebhookSinkSpec{URL: "https://shared/events", Headers: headers}})
	}
	// A header that selects the tenant on a shared endpoint is part of the
	// destination; header order is not.
	require.NotEqual(t, withHeaders(map[string]string{"X-Tenant": "a"}), withHeaders(map[string]string{"X-Tenant": "b"}))
	require.NotEqual(t, withHeaders(nil), withHeaders(map[string]string{"X-Tenant": "a"}))
	require.Equal(t, withHeaders(map[string]string{"X-Tenant": "a", "X-Stream": "audit"}),
		withHeaders(map[string]string{"X-Stream": "audit", "X-Tenant": "a"}))
	// An empty batch URL means "use the URL": equivalent configurations
	// keep the handover.
	require.Equal(t, webhook("https://a/events", ""), webhook("https://a/events", "https://a/events"))
}

// End to end through the service: a reload that only rotates a sink Secret
// hands the backlog over; a reload that retargets the sink drops it as
// "shutdown" instead of delivering it to the new destination.
func TestReloadHandsOverOnRotationButNotOnRetarget(t *testing.T) {
	for name, tc := range map[string]struct {
		next     breakglassv1alpha1.AuditSinkConfig
		handOver bool
	}{
		"rotated-secret": {kafkaSinkConfig([]string{"a:9093"}, "audit", "kafka-ca"), true},
		"retargeted":     {kafkaSinkConfig([]string{"a:9093"}, "audit-elsewhere", "kafka-ca"), false},
	} {
		t.Run(name, func(t *testing.T) {
			held := &flakySink{}
			held.down.Store(true)
			old := NewIsolatedMultiSink([]Sink{held}, outageConfig(), zap.NewNop())
			old.sinks[0].owner = handOverKey("config", kafkaSinkConfig([]string{"a:9093"}, "audit", "kafka-ca"))
			require.NoError(t, old.Write(context.Background(), &Event{ID: "held", Type: EventConfigChanged}))
			require.Eventually(t, func() bool { return old.sinks[0].Health().FailedEvents > 0 }, time.Second, 5*time.Millisecond)
			up := &flakySink{}
			next := NewIsolatedMultiSink([]Sink{up}, outageConfig(), zap.NewNop())
			next.sinks[0].owner = handOverKey("config", tc.next)
			t.Cleanup(func() { require.NoError(t, next.Close()) })
			old.handOver(next)
			require.NoError(t, old.Close())
			if tc.handOver {
				require.Eventually(t, func() bool { return up.delivered.Load() == 1 }, time.Second, 5*time.Millisecond)
				require.Zero(t, old.sinks[0].Health().DroppedEvents)
				return
			}
			time.Sleep(50 * time.Millisecond)
			require.Zero(t, up.delivered.Load())
			require.Equal(t, int64(1), old.sinks[0].Health().DroppedEvents)
		})
	}
}

// A late handover whose shared deadline has already passed still enqueues
// into free capacity of a blocking (dropOnFull: false) replacement.
func TestLateHandOverUsesFreeCapacity(t *testing.T) {
	cfg := outageConfig()
	old := NewQueuedSink(&flakySink{}, cfg, zap.NewNop())
	nextCfg := outageConfig()
	// No worker drains during the handover and capacity exceeds the batch,
	// so every event must be enqueued. Without the non-blocking first send,
	// each of the 1000 events has an even chance of a timeout.
	nextCfg.QueueSize, nextCfg.DropOnFull, nextCfg.BatchTimeout = 2000, false, time.Hour
	nextCfg.BatchSize = 5000
	next := NewQueuedSink(&flakySink{}, nextCfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	old.HandOver(next)
	old.handOverDeadline.Store(time.Now().Add(-time.Second).UnixNano()) // budget already spent
	events := make([]*Event, 1000)
	for i := range events {
		events[i] = &Event{ID: fmt.Sprint(i), Type: EventConfigChanged}
	}
	old.shutdownDrop(events)
	require.Zero(t, next.Health().DroppedEvents, "free capacity must win over the expired context")
	require.Zero(t, old.Health().DroppedEvents)
}

// Handed-over events are filtered and counted by the sink that finally
// receives them, also when the hand-over passes a closed replacement.
func TestHandOverCountsFilteringAtTheReceivingSink(t *testing.T) {
	include := func(types ...EventType) EventFilterConfig {
		names := make([]string, len(types))
		for i, typ := range types {
			names[i] = string(typ)
		}
		return EventFilterConfig{IncludeEventTypes: names}
	}
	a := NewQueuedSink(newFuncSink("chain-a", func([]*Event) error { return nil }), outageConfig(), zap.NewNop())
	// B would allow config.changed; C, the sink that receives the events,
	// allows only session.requested.
	b := NewQueuedSink(NewFilteredSink(newFuncSink("chain-b", func([]*Event) error { return nil }),
		include(EventConfigChanged)), outageConfig(), zap.NewNop())
	var delivered atomic.Int64
	c := NewQueuedSink(NewFilteredSink(newFuncSink("chain-c", func(events []*Event) error {
		delivered.Add(int64(len(events)))
		return nil
	}), include(EventSessionRequested)), outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	a.HandOver(b)
	b.HandOver(c)
	require.NoError(t, b.Close())
	filteredB := metrics.AuditEventsDropped.WithLabelValues("chain-b", "handover_filtered")
	filteredC := metrics.AuditEventsDropped.WithLabelValues("chain-c", "handover_filtered")
	beforeB, beforeC := testutil.ToFloat64(filteredB), testutil.ToFloat64(filteredC)
	a.shutdownDrop([]*Event{{ID: "session", Type: EventSessionRequested}, {ID: "config", Type: EventConfigChanged}})
	require.Eventually(t, func() bool { return delivered.Load() == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, beforeC+1, testutil.ToFloat64(filteredC), "C excludes config.changed")
	require.Equal(t, int64(1), c.Health().DroppedEvents, "the in-memory counter matches")
	require.Equal(t, beforeB, testutil.ToFloat64(filteredB), "B's filters do not apply")
}

// namePanicSink panics once in Name() after a successful write, i.e. in the
// worker's bookkeeping outside the guarded sink write.
type namePanicSink struct{ armed atomic.Bool }

func (s *namePanicSink) Name() string {
	if s.armed.CompareAndSwap(true, false) {
		panic("bookkeeping bug")
	}
	return "worker-panic"
}
func (s *namePanicSink) Close() error { return nil }
func (s *namePanicSink) Write(ctx context.Context, e *Event) error {
	return s.WriteBatch(ctx, []*Event{e})
}
func (s *namePanicSink) WriteBatch(context.Context, []*Event) error {
	s.armed.Store(true)
	return nil
}

// A worker panic outside the guarded write counts the held events as a
// "panic" drop and releases them from inFlight, so drain does not wait.
func TestWorkerPanicReleasesItsBatch(t *testing.T) {
	sink := &namePanicSink{}
	cfg := splitConfig(2)
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	panics := metrics.AuditEventsDropped.WithLabelValues("worker-panic", "panic")
	before := testutil.ToFloat64(panics)
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "a", Type: EventConfigChanged}))
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "b", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return testutil.ToFloat64(panics) == before+2 }, time.Second, 5*time.Millisecond)
	require.Eventually(t, qs.idle, time.Second, 5*time.Millisecond)
	// The restarted worker takes the next batch (which panics the same way).
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "c", Type: EventConfigChanged}))
	require.NoError(t, qs.Write(context.Background(), &Event{ID: "d", Type: EventConfigChanged}))
	require.Eventually(t, func() bool { return testutil.ToFloat64(panics) == before+4 }, time.Second, 5*time.Millisecond)
	require.Eventually(t, qs.idle, time.Second, 5*time.Millisecond)
}

// ingressPipeline is a manager in front of one queued sink, as the service
// builds it, with the given handover key.
func ingressPipeline(t *testing.T, sink Sink, key string, cfg QueuedSinkConfig, mcfg ManagerConfig) (*Manager, *IsolatedMultiSink) {
	t.Helper()
	multi := NewIsolatedMultiSink([]Sink{sink}, cfg, zap.NewNop())
	multi.sinks[0].owner = key
	return NewManager(multi, mcfg, zap.NewNop()), multi
}

// Ingress events the old manager has not routed yet follow the per-sink
// handover: they reach a matching successor, but a retargeted sink counts
// them as "shutdown" instead of sending them to the new destination.
func TestManagerIngressFollowsThePerSinkHandover(t *testing.T) {
	for name, retarget := range map[string]bool{"matching": false, "retargeted": true} {
		t.Run(name, func(t *testing.T) {
			// The old sink's queue is full and its worker blocked, so the
			// manager's ingress backs up (dropOnFull: false).
			release := make(chan struct{})
			blocked := newFuncSink("ingress-"+name, func([]*Event) error { <-release; return nil })
			cfg := outageConfig()
			cfg.QueueSize, cfg.WorkerCount, cfg.DropOnFull = 1, 1, false
			cfg.WriteTimeout = time.Minute
			mcfg := DefaultManagerConfig()
			mcfg.WorkerCount, mcfg.BatchSize, mcfg.QueueSize = 1, 1, 100
			// Only the manager's five-second drain deadline ends the blocked
			// write, so the ingress queue stays populated until then.
			mcfg.WriteTimeout = time.Minute
			key := handOverKey("config", kafkaSinkConfig([]string{"a:9093"}, "audit", "ca"))
			oldManager, oldMulti := ingressPipeline(t, blocked, key, cfg, mcfg)

			var delivered atomic.Int64
			nextKey := key
			if retarget {
				nextKey = handOverKey("config", kafkaSinkConfig([]string{"a:9093"}, "elsewhere", "ca"))
			}
			nextManager, nextMulti := ingressPipeline(t, newFuncSink("ingress-"+name, func(events []*Event) error {
				delivered.Add(int64(len(events)))
				return nil
			}), nextKey, outageConfig(), DefaultManagerConfig())
			t.Cleanup(func() { require.NoError(t, nextManager.Close()) })

			for i := range 10 {
				require.True(t, oldManager.Emit(context.Background(), &Event{ID: fmt.Sprint(i), Type: EventConfigChanged}))
			}
			require.Eventually(t, func() bool { return len(oldManager.asyncQueue) >= 5 }, time.Second, 5*time.Millisecond)
			oldMulti.handOver(nextMulti)
			closed := make(chan struct{})
			go func() { _ = oldManager.Close(); close(closed) }()
			time.Sleep(6 * time.Second) // past the manager's drain deadline
			close(release)
			<-closed
			if retarget {
				time.Sleep(100 * time.Millisecond)
				require.Zero(t, delivered.Load(), "nothing reaches the retargeted destination")
				require.GreaterOrEqual(t, oldManager.Stats().DroppedEvents, int64(5), "counted as shutdown")
				return
			}
			require.Eventually(t, func() bool { return delivered.Load() >= 5 }, 2*time.Second, 10*time.Millisecond)
			require.Zero(t, oldManager.Stats().DroppedEvents)
		})
	}
}

// A handover that waits on a full successor B follows B's own successor C
// as soon as B closes, instead of timing out and dropping.
func TestHandOverFollowsASuccessorThatClosesDuringTheWait(t *testing.T) {
	cfg := outageConfig()
	cfg.QueueSize, cfg.WorkerCount, cfg.DropOnFull = 1, 1, false
	cfg.WriteTimeout = 5 * time.Second
	release := make(chan struct{})
	b := NewQueuedSink(newFuncSink("wait-b", func([]*Event) error { <-release; return nil }), cfg, zap.NewNop())
	require.NoError(t, b.Write(context.Background(), &Event{ID: "busy", Type: EventConfigChanged}))
	require.NoError(t, b.Write(context.Background(), &Event{ID: "fills-queue", Type: EventConfigChanged}))
	var delivered atomic.Int64
	c := NewQueuedSink(newFuncSink("wait-c", func(events []*Event) error {
		delivered.Add(int64(len(events)))
		return nil
	}), outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	b.HandOver(c)
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- b.writeHandedOver(context.Background(), &Event{ID: "from-a", Type: EventConfigChanged})
	}()
	time.Sleep(50 * time.Millisecond)
	closed := make(chan struct{})
	go func() { _ = b.Close(); close(closed) }()
	require.NoError(t, <-done)
	require.Less(t, time.Since(start), 2*time.Second, "the wait ends when B closes")
	close(release)
	<-closed
	require.Eventually(t, func() bool { return delivered.Load() >= 1 }, time.Second, 5*time.Millisecond)
}

// A handover waiting on a full successor B that then closes follows B's
// successor C; an event C's filters exclude is counted, not lost silently.
func TestHandOverViaClosingSuccessorCountsFilteredEvents(t *testing.T) {
	cfg := outageConfig()
	cfg.QueueSize, cfg.WorkerCount, cfg.DropOnFull = 1, 1, false
	cfg.WriteTimeout = 5 * time.Second
	release := make(chan struct{})
	b := NewQueuedSink(newFuncSink("probe-b", func([]*Event) error { <-release; return nil }), cfg, zap.NewNop())
	require.NoError(t, b.Write(context.Background(), &Event{ID: "busy", Type: EventSessionRequested}))
	require.NoError(t, b.Write(context.Background(), &Event{ID: "fills-queue", Type: EventSessionRequested}))
	var delivered atomic.Int64
	c := NewQueuedSink(NewFilteredSink(newFuncSink("probe-c", func(events []*Event) error {
		delivered.Add(int64(len(events)))
		return nil
	}), EventFilterConfig{IncludeEventTypes: []string{string(EventSessionRequested)}}), outageConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, c.Close()) })
	b.HandOver(c)
	filtered := metrics.AuditEventsDropped.WithLabelValues("probe-c", "handover_filtered")
	before := testutil.ToFloat64(filtered)
	done := make(chan error, 1)
	go func() {
		done <- b.writeHandedOver(context.Background(), &Event{ID: "excluded-by-c", Type: EventConfigChanged})
	}()
	time.Sleep(50 * time.Millisecond) // the handover waits on B's full queue
	closed := make(chan struct{})
	go func() { _ = b.Close(); close(closed) }()
	require.NoError(t, <-done)
	close(release)
	<-closed
	require.Equal(t, before+1, testutil.ToFloat64(filtered))
	require.Equal(t, int64(1), c.Health().DroppedEvents)
}

// With two sinks, each old sink's pending ingress events reach only its own
// successor: nothing crosses to the other sink's replacement.
func TestManagerIngressHandOverNeverCrossesSinks(t *testing.T) {
	release := make(chan struct{})
	blocked := func(name string) Sink {
		return newFuncSink(name, func([]*Event) error { <-release; return nil })
	}
	cfg := outageConfig()
	cfg.QueueSize, cfg.WorkerCount, cfg.DropOnFull = 1, 1, false
	cfg.WriteTimeout = time.Minute
	only := func(sink Sink, typ EventType) Sink {
		return NewFilteredSink(sink, EventFilterConfig{IncludeEventTypes: []string{string(typ)}})
	}
	// Old sink A takes session events, old sink B config events.
	oldMulti := NewIsolatedMultiSink([]Sink{only(blocked("cross-a"), EventSessionRequested), only(blocked("cross-b"), EventConfigChanged)}, cfg, zap.NewNop())
	oldMulti.sinks[0].owner, oldMulti.sinks[1].owner = "config/kafka/a", "config/kafka/b"
	mcfg := DefaultManagerConfig()
	mcfg.WorkerCount, mcfg.BatchSize, mcfg.QueueSize = 1, 1, 100
	mcfg.WriteTimeout = time.Minute
	oldManager := NewManager(oldMulti, mcfg, zap.NewNop())

	// The replacements accept everything and record what they receive.
	var mu sync.Mutex
	received := map[string][]EventType{}
	recorder := func(name string) Sink {
		return newFuncSink(name, func(events []*Event) error {
			mu.Lock()
			defer mu.Unlock()
			for _, e := range events {
				received[name] = append(received[name], e.Type)
			}
			return nil
		})
	}
	nextMulti := NewIsolatedMultiSink([]Sink{recorder("cross-a"), recorder("cross-b")}, outageConfig(), zap.NewNop())
	nextMulti.sinks[0].owner, nextMulti.sinks[1].owner = "config/kafka/a", "config/kafka/b"
	nextManager := NewManager(nextMulti, DefaultManagerConfig(), zap.NewNop())
	t.Cleanup(func() { require.NoError(t, nextManager.Close()) })

	for i := range 10 {
		typ := EventSessionRequested
		if i%2 == 1 {
			typ = EventConfigChanged
		}
		require.True(t, oldManager.Emit(context.Background(), &Event{ID: fmt.Sprint(i), Type: typ}))
	}
	require.Eventually(t, func() bool { return len(oldManager.asyncQueue) >= 4 }, time.Second, 5*time.Millisecond)
	oldMulti.handOver(nextMulti)
	closed := make(chan struct{})
	go func() { _ = oldManager.Close(); close(closed) }()
	time.Sleep(6 * time.Second) // past the manager's drain deadline
	close(release)
	<-closed
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received["cross-a"]) > 0 && len(received["cross-b"]) > 0
	}, 2*time.Second, 10*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, typ := range received["cross-a"] {
		require.Equal(t, EventSessionRequested, typ, "sink a's replacement got sink b's event")
	}
	for _, typ := range received["cross-b"] {
		require.Equal(t, EventConfigChanged, typ, "sink b's replacement got sink a's event")
	}
}

// healthyProduce answers metadata and Produce requests at once, counting
// the records it receives.
type healthyProduce struct{ records atomic.Int64 }

func (h *healthyProduce) RoundTrip(_ context.Context, _ net.Addr, req kafka.Request) (protocol.Message, error) {
	switch r := req.(type) {
	case *metadataAPI.Request:
		return &metadataAPI.Response{
			Brokers: []metadataAPI.ResponseBroker{{NodeID: 1, Host: "127.0.0.1", Port: 1}},
			Topics: []metadataAPI.ResponseTopic{{Name: r.TopicNames[0],
				Partitions: []metadataAPI.ResponsePartition{{PartitionIndex: 0, LeaderID: 1}}}},
		}, nil
	case *produceAPI.Request:
		for _, p := range r.Topics[0].Partitions {
			for {
				if _, err := p.RecordSet.Records.ReadRecord(); err != nil {
					break
				}
				h.records.Add(1)
			}
		}
		return &produceAPI.Response{Topics: []produceAPI.ResponseTopic{{Topic: r.Topics[0].Topic,
			Partitions: []produceAPI.ResponsePartition{{Partition: 0}}}}}, nil
	}
	return nil, errors.New("unexpected request")
}

// Single-partition topic, Kafka batchSize 200 and batchTimeoutSeconds 10,
// two queue workers writing 100-event batches: each partial batch is
// delivered well within the queue's write deadline instead of waiting for
// the Kafka batch timeout, so nothing is retried or dropped.
func TestKafkaPartialBatchesFlushWithinTheWriteDeadline(t *testing.T) {
	transport := &healthyProduce{}
	sink, err := NewKafkaSink(KafkaSinkConfig{Name: "partial-batches", Brokers: []string{"127.0.0.1:1"}, Topic: "audit",
		BatchSize: 200, BatchTimeout: 10 * time.Second}, zap.NewNop())
	require.NoError(t, err)
	sink.writer.Transport = transport
	cfg := DefaultQueuedSinkConfig()
	cfg.WorkerCount, cfg.BatchSize = 2, 100
	qs := NewQueuedSink(sink, cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, qs.Close()) })
	start := time.Now()
	for i := range 400 {
		require.NoError(t, qs.Write(context.Background(), &Event{ID: fmt.Sprint(i), Type: EventConfigChanged}))
	}
	require.Eventually(t, func() bool { return transport.records.Load() == 400 }, 5*time.Second, 10*time.Millisecond)
	require.Less(t, time.Since(start), 5*time.Second)
	require.Eventually(t, func() bool { return qs.Health().ProcessedEvents == 400 }, time.Second, 10*time.Millisecond)
	health := qs.Health()
	require.Zero(t, health.FailedEvents, "no write ran into the queue's deadline")
	require.Zero(t, health.DroppedEvents)
}

// During a reload with dropOnFull: false, a manager batch already waiting in
// WriteBatch on the old sink's full queue hands its unqueued events to the
// matching successor when the manager's drain deadline cancels it. Every
// accepted event reaches the replacement or the old sink.
func TestReloadHandsOverABatchWaitingOnAFullQueue(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	seen := map[string]int{}
	record := func(events []*Event) {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range events {
			seen[e.ID]++
		}
	}
	oldSink := newFuncSink("waiting-batch", func(events []*Event) error { <-release; record(events); return nil })
	cfg := outageConfig()
	cfg.QueueSize, cfg.WorkerCount, cfg.BatchSize, cfg.DropOnFull = 1, 1, 1, false
	cfg.WriteTimeout = time.Minute
	oldMulti := NewIsolatedMultiSink([]Sink{oldSink}, cfg, zap.NewNop())
	oldMulti.sinks[0].owner = "config/kafka/events"
	mcfg := DefaultManagerConfig()
	// One manager batch holds all events, so they are all inside WriteBatch.
	mcfg.WorkerCount, mcfg.BatchSize, mcfg.QueueSize, mcfg.BatchTimeout = 1, 10, 100, time.Hour
	mcfg.WriteTimeout = time.Minute
	oldManager := NewManager(oldMulti, mcfg, zap.NewNop())

	nextMulti := NewIsolatedMultiSink([]Sink{newFuncSink("waiting-batch", func(events []*Event) error {
		record(events)
		return nil
	})}, outageConfig(), zap.NewNop())
	nextMulti.sinks[0].owner = "config/kafka/events"
	t.Cleanup(func() { require.NoError(t, nextMulti.Close()) })

	ids := make([]string, 10)
	for i := range ids {
		ids[i] = fmt.Sprint("accepted-", i)
		require.True(t, oldManager.Emit(context.Background(), &Event{ID: ids[i], Type: EventConfigChanged}))
	}
	require.Eventually(t, func() bool { return len(oldMulti.sinks[0].queue) == 1 }, time.Second, 5*time.Millisecond)
	oldMulti.handOver(nextMulti)
	timeouts := metrics.AuditEventsDropped.WithLabelValues("waiting-batch", "enqueue_timeout")
	before := testutil.ToFloat64(timeouts)
	closed := make(chan struct{})
	go func() { _ = oldManager.Close(); close(closed) }()
	time.Sleep(6 * time.Second) // past the manager's drain deadline
	close(release)
	<-closed
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(seen) == len(ids)
	}, 3*time.Second, 10*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		require.Positive(t, seen[id], "accepted event %s was lost", id)
	}
	require.Equal(t, before, testutil.ToFloat64(timeouts), "no event counted as enqueue_timeout")
}

// A handover that reaches a full, still-open replacement which itself has a
// successor keeps its original deadline: an intermediate hop must not start
// a fresh write timeout.
func TestHandOverKeepsItsDeadlineAcrossFullOpenHops(t *testing.T) {
	full := func(name string) *QueuedSink {
		cfg := outageConfig()
		cfg.QueueSize, cfg.WorkerCount, cfg.DropOnFull = 1, 1, false
		cfg.WriteTimeout = 2 * time.Second
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		qs := NewQueuedSink(newFuncSink(name, func([]*Event) error { <-block; return nil }), cfg, zap.NewNop())
		require.NoError(t, qs.Write(context.Background(), &Event{ID: name + "-busy", Type: EventConfigChanged}))
		require.NoError(t, qs.Write(context.Background(), &Event{ID: name + "-queued", Type: EventConfigChanged}))
		return qs
	}
	// B and C are full and still open, D is the end of the chain and full too.
	b, c, d := full("hop-b"), full("hop-c"), full("hop-d")
	b.HandOver(c)
	c.HandOver(d)
	a := NewQueuedSink(&flakySink{}, outageConfig(), zap.NewNop())
	a.config.WriteTimeout = 300 * time.Millisecond
	a.HandOver(b)
	start := time.Now()
	a.shutdownDrop([]*Event{{ID: "late", Type: EventConfigChanged}})
	// One budget (300 ms) for the whole chain, not one write timeout (2 s)
	// per hop.
	require.Less(t, time.Since(start), time.Second)
}

// A handover started by a cancelled caller (a manager batch the reload drain
// cancelled) still waits within its own budget for a replacement whose queue
// frees up shortly, instead of failing at once with the caller's
// cancellation.
func TestUnmarkedHandOverIgnoresTheCallersCancellation(t *testing.T) {
	cfg := outageConfig()
	cfg.QueueSize, cfg.WorkerCount, cfg.DropOnFull = 1, 1, false
	cfg.WriteTimeout = 2 * time.Second
	release := make(chan struct{})
	next := NewQueuedSink(newFuncSink("detached", func([]*Event) error { <-release; return nil }), cfg, zap.NewNop())
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	require.NoError(t, next.Write(context.Background(), &Event{ID: "busy", Type: EventConfigChanged}))
	require.NoError(t, next.Write(context.Background(), &Event{ID: "fills-queue", Type: EventConfigChanged}))
	old := NewQueuedSink(&flakySink{}, cfg, zap.NewNop())
	old.HandOver(next)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	timeouts := metrics.AuditEventsDropped.WithLabelValues("detached", "enqueue_timeout")
	before := testutil.ToFloat64(timeouts)
	go func() { time.Sleep(100 * time.Millisecond); close(release) }() // capacity frees up within the budget
	old.handOverWithin(cancelled, []*Event{{ID: "handed-over", Type: EventConfigChanged}})
	require.Equal(t, before, testutil.ToFloat64(timeouts), "the event waited for capacity")
	require.Zero(t, next.Health().DroppedEvents)
}

// One panicking event behind a real circuit breaker (threshold 2), with
// and without retention past the window: the panics neither open the
// breaker nor make later attempts fail as "circuit open", so the batch is
// split, a and b are delivered and only boom is dropped as "panic". The
// breaker stays closed, so other batches are not rejected.
func TestPanickingEventDoesNotTripTheBreakerForItsBatch(t *testing.T) {
	for _, dropAfterWindow := range []bool{false, true} {
		t.Run(fmt.Sprintf("dropAfterRetryWindow=%t", dropAfterWindow), func(t *testing.T) {
			sink := &batchLimitSink{limit: 100}
			cb := NewCircuitBreakerSink(sink, CircuitBreakerConfig{
				FailureThreshold: 2, SuccessThreshold: 1, OpenTimeout: time.Hour, HalfOpenMaxRequests: 1,
			}, zap.NewNop())
			cfg := splitConfig(3)
			cfg.RetryAttempts = 4
			cfg.DropAfterRetryWindow = dropAfterWindow
			qs := NewQueuedSink(cb, cfg, zap.NewNop())
			t.Cleanup(func() { require.NoError(t, qs.Close()) })
			panics := metrics.AuditEventsDropped.WithLabelValues(sink.Name(), "panic")
			before := testutil.ToFloat64(panics)
			for _, id := range []string{"a", "boom", "b"} {
				require.NoError(t, qs.Write(context.Background(), &Event{ID: id, Type: EventConfigChanged}))
			}
			require.Eventually(t, func() bool { return len(sink.ids()) == 2 && qs.Health().DroppedEvents == 1 },
				2*time.Second, 5*time.Millisecond)
			require.ElementsMatch(t, []string{"a", "b"}, sink.ids())
			require.Equal(t, before+1, testutil.ToFloat64(panics), "only boom is dropped, as panic")
			require.Equal(t, CircuitClosed, cb.Stats().State, "a poison event must not open the breaker")
			require.Zero(t, testutil.ToFloat64(metrics.AuditEventsRetained.WithLabelValues(sink.Name())))
		})
	}
}
