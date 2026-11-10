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
	old.sinks[0].owner, old.sinks[1].owner = "config-a", "config-b"
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
	next.sinks[0].owner, next.sinks[1].owner = "config-b", "config-a"
	t.Cleanup(func() { require.NoError(t, next.Close()) })
	old.handOver(next)
	require.NoError(t, old.Close())
	require.Eventually(t, func() bool { return toA.Load() == 1 && toB.Load() == 1 }, time.Second, 5*time.Millisecond)
}
