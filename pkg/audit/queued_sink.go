/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package audit

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"k8s.io/apimachinery/pkg/util/wait"
)

// QueuedSinkConfig configures a QueuedSink.
type QueuedSinkConfig struct {
	// QueueSize is the size of the async event queue.
	// Default: 10000
	QueueSize int

	// WorkerCount is the number of async processing workers.
	// Default: 2
	WorkerCount int

	// Batching config for underlying BatchSinks
	BatchSize    int
	BatchTimeout time.Duration

	// WriteTimeout is the timeout for writing to the underlying sink.
	// Default: 5s
	WriteTimeout time.Duration

	// DropOnFull controls behavior when queue is full.
	// If true, new events are dropped (non-blocking).
	// If false, enqueue waits up to WriteTimeout or the caller deadline.
	// Default: true
	DropOnFull bool

	RetryAttempts       int
	RetryInitialBackoff time.Duration
	RetryMaxBackoff     time.Duration
	RetryTimeout        time.Duration

	// DropAfterRetryWindow drops a batch once RetryAttempts or RetryTimeout
	// is exhausted. When false (default), the worker retains the batch and
	// retries it every RetryMaxBackoff until it is delivered or the sink
	// closes; memory stays bounded by the queue plus one batch per worker,
	// and new events beyond that are counted as queue_full/enqueue_timeout.
	DropAfterRetryWindow bool

	// CircuitBreakerThreshold is the number of consecutive failures before opening the circuit.
	// Default: 5
	CircuitBreakerThreshold int

	// CircuitBreakerResetTime is how long to wait before attempting to close the circuit.
	// Default: 30s
	CircuitBreakerResetTime time.Duration
}

// DefaultQueuedSinkConfig returns sensible defaults for a queued sink.
func DefaultQueuedSinkConfig() QueuedSinkConfig {
	return QueuedSinkConfig{
		QueueSize:               10000,
		WorkerCount:             2,
		BatchSize:               100,
		BatchTimeout:            100 * time.Millisecond,
		WriteTimeout:            5 * time.Second,
		DropOnFull:              true,
		RetryAttempts:           8,
		RetryInitialBackoff:     time.Second,
		RetryMaxBackoff:         10 * time.Second,
		RetryTimeout:            time.Minute,
		CircuitBreakerThreshold: 5,
		CircuitBreakerResetTime: 30 * time.Second,
	}
}

// QueuedSinkHealth represents the health status of a queued sink.
type QueuedSinkHealth struct {
	Name             string    `json:"name"`
	Healthy          bool      `json:"healthy"`
	QueueLength      int       `json:"queueLength"`
	QueueCapacity    int       `json:"queueCapacity"`
	DroppedEvents    int64     `json:"droppedEvents"`
	ProcessedEvents  int64     `json:"processedEvents"`
	FailedEvents     int64     `json:"failedEvents"`
	ConsecutiveFails int       `json:"consecutiveFails"`
	CircuitOpen      bool      `json:"circuitOpen"`
	CircuitState     string    `json:"circuitState"`
	LastError        string    `json:"lastError,omitempty"`
	LastErrorTime    time.Time `json:"lastErrorTime,omitempty"`
	LastSuccessTime  time.Time `json:"lastSuccessTime,omitempty"`
}

// QueuedHealthCheckable is an interface for sinks that can report health.
type QueuedHealthCheckable interface {
	Health() QueuedSinkHealth
}

// QueuedSink wraps a Sink with its own dedicated queue for isolation.
// Each QueuedSink operates independently - if one overflows or fails,
// it doesn't affect other sinks.
type QueuedSink struct {
	sink   Sink
	queue  chan *Event
	config QueuedSinkConfig
	logger *zap.Logger

	// Metrics
	droppedEvents   atomic.Int64
	processedEvents atomic.Int64
	failedEvents    atomic.Int64
	// inFlight counts events that workers took from the queue and have not
	// finished delivering or dropping (see idle).
	inFlight atomic.Int64

	// Circuit breaker state
	consecutiveFails atomic.Int32
	circuitOpen      atomic.Bool
	lastResetAttempt atomic.Int64 // Unix timestamp
	lastDropLog      atomic.Int64 // Unix nanoseconds

	// successor receives the events held at shutdown (see HandOver).
	successor atomic.Pointer[QueuedSink]
	// handOverDeadline bounds all hand-overs of this sink together (Unix
	// nanoseconds, set on the first one): worker batches and retained
	// batches share one WriteTimeout instead of one each.
	handOverDeadline atomic.Int64

	// owner identifies the AuditConfig and sink type that define the sink;
	// sink names are unique only within one AuditConfig, and a reload may
	// change a sink's type while keeping its name.
	owner string

	// Error tracking
	mu              sync.RWMutex
	lastError       string
	lastErrorTime   time.Time
	lastSuccessTime time.Time

	// Lifecycle
	wg               sync.WaitGroup
	closed           atomic.Bool
	shutdownDeadline atomic.Int64

	// sendMu serialises sends on queue against the close in Close.
	// Every send goes through [QueuedSink.enqueue], which holds the read lock
	// and re-checks closed; Close takes the write lock before closing the
	// channel, so no send can be in flight when the channel is closed.
	sendMu sync.RWMutex
	stop   chan struct{}
}

// enqueue performs a non-blocking send on the event queue that is safe against a
// concurrent Close. It returns false when the sink is already closed or the
// queue is full; callers distinguish the two via qs.closed.
func (qs *QueuedSink) enqueue(event *Event) bool {
	qs.sendMu.RLock()
	defer qs.sendMu.RUnlock()

	// Re-check under the lock: Close sets closed before taking the write lock,
	// so observing closed==false here guarantees the channel is still open for
	// as long as we hold the read lock.
	if qs.closed.Load() {
		return false
	}

	select {
	case qs.queue <- event:
		return true
	default:
		return false
	}
}

// NewQueuedSink creates a new QueuedSink wrapper around an existing sink.
func NewQueuedSink(sink Sink, cfg QueuedSinkConfig, logger *zap.Logger) *QueuedSink {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 2
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.CircuitBreakerThreshold <= 0 {
		cfg.CircuitBreakerThreshold = 5
	}
	if cfg.CircuitBreakerResetTime <= 0 {
		cfg.CircuitBreakerResetTime = 30 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 100 * time.Millisecond
	}
	if cfg.RetryAttempts <= 0 {
		cfg.RetryAttempts = 8
	}
	if cfg.RetryInitialBackoff <= 0 {
		cfg.RetryInitialBackoff = time.Second
	}
	if cfg.RetryMaxBackoff <= 0 {
		cfg.RetryMaxBackoff = 10 * time.Second
	}
	if cfg.RetryTimeout <= 0 {
		cfg.RetryTimeout = time.Minute
	}
	if cfg.RetryInitialBackoff > cfg.RetryMaxBackoff {
		cfg.RetryInitialBackoff = cfg.RetryMaxBackoff
	}

	qs := &QueuedSink{
		sink:   sink,
		queue:  make(chan *Event, cfg.QueueSize),
		config: cfg,
		logger: logger.Named("queued-sink").With(zap.String("sink", sink.Name())),
		stop:   make(chan struct{}),
	}

	batchSink, isBatchSink := asBatchSink(sink)

	// Start workers
	for i := 0; i < cfg.WorkerCount; i++ {
		qs.wg.Add(1)
		if isBatchSink {
			go qs.processBatchQueue(i, batchSink)
		} else {
			go qs.processQueue(i)
		}
	}

	qs.logger.Info("queued sink started",
		zap.Int("queue_size", cfg.QueueSize),
		zap.Int("workers", cfg.WorkerCount),
		zap.Duration("write_timeout", cfg.WriteTimeout),
		zap.Int("circuit_breaker_threshold", cfg.CircuitBreakerThreshold))

	return qs
}

// closedWrite handles a write to a closed sink: a replaced sink forwards
// the event to its successor (which may itself forward further along a chain
// of reloads), otherwise the event is counted as a shutdown drop.
func (qs *QueuedSink) closedWrite(ctx context.Context, event *Event) error {
	if successor := qs.successor.Load(); successor != nil {
		// writeHandedOver, not Write: an event the successor's filters
		// exclude is counted ("handover_filtered") instead of vanishing.
		return successor.writeHandedOver(ctx, event)
	}
	qs.recordDrop(1, "shutdown")
	return fmt.Errorf("queued sink %s is closed", qs.sink.Name())
}

// writeHandedOver accepts an event handed over by the sink this one
// replaced. A closed sink forwards it along the chain of reloads; the sink
// that finally receives it counts it as "handover_filtered" when its filters
// exclude it, since such an event is not delivered anywhere.
func (qs *QueuedSink) writeHandedOver(ctx context.Context, event *Event) error {
	if qs.closed.Load() {
		if successor := qs.successor.Load(); successor != nil {
			return successor.writeHandedOver(ctx, event)
		}
	}
	if !qs.closed.Load() && !queuedEventAllowed(qs.sink, event) {
		metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "handover_filtered").Inc()
		qs.droppedEvents.Add(1)
		qs.logger.Debug("handed-over audit event excluded by this sink's filters",
			zap.String("event_id", event.ID), zap.String("event_type", string(event.Type)))
		return nil
	}
	return qs.Write(ctx, event)
}

// Write enqueues an event for async processing. A sensitive event may
// synchronously fall back to the underlying sink when a queue is full or its
// circuit is open.
func (qs *QueuedSink) Write(ctx context.Context, event *Event) error {
	if qs.closed.Load() {
		return qs.closedWrite(ctx, event)
	}
	if !queuedEventAllowed(qs.sink, event) {
		return nil
	}
	if !qs.config.DropOnFull {
		enqueued, closed, err := qs.blockingEnqueue(ctx, event)
		if errors.Is(err, errHandOverPending) {
			// The caller gave up while this sink is being replaced: the
			// matching successor takes the event. A cancelled manager write
			// starts this sink's handover budget; a handover passing through
			// keeps its own deadline.
			qs.handOverWithin(ctx, []*Event{event})
			return nil
		}
		if closed {
			// Follow the successor without holding sendMu, so Close of this
			// sink is not delayed by a forward into a full replacement.
			return qs.closedWrite(ctx, event)
		}
		if enqueued {
			return nil
		}
		return err
	}
	return qs.writeNonBlocking(ctx, event)
}

// errHandOverPending reports a blocking enqueue that ran out of time while
// the sink is being replaced; the caller hands the event to the successor.
var errHandOverPending = errors.New("audit sink is being replaced")

// blockingEnqueue waits for queue capacity up to WriteTimeout or ctx. It
// reports closed when the sink closed before or during the wait.
func (qs *QueuedSink) blockingEnqueue(ctx context.Context, event *Event) (enqueued, closed bool, err error) {
	writeCtx, cancel := context.WithTimeout(ctx, qs.config.WriteTimeout)
	defer cancel()
	qs.sendMu.RLock()
	defer qs.sendMu.RUnlock()
	if qs.closed.Load() {
		return false, true, nil
	}
	// Free capacity always wins, even with an expired context (for example a
	// late handover sharing an already spent deadline); the select below
	// would otherwise pick at random between the send and Done.
	select {
	case qs.queue <- event:
		return true, false, nil
	default:
	}
	select {
	case qs.queue <- event:
		return true, false, nil
	case <-qs.stop:
		return false, true, nil
	case <-writeCtx.Done():
		if qs.successor.Load() != nil {
			return false, false, errHandOverPending
		}
		// Count every drop, but rate-limit the warning: with a full queue
		// this path runs once per emitted event.
		metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "enqueue_timeout").Inc()
		qs.droppedEvents.Add(1)
		qs.logDropThrottled("enqueue_timeout")
		return false, false, fmt.Errorf("enqueue audit event: %w", writeCtx.Err())
	}
}

// writeNonBlocking enqueues with dropOnFull: true semantics.
func (qs *QueuedSink) writeNonBlocking(ctx context.Context, event *Event) error {
	// Check circuit breaker
	if qs.circuitOpen.Load() {
		// Try to reset circuit if enough time has passed
		lastReset := qs.lastResetAttempt.Load()
		now := time.Now().Unix()
		if now-lastReset >= int64(qs.config.CircuitBreakerResetTime.Seconds()) {
			if qs.lastResetAttempt.CompareAndSwap(lastReset, now) {
				qs.logger.Info("attempting to close circuit breaker",
					zap.String("sink", qs.sink.Name()))
				qs.circuitOpen.Store(false)
				qs.consecutiveFails.Store(0)
			}
		} else {
			// Circuit still open
			if IsSensitiveEvent(event.Type) {
				// Synchronous fallback for sensitive events
				qs.logger.Warn("circuit open but event is sensitive, attempting synchronous write",
					zap.String("sink", qs.sink.Name()),
					zap.String("event_type", string(event.Type)))
				return qs.syncFallback(ctx, event)
			}
			// Non-sensitive event: drop
			qs.droppedEvents.Add(1)
			metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "circuit_open").Inc()
			qs.logDropThrottled("circuit_open")
			return nil
		}
	}

	// Non-blocking send to queue (safe against a concurrent Close).
	if qs.enqueue(event) {
		return nil
	}
	if qs.closed.Load() {
		return qs.closedWrite(ctx, event)
	}
	// Queue is full
	if IsSensitiveEvent(event.Type) {
		// Synchronous fallback for sensitive events
		qs.logger.Warn("queue full but event is sensitive, attempting synchronous write",
			zap.String("sink", qs.sink.Name()),
			zap.String("event_type", string(event.Type)))
		return qs.syncFallback(ctx, event)
	}
	// Non-sensitive event: drop
	qs.droppedEvents.Add(1)
	metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "queue_full").Inc()
	qs.logDropThrottled("queue_full")
	return nil
}

// dropLogInterval rate-limits warnings for per-event drops, which can occur
// once per emitted event while a queue is full.
const dropLogInterval = 10 * time.Second

func (qs *QueuedSink) logDropThrottled(reason string) {
	now := time.Now().UnixNano()
	last := qs.lastDropLog.Load()
	if now-last < int64(dropLogInterval) || !qs.lastDropLog.CompareAndSwap(last, now) {
		return
	}
	qs.logger.Warn("audit events dropped",
		zap.String("reason", reason),
		zap.Int64("dropped_total", qs.droppedEvents.Load()),
		zap.Int("queue_length", len(qs.queue)))
}

func queuedEventAllowed(sink Sink, event *Event) bool {
	switch filtered := sink.(type) {
	case *filteredBatchSink:
		return filtered.filter.allows(event) && queuedEventAllowed(filtered.sink, event)
	case *filteredSink:
		return filtered.filter.allows(event) && queuedEventAllowed(filtered.sink, event)
	default:
		return true
	}
}

func (qs *QueuedSink) syncFallback(ctx context.Context, event *Event) error {
	writeCtx, cancel := context.WithTimeout(ctx, qs.config.WriteTimeout)
	defer cancel()
	err := qs.invokeWrite(writeCtx, func(ctx context.Context) error { return qs.sink.Write(ctx, event) })
	if err != nil {
		qs.failedEvents.Add(1)
		metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "sync_fallback").Inc()
		reason := "sync_fallback"
		if permanentDeliveryError(err) {
			reason = lossReason(err)
		}
		qs.recordDrop(1, reason)
	}
	return err
}

// processQueue is the worker goroutine that processes events from the queue.
func (qs *QueuedSink) processQueue(workerID int) {
	defer qs.wg.Done()
	var held int64 // events this worker took from the queue and still holds
	defer func() {
		if r := recover(); r != nil {
			qs.logger.Error("panic in audit queue worker recovered",
				zap.Int("worker", workerID),
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
			metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "panic").Inc()
			qs.releasePanickedBatch(held)
			// Restart the worker to maintain processing capacity
			qs.wg.Add(1)
			go qs.processQueue(workerID)
		}
	}()

	for event := range qs.queue {
		if qs.dropShutdownBacklog([]*Event{event}) {
			return
		}
		qs.inFlight.Add(1)
		held = 1
		qs.deliver([]*Event{event}, "write", qs.writeSingle, false, false)
		held = 0
		qs.inFlight.Add(-1)
	}
}

// writeSingle writes a one-event batch through the sink's single-event API.
func (qs *QueuedSink) writeSingle(ctx context.Context, events []*Event) error {
	return qs.sink.Write(ctx, events[0])
}

// dropShutdownBacklog hands pending and every still queued event over (or
// drops them as "shutdown") once the shutdown deadline has passed.
func (qs *QueuedSink) dropShutdownBacklog(pending []*Event) bool {
	deadline := qs.shutdownDeadline.Load()
	if deadline == 0 || time.Now().UnixNano() < deadline {
		return false
	}
	backlog := append([]*Event(nil), pending...)
	for {
		select {
		case event, ok := <-qs.queue:
			if ok {
				backlog = append(backlog, event)
				continue
			}
		default:
		}
		qs.shutdownDrop(backlog)
		return true
	}
}

// HandOver makes this sink pass the events it still holds at shutdown
// (queued, in retry or retained) to successor instead of dropping them with
// reason "shutdown". Used when a reload replaces the pipeline.
func (qs *QueuedSink) HandOver(successor *QueuedSink) {
	qs.successor.Store(successor)
}

// shutdownDrop hands events to the successor sink, or counts them as lost.
func (qs *QueuedSink) shutdownDrop(events []*Event) {
	qs.handOverWithin(context.Background(), events)
}

type handOverContextKey struct{}

// withHandOverDeadline marks ctx as a handover context whose deadline later
// hops must keep.
func withHandOverDeadline(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(context.WithValue(parent, handOverContextKey{}, true), deadline)
}

// handOverWithin hands events to the successor, or counts them lost. A
// handover started here gets this sink's shared deadline; a handover that
// already carries one (it is passing through this sink along a chain of
// reloads) keeps the originating, possibly earlier deadline, so each hop
// cannot add a fresh write timeout.
func (qs *QueuedSink) handOverWithin(parent context.Context, events []*Event) {
	if len(events) == 0 {
		return
	}
	if successor := qs.successor.Load(); successor != nil {
		qs.handOverDeadline.CompareAndSwap(0, time.Now().Add(qs.config.WriteTimeout).UnixNano())
		deadline := time.Unix(0, qs.handOverDeadline.Load())
		ctx := parent
		if parent.Value(handOverContextKey{}) == nil {
			// A handover starts here, detached from the caller's
			// cancellation (a manager batch cancelled by the reload drain
			// must not cancel its own handover). A write from a retiring
			// manager uses that manager's single handover budget, shared
			// with its queued ingress; otherwise this sink's budget applies.
			if m, ok := parent.Value(managerHandOverKey{}).(*Manager); ok {
				deadline = m.handOverBudget()
			}
			var cancel context.CancelFunc
			ctx, cancel = withHandOverDeadline(context.WithoutCancel(parent), deadline)
			defer cancel()
		}
		// The successor counts its own losses (queue_full, enqueue_timeout).
		for _, event := range events {
			// The receiving sink, which may sit further along a chain of
			// reloads, counts events its filters exclude.
			_ = successor.writeHandedOver(ctx, event)
		}
		qs.logger.Info("audit events handed over to the replacement pipeline", zap.Int("count", len(events)))
		return
	}
	qs.recordDrop(len(events), "shutdown")
}

func (qs *QueuedSink) recordDrop(count int, reason string) {
	// Update the metric first: a reader that sees the new Health().DroppedEvents
	// then also sees the metric.
	metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), reason).Add(float64(count))
	qs.droppedEvents.Add(int64(count))
	qs.logger.Warn("audit events dropped", zap.Int("count", count), zap.String("reason", reason))
}

// errSinkPanic marks a write that panicked. It is retried within the retry
// window (a panic may depend on transient sink state), then treated as
// permanent so that a deterministic panic cannot hold a worker forever.
var errSinkPanic = errors.New("audit sink panic")

func (qs *QueuedSink) invokeWrite(ctx context.Context, write func(context.Context) error) error {
	return invokeQueuedWrite(ctx, qs.logger, write)
}

func invokeQueuedWrite(ctx context.Context, logger *zap.Logger, write func(context.Context) error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("audit sink write panicked",
				zap.Any("panic", recovered), zap.ByteString("stack", debug.Stack()))
			err = fmt.Errorf("%w: %v", errSinkPanic, recovered)
		}
	}()
	return write(ctx)
}

// deliver retains the same event identities in the worker through bounded retries.
// A Kafka acknowledgement may be lost after delivery, so consumers must deduplicate IDs.
// split marks a half of a batch that already failed permanently; it treats a
// panic as permanent at once instead of after another retry window. held
// marks events that a retained ancestor batch already counts in
// breakglass_audit_events_retained; deliver removes them from the gauge once
// they are delivered or dropped, and leaves that to the halves when it splits.
func (qs *QueuedSink) deliver(events []*Event, operation string, write func(context.Context, []*Event) error, split, held bool) {
	count := len(events)
	retained := metrics.AuditEventsRetained.WithLabelValues(qs.sink.Name())
	handedToHalves := false
	defer func() {
		if held && !handedToHalves {
			retained.Sub(float64(count))
		}
	}()
	writeEvents := func(ctx context.Context) error { return write(ctx, events) }
	retryCtx, cancel := context.WithTimeout(context.Background(), qs.config.RetryTimeout)
	defer cancel()
	if deadline := qs.shutdownDeadline.Load(); deadline != 0 {
		var shutdownCancel context.CancelFunc
		retryCtx, shutdownCancel = context.WithDeadline(retryCtx, time.Unix(0, deadline))
		defer shutdownCancel()
	}
	backoff := wait.Backoff{
		Duration: qs.config.RetryInitialBackoff, Factor: 2,
		Steps: qs.config.RetryAttempts, Cap: qs.config.RetryMaxBackoff,
	}
	var err error
	// panicked remembers a panic in any attempt: a later attempt can fail
	// differently (for example circuit open because of other failures),
	// which must not hide that the batch carries a panicking event.
	panicked := false
	for attempt := 0; attempt < qs.config.RetryAttempts; attempt++ {
		if retryCtx.Err() != nil {
			if qs.shutdownDeadline.Load() != 0 {
				qs.shutdownDrop(events)
				return
			}
			break
		}
		writeCtx, writeCancel := context.WithTimeout(retryCtx, qs.config.WriteTimeout)
		err = qs.invokeWrite(writeCtx, writeEvents)
		panicked = panicked || errors.Is(err, errSinkPanic)
		writeCancel()
		if err == nil {
			qs.recordDelivered(count)
			return
		}
		qs.recordFailure(count, operation, err)
		if permanentDeliveryError(err) || (split && errors.Is(err, errSinkPanic)) {
			handedToHalves = qs.splitOrDrop(events, operation, write, err, held)
			return
		}
		if attempt+1 == qs.config.RetryAttempts || qs.closed.Load() || retryCtx.Err() != nil {
			break
		}
		metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "retry").Inc()
		timer := time.NewTimer(backoff.Step())
		select {
		case <-timer.C:
		case <-retryCtx.Done():
		case <-qs.stop:
		}
		timer.Stop()
		if qs.closed.Load() || retryCtx.Err() != nil {
			break
		}
	}
	if qs.closed.Load() {
		qs.consecutiveFails.Add(1)
		qs.shutdownDrop(events)
		return
	}
	// A panic in any attempt marks the batch as possibly poisoned: split it
	// so the halves retry independently (a half panics as permanent at
	// once). A single event is dropped only if its last attempt panicked;
	// if it last failed transiently it is retained like any other event.
	if panicked && (len(events) > 1 || errors.Is(err, errSinkPanic)) {
		if !errors.Is(err, errSinkPanic) {
			err = fmt.Errorf("%w (an earlier attempt panicked): %w", errSinkPanic, err)
		}
		handedToHalves = qs.splitOrDrop(events, operation, write, err, held)
		return
	}
	if !qs.config.DropAfterRetryWindow {
		if !held {
			retained.Add(float64(count))
			held = true
		}
		handedToHalves = qs.retain(events, operation, write, err)
		return
	}
	fails := qs.consecutiveFails.Add(1)
	if int(fails) >= qs.config.CircuitBreakerThreshold {
		qs.circuitOpen.Store(true)
		qs.lastResetAttempt.Store(time.Now().Unix())
	}
	qs.recordDrop(count, "retry_exhausted")
	qs.logger.Error("audit delivery retries exhausted",
		zap.Int("count", count), zap.String("operation", operation), zap.Error(err))
}

// splitOrDrop handles a batch that failed permanently. The failure may be
// caused by one event (a record that cannot be serialized or panics the
// sink) or by the batch size (HTTP 413, Kafka MESSAGE_TOO_LARGE), so a batch
// is halved and each half delivered again; only a single event is dropped.
// It reports whether it split (and so passed held to the halves).
func (qs *QueuedSink) splitOrDrop(events []*Event, operation string, write func(context.Context, []*Event) error, err error, held bool) bool {
	if len(events) > 1 {
		mid := len(events) / 2
		qs.logger.Info("splitting audit batch after a permanent failure",
			zap.Int("count", len(events)), zap.Error(err))
		qs.deliver(events[:mid], operation, write, true, held)
		qs.deliver(events[mid:], operation, write, true, held)
		return true
	}
	qs.recordDrop(1, lossReason(err))
	qs.logger.Error("audit event cannot be delivered",
		zap.String("event_id", events[0].ID), zap.String("event_type", string(events[0].Type)),
		zap.String("operation", operation), zap.Error(err))
	return false
}

// releasePanickedBatch accounts for the events a worker held when it panicked
// outside the guarded sink write: they are lost, so they count as a "panic"
// drop and no longer as in flight (drain would otherwise wait for them).
func (qs *QueuedSink) releasePanickedBatch(count int64) {
	if count == 0 {
		return
	}
	qs.inFlight.Add(-count)
	qs.recordDrop(int(count), "panic")
}

// recordDelivered records a successful write of count events.
func (qs *QueuedSink) recordDelivered(count int) {
	if asynchronousKafkaSink(qs.sink) != nil {
		return
	}
	// Record the success first: a reader that sees the new
	// Health().ProcessedEvents then also sees the healthy state.
	qs.mu.Lock()
	qs.lastSuccessTime = time.Now()
	qs.mu.Unlock()
	qs.consecutiveFails.Store(0)
	qs.circuitOpen.Store(false)
	metrics.AuditEventsProcessed.WithLabelValues(qs.sink.Name()).Add(float64(count))
	qs.processedEvents.Add(int64(count))
}

// recordFailure records a failed write of count events.
func (qs *QueuedSink) recordFailure(count int, operation string, err error) {
	qs.failedEvents.Add(int64(count))
	metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), operation).Add(float64(count))
	qs.recordLastError(err)
}

func (qs *QueuedSink) recordLastError(err error) {
	qs.mu.Lock()
	qs.lastError = err.Error()
	qs.lastErrorTime = time.Now()
	qs.mu.Unlock()
}

// retain keeps a batch whose retry window is exhausted and retries it every
// RetryMaxBackoff until it is delivered, fails permanently or the sink
// closes. Each write still goes through the sink's circuit breaker, whose
// half-open probes therefore continue during a long outage. Retained
// retries count only as error_type="retry", not as further failed events.
// The caller accounts the events in the retained gauge; retain reports
// whether it split the batch.
func (qs *QueuedSink) retain(events []*Event, operation string, write func(context.Context, []*Event) error, lastErr error) bool {
	count := len(events)
	name := qs.sink.Name()
	qs.logger.Warn("audit delivery retry window exhausted; retaining events until the sink recovers",
		zap.Int("count", count), zap.String("operation", operation), zap.Error(lastErr))
	start := time.Now()
	for {
		timer := time.NewTimer(qs.config.RetryMaxBackoff)
		select {
		case <-timer.C:
		case <-qs.stop:
			timer.Stop()
			qs.shutdownDrop(events)
			return false
		}
		// Close bounds its drain by WriteTimeout too, so this write cannot
		// outlive the shutdown budget by more than one write.
		writeCtx, cancel := context.WithTimeout(withRetainedAttempt(context.Background()), qs.config.WriteTimeout)
		err := qs.invokeWrite(writeCtx, func(ctx context.Context) error { return write(ctx, events) })
		cancel()
		if err == nil {
			qs.recordDelivered(count)
			qs.logger.Info("retained audit events delivered",
				zap.Int("count", count), zap.Duration("retained_for", time.Since(start)))
			return false
		}
		qs.recordLastError(err)
		metrics.AuditSinkErrors.WithLabelValues(name, "retry").Inc()
		if permanentDeliveryError(err) || errors.Is(err, errSinkPanic) {
			return qs.splitOrDrop(events, operation, write, err, true)
		}
	}
}

type retainedAttemptKey struct{}

// withRetainedAttempt marks a periodic retry of a retained batch. Sinks then
// skip their own per-attempt error counters: retained retries count only as
// error_type="retry".
func withRetainedAttempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, retainedAttemptKey{}, true)
}

func isRetainedAttempt(ctx context.Context) bool {
	retained, _ := ctx.Value(retainedAttemptKey{}).(bool)
	return retained
}

func asynchronousKafkaSink(sink Sink) *KafkaSink {
	switch sink := sink.(type) {
	case *KafkaSink:
		if sink.writer != nil && sink.writer.Async {
			return sink
		}
	case *CircuitBreakerSink:
		return asynchronousKafkaSink(sink.sink)
	case *filteredBatchSink:
		return asynchronousKafkaSink(sink.sink)
	case *filteredSink:
		return asynchronousKafkaSink(sink.sink)
	}
	return nil
}

func queuedCircuitBreaker(sink Sink) *CircuitBreakerSink {
	switch sink := sink.(type) {
	case *CircuitBreakerSink:
		return sink
	case *filteredBatchSink:
		return queuedCircuitBreaker(sink.sink)
	case *filteredSink:
		return queuedCircuitBreaker(sink.sink)
	default:
		return nil
	}
}

// Health returns the current health status of this sink.
func (qs *QueuedSink) Health() QueuedSinkHealth {
	qs.mu.RLock()
	lastError := qs.lastError
	lastErrorTime := qs.lastErrorTime
	lastSuccessTime := qs.lastSuccessTime
	qs.mu.RUnlock()

	queueLen := len(qs.queue)
	queueCap := cap(qs.queue)
	circuitOpen := qs.circuitOpen.Load()
	consecutiveFails := int(qs.consecutiveFails.Load())
	circuitState := "closed"
	if circuitOpen {
		circuitState = "open"
	}
	if sink := queuedCircuitBreaker(qs.sink); sink != nil {
		stats := sink.Stats()
		circuitState = stats.State.String()
		circuitOpen = stats.State == CircuitOpen
		consecutiveFails = int(stats.ConsecutiveFails)
	}

	// Consider healthy if:
	// - Circuit is not open. A half-open breaker that delivered its probe
	//   stays half-open until the next event, and the sink is working.
	// - Queue is not > 80% full
	// - The latest delivery succeeded OR no errors yet. An idle sink keeps
	//   the result of its last delivery: audit traffic can pause for hours.
	processed := qs.processedEvents.Load()
	dropped, failed := qs.droppedEvents.Load(), qs.failedEvents.Load()
	if sink := asynchronousKafkaSink(qs.sink); sink != nil {
		processed = sink.messagesWritten.Load()
		dropped += sink.asyncFailures.Load()
		failed += sink.asyncFailures.Load()
		if completed, err := sink.LastError(); completed.After(lastErrorTime) {
			lastErrorTime = completed
			lastError = err.Error()
		}
		if completed, ok := sink.lastSuccessTime.Load().(time.Time); ok && completed.After(lastSuccessTime) {
			lastSuccessTime = completed
		}
	}
	healthy := !circuitOpen &&
		float64(queueLen) < float64(queueCap)*0.8 &&
		(lastSuccessTime.After(lastErrorTime) || lastErrorTime.IsZero())
	return QueuedSinkHealth{
		Name:             qs.sink.Name(),
		Healthy:          healthy,
		QueueLength:      queueLen,
		QueueCapacity:    queueCap,
		DroppedEvents:    dropped,
		ProcessedEvents:  processed,
		FailedEvents:     failed,
		ConsecutiveFails: consecutiveFails,
		CircuitOpen:      circuitOpen,
		CircuitState:     circuitState,
		LastError:        lastError,
		LastErrorTime:    lastErrorTime,
		LastSuccessTime:  lastSuccessTime,
	}
}

// idle reports that the queue is empty and no worker holds an event.
func (qs *QueuedSink) idle() bool {
	return len(qs.queue) == 0 && qs.inFlight.Load() == 0
}

// Close shuts down the queued sink gracefully.
func (qs *QueuedSink) Close() error {
	qs.shutdownDeadline.CompareAndSwap(0, time.Now().Add(qs.config.WriteTimeout).UnixNano())
	if qs.closed.Swap(true) {
		return nil // Already closed
	}
	close(qs.stop)

	// Take the write lock so no enqueue() is in flight, then close. Every send
	// site re-checks qs.closed under the read lock, so after this point no
	// goroutine can send on qs.queue.
	qs.sendMu.Lock()
	close(qs.queue)
	qs.sendMu.Unlock()

	qs.wg.Wait()

	// Close underlying sink
	return qs.sink.Close()
}

// Name returns the underlying sink's name.
func (qs *QueuedSink) Name() string {
	return qs.sink.Name()
}

// IsolatedMultiSink wraps multiple QueuedSinks, each with their own queue.
// Events are broadcast to all sinks independently.
type IsolatedMultiSink struct {
	sinks  []*QueuedSink
	logger *zap.Logger
}

// NewIsolatedMultiSink creates a multi-sink where each underlying sink
// has its own queue and operates independently.
func NewIsolatedMultiSink(sinks []Sink, cfg QueuedSinkConfig, logger *zap.Logger, perSink ...QueuedSinkConfig) *IsolatedMultiSink {
	queuedSinks := make([]*QueuedSink, 0, len(sinks))
	for i, sink := range sinks {
		sinkConfig := cfg
		if i < len(perSink) {
			sinkConfig = perSink[i]
		}
		queuedSinks = append(queuedSinks, NewQueuedSink(sink, sinkConfig, logger))
	}

	return &IsolatedMultiSink{
		sinks:  queuedSinks,
		logger: logger.Named("isolated-multi-sink"),
	}
}

// Write broadcasts the event to all queued sinks. Per-sink DropOnFull=false
// waits for capacity up to the write or caller deadline; sensitive events may fall back to
// the underlying sink when a queue is full or its circuit is open.
func (ims *IsolatedMultiSink) Write(ctx context.Context, event *Event) error {
	return ims.WriteBatch(ctx, []*Event{event})
}

// Close shuts down all queued sinks.
func (ims *IsolatedMultiSink) Close() error {
	var wg sync.WaitGroup
	errs := make([]error, len(ims.sinks))
	for i, qs := range ims.sinks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = qs.Close()
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Name returns the sink identifier.
func (ims *IsolatedMultiSink) Name() string {
	return "isolated-multi"
}

// Health returns the health status of all underlying sinks.
func (ims *IsolatedMultiSink) Health() []QueuedSinkHealth {
	healths := make([]QueuedSinkHealth, 0, len(ims.sinks))
	for _, qs := range ims.sinks {
		healths = append(healths, qs.Health())
	}
	return healths
}

// drain waits until every queued sink is idle, or at most the longest retry
// window of its sinks, so a replaced pipeline delivers the events it holds.
// It returns early when stop is closed (the service is shutting down).
// ponytail: polls, and treats two idle polls 200 ms apart as drained, which
// covers the manager's 100 ms batch timeout; a pending-event handoff to the
// new pipeline would avoid the wait.
func (ims *IsolatedMultiSink) drain(manager *Manager, stop <-chan struct{}) {
	var window time.Duration
	for _, qs := range ims.sinks {
		window = max(window, qs.config.RetryTimeout)
	}
	deadline := time.Now().Add(window)
	idle := func() bool {
		if manager != nil && len(manager.asyncQueue) > 0 {
			return false
		}
		for _, qs := range ims.sinks {
			if !qs.idle() {
				return false
			}
		}
		return true
	}
	for quiet := 0; quiet < 2 && time.Now().Before(deadline); {
		select {
		case <-stop:
			return
		case <-time.After(200 * time.Millisecond):
		}
		if idle() {
			quiet++
		} else {
			quiet = 0
		}
	}
}

// handOver makes each sink pass the events it holds at shutdown to the sink
// with the same AuditConfig, sink type and sink name in next. That key is
// unique: AuditConfig is cluster-scoped and its validation rejects duplicate
// sink names. A sink without
// a successor (removed or retyped by the reload) still counts them as
// "shutdown" drops. Each hand-over is bounded by the receiving queue's
// enqueue rules and one handover deadline per retiring sink and manager.
func (ims *IsolatedMultiSink) handOver(next *IsolatedMultiSink) {
	for _, old := range ims.sinks {
		for _, successor := range next.sinks {
			if successor.owner == old.owner && successor.Name() == old.Name() {
				old.HandOver(successor)
				break
			}
		}
	}
}

// handingOver reports whether a reload set successors for this pipeline.
func (ims *IsolatedMultiSink) handingOver() bool {
	for _, qs := range ims.sinks {
		if qs.successor.Load() != nil {
			return true
		}
	}
	return false
}

// handOverIngress passes an event the manager accepted but did not yet route
// to every sink of this retiring pipeline that would have taken it. Each
// sink forwards it only to its own matching successor, so a retargeted or
// removed sink counts it as "shutdown" instead of sending it elsewhere.
func (ims *IsolatedMultiSink) handOverIngress(ctx context.Context, event *Event) {
	for _, qs := range ims.sinks {
		if !queuedEventAllowed(qs.sink, event) {
			continue
		}
		successor := qs.successor.Load()
		if successor == nil {
			qs.recordDrop(1, "shutdown")
			continue
		}
		_ = successor.writeHandedOver(ctx, event)
	}
}

// IsHealthy returns true if all sinks are healthy.
func (ims *IsolatedMultiSink) IsHealthy() bool {
	for _, qs := range ims.sinks {
		if !qs.Health().Healthy {
			return false
		}
	}
	return true
}

// processBatchQueue handles events from the async queue using batch writes.
func (qs *QueuedSink) processBatchQueue(workerID int, batchSink BatchSink) {
	defer qs.wg.Done()
	batch := make([]*Event, 0, qs.config.BatchSize)
	defer func() {
		if r := recover(); r != nil {
			qs.logger.Error("panic in audit batch queue worker recovered",
				zap.Int("worker", workerID),
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
			metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "panic").Inc()
			qs.releasePanickedBatch(int64(len(batch)))
			qs.wg.Add(1)
			go qs.processBatchQueue(workerID, batchSink)
		}
	}()

	ticker := time.NewTicker(qs.config.BatchTimeout)
	defer ticker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		if qs.dropShutdownBacklog(batch) {
			qs.inFlight.Add(-int64(len(batch)))
			batch = batch[:0]
			return
		}
		qs.deliver(batch, "batch_write", batchSink.WriteBatch, false, false)
		qs.inFlight.Add(-int64(len(batch)))
		batch = batch[:0]
	}

	for {
		select {
		case event, ok := <-qs.queue:
			if !ok {
				flushBatch()
				return
			}
			qs.inFlight.Add(1)
			batch = append(batch, event)
			if len(batch) >= qs.config.BatchSize {
				flushBatch()
			}
		case <-ticker.C:
			flushBatch()
		}
	}
}

// WriteBatch enqueues multiple events for async processing. A sensitive event
// may synchronously fall back to the underlying sink when a queue is full or
// its circuit is open.
func (qs *QueuedSink) WriteBatch(ctx context.Context, events []*Event) error {
	var errs []error
	for _, event := range events {
		if err := qs.Write(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// WriteBatch broadcasts the batch to all queued sinks in parallel. Per-sink
// DropOnFull=false waits for capacity up to the write or caller deadline;
// sensitive events may synchronously fall back to
// the underlying sinks when a queue is full or a circuit is open.
func (ims *IsolatedMultiSink) WriteBatch(ctx context.Context, events []*Event) error {
	var wg sync.WaitGroup
	errs := make([]error, len(ims.sinks))
	for i, qs := range ims.sinks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, event := range events {
				if err := qs.Write(ctx, event); err != nil {
					errs[i] = errors.Join(errs[i], err)
				}
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
