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

	// Circuit breaker state
	consecutiveFails atomic.Int32
	circuitOpen      atomic.Bool
	lastResetAttempt atomic.Int64 // Unix timestamp

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

	batchSink, isBatchSink := sink.(BatchSink)

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

// Write enqueues an event for async processing. A sensitive event may
// synchronously fall back to the underlying sink when a queue is full or its
// circuit is open.
func (qs *QueuedSink) Write(ctx context.Context, event *Event) error {
	if qs.closed.Load() {
		return fmt.Errorf("queued sink %s is closed", qs.sink.Name())
	}
	if !qs.config.DropOnFull {
		writeCtx, cancel := context.WithTimeout(ctx, qs.config.WriteTimeout)
		defer cancel()
		qs.sendMu.RLock()
		defer qs.sendMu.RUnlock()
		if qs.closed.Load() {
			return fmt.Errorf("queued sink %s is closed", qs.sink.Name())
		}
		select {
		case qs.queue <- event:
			return nil
		case <-qs.stop:
			return fmt.Errorf("queued sink %s is closed", qs.sink.Name())
		case <-writeCtx.Done():
			qs.recordDrop(1, "enqueue_timeout")
			return fmt.Errorf("enqueue audit event: %w", writeCtx.Err())
		}
	}

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
			// Non-sensitive event: drop silently
			qs.droppedEvents.Add(1)
			metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "circuit_open").Inc()
			return nil
		}
	}

	// Non-blocking send to queue (safe against a concurrent Close).
	if qs.enqueue(event) {
		return nil
	}
	if qs.closed.Load() {
		return fmt.Errorf("queued sink %s is closed", qs.sink.Name())
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
	if !qs.config.DropOnFull {
		qs.logger.Warn("audit queue full, dropping event",
			zap.String("sink", qs.sink.Name()),
			zap.String("event_type", string(event.Type)),
			zap.String("event_id", event.ID))
	}
	return nil
}

func (qs *QueuedSink) syncFallback(ctx context.Context, event *Event) error {
	writeCtx, cancel := context.WithTimeout(ctx, qs.config.WriteTimeout)
	defer cancel()
	err := qs.sink.Write(writeCtx, event)
	if err != nil {
		qs.failedEvents.Add(1)
		metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "sync_fallback").Inc()
		qs.recordDrop(1, "sync_fallback")
	}
	return err
}

// processQueue is the worker goroutine that processes events from the queue.
func (qs *QueuedSink) processQueue(workerID int) {
	defer qs.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			qs.logger.Error("panic in audit queue worker recovered",
				zap.Int("worker", workerID),
				zap.Any("panic", r))
			metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "panic").Inc()
			// Restart the worker to maintain processing capacity
			qs.wg.Add(1)
			go qs.processQueue(workerID)
		}
	}()

	for event := range qs.queue {
		qs.deliver(1, "write", func(ctx context.Context) error {
			return qs.sink.Write(ctx, event)
		})
	}
}

func (qs *QueuedSink) recordDrop(count int, reason string) {
	qs.droppedEvents.Add(int64(count))
	metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), reason).Add(float64(count))
	qs.logger.Warn("audit events dropped", zap.Int("count", count), zap.String("reason", reason))
}

// deliver retains the same event identities in the worker through bounded retries.
// A Kafka acknowledgement may be lost after delivery, so consumers must deduplicate IDs.
func (qs *QueuedSink) deliver(count int, operation string, write func(context.Context) error) {
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
	for attempt := 0; attempt < qs.config.RetryAttempts; attempt++ {
		writeCtx, writeCancel := context.WithTimeout(retryCtx, qs.config.WriteTimeout)
		err = write(writeCtx)
		writeCancel()
		if err == nil {
			qs.processedEvents.Add(int64(count))
			qs.consecutiveFails.Store(0)
			qs.circuitOpen.Store(false)
			metrics.AuditEventsProcessed.WithLabelValues(qs.sink.Name()).Add(float64(count))
			qs.mu.Lock()
			qs.lastSuccessTime = time.Now()
			qs.mu.Unlock()
			return
		}
		qs.failedEvents.Add(int64(count))
		metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), operation).Add(float64(count))
		qs.mu.Lock()
		qs.lastError = err.Error()
		qs.lastErrorTime = time.Now()
		qs.mu.Unlock()
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
	fails := qs.consecutiveFails.Add(1)
	if int(fails) >= qs.config.CircuitBreakerThreshold {
		qs.circuitOpen.Store(true)
		qs.lastResetAttempt.Store(time.Now().Unix())
	}
	qs.recordDrop(count, "retry_exhausted")
	qs.logger.Error("audit delivery retries exhausted",
		zap.Int("count", count), zap.String("operation", operation), zap.Error(err))
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

	// Consider healthy if:
	// - Circuit is not open
	// - Queue is not > 80% full
	// - Had a recent success (within last minute) OR no errors yet
	healthy := !circuitOpen &&
		float64(queueLen) < float64(queueCap)*0.8 &&
		(lastSuccessTime.After(time.Now().Add(-1*time.Minute)) || lastErrorTime.IsZero())

	return QueuedSinkHealth{
		Name:             qs.sink.Name(),
		Healthy:          healthy,
		QueueLength:      queueLen,
		QueueCapacity:    queueCap,
		DroppedEvents:    qs.droppedEvents.Load(),
		ProcessedEvents:  qs.processedEvents.Load(),
		FailedEvents:     qs.failedEvents.Load(),
		ConsecutiveFails: consecutiveFails,
		CircuitOpen:      circuitOpen,
		LastError:        lastError,
		LastErrorTime:    lastErrorTime,
		LastSuccessTime:  lastSuccessTime,
	}
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

// Write broadcasts the event to all queued sinks. Ordinary events are
// enqueued without waiting; sensitive events may synchronously fall back to
// the underlying sink when a queue is full or its circuit is open.
func (ims *IsolatedMultiSink) Write(ctx context.Context, event *Event) error {
	var errs []error
	for _, qs := range ims.sinks {
		// Each sink may synchronously write sensitive events on fallback paths.
		if err := qs.Write(ctx, event); err != nil && IsSensitiveEvent(event.Type) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close shuts down all queued sinks.
func (ims *IsolatedMultiSink) Close() error {
	var lastErr error
	for _, qs := range ims.sinks {
		if err := qs.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
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
	defer func() {
		if r := recover(); r != nil {
			qs.logger.Error("panic in audit batch queue worker recovered",
				zap.Int("worker", workerID),
				zap.Any("panic", r))
			metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "panic").Inc()
			qs.wg.Add(1)
			go qs.processBatchQueue(workerID, batchSink)
		}
	}()

	batch := make([]*Event, 0, qs.config.BatchSize)
	ticker := time.NewTicker(qs.config.BatchTimeout)
	defer ticker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}

		qs.deliver(len(batch), "batch_write", func(ctx context.Context) error {
			return batchSink.WriteBatch(ctx, batch)
		})
		batch = batch[:0]
	}

	for {
		select {
		case event, ok := <-qs.queue:
			if !ok {
				flushBatch()
				return
			}
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
	for _, event := range events {
		if err := qs.Write(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

// WriteBatch broadcasts the batch to all queued sinks. Ordinary events are
// enqueued without waiting; sensitive events may synchronously fall back to
// the underlying sinks when a queue is full or a circuit is open.
func (ims *IsolatedMultiSink) WriteBatch(ctx context.Context, events []*Event) error {
	var errs []error
	for _, qs := range ims.sinks {
		for _, event := range events {
			if err := qs.Write(ctx, event); err != nil && IsSensitiveEvent(event.Type) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
