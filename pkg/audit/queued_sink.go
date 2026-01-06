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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// QueuedSinkConfig configures a QueuedSink.
type QueuedSinkConfig struct {
	// QueueSize is the size of the async event queue.
	// Default: 10000
	QueueSize int

	// WorkerCount is the number of async processing workers.
	// Default: 2
	WorkerCount int

	// WriteTimeout is the timeout for writing to the underlying sink.
	// Default: 5s
	WriteTimeout time.Duration

	// DropOnFull controls behavior when queue is full.
	// If true, new events are dropped silently (non-blocking).
	// If false, events are still dropped but a warning is logged.
	// Default: true
	DropOnFull bool

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
		WriteTimeout:            5 * time.Second,
		DropOnFull:              true,
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
	wg     sync.WaitGroup
	closed atomic.Bool
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

	qs := &QueuedSink{
		sink:   sink,
		queue:  make(chan *Event, cfg.QueueSize),
		config: cfg,
		logger: logger.Named("queued-sink").With(zap.String("sink", sink.Name())),
	}

	// Start workers
	for i := 0; i < cfg.WorkerCount; i++ {
		qs.wg.Add(1)
		go qs.processQueue(i)
	}

	qs.logger.Info("queued sink started",
		zap.Int("queue_size", cfg.QueueSize),
		zap.Int("workers", cfg.WorkerCount),
		zap.Duration("write_timeout", cfg.WriteTimeout),
		zap.Int("circuit_breaker_threshold", cfg.CircuitBreakerThreshold))

	return qs
}

// Write enqueues an event for async processing (non-blocking).
func (qs *QueuedSink) Write(_ context.Context, event *Event) error {
	if qs.closed.Load() {
		return fmt.Errorf("queued sink %s is closed", qs.sink.Name())
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
			// Circuit still open, drop event
			qs.droppedEvents.Add(1)
			metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "circuit_open").Inc()
			return nil // Don't return error - just drop silently
		}
	}

	// Non-blocking send to queue
	select {
	case qs.queue <- event:
		return nil
	default:
		// Queue is full - drop event
		qs.droppedEvents.Add(1)
		metrics.AuditEventsDropped.WithLabelValues(qs.sink.Name(), "queue_full").Inc()
		if !qs.config.DropOnFull {
			qs.logger.Warn("audit queue full, dropping event",
				zap.String("sink", qs.sink.Name()),
				zap.String("event_type", string(event.Type)),
				zap.String("event_id", event.ID))
		}
		return nil // Don't return error - just drop silently
	}
}

// processQueue is the worker goroutine that processes events from the queue.
func (qs *QueuedSink) processQueue(workerID int) {
	defer qs.wg.Done()

	for event := range qs.queue {
		ctx, cancel := context.WithTimeout(context.Background(), qs.config.WriteTimeout)
		err := qs.sink.Write(ctx, event)
		cancel()

		if err != nil {
			qs.failedEvents.Add(1)
			fails := qs.consecutiveFails.Add(1)
			metrics.AuditSinkErrors.WithLabelValues(qs.sink.Name(), "write").Inc()

			qs.mu.Lock()
			qs.lastError = err.Error()
			qs.lastErrorTime = time.Now()
			qs.mu.Unlock()

			qs.logger.Error("failed to write audit event",
				zap.Int("worker", workerID),
				zap.String("event_id", event.ID),
				zap.String("event_type", string(event.Type)),
				zap.String("error", err.Error()),
				zap.Int32("consecutive_fails", fails))

			// Check if we should open the circuit breaker
			if int(fails) >= qs.config.CircuitBreakerThreshold {
				if qs.circuitOpen.CompareAndSwap(false, true) {
					qs.lastResetAttempt.Store(time.Now().Unix())
					qs.logger.Warn("circuit breaker opened for sink",
						zap.String("sink", qs.sink.Name()),
						zap.Int32("consecutive_fails", fails))
				}
			}
		} else {
			qs.processedEvents.Add(1)
			qs.consecutiveFails.Store(0)
			metrics.AuditEventsProcessed.WithLabelValues(qs.sink.Name()).Inc()

			qs.mu.Lock()
			qs.lastSuccessTime = time.Now()
			qs.mu.Unlock()
		}
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
	if qs.closed.Swap(true) {
		return nil // Already closed
	}

	close(qs.queue)
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
func NewIsolatedMultiSink(sinks []Sink, cfg QueuedSinkConfig, logger *zap.Logger) *IsolatedMultiSink {
	queuedSinks := make([]*QueuedSink, 0, len(sinks))
	for _, sink := range sinks {
		queuedSinks = append(queuedSinks, NewQueuedSink(sink, cfg, logger))
	}

	return &IsolatedMultiSink{
		sinks:  queuedSinks,
		logger: logger.Named("isolated-multi-sink"),
	}
}

// Write broadcasts the event to all queued sinks (non-blocking).
// Each sink receives the event independently in its own queue.
func (ims *IsolatedMultiSink) Write(ctx context.Context, event *Event) error {
	for _, qs := range ims.sinks {
		// Each QueuedSink.Write is non-blocking
		_ = qs.Write(ctx, event)
	}
	return nil
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
