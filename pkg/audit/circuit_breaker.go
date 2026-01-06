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
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// CircuitState represents the current state of the circuit breaker.
type CircuitState int32

const (
	// CircuitClosed indicates normal operation - requests flow through.
	CircuitClosed CircuitState = iota
	// CircuitOpen indicates the circuit is tripped - requests are blocked.
	CircuitOpen
	// CircuitHalfOpen indicates the circuit is testing - limited requests allowed.
	CircuitHalfOpen
)

// String returns the string representation of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures the circuit breaker behavior.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening the circuit.
	// Default: 5
	FailureThreshold int

	// SuccessThreshold is the number of consecutive successes in half-open state
	// required to close the circuit.
	// Default: 2
	SuccessThreshold int

	// OpenTimeout is how long to wait before transitioning from open to half-open.
	// Default: 30s
	OpenTimeout time.Duration

	// HalfOpenMaxRequests is the maximum number of requests allowed in half-open state.
	// Default: 1
	HalfOpenMaxRequests int

	// OnStateChange is an optional callback when the circuit state changes.
	OnStateChange func(from, to CircuitState)
}

// DefaultCircuitBreakerConfig returns sensible default configuration.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:    5,
		SuccessThreshold:    2,
		OpenTimeout:         30 * time.Second,
		HalfOpenMaxRequests: 1,
	}
}

// ErrCircuitOpen is returned when the circuit breaker is open.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreaker implements the circuit breaker pattern for sink resilience.
// It prevents cascading failures by temporarily blocking requests to failing sinks.
type CircuitBreaker struct {
	name   string
	config CircuitBreakerConfig
	logger *zap.Logger

	// State tracking
	state            atomic.Int32 // CircuitState
	consecutiveFails atomic.Int64
	consecutiveSuccs atomic.Int64
	halfOpenRequests atomic.Int64
	lastFailureTime  atomic.Value // time.Time
	lastStateChange  atomic.Value // time.Time
	lastError        atomic.Value // error

	// Metrics
	totalRequests   atomic.Int64
	totalSuccesses  atomic.Int64
	totalFailures   atomic.Int64
	totalRejections atomic.Int64

	// Mutex for state transitions
	mu sync.Mutex
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(name string, cfg CircuitBreakerConfig, logger *zap.Logger) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.SuccessThreshold <= 0 {
		cfg.SuccessThreshold = 2
	}
	if cfg.OpenTimeout <= 0 {
		cfg.OpenTimeout = 30 * time.Second
	}
	if cfg.HalfOpenMaxRequests <= 0 {
		cfg.HalfOpenMaxRequests = 1
	}

	cb := &CircuitBreaker{
		name:   name,
		config: cfg,
		logger: logger.Named("circuit-breaker").With(zap.String("sink", name)),
	}
	cb.state.Store(int32(CircuitClosed))
	cb.lastStateChange.Store(time.Now())

	logger.Info("circuit breaker created",
		zap.String("sink", name),
		zap.Int("failure_threshold", cfg.FailureThreshold),
		zap.Int("success_threshold", cfg.SuccessThreshold),
		zap.Duration("open_timeout", cfg.OpenTimeout))

	return cb
}

// Execute wraps a function call with circuit breaker protection.
// Returns ErrCircuitOpen if the circuit is open.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	if !cb.canExecute() {
		cb.totalRejections.Add(1)
		metrics.AuditCircuitBreakerRejections.WithLabelValues(cb.name).Inc()
		return ErrCircuitOpen
	}

	cb.totalRequests.Add(1)

	err := fn(ctx)

	if err != nil {
		cb.recordFailure(err)
		return err
	}

	cb.recordSuccess()
	return nil
}

// canExecute checks if a request can be executed based on circuit state.
func (cb *CircuitBreaker) canExecute() bool {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if we should transition to half-open
		lastChange, ok := cb.lastStateChange.Load().(time.Time)
		if ok && time.Since(lastChange) >= cb.config.OpenTimeout {
			cb.transitionTo(CircuitHalfOpen)
			return true
		}
		return false

	case CircuitHalfOpen:
		// Only allow limited requests in half-open
		current := cb.halfOpenRequests.Add(1)
		if current <= int64(cb.config.HalfOpenMaxRequests) {
			return true
		}
		cb.halfOpenRequests.Add(-1) // Revert the increment
		return false

	default:
		return false
	}
}

// recordSuccess records a successful operation.
func (cb *CircuitBreaker) recordSuccess() {
	cb.totalSuccesses.Add(1)
	cb.consecutiveFails.Store(0)
	successes := cb.consecutiveSuccs.Add(1)

	state := CircuitState(cb.state.Load())
	if state == CircuitHalfOpen && int(successes) >= cb.config.SuccessThreshold {
		cb.transitionTo(CircuitClosed)
	}
}

// recordFailure records a failed operation.
func (cb *CircuitBreaker) recordFailure(err error) {
	cb.totalFailures.Add(1)
	cb.consecutiveSuccs.Store(0)
	cb.lastError.Store(err)
	cb.lastFailureTime.Store(time.Now())
	failures := cb.consecutiveFails.Add(1)

	state := CircuitState(cb.state.Load())
	switch state {
	case CircuitClosed:
		if int(failures) >= cb.config.FailureThreshold {
			cb.transitionTo(CircuitOpen)
		}
	case CircuitHalfOpen:
		// Any failure in half-open trips back to open
		cb.transitionTo(CircuitOpen)
	}
}

// transitionTo changes the circuit state.
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	oldState := CircuitState(cb.state.Load())
	if oldState == newState {
		return
	}

	cb.state.Store(int32(newState))
	cb.lastStateChange.Store(time.Now())
	cb.consecutiveFails.Store(0)
	cb.consecutiveSuccs.Store(0)
	cb.halfOpenRequests.Store(0)

	cb.logger.Info("circuit breaker state changed",
		zap.String("from", oldState.String()),
		zap.String("to", newState.String()))

	// Update metrics
	metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(newState))

	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(oldState, newState)
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// Stats returns circuit breaker statistics.
type CircuitBreakerStats struct {
	State            CircuitState
	ConsecutiveFails int64
	ConsecutiveSuccs int64
	TotalRequests    int64
	TotalSuccesses   int64
	TotalFailures    int64
	TotalRejections  int64
	LastFailureTime  time.Time
	LastStateChange  time.Time
	LastError        error
}

// Stats returns the current circuit breaker statistics.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	stats := CircuitBreakerStats{
		State:            CircuitState(cb.state.Load()),
		ConsecutiveFails: cb.consecutiveFails.Load(),
		ConsecutiveSuccs: cb.consecutiveSuccs.Load(),
		TotalRequests:    cb.totalRequests.Load(),
		TotalSuccesses:   cb.totalSuccesses.Load(),
		TotalFailures:    cb.totalFailures.Load(),
		TotalRejections:  cb.totalRejections.Load(),
	}

	if t, ok := cb.lastFailureTime.Load().(time.Time); ok {
		stats.LastFailureTime = t
	}
	if t, ok := cb.lastStateChange.Load().(time.Time); ok {
		stats.LastStateChange = t
	}
	if err, ok := cb.lastError.Load().(error); ok {
		stats.LastError = err
	}

	return stats
}

// ForceOpen forces the circuit to open state (for testing/maintenance).
func (cb *CircuitBreaker) ForceOpen() {
	cb.transitionTo(CircuitOpen)
}

// ForceClose forces the circuit to closed state (for recovery).
func (cb *CircuitBreaker) ForceClose() {
	cb.transitionTo(CircuitClosed)
}

// Reset resets the circuit breaker to its initial state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state.Store(int32(CircuitClosed))
	cb.consecutiveFails.Store(0)
	cb.consecutiveSuccs.Store(0)
	cb.halfOpenRequests.Store(0)
	cb.totalRequests.Store(0)
	cb.totalSuccesses.Store(0)
	cb.totalFailures.Store(0)
	cb.totalRejections.Store(0)
	cb.lastStateChange.Store(time.Now())

	cb.logger.Info("circuit breaker reset")
	metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(CircuitClosed))
}

// IsHealthy returns true if the circuit is closed (healthy).
func (cb *CircuitBreaker) IsHealthy() bool {
	return CircuitState(cb.state.Load()) == CircuitClosed
}

// CircuitBreakerSink wraps a Sink with circuit breaker protection.
type CircuitBreakerSink struct {
	sink    Sink
	breaker *CircuitBreaker
	logger  *zap.Logger
}

// NewCircuitBreakerSink wraps a sink with circuit breaker protection.
func NewCircuitBreakerSink(sink Sink, cfg CircuitBreakerConfig, logger *zap.Logger) *CircuitBreakerSink {
	return &CircuitBreakerSink{
		sink:    sink,
		breaker: NewCircuitBreaker(sink.Name(), cfg, logger),
		logger:  logger.Named("cb-sink").With(zap.String("sink", sink.Name())),
	}
}

// Write implements Sink interface with circuit breaker protection.
func (s *CircuitBreakerSink) Write(ctx context.Context, event *Event) error {
	return s.breaker.Execute(ctx, func(ctx context.Context) error {
		return s.sink.Write(ctx, event)
	})
}

// WriteBatch implements BatchSink interface with circuit breaker protection.
func (s *CircuitBreakerSink) WriteBatch(ctx context.Context, events []*Event) error {
	batchSink, ok := s.sink.(BatchSink)
	if !ok {
		// Fallback to individual writes
		for _, event := range events {
			if err := s.Write(ctx, event); err != nil {
				return err
			}
		}
		return nil
	}

	return s.breaker.Execute(ctx, func(ctx context.Context) error {
		return batchSink.WriteBatch(ctx, events)
	})
}

// Close closes the underlying sink.
func (s *CircuitBreakerSink) Close() error {
	s.logger.Info("closing circuit breaker sink",
		zap.String("state", s.breaker.State().String()))
	return s.sink.Close()
}

// Name returns the sink name.
func (s *CircuitBreakerSink) Name() string {
	return s.sink.Name()
}

// CircuitBreaker returns the underlying circuit breaker for status checks.
func (s *CircuitBreakerSink) CircuitBreaker() *CircuitBreaker {
	return s.breaker
}

// IsHealthy returns true if the circuit is in healthy state.
func (s *CircuitBreakerSink) IsHealthy() bool {
	return s.breaker.IsHealthy()
}

// Stats returns circuit breaker statistics.
func (s *CircuitBreakerSink) Stats() CircuitBreakerStats {
	return s.breaker.Stats()
}
