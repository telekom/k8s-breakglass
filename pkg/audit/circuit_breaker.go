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

	gobreaker "github.com/sony/gobreaker/v2"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

type CircuitState int32

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

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

type CircuitBreakerConfig struct {
	FailureThreshold    int
	SuccessThreshold    int
	OpenTimeout         time.Duration
	HalfOpenMaxRequests int
	OnStateChange       func(from, to CircuitState)
}

func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:    5,
		SuccessThreshold:    2,
		OpenTimeout:         30 * time.Second,
		HalfOpenMaxRequests: 1,
	}
}

var ErrCircuitOpen = errors.New("circuit breaker is open")

var errHalfOpenProbeLimit = errors.New("half-open probe limit reached")

type storedError struct {
	err error
}

type CircuitBreaker struct {
	name   string
	config CircuitBreakerConfig
	logger *zap.Logger

	mu      sync.Mutex
	breaker *gobreaker.TwoStepCircuitBreaker[struct{}]

	state             atomic.Int32
	forcedOpen        atomic.Bool
	halfOpenRequests  atomic.Int64
	halfOpenSuccesses atomic.Int64
	lastFailureTime   atomic.Value
	lastStateChange   atomic.Value
	lastError         atomic.Value

	totalRequests   atomic.Int64
	totalSuccesses  atomic.Int64
	totalFailures   atomic.Int64
	totalRejections atomic.Int64
}

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
	cb.lastFailureTime.Store(time.Time{})
	cb.lastError.Store(storedError{})
	cb.breaker = cb.newBreaker()
	metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(CircuitClosed))

	logger.Info("circuit breaker created",
		zap.String("sink", name),
		zap.Int("failure_threshold", cfg.FailureThreshold),
		zap.Int("success_threshold", cfg.SuccessThreshold),
		zap.Duration("open_timeout", cfg.OpenTimeout))

	return cb
}

func (cb *CircuitBreaker) newBreaker() *gobreaker.TwoStepCircuitBreaker[struct{}] {
	return gobreaker.NewTwoStepCircuitBreaker[struct{}](gobreaker.Settings{
		Name:        cb.name,
		MaxRequests: uint32(maxInt(cb.config.SuccessThreshold, cb.config.HalfOpenMaxRequests)),
		Timeout:     cb.config.OpenTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return int(counts.ConsecutiveFailures) >= cb.config.FailureThreshold
		},
		OnStateChange: func(_ string, from, to gobreaker.State) {
			cb.transitionState(mapGobreakerState(from), mapGobreakerState(to))
		},
		IsExcluded: func(err error) bool {
			return errors.Is(err, errHalfOpenProbeLimit)
		},
	})
}

func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	if cb.forcedOpen.Load() {
		cb.recordRejection()
		return ErrCircuitOpen
	}

	done, err := cb.breaker.Allow()
	if err != nil {
		cb.recordRejection()
		return ErrCircuitOpen
	}

	halfOpenProbe := cb.State() == CircuitHalfOpen
	if halfOpenProbe && cb.halfOpenRequests.Add(1) > int64(cb.config.HalfOpenMaxRequests) {
		cb.halfOpenRequests.Add(-1)
		done(errHalfOpenProbeLimit)
		cb.recordRejection()
		return ErrCircuitOpen
	}

	cb.totalRequests.Add(1)
	err = fn(ctx)
	if halfOpenProbe {
		cb.halfOpenRequests.Add(-1)
	}
	if err != nil {
		cb.totalFailures.Add(1)
		cb.lastError.Store(storedError{err: err})
		cb.lastFailureTime.Store(time.Now())
		done(err)
		return err
	}

	cb.totalSuccesses.Add(1)
	done(nil)
	if halfOpenProbe {
		successes := cb.halfOpenSuccesses.Add(1)
		cb.maybeCloseAfterHalfOpenSuccess(successes)
	}
	return nil
}

func (cb *CircuitBreaker) maybeCloseAfterHalfOpenSuccess(successes int64) {
	if int(successes) < cb.config.SuccessThreshold {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.forcedOpen.Load() || CircuitState(cb.state.Load()) != CircuitHalfOpen {
		return
	}
	if int(cb.halfOpenSuccesses.Load()) < cb.config.SuccessThreshold {
		return
	}

	cb.breaker = cb.newBreaker()
	cb.transitionStateLocked(CircuitHalfOpen, CircuitClosed)
	cb.lastError.Store(storedError{})
	cb.lastFailureTime.Store(time.Time{})
	cb.halfOpenRequests.Store(0)
	cb.halfOpenSuccesses.Store(0)
	metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(CircuitClosed))
	metrics.AuditCircuitBreakerStateTransitions.WithLabelValues(cb.name, CircuitHalfOpen.String(), CircuitClosed.String()).Inc()
	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(CircuitHalfOpen, CircuitClosed)
	}
	cb.logger.Info("circuit breaker state changed",
		zap.String("from", CircuitHalfOpen.String()),
		zap.String("to", CircuitClosed.String()))
}

func (cb *CircuitBreaker) recordRejection() {
	cb.totalRejections.Add(1)
	metrics.AuditCircuitBreakerRejections.WithLabelValues(cb.name).Inc()
}

func (cb *CircuitBreaker) transitionState(from, to CircuitState) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.transitionStateLocked(from, to)
	metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(to))
	metrics.AuditCircuitBreakerStateTransitions.WithLabelValues(cb.name, from.String(), to.String()).Inc()
	if cb.config.OnStateChange != nil {
		cb.config.OnStateChange(from, to)
	}
	cb.logger.Info("circuit breaker state changed",
		zap.String("from", from.String()),
		zap.String("to", to.String()))
}

func (cb *CircuitBreaker) transitionStateLocked(from, to CircuitState) {
	if from == to {
		return
	}
	cb.state.Store(int32(to))
	cb.lastStateChange.Store(time.Now())
	cb.halfOpenRequests.Store(0)
	cb.halfOpenSuccesses.Store(0)
	if to == CircuitClosed {
		cb.forcedOpen.Store(false)
	}
}

func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

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

func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	counts := cb.breaker.Counts()
	stats := CircuitBreakerStats{
		State:            cb.State(),
		ConsecutiveFails: int64(counts.ConsecutiveFailures),
		ConsecutiveSuccs: int64(counts.ConsecutiveSuccesses),
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
	if stored, ok := cb.lastError.Load().(storedError); ok {
		stats.LastError = stored.err
	}
	return stats
}

func (cb *CircuitBreaker) ForceOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	oldState := cb.State()
	cb.forcedOpen.Store(true)
	cb.transitionStateLocked(oldState, CircuitOpen)
	if oldState != CircuitOpen {
		metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(CircuitOpen))
		metrics.AuditCircuitBreakerStateTransitions.WithLabelValues(cb.name, oldState.String(), CircuitOpen.String()).Inc()
		if cb.config.OnStateChange != nil {
			cb.config.OnStateChange(oldState, CircuitOpen)
		}
	}
}

func (cb *CircuitBreaker) ForceClose() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	oldState := cb.State()
	cb.forcedOpen.Store(false)
	cb.breaker = cb.newBreaker()
	cb.transitionStateLocked(oldState, CircuitClosed)
	if oldState != CircuitClosed {
		metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(CircuitClosed))
		metrics.AuditCircuitBreakerStateTransitions.WithLabelValues(cb.name, oldState.String(), CircuitClosed.String()).Inc()
		if cb.config.OnStateChange != nil {
			cb.config.OnStateChange(oldState, CircuitClosed)
		}
	}
}

func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	oldState := cb.State()
	cb.forcedOpen.Store(false)
	cb.breaker = cb.newBreaker()
	cb.totalRequests.Store(0)
	cb.totalSuccesses.Store(0)
	cb.totalFailures.Store(0)
	cb.totalRejections.Store(0)
	cb.lastError.Store(storedError{})
	cb.lastFailureTime.Store(time.Time{})
	cb.transitionStateLocked(oldState, CircuitClosed)
	metrics.AuditCircuitBreakerState.WithLabelValues(cb.name).Set(float64(CircuitClosed))
	cb.logger.Info("circuit breaker reset")
}

func (cb *CircuitBreaker) IsHealthy() bool {
	return cb.State() == CircuitClosed
}

type CircuitBreakerSink struct {
	sink    Sink
	breaker *CircuitBreaker
	logger  *zap.Logger
}

func NewCircuitBreakerSink(sink Sink, cfg CircuitBreakerConfig, logger *zap.Logger) *CircuitBreakerSink {
	return &CircuitBreakerSink{
		sink:    sink,
		breaker: NewCircuitBreaker(sink.Name(), cfg, logger),
		logger:  logger.Named("cb-sink").With(zap.String("sink", sink.Name())),
	}
}

func (s *CircuitBreakerSink) Write(ctx context.Context, event *Event) error {
	return s.breaker.Execute(ctx, func(ctx context.Context) error {
		return s.sink.Write(ctx, event)
	})
}

func (s *CircuitBreakerSink) WriteBatch(ctx context.Context, events []*Event) error {
	batchSink, ok := s.sink.(BatchSink)
	if !ok {
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

func (s *CircuitBreakerSink) Close() error {
	s.logger.Info("closing circuit breaker sink", zap.String("state", s.breaker.State().String()))
	return s.sink.Close()
}

func (s *CircuitBreakerSink) Name() string { return s.sink.Name() }

func (s *CircuitBreakerSink) CircuitBreaker() *CircuitBreaker { return s.breaker }

func (s *CircuitBreakerSink) IsHealthy() bool { return s.breaker.IsHealthy() }

func (s *CircuitBreakerSink) Stats() CircuitBreakerStats { return s.breaker.Stats() }

func mapGobreakerState(state gobreaker.State) CircuitState {
	switch state {
	case gobreaker.StateClosed:
		return CircuitClosed
	case gobreaker.StateOpen:
		return CircuitOpen
	case gobreaker.StateHalfOpen:
		return CircuitHalfOpen
	default:
		return CircuitClosed
	}
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
