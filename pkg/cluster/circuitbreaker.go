// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// CircuitState represents the current state of a cluster circuit breaker.
type CircuitState int32

const (
	// CircuitClosed indicates normal operation — requests flow through to the spoke cluster.
	CircuitClosed CircuitState = iota
	// CircuitOpen indicates the spoke is unreachable — requests are rejected immediately.
	CircuitOpen
	// CircuitHalfOpen indicates the circuit is probing — a limited number of requests are allowed.
	CircuitHalfOpen
)

// String returns a human-readable representation of the circuit state.
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

// ErrCircuitOpen is returned when a cluster's circuit breaker is in the open state.
var ErrCircuitOpen = errors.New("circuit breaker is open: cluster unavailable")

// ClusterCircuitBreakerConfig configures the circuit breaker behavior for spoke clusters.
type ClusterCircuitBreakerConfig struct {
	// Enabled controls whether circuit breaker protection is active.
	// When false, all requests pass through without circuit breaker checks.
	Enabled bool

	// FailureThreshold is the number of consecutive failures before opening the circuit.
	// Default: 3
	FailureThreshold int

	// SuccessThreshold is the number of consecutive successes in half-open state
	// required to close the circuit.
	// Default: 2
	SuccessThreshold int

	// OpenDuration is how long the circuit stays open before transitioning to half-open.
	// This is the probe interval — after this duration, probe requests are allowed through
	// (limited by HalfOpenMaxRequests).
	// Default: 30s
	OpenDuration time.Duration

	// HalfOpenMaxRequests is the maximum number of concurrent requests allowed in half-open state.
	// Default: 1
	HalfOpenMaxRequests int
}

// DefaultClusterCircuitBreakerConfig returns sensible defaults for spoke cluster circuit breaking.
func DefaultClusterCircuitBreakerConfig() ClusterCircuitBreakerConfig {
	return ClusterCircuitBreakerConfig{
		Enabled:             false, // opt-in by default
		FailureThreshold:    3,
		SuccessThreshold:    2,
		OpenDuration:        30 * time.Second,
		HalfOpenMaxRequests: 1,
	}
}

// clusterBreaker tracks circuit breaker state for a single spoke cluster.
type clusterBreaker struct {
	name   string
	config ClusterCircuitBreakerConfig
	logger *zap.SugaredLogger

	// untracked is true for the shared always-closed sentinel breaker.
	// When set, RecordSuccess/RecordFailure skip metrics and state transitions.
	untracked bool

	// Atomic state tracking for lock-free reads
	state            atomic.Int32 // CircuitState
	consecutiveFails atomic.Int64
	consecutiveSuccs atomic.Int64
	halfOpenRequests atomic.Int64
	lastFailureTime  atomic.Value // time.Time
	lastStateChange  atomic.Value // time.Time
	lastError        atomic.Value // error

	// Statistics
	totalRequests   atomic.Int64
	totalSuccesses  atomic.Int64
	totalFailures   atomic.Int64
	totalRejections atomic.Int64

	// Mutex for state transitions only
	mu sync.Mutex
}

// newClusterBreaker creates a breaker for the named cluster.
func newClusterBreaker(name string, cfg ClusterCircuitBreakerConfig, logger *zap.SugaredLogger) *clusterBreaker {
	if cfg.FailureThreshold <= 0 {
		logger.Warnw("invalid circuitBreaker failureThreshold, using default", "value", cfg.FailureThreshold, "default", 3)
		cfg.FailureThreshold = 3
	}
	if cfg.SuccessThreshold <= 0 {
		logger.Warnw("invalid circuitBreaker successThreshold, using default", "value", cfg.SuccessThreshold, "default", 2)
		cfg.SuccessThreshold = 2
	}
	if cfg.OpenDuration <= 0 {
		logger.Warnw("invalid circuitBreaker openDuration, using default", "value", cfg.OpenDuration, "default", 30*time.Second)
		cfg.OpenDuration = 30 * time.Second
	}
	if cfg.HalfOpenMaxRequests <= 0 {
		logger.Warnw("invalid circuitBreaker halfOpenMaxRequests, using default", "value", cfg.HalfOpenMaxRequests, "default", 1)
		cfg.HalfOpenMaxRequests = 1
	}

	cb := &clusterBreaker{
		name:   name,
		config: cfg,
		logger: logger.With("cluster", name, "component", "circuit-breaker"),
	}
	cb.state.Store(int32(CircuitClosed))
	cb.lastStateChange.Store(time.Now())

	// Initialize metrics
	metrics.ClusterCircuitBreakerState.WithLabelValues(name).Set(float64(CircuitClosed))

	return cb
}

// Allow checks whether a request to this cluster should be permitted.
// Returns nil if allowed, ErrCircuitOpen if the circuit is open.
func (cb *clusterBreaker) Allow() error {
	if cb.untracked {
		return nil // sentinel breaker always allows
	}

	for {
		state := CircuitState(cb.state.Load())

		switch state {
		case CircuitClosed:
			return nil

		case CircuitOpen:
			// Check if enough time has passed to probe — use the mutex to prevent
			// multiple goroutines from simultaneously transitioning to half-open.
			cb.mu.Lock()
			// Re-check state under lock (another goroutine may have transitioned already)
			if CircuitState(cb.state.Load()) != CircuitOpen {
				cb.mu.Unlock()
				continue // state changed while we waited; re-evaluate
			}
			lastChange, ok := cb.lastStateChange.Load().(time.Time)
			if ok && time.Since(lastChange) >= cb.config.OpenDuration {
				cb.transitionToLocked(CircuitHalfOpen)
				cb.halfOpenRequests.Add(1) // count this probe request
				cb.mu.Unlock()
				return nil
			}
			cb.mu.Unlock()
			cb.totalRejections.Add(1)
			metrics.ClusterCircuitBreakerRejections.WithLabelValues(cb.name).Inc()
			return fmt.Errorf("%w: cluster %s temporarily unavailable", ErrCircuitOpen, cb.name)

		case CircuitHalfOpen:
			current := cb.halfOpenRequests.Add(1)
			if current <= int64(cb.config.HalfOpenMaxRequests) {
				return nil
			}
			cb.halfOpenRequests.Add(-1) // revert
			cb.totalRejections.Add(1)
			metrics.ClusterCircuitBreakerRejections.WithLabelValues(cb.name).Inc()
			return fmt.Errorf("%w: cluster %s (half-open, max probe requests reached)", ErrCircuitOpen, cb.name)

		default:
			return nil
		}
	}
}

// RecordSuccess records a successful operation against this cluster.
//
// Note: consecutive counters use relaxed atomic ordering — brief inconsistencies
// between consecutiveFails and consecutiveSuccs are acceptable since threshold
// checks use local return values from Add().
func (cb *clusterBreaker) RecordSuccess() {
	if cb.untracked {
		return // sentinel breaker — no metrics or state transitions
	}
	cb.totalSuccesses.Add(1)
	cb.totalRequests.Add(1)
	cb.consecutiveFails.Store(0)
	cb.consecutiveSuccs.Add(1)

	metrics.ClusterCircuitBreakerSuccesses.WithLabelValues(cb.name).Inc()
	metrics.ClusterCircuitBreakerConsecutiveFailures.WithLabelValues(cb.name).Set(0)

	if CircuitState(cb.state.Load()) == CircuitHalfOpen {
		cb.mu.Lock()
		// Re-check under lock to avoid TOCTOU race on state transitions
		if CircuitState(cb.state.Load()) == CircuitHalfOpen {
			cb.halfOpenRequests.Add(-1)
			// Re-read counter under lock to avoid stale threshold check
			if int(cb.consecutiveSuccs.Load()) >= cb.config.SuccessThreshold {
				cb.transitionToLocked(CircuitClosed)
			}
		}
		cb.mu.Unlock()
	}
}

// RecordFailure records a failed operation against this cluster.
// Only transient failures (network errors, timeouts) should trip the breaker.
// Authentication or authorization errors are not counted.
func (cb *clusterBreaker) RecordFailure(err error) {
	if cb.untracked {
		return // sentinel breaker — no metrics or state transitions
	}
	if !IsTransientError(err) {
		// Non-transient errors (auth, not-found) should not trip the breaker
		return
	}

	cb.totalFailures.Add(1)
	cb.totalRequests.Add(1)
	cb.consecutiveSuccs.Store(0)
	cb.lastError.Store(storedError{err: err})
	cb.lastFailureTime.Store(time.Now())
	failures := cb.consecutiveFails.Add(1)

	metrics.ClusterCircuitBreakerFailures.WithLabelValues(cb.name).Inc()
	metrics.ClusterCircuitBreakerConsecutiveFailures.WithLabelValues(cb.name).Set(float64(failures))

	switch CircuitState(cb.state.Load()) {
	case CircuitClosed:
		if int(failures) >= cb.config.FailureThreshold {
			cb.mu.Lock()
			// Re-read counter under lock to avoid stale threshold check
			if CircuitState(cb.state.Load()) == CircuitClosed &&
				int(cb.consecutiveFails.Load()) >= cb.config.FailureThreshold {
				cb.transitionToLocked(CircuitOpen)
			}
			cb.mu.Unlock()
		}
	case CircuitHalfOpen:
		cb.mu.Lock()
		if CircuitState(cb.state.Load()) == CircuitHalfOpen {
			cb.halfOpenRequests.Add(-1)
			cb.transitionToLocked(CircuitOpen)
		}
		cb.mu.Unlock()
	}
}

// transitionToLocked performs the state transition. Caller MUST hold cb.mu.
func (cb *clusterBreaker) transitionToLocked(newState CircuitState) {
	oldState := CircuitState(cb.state.Load())
	if oldState == newState {
		return
	}

	cb.state.Store(int32(newState))
	cb.lastStateChange.Store(time.Now())
	cb.consecutiveFails.Store(0)
	cb.consecutiveSuccs.Store(0)
	cb.halfOpenRequests.Store(0)

	cb.logger.Infow("circuit breaker state changed",
		"from", oldState.String(),
		"to", newState.String())

	// Update metrics
	metrics.ClusterCircuitBreakerState.WithLabelValues(cb.name).Set(float64(newState))
	metrics.ClusterCircuitBreakerStateTransitions.WithLabelValues(cb.name, oldState.String(), newState.String()).Inc()
}

// State returns the current circuit state.
func (cb *clusterBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// IsDefinitelyOpen reports whether the circuit is open AND the OpenDuration has not yet elapsed.
// This is a lock-free read-only check that does NOT consume a half-open probe slot.
// Use this for fast-fail checks at call sites that cannot complete the full Allow/Record lifecycle
// (e.g., GetRESTConfig where the actual HTTP request happens later via circuitBreakerTransport).
func (cb *clusterBreaker) IsDefinitelyOpen() bool {
	if cb.untracked {
		return false // sentinel breaker is always closed
	}
	if CircuitState(cb.state.Load()) != CircuitOpen {
		return false
	}
	lastChange, ok := cb.lastStateChange.Load().(time.Time)
	return ok && time.Since(lastChange) < cb.config.OpenDuration
}

// ClusterBreakerStats holds statistics for a single cluster's circuit breaker.
type ClusterBreakerStats struct {
	Name             string
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

// Stats returns the current statistics for this breaker.
func (cb *clusterBreaker) Stats() ClusterBreakerStats {
	stats := ClusterBreakerStats{
		Name:             cb.name,
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
	if se, ok := cb.lastError.Load().(storedError); ok {
		stats.LastError = se.err
	}
	return stats
}

// maxBreakers is the upper bound on the number of per-cluster circuit breakers
// the registry will track. This prevents a Prometheus cardinality bomb if an
// attacker or misconfiguration creates an unbounded number of cluster names.
const maxBreakers = 1000

// alwaysClosedBreaker is a shared sentinel returned when the registry has
// reached maxBreakers. It permanently stays in CircuitClosed state:
//   - Allow() always returns nil
//   - RecordSuccess / RecordFailure are no-ops (no metrics, no state transitions)
//
// This avoids both metric-cardinality leaks and nil-pointer panics.
var alwaysClosedBreaker = func() *clusterBreaker {
	cb := &clusterBreaker{
		name:      "_overflow_sentinel",
		config:    DefaultClusterCircuitBreakerConfig(),
		logger:    zap.NewNop().Sugar(),
		untracked: true,
	}
	cb.state.Store(int32(CircuitClosed))
	return cb
}()

// storedError wraps an error in a consistent concrete type so that
// atomic.Value never panics on type mismatch when different error types
// are stored across calls (atomic.Value requires all stores to use the
// same concrete type).
type storedError struct{ err error }

// CircuitBreakerRegistry manages per-cluster circuit breakers.
type CircuitBreakerRegistry struct {
	mu            sync.RWMutex
	breakers      map[string]*clusterBreaker
	config        ClusterCircuitBreakerConfig
	logger        *zap.SugaredLogger
	overflowCount int64 // tracks how many times capacity was exceeded (for log rate-limiting)
}

// NewCircuitBreakerRegistry creates a registry that manages per-cluster breakers.
func NewCircuitBreakerRegistry(cfg ClusterCircuitBreakerConfig, logger *zap.SugaredLogger) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		breakers: make(map[string]*clusterBreaker),
		config:   cfg,
		logger:   logger,
	}
}

// Get returns the circuit breaker for the named cluster, creating one if it doesn't exist.
// If the registry has reached maxBreakers, new clusters receive a no-op sentinel breaker
// to prevent unbounded metric cardinality.
func (r *CircuitBreakerRegistry) Get(clusterName string) *clusterBreaker {
	r.mu.RLock()
	cb, ok := r.breakers[clusterName]
	r.mu.RUnlock()
	if ok {
		return cb
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if cb, ok = r.breakers[clusterName]; ok {
		return cb
	}

	if len(r.breakers) >= maxBreakers {
		// Rate-limit capacity warnings — log only on the first overflow and then
		// every 100th overflow to avoid a log-volume DoS from misconfigured or
		// malicious cluster names.
		r.overflowCount++
		if r.overflowCount == 1 || r.overflowCount%100 == 0 {
			r.logger.Warnw("circuit breaker registry at capacity, returning always-closed sentinel",
				"cluster", clusterName, "max", maxBreakers, "overflowCount", r.overflowCount)
		}
		return alwaysClosedBreaker
	}

	cb = newClusterBreaker(clusterName, r.config, r.logger)
	r.breakers[clusterName] = cb

	r.logger.Debugw("created circuit breaker for cluster", "cluster", clusterName)
	return cb
}

// Remove deletes the breaker for a cluster (e.g., when a ClusterConfig is deleted)
// and cleans up associated Prometheus metric series to prevent stale data.
func (r *CircuitBreakerRegistry) Remove(clusterName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.breakers, clusterName)

	// Clean up Prometheus series for this cluster
	metrics.ClusterCircuitBreakerState.DeleteLabelValues(clusterName)
	metrics.ClusterCircuitBreakerRejections.DeleteLabelValues(clusterName)
	metrics.ClusterCircuitBreakerStateTransitions.DeletePartialMatch(prometheus.Labels{"cluster": clusterName})
	metrics.ClusterCircuitBreakerFailures.DeleteLabelValues(clusterName)
	metrics.ClusterCircuitBreakerSuccesses.DeleteLabelValues(clusterName)
	metrics.ClusterCircuitBreakerConsecutiveFailures.DeleteLabelValues(clusterName)
}

// AllStats returns statistics for all tracked clusters.
func (r *CircuitBreakerRegistry) AllStats() []ClusterBreakerStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make([]ClusterBreakerStats, 0, len(r.breakers))
	for _, cb := range r.breakers {
		stats = append(stats, cb.Stats())
	}
	return stats
}

// IsEnabled reports whether circuit breaker protection is active.
func (r *CircuitBreakerRegistry) IsEnabled() bool {
	return r.config.Enabled
}

// TransientServerError represents an HTTP server error (5xx) from a spoke cluster
// that should be treated as a transient failure by the circuit breaker.
type TransientServerError struct {
	StatusCode  int
	ClusterName string
}

func (e *TransientServerError) Error() string {
	return fmt.Sprintf("http %d from spoke cluster %s", e.StatusCode, e.ClusterName)
}

// transientPatterns is the set of error message substrings that indicate transient
// network failures. Hoisted to package level to avoid per-call allocation.
var transientPatterns = []string{
	"connection refused",
	"connection reset",
	"no route to host",
	"network is unreachable",
	"i/o timeout",
	"dial tcp",
	"dial timeout",
	"context deadline exceeded",
	"tls handshake timeout",
	"unexpected eof",
	"broken pipe",
	"connection timed out",
}

// IsTransientError determines whether an error should count as a transient failure
// that should trip the circuit breaker. Only network-level and timeout errors count.
// Authentication, authorization, and "not found" errors are NOT transient — they indicate
// the cluster is reachable but the request itself is invalid.
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}

	// --- Type-based checks (preferred over string matching) ---

	// Server errors (5xx) from spoke clusters
	var serverErr *TransientServerError
	if errors.As(err, &serverErr) {
		return true
	}

	// Standard sentinel errors
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// net.Error — only treat as transient when it's a timeout or temporary condition.
	// Other net.Error values (e.g., DNS resolution failures for invalid hosts) are
	// configuration issues that should not trip the breaker.
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
		// Check deprecated Temporary() as a fallback for legacy error types.
		type temporaryError interface {
			Temporary() bool
		}
		if te, ok := netErr.(temporaryError); ok && te.Temporary() { //nolint:staticcheck // Temporary() is deprecated but still useful for legacy types
			return true
		}
	}

	// net.OpError — delegate to the wrapped error instead of blanket-accepting.
	// A bare OpError (e.g. DNS "no such host") is a configuration issue, not a
	// transient network failure.  Only treat it as transient when the inner error
	// is itself transient (timeout, connection refused, etc.).
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return true
		}
		if opErr.Err != nil {
			return IsTransientError(opErr.Err)
		}
		return false
	}

	// url.Error — only treat as transient if it's a timeout or if the wrapped
	// error is itself transient. url.Error frequently wraps TLS/cert verification
	// failures (e.g., x509 unknown authority) which are configuration issues.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return true
		}
		if urlErr.Err != nil && IsTransientError(urlErr.Err) {
			return true
		}
	}

	// --- String matching fallback for wrapped/foreign errors ---
	msg := strings.ToLower(err.Error())
	for _, pattern := range transientPatterns {
		if strings.Contains(msg, pattern) {
			return true
		}
	}

	return false
}

// circuitBreakerTransport wraps an http.RoundTripper to automatically record
// success/failure for circuit breaker tracking.
type circuitBreakerTransport struct {
	inner       http.RoundTripper
	clusterName string
	breakers    *CircuitBreakerRegistry
}

// RoundTrip implements http.RoundTripper. It checks the circuit breaker before
// delegating to the inner transport and records the outcome.
// Server errors (5xx) are treated as transient failures since they typically
// indicate the spoke cluster's API server is overloaded or proxying failures.
func (t *circuitBreakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cb := t.breakers.Get(t.clusterName)
	if err := cb.Allow(); err != nil {
		return nil, err
	}
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		cb.RecordFailure(err)
	} else if resp.StatusCode >= http.StatusInternalServerError {
		cb.RecordFailure(&TransientServerError{StatusCode: resp.StatusCode, ClusterName: t.clusterName})
	} else {
		cb.RecordSuccess()
	}
	return resp, err
}
