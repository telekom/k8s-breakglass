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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testLogger() *zap.SugaredLogger {
	l, _ := zap.NewDevelopment()
	return l.Sugar()
}

func testConfig() ClusterCircuitBreakerConfig {
	return ClusterCircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    3,
		SuccessThreshold:    2,
		OpenDuration:        100 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
}

// --- CircuitState tests ---

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.state.String())
	}
}

// --- clusterBreaker tests ---

func TestClusterBreaker_InitialState(t *testing.T) {
	cb := newClusterBreaker("test-cluster", testConfig(), testLogger())
	assert.Equal(t, CircuitClosed, cb.State())
	assert.Nil(t, cb.Allow())
}

func TestClusterBreaker_ClosedToOpen(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 3
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Record 3 transient failures
	for i := 0; i < 3; i++ {
		cb.RecordFailure(fmt.Errorf("connection refused"))
	}

	assert.Equal(t, CircuitOpen, cb.State())

	// Further requests should be rejected
	err := cb.Allow()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCircuitOpen))
}

// TestClusterBreaker_MixedErrorTypes verifies that storing different concrete error
// types via RecordFailure does not panic (regression test for atomic.Value type
// mismatch — the storedError wrapper ensures a consistent concrete type).
func TestClusterBreaker_MixedErrorTypes(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 100 // high threshold so breaker stays closed
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Alternate between different concrete error types — this panicked before
	// the storedError wrapper was introduced.
	require.NotPanics(t, func() {
		cb.RecordFailure(fmt.Errorf("connection refused"))
		cb.RecordFailure(&TransientServerError{StatusCode: 503, ClusterName: "test"})
		cb.RecordFailure(&net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")})
		cb.RecordFailure(fmt.Errorf("broken pipe"))
		cb.RecordFailure(&TransientServerError{StatusCode: 502, ClusterName: "test"})
	})

	// Verify Stats() correctly retrieves the last error
	stats := cb.Stats()
	assert.NotNil(t, stats.LastError)
}

func TestClusterBreaker_OpenToHalfOpen(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	cfg.OpenDuration = 50 * time.Millisecond
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Trip the breaker
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait for open duration to elapse using require.Eventually to avoid flaky timing
	require.Eventually(t, func() bool {
		return cb.Allow() == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.State())
}

func TestClusterBreaker_HalfOpenToClosed(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	cfg.SuccessThreshold = 2
	cfg.OpenDuration = 50 * time.Millisecond
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Trip the breaker
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait and transition to half-open
	require.Eventually(t, func() bool {
		return cb.Allow() == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// First success frees the half-open slot
	cb.RecordSuccess()
	// Must call Allow() again to re-admit a probe request before second success
	require.NoError(t, cb.Allow())
	cb.RecordSuccess()

	assert.Equal(t, CircuitClosed, cb.State())
}

func TestClusterBreaker_HalfOpenToOpen(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	cfg.OpenDuration = 50 * time.Millisecond
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Trip the breaker
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())

	// Transition to half-open
	require.Eventually(t, func() bool {
		return cb.Allow() == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Failure in half-open should trip back to open
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())
}

func TestClusterBreaker_HalfOpenMaxRequests(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	cfg.OpenDuration = 50 * time.Millisecond
	cfg.HalfOpenMaxRequests = 1
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Trip the breaker
	cb.RecordFailure(fmt.Errorf("dial tcp: connection refused"))

	// Wait for open duration to elapse
	require.Eventually(t, func() bool {
		return cb.Allow() == nil
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Second request should be denied (max 1 in half-open)
	err := cb.Allow()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCircuitOpen))
}

func TestClusterBreaker_NonTransientErrorDoesNotTripBreaker(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Auth errors should NOT trip the breaker
	cb.RecordFailure(fmt.Errorf("Unauthorized"))
	assert.Equal(t, CircuitClosed, cb.State())

	cb.RecordFailure(fmt.Errorf("Forbidden"))
	assert.Equal(t, CircuitClosed, cb.State())

	cb.RecordFailure(fmt.Errorf("resource not found"))
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestClusterBreaker_Stats(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 5
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	cb.RecordSuccess()
	cb.RecordSuccess()
	cb.RecordFailure(fmt.Errorf("connection refused"))

	stats := cb.Stats()
	assert.Equal(t, "test-cluster", stats.Name)
	assert.Equal(t, CircuitClosed, stats.State)
	assert.Equal(t, int64(1), stats.ConsecutiveFails)
	assert.Equal(t, int64(3), stats.TotalRequests)
	assert.Equal(t, int64(2), stats.TotalSuccesses)
	assert.Equal(t, int64(1), stats.TotalFailures)
	assert.False(t, stats.LastFailureTime.IsZero())
	assert.NotNil(t, stats.LastError)
}

func TestClusterBreaker_IsDefinitelyOpen(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 1
	cfg.OpenDuration = 50 * time.Millisecond
	cb := newClusterBreaker("test-cluster", cfg, testLogger())

	// Closed → not definitely open
	assert.False(t, cb.IsDefinitelyOpen())

	// Trip to Open
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())
	assert.True(t, cb.IsDefinitelyOpen(), "should be true while within OpenDuration")

	// Wait for open duration to elapse
	require.Eventually(t, func() bool {
		return !cb.IsDefinitelyOpen()
	}, 5*time.Second, 10*time.Millisecond, "should become false after OpenDuration elapses")
}

func TestClusterBreaker_IsDefinitelyOpen_Sentinel(t *testing.T) {
	// The always-closed sentinel should never report as definitely open
	assert.False(t, alwaysClosedBreaker.IsDefinitelyOpen())
}

func TestClusterBreaker_DefaultConfigValidation(t *testing.T) {
	// Zero/negative values should be replaced with defaults
	cfg := ClusterCircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    -1,
		SuccessThreshold:    0,
		OpenDuration:        -1 * time.Second,
		HalfOpenMaxRequests: 0,
	}
	cb := newClusterBreaker("test", cfg, testLogger())

	// Should not panic, should use defaults
	assert.Equal(t, CircuitClosed, cb.State())

	// With default threshold of 3, need 3 failures to trip
	cb.RecordFailure(fmt.Errorf("connection refused"))
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitClosed, cb.State())

	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())
}

func TestClusterBreaker_SuccessResetsConsecutiveFailures(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 3
	cb := newClusterBreaker("test", cfg, testLogger())

	// 2 failures, then a success
	cb.RecordFailure(fmt.Errorf("connection refused"))
	cb.RecordFailure(fmt.Errorf("connection refused"))
	cb.RecordSuccess()

	// Counter should be reset, so 2 more failures shouldn't trip it
	cb.RecordFailure(fmt.Errorf("connection refused"))
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitClosed, cb.State())

	// One more failure should trip it (3 consecutive)
	cb.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitOpen, cb.State())
}

// --- CircuitBreakerRegistry tests ---

func TestRegistry_GetCreatesBreaker(t *testing.T) {
	r := NewCircuitBreakerRegistry(testConfig(), testLogger())

	cb1 := r.Get("cluster-a")
	assert.NotNil(t, cb1)
	assert.Equal(t, CircuitClosed, cb1.State())

	// Same cluster returns same breaker
	cb2 := r.Get("cluster-a")
	assert.Equal(t, cb1, cb2)

	// Different cluster returns different breaker
	cb3 := r.Get("cluster-b")
	assert.NotEqual(t, cb1, cb3)
}

func TestRegistry_Remove(t *testing.T) {
	r := NewCircuitBreakerRegistry(testConfig(), testLogger())

	cb1 := r.Get("cluster-a")
	r.Remove("cluster-a")

	// After removal, a new breaker should be created
	cb2 := r.Get("cluster-a")
	assert.NotEqual(t, cb1, cb2)
}

func TestRegistry_AllStats(t *testing.T) {
	r := NewCircuitBreakerRegistry(testConfig(), testLogger())

	r.Get("cluster-a").RecordSuccess()
	r.Get("cluster-b").RecordFailure(fmt.Errorf("connection refused"))

	stats := r.AllStats()
	assert.Len(t, stats, 2)

	// Verify both clusters are represented
	names := make(map[string]bool)
	for _, s := range stats {
		names[s.Name] = true
	}
	assert.True(t, names["cluster-a"])
	assert.True(t, names["cluster-b"])
}

func TestRegistry_IsEnabled(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = true
	r := NewCircuitBreakerRegistry(cfg, testLogger())
	assert.True(t, r.IsEnabled())

	cfg.Enabled = false
	r2 := NewCircuitBreakerRegistry(cfg, testLogger())
	assert.False(t, r2.IsEnabled())
}

// --- Full lifecycle test ---

func TestCircuitBreaker_FullLifecycle(t *testing.T) {
	cfg := ClusterCircuitBreakerConfig{
		Enabled:             true,
		FailureThreshold:    3,
		SuccessThreshold:    2,
		OpenDuration:        50 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	r := NewCircuitBreakerRegistry(cfg, testLogger())
	cb := r.Get("spoke-1")

	// Phase 1: Normal operation (closed)
	assert.Equal(t, CircuitClosed, cb.State())
	assert.NoError(t, cb.Allow())
	cb.RecordSuccess()
	cb.RecordSuccess()

	// Phase 2: Failures accumulate
	cb.RecordFailure(fmt.Errorf("connection refused"))
	cb.RecordFailure(fmt.Errorf("dial tcp: i/o timeout"))
	assert.Equal(t, CircuitClosed, cb.State()) // Still closed, need 3

	cb.RecordFailure(fmt.Errorf("no route to host"))
	assert.Equal(t, CircuitOpen, cb.State()) // Now open

	// Phase 3: Requests rejected while open
	err := cb.Allow()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrCircuitOpen))

	// Phase 4: Wait for probe interval
	require.Eventually(t, func() bool {
		return cb.Allow() == nil
	}, 5*time.Second, 10*time.Millisecond)

	// Phase 5: Half-open — one request allowed
	assert.Equal(t, CircuitHalfOpen, cb.State())

	// Phase 6: Success → close the circuit
	cb.RecordSuccess()
	require.NoError(t, cb.Allow()) // re-admit probe after first success
	cb.RecordSuccess()
	assert.Equal(t, CircuitClosed, cb.State())

	// Phase 7: Normal operation resumes
	assert.NoError(t, cb.Allow())
}

// --- IsTransientError tests ---

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"io.EOF via errors.Is", io.EOF, true},
		{"TransientServerError 503", &TransientServerError{StatusCode: 503, ClusterName: "test-cluster"}, true},
		{"io.EOF wrapped", fmt.Errorf("read failed: %w", io.EOF), true},
		{"context.DeadlineExceeded", context.DeadlineExceeded, true},
		{"context.DeadlineExceeded wrapped", fmt.Errorf("op: %w", context.DeadlineExceeded), true},
		{"context.Canceled", context.Canceled, false},
		{"net.OpError with connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}, true},
		{"net.OpError with DNS no such host", &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("no such host")}, false},
		{"url.Error with timeout", &url.Error{Op: "Get", URL: "https://example.com", Err: &netTimeoutError{}}, true},
		{"url.Error with TLS cert failure", &url.Error{Op: "Get", URL: "https://example.com", Err: fmt.Errorf("x509: certificate signed by unknown authority")}, false},
		{"url.Error with connection refused", &url.Error{Op: "Get", URL: "https://example.com", Err: &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")}}, true},
		{"connection refused", fmt.Errorf("dial tcp 10.0.0.1:443: connection refused"), true},
		{"connection reset", fmt.Errorf("read tcp: connection reset by peer"), true},
		{"no route to host", fmt.Errorf("dial tcp: no route to host"), true},
		{"network unreachable", fmt.Errorf("dial tcp: network is unreachable"), true},
		{"i/o timeout", fmt.Errorf("net/http: request canceled (Client.Timeout exceeded) i/o timeout"), true},
		{"dial tcp", fmt.Errorf("dial tcp 10.0.0.1:6443: connect: connection refused"), true},
		{"dial timeout", fmt.Errorf("dial timeout"), true},
		{"context deadline exceeded", fmt.Errorf("context deadline exceeded"), true},
		{"tls handshake timeout", fmt.Errorf("net/http: TLS handshake timeout"), true},
		{"eof", fmt.Errorf("unexpected EOF"), true},
		{"substring 'eof' without matching pattern", fmt.Errorf("some eof-like thing"), false},
		{"broken pipe", fmt.Errorf("write: broken pipe"), true},
		{"connection timed out", fmt.Errorf("dial tcp: lookup hostname: connection timed out"), true},
		{"unauthorized", fmt.Errorf("Unauthorized"), false},
		{"forbidden", fmt.Errorf("Forbidden"), false},
		{"not found", fmt.Errorf("not found"), false},
		{"auth error", fmt.Errorf("authentication failed"), false},
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"net.Error timeout", &netTimeoutError{}, true},
		{"TransientServerError wrapped", fmt.Errorf("operation failed: %w", &TransientServerError{StatusCode: 503, ClusterName: "test"}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsTransientError(tt.err), "IsTransientError(%v)", tt.err)
		})
	}
}

// netTimeoutError implements net.Error for testing.
type netTimeoutError struct{}

func (e *netTimeoutError) Error() string   { return "test timeout" }
func (e *netTimeoutError) Timeout() bool   { return true }
func (e *netTimeoutError) Temporary() bool { return true }

var _ net.Error = (*netTimeoutError)(nil)

// --- ClientProvider integration ---

func TestClientProvider_RecordSuccess_DisabledNoop(t *testing.T) {
	cfg := DefaultClusterCircuitBreakerConfig()
	cfg.Enabled = false
	p := &ClientProvider{
		circuitBreakers: NewCircuitBreakerRegistry(cfg, testLogger()),
	}
	// Should not panic
	p.RecordSuccess("any-cluster")
}

func TestClientProvider_RecordFailure_DisabledNoop(t *testing.T) {
	cfg := DefaultClusterCircuitBreakerConfig()
	cfg.Enabled = false
	p := &ClientProvider{
		circuitBreakers: NewCircuitBreakerRegistry(cfg, testLogger()),
	}
	// Should not panic
	p.RecordFailure("any-cluster", fmt.Errorf("connection refused"))
}

func TestClientProvider_RecordFailure_EnabledTripsBreaker(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 2
	p := &ClientProvider{
		circuitBreakers: NewCircuitBreakerRegistry(cfg, testLogger()),
	}

	p.RecordFailure("spoke-1", fmt.Errorf("connection refused"))
	p.RecordFailure("spoke-1", fmt.Errorf("connection refused"))

	cb := p.CircuitBreakers().Get("spoke-1")
	assert.Equal(t, CircuitOpen, cb.State())
}

func TestClientProvider_CircuitBreakers_Accessor(t *testing.T) {
	cfg := testConfig()
	p := &ClientProvider{
		circuitBreakers: NewCircuitBreakerRegistry(cfg, testLogger()),
	}
	require.NotNil(t, p.CircuitBreakers())
	assert.True(t, p.CircuitBreakers().IsEnabled())
}

func TestDefaultClusterCircuitBreakerConfig(t *testing.T) {
	cfg := DefaultClusterCircuitBreakerConfig()
	assert.False(t, cfg.Enabled)
	assert.Equal(t, 3, cfg.FailureThreshold)
	assert.Equal(t, 2, cfg.SuccessThreshold)
	assert.Equal(t, 30*time.Second, cfg.OpenDuration)
	assert.Equal(t, 1, cfg.HalfOpenMaxRequests)
}

func TestCircuitBreakerRegistry_MaxBreakers(t *testing.T) {
	cfg := testConfig()
	reg := NewCircuitBreakerRegistry(cfg, testLogger())

	// Fill to capacity
	for i := 0; i < maxBreakers; i++ {
		name := fmt.Sprintf("cluster-%d", i)
		cb := reg.Get(name)
		require.NotNil(t, cb)
	}

	// One more should still return a breaker (not nil) but not grow the registry
	extra := reg.Get("overflow-cluster")
	require.NotNil(t, extra, "should return a breaker even at capacity")
	assert.Same(t, alwaysClosedBreaker, extra, "overflow should return shared sentinel")
	assert.NoError(t, extra.Allow(), "sentinel should always allow")

	// Sentinel should be a no-op for record methods (no panic, no metrics leak)
	extra.RecordSuccess()
	extra.RecordFailure(fmt.Errorf("connection refused"))
	assert.Equal(t, CircuitClosed, extra.State(), "sentinel should stay closed")

	reg.mu.RLock()
	count := len(reg.breakers)
	reg.mu.RUnlock()
	assert.Equal(t, maxBreakers, count, "registry should not exceed maxBreakers")
}

// mockRoundTripper is a test helper that returns a fixed response.
type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return m.resp, m.err
}

func TestCircuitBreakerTransport_AllowCheck(t *testing.T) {
	cfg := testConfig()
	reg := NewCircuitBreakerRegistry(cfg, testLogger())

	cluster := "test-cluster-allow"
	cb := reg.Get(cluster)

	// Trip the breaker by recording enough failures.
	for i := 0; i < cfg.FailureThreshold; i++ {
		cb.RecordFailure(errors.New("connection refused"))
	}
	require.Equal(t, CircuitOpen, cb.State(), "breaker should be open")

	// Wrap a mock transport that should never be called.
	inner := &mockRoundTripper{
		resp: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody},
	}

	transport := &circuitBreakerTransport{
		inner:       inner,
		clusterName: cluster,
		breakers:    reg,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://spoke-cluster/api/v1/pods", nil)
	resp, err := transport.RoundTrip(req) //nolint:bodyclose // resp is nil when circuit is open

	assert.Nil(t, resp, "response should be nil when circuit is open")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCircuitOpen, "should return ErrCircuitOpen")
}

func TestCircuitBreakerTransport_ServerErrorCountsAsFailure(t *testing.T) {
	cfg := testConfig()
	reg := NewCircuitBreakerRegistry(cfg, testLogger())

	cluster := "test-cluster-5xx"

	mock := &mockRoundTripper{
		resp: &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody},
	}

	transport := &circuitBreakerTransport{
		inner:       mock,
		clusterName: cluster,
		breakers:    reg,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://spoke-cluster/api/v1/pods", nil)

	// Each 503 response should count as a failure.
	for i := 0; i < cfg.FailureThreshold; i++ {
		resp, err := transport.RoundTrip(req)
		assert.NotNil(t, resp, "5xx should still return the response")
		assert.NoError(t, err, "no transport error occurred")
		resp.Body.Close()
	}

	// The breaker should now be open.
	cb := reg.Get(cluster)
	assert.Equal(t, CircuitOpen, cb.State(), "breaker should be open after enough 5xx responses")

	// Next request should be rejected.
	resp, err := transport.RoundTrip(req) //nolint:bodyclose // resp is nil when circuit is open
	assert.Nil(t, resp)
	require.ErrorIs(t, err, ErrCircuitOpen)
}

func TestCircuitBreakerTransport_SuccessfulResponse(t *testing.T) {
	cfg := testConfig()
	reg := NewCircuitBreakerRegistry(cfg, testLogger())

	cluster := "test-cluster-success"

	mock := &mockRoundTripper{
		resp: &http.Response{StatusCode: http.StatusOK, Body: http.NoBody},
	}

	transport := &circuitBreakerTransport{
		inner:       mock,
		clusterName: cluster,
		breakers:    reg,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://spoke-cluster/api/v1/pods", nil)
	resp, err := transport.RoundTrip(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	cb := reg.Get(cluster)
	assert.Equal(t, CircuitClosed, cb.State(), "breaker should stay closed after success")
}

func TestCircuitBreakerTransport_NetworkError(t *testing.T) {
	cfg := testConfig()
	reg := NewCircuitBreakerRegistry(cfg, testLogger())

	cluster := "test-cluster-neterror"

	mock := &mockRoundTripper{
		err: &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("connection refused")},
	}

	transport := &circuitBreakerTransport{
		inner:       mock,
		clusterName: cluster,
		breakers:    reg,
	}

	req, _ := http.NewRequest(http.MethodGet, "https://spoke-cluster/api/v1/pods", nil)

	// Each network error should count as a failure.
	for i := 0; i < cfg.FailureThreshold; i++ {
		resp, err := transport.RoundTrip(req) //nolint:bodyclose // mock returns nil response on error
		require.Error(t, err)
		require.Nil(t, resp)
	}

	// The breaker should now be open.
	cb := reg.Get(cluster)
	assert.Equal(t, CircuitOpen, cb.State(), "breaker should be open after enough network errors")
}

func TestTransientServerError_ErrorMessage(t *testing.T) {
	err := &TransientServerError{StatusCode: 503, ClusterName: "spoke-eu-west"}
	assert.Equal(t, "http 503 from spoke cluster spoke-eu-west", err.Error())
}

func TestClusterBreaker_ConcurrentAccess(t *testing.T) {
	cfg := testConfig()
	cfg.FailureThreshold = 10000 // must exceed goroutines*ops to avoid tripping during test
	reg := NewCircuitBreakerRegistry(cfg, testLogger())

	cluster := "test-cluster-concurrent"
	cb := reg.Get(cluster)

	const goroutines = 50
	const ops = 100

	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < ops; j++ {
				_ = cb.Allow()
				cb.RecordSuccess()
				cb.RecordFailure(errors.New("connection refused"))
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	stats := cb.Stats()
	assert.Equal(t, int64(goroutines*ops), stats.TotalSuccesses)
	assert.Equal(t, int64(goroutines*ops), stats.TotalFailures)
}
