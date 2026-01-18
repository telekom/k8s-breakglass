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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestCircuitBreaker_ClosedState(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	// Circuit should start closed
	assert.Equal(t, CircuitClosed, cb.State())
	assert.True(t, cb.IsHealthy())

	// Should allow execution
	executed := false
	err := cb.Execute(context.Background(), func(ctx context.Context) error {
		executed = true
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, executed)

	stats := cb.Stats()
	assert.Equal(t, int64(1), stats.TotalRequests)
	assert.Equal(t, int64(1), stats.TotalSuccesses)
	assert.Equal(t, int64(0), stats.TotalFailures)
}

func TestCircuitBreaker_OpensAfterFailureThreshold(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := CircuitBreakerConfig{
		FailureThreshold: 3,
		OpenTimeout:      1 * time.Second,
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	testErr := errors.New("test error")

	// Cause failures up to threshold
	for i := 0; i < 3; i++ {
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			return testErr
		})
		assert.ErrorIs(t, err, testErr)
	}

	// Circuit should now be open
	assert.Equal(t, CircuitOpen, cb.State())
	assert.False(t, cb.IsHealthy())

	// Requests should be rejected
	err := cb.Execute(context.Background(), func(ctx context.Context) error {
		t.Fatal("should not execute")
		return nil
	})
	assert.ErrorIs(t, err, ErrCircuitOpen)

	stats := cb.Stats()
	assert.Equal(t, int64(3), stats.TotalFailures)
	assert.Equal(t, int64(1), stats.TotalRejections)
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := CircuitBreakerConfig{
		FailureThreshold:    2,
		OpenTimeout:         50 * time.Millisecond,
		HalfOpenMaxRequests: 1,
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	// Trip the circuit
	for i := 0; i < 2; i++ {
		_ = cb.Execute(context.Background(), func(ctx context.Context) error {
			return errors.New("fail")
		})
	}
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait for open timeout
	time.Sleep(60 * time.Millisecond)

	// Next request should transition to half-open and execute
	executed := false
	err := cb.Execute(context.Background(), func(ctx context.Context) error {
		executed = true
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, executed)
	// After success in half-open, it needs more successes (default 2)
	// So it stays in half-open or transitions based on threshold
}

func TestCircuitBreaker_ClosesAfterSuccessThreshold(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 2,
		OpenTimeout:      10 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	// Trip the circuit
	_ = cb.Execute(context.Background(), func(ctx context.Context) error {
		return errors.New("fail")
	})
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait for open timeout
	time.Sleep(20 * time.Millisecond)

	// Execute success threshold times
	for i := 0; i < 2; i++ {
		err := cb.Execute(context.Background(), func(ctx context.Context) error {
			return nil
		})
		assert.NoError(t, err)
	}

	// Circuit should be closed
	assert.Equal(t, CircuitClosed, cb.State())
	assert.True(t, cb.IsHealthy())
}

func TestCircuitBreaker_FailureInHalfOpenReturnsToOpen(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := CircuitBreakerConfig{
		FailureThreshold: 1,
		OpenTimeout:      10 * time.Millisecond,
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	// Trip the circuit
	_ = cb.Execute(context.Background(), func(ctx context.Context) error {
		return errors.New("fail")
	})
	assert.Equal(t, CircuitOpen, cb.State())

	// Wait for open timeout
	time.Sleep(20 * time.Millisecond)

	// Fail in half-open
	_ = cb.Execute(context.Background(), func(ctx context.Context) error {
		return errors.New("fail again")
	})

	// Should be back to open
	assert.Equal(t, CircuitOpen, cb.State())
}

func TestCircuitBreaker_ForceOpenAndClose(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cb := NewCircuitBreaker("test-sink", DefaultCircuitBreakerConfig(), logger)

	assert.Equal(t, CircuitClosed, cb.State())

	cb.ForceOpen()
	assert.Equal(t, CircuitOpen, cb.State())

	cb.ForceClose()
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreaker_Reset(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := CircuitBreakerConfig{
		FailureThreshold: 1,
		OpenTimeout:      1 * time.Hour, // Long timeout
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	// Trip the circuit
	_ = cb.Execute(context.Background(), func(ctx context.Context) error {
		return errors.New("fail")
	})
	assert.Equal(t, CircuitOpen, cb.State())

	// Reset
	cb.Reset()
	assert.Equal(t, CircuitClosed, cb.State())

	stats := cb.Stats()
	assert.Equal(t, int64(0), stats.TotalRequests)
	assert.Equal(t, int64(0), stats.TotalFailures)
}

func TestCircuitBreaker_StateCallback(t *testing.T) {
	logger := zaptest.NewLogger(t)
	var transitions []string

	cfg := CircuitBreakerConfig{
		FailureThreshold: 1,
		OnStateChange: func(from, to CircuitState) {
			transitions = append(transitions, from.String()+"->"+to.String())
		},
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	// Trip the circuit
	_ = cb.Execute(context.Background(), func(ctx context.Context) error {
		return errors.New("fail")
	})

	require.Len(t, transitions, 1)
	assert.Equal(t, "closed->open", transitions[0])
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cfg := CircuitBreakerConfig{
		FailureThreshold: 100, // High threshold
		OpenTimeout:      1 * time.Second,
	}
	cb := NewCircuitBreaker("test-sink", cfg, logger)

	var executed atomic.Int64
	done := make(chan struct{})

	// Start many goroutines
	for i := 0; i < 100; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = cb.Execute(context.Background(), func(ctx context.Context) error {
					executed.Add(1)
					return nil
				})
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	assert.Equal(t, int64(10000), executed.Load())
	assert.Equal(t, CircuitClosed, cb.State())
}

func TestCircuitBreakerSink_Write(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockSink := &mockSink{}

	cfg := CircuitBreakerConfig{
		FailureThreshold: 2,
		OpenTimeout:      1 * time.Second,
	}
	cbSink := NewCircuitBreakerSink(mockSink, cfg, logger)

	event := &Event{
		ID:   "test-1",
		Type: "session.created",
	}

	// Successful write
	err := cbSink.Write(context.Background(), event)
	assert.NoError(t, err)
	assert.Equal(t, 1, mockSink.writeCount)
	assert.True(t, cbSink.IsHealthy())

	// Configure sink to fail
	mockSink.failNext = true
	err = cbSink.Write(context.Background(), event)
	assert.Error(t, err)

	mockSink.failNext = true
	err = cbSink.Write(context.Background(), event)
	assert.Error(t, err)

	// Circuit should be open now
	assert.False(t, cbSink.IsHealthy())
	assert.Equal(t, CircuitOpen, cbSink.CircuitBreaker().State())
}

func TestCircuitBreakerSink_WriteBatch(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockSink := &mockBatchSink{}

	cfg := DefaultCircuitBreakerConfig()
	cbSink := NewCircuitBreakerSink(mockSink, cfg, logger)

	events := []*Event{
		{ID: "1", Type: "session.created"},
		{ID: "2", Type: "session.approved"},
	}

	err := cbSink.WriteBatch(context.Background(), events)
	assert.NoError(t, err)
	assert.Equal(t, 1, mockSink.batchCount)
	assert.Equal(t, 2, mockSink.eventCount)
}

// mockSink is a test sink that tracks calls.
type mockSink struct {
	writeCount int
	failNext   bool
	closed     bool
}

func (s *mockSink) Write(ctx context.Context, event *Event) error {
	s.writeCount++
	if s.failNext {
		s.failNext = false
		return errors.New("mock error")
	}
	return nil
}

func (s *mockSink) Close() error {
	s.closed = true
	return nil
}

func (s *mockSink) Name() string {
	return "mock"
}

// mockBatchSink is a test sink that supports batching.
type mockBatchSink struct {
	mockSink
	batchCount int
	eventCount int
}

func (s *mockBatchSink) WriteBatch(ctx context.Context, events []*Event) error {
	s.batchCount++
	s.eventCount += len(events)
	if s.failNext {
		s.failNext = false
		return errors.New("mock batch error")
	}
	return nil
}

func TestCircuitBreakerSink_Stats(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockSink := &mockSink{}

	cfg := DefaultCircuitBreakerConfig()
	cbSink := NewCircuitBreakerSink(mockSink, cfg, logger)

	// Write a successful event
	err := cbSink.Write(context.Background(), &Event{ID: "1", Type: "test.event"})
	assert.NoError(t, err)

	// Get stats from CircuitBreakerSink
	stats := cbSink.Stats()
	assert.Equal(t, int64(1), stats.TotalRequests)
	assert.Equal(t, int64(1), stats.TotalSuccesses)
	assert.Equal(t, int64(0), stats.TotalFailures)
	assert.Equal(t, CircuitClosed, stats.State)
}

func TestCircuitBreakerSink_IsHealthy(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockSink := &mockSink{failNext: true}

	cfg := CircuitBreakerConfig{
		FailureThreshold: 1,
		OpenTimeout:      1 * time.Second,
	}
	cbSink := NewCircuitBreakerSink(mockSink, cfg, logger)

	// Initially healthy
	assert.True(t, cbSink.IsHealthy())

	// Cause a failure to trip the circuit
	_ = cbSink.Write(context.Background(), &Event{ID: "1", Type: "test.event"})

	// Should now be unhealthy
	assert.False(t, cbSink.IsHealthy())
}

func TestCircuitBreakerSink_Name(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockSink := &mockSink{}

	cfg := DefaultCircuitBreakerConfig()
	cbSink := NewCircuitBreakerSink(mockSink, cfg, logger)

	assert.Equal(t, "mock", cbSink.Name())
}

func TestCircuitBreakerSink_Close(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockSink := &mockSink{}

	cfg := DefaultCircuitBreakerConfig()
	cbSink := NewCircuitBreakerSink(mockSink, cfg, logger)

	err := cbSink.Close()
	assert.NoError(t, err)
	assert.True(t, mockSink.closed)
}
