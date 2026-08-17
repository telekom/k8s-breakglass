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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// queuedMockSink is a test sink that tracks events and can simulate failures
type queuedMockSink struct {
	name         string
	events       []*Event
	mu           sync.Mutex
	failAfter    int  // fail after this many events
	alwaysFail   bool // if true, always fail
	failCount    int
	writeDelay   time.Duration
	writtenCount atomic.Int64
}

func newQueuedMockSink(name string) *queuedMockSink {
	return &queuedMockSink{
		name:   name,
		events: make([]*Event, 0),
	}
}

func (s *queuedMockSink) Write(_ context.Context, event *Event) error {
	if s.writeDelay > 0 {
		time.Sleep(s.writeDelay)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alwaysFail || (s.failAfter > 0 && len(s.events) >= s.failAfter) {
		s.failCount++
		return errors.New("simulated failure")
	}

	s.events = append(s.events, event)
	s.writtenCount.Add(1)
	return nil
}

func (s *queuedMockSink) Close() error {
	return nil
}

func (s *queuedMockSink) Name() string {
	return s.name
}

func (s *queuedMockSink) EventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func TestQueuedSink_BasicOperation(t *testing.T) {
	logger := zap.NewNop()
	mock := newQueuedMockSink("test")

	cfg := QueuedSinkConfig{
		QueueSize:               100,
		WorkerCount:             2,
		WriteTimeout:            5 * time.Second,
		DropOnFull:              true,
		CircuitBreakerThreshold: 5,
		CircuitBreakerResetTime: time.Second,
	}

	qs := NewQueuedSink(mock, cfg, logger)
	defer func() { _ = qs.Close() }()

	// Write some events
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		event := &Event{
			ID:   "test-" + string(rune('0'+i)),
			Type: EventSessionRequested,
		}
		err := qs.Write(ctx, event)
		require.NoError(t, err)
	}

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check events were processed
	assert.Equal(t, 10, mock.EventCount())

	// Check health
	health := qs.Health()
	assert.True(t, health.Healthy)
	assert.Equal(t, "test", health.Name)
	assert.Equal(t, int64(10), health.ProcessedEvents)
	assert.Equal(t, int64(0), health.DroppedEvents)
	assert.Equal(t, int64(0), health.FailedEvents)
	assert.False(t, health.CircuitOpen)
}

func TestQueuedSink_QueueOverflow(t *testing.T) {
	logger := zap.NewNop()
	mock := newQueuedMockSink("slow-sink")
	mock.writeDelay = 100 * time.Millisecond // Slow writes

	cfg := QueuedSinkConfig{
		QueueSize:   5, // Small queue
		WorkerCount: 1, // Only one worker
		DropOnFull:  true,
	}

	qs := NewQueuedSink(mock, cfg, logger)
	defer func() { _ = qs.Close() }()

	// Flood the queue - this should cause drops
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		event := &Event{
			ID:   "flood-" + string(rune('0'+i)),
			Type: EventHealthCheck,
		}
		_ = qs.Write(ctx, event)
	}

	// Wait a bit for processing
	time.Sleep(50 * time.Millisecond)

	// Check health - should show drops
	health := qs.Health()
	assert.Greater(t, health.DroppedEvents, int64(0), "Should have dropped some events")
}

func TestQueuedSink_CircuitBreaker(t *testing.T) {
	logger := zap.NewNop()
	mock := newQueuedMockSink("failing-sink")
	mock.alwaysFail = true // Fail all writes

	cfg := QueuedSinkConfig{
		QueueSize:               100,
		WorkerCount:             1,
		WriteTimeout:            100 * time.Millisecond,
		CircuitBreakerThreshold: 3,
		CircuitBreakerResetTime: 100 * time.Millisecond,
	}

	qs := NewQueuedSink(mock, cfg, logger)
	defer func() { _ = qs.Close() }()

	// Write events that will fail
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		event := &Event{
			ID:   "fail-" + string(rune('0'+i)),
			Type: EventSessionRequested,
		}
		_ = qs.Write(ctx, event)
	}

	// Wait for processing and circuit to open.
	require.Eventually(t, func() bool {
		health := qs.Health()
		return health.CircuitOpen && health.ConsecutiveFails >= 3
	}, 5*time.Second, 10*time.Millisecond, "circuit breaker should open after failures")

	// Now allow writes to succeed
	mock.failAfter = 1000 // Won't fail anymore

	// Keep attempting the write until the reset closes the circuit.
	require.Eventually(t, func() bool {
		_ = qs.Write(ctx, &Event{ID: "retry", Type: EventSessionRequested})
		return !qs.Health().CircuitOpen
	}, 5*time.Second, 10*time.Millisecond, "circuit breaker should reset")
}

func TestIsolatedMultiSink_Independence(t *testing.T) {
	logger := zap.NewNop()

	// Create one fast sink and one slow sink
	fastSink := newQueuedMockSink("fast")
	slowSink := newQueuedMockSink("slow")
	slowSink.writeDelay = 50 * time.Millisecond

	cfg := QueuedSinkConfig{
		QueueSize:   100,
		WorkerCount: 2,
	}

	ims := NewIsolatedMultiSink([]Sink{fastSink, slowSink}, cfg, logger)
	defer func() { _ = ims.Close() }()

	// Write events
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 10; i++ {
		event := &Event{
			ID:   "multi-" + string(rune('0'+i)),
			Type: EventSessionRequested,
		}
		err := ims.Write(ctx, event)
		require.NoError(t, err)
	}
	writeTime := time.Since(start)

	// Writes should be fast (non-blocking)
	assert.Less(t, writeTime, 10*time.Millisecond, "Writes should be non-blocking")

	// Wait for fast sink to process
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 10, fastSink.EventCount(), "Fast sink should have all events")

	// Slow sink should still be processing or done
	time.Sleep(600 * time.Millisecond) // Wait for slow sink
	assert.Equal(t, 10, slowSink.EventCount(), "Slow sink should eventually have all events")

	// Check health
	healths := ims.Health()
	assert.Len(t, healths, 2)
	assert.True(t, ims.IsHealthy())
}

func TestIsolatedMultiSink_FailureIsolation(t *testing.T) {
	logger := zap.NewNop()

	// Create one working sink and one failing sink
	workingSink := newQueuedMockSink("working")
	failingSink := newQueuedMockSink("failing")
	failingSink.alwaysFail = true // Fail all writes

	cfg := QueuedSinkConfig{
		QueueSize:               100,
		WorkerCount:             1,
		CircuitBreakerThreshold: 3,
		CircuitBreakerResetTime: time.Hour, // Long reset to keep circuit open
	}

	ims := NewIsolatedMultiSink([]Sink{workingSink, failingSink}, cfg, logger)
	defer func() { _ = ims.Close() }()

	// Write events
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		event := &Event{
			ID:   "isolated-" + string(rune('0'+i)),
			Type: EventSessionRequested,
		}
		_ = ims.Write(ctx, event)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Working sink should have all events
	assert.Equal(t, 10, workingSink.EventCount(), "Working sink should have all events")

	// Failing sink should have no events
	assert.Equal(t, 0, failingSink.EventCount(), "Failing sink should have no events")

	// Overall health should be false (one sink unhealthy)
	assert.False(t, ims.IsHealthy(), "Overall health should be false with one failing sink")

	// But individual healths should show the difference
	healths := ims.Health()
	var workingHealth, failingHealth QueuedSinkHealth
	for _, h := range healths {
		if h.Name == "working" {
			workingHealth = h
		} else {
			failingHealth = h
		}
	}

	assert.True(t, workingHealth.Healthy, "Working sink should be healthy")
	assert.True(t, failingHealth.CircuitOpen, "Failing sink circuit should be open")
}

func TestQueuedSink_Name(t *testing.T) {
	mockSink := newQueuedMockSink("test-sink")
	cfg := DefaultQueuedSinkConfig()
	logger := zap.NewNop()

	qs := NewQueuedSink(mockSink, cfg, logger)
	defer func() { _ = qs.Close() }()

	assert.Equal(t, "test-sink", qs.Name())
}

// circuitOpenSink always returns ErrCircuitOpen from Write, which drives the
// requeue branch of processQueue.
type circuitOpenSink struct {
	name  string
	calls atomic.Int64
}

func (s *circuitOpenSink) Write(_ context.Context, _ *Event) error {
	s.calls.Add(1)
	return ErrCircuitOpen
}

func (s *circuitOpenSink) Close() error { return nil }

func (s *circuitOpenSink) Name() string { return s.name }

// TestQueuedSink_CloseDuringCircuitOpenRequeue is a regression test for the
// "send on closed channel" panic (#053). When the underlying sink returns
// ErrCircuitOpen the worker requeues the event; that requeue used to happen in
// an untracked goroutine, so Close() could close qs.queue while the send was
// still pending, panicking the process unrecoverably.
//
// The panic surfaces as a process-level crash (not a recovered panic), so this
// test drives many concurrent Write/requeue cycles against a Close to make the
// window reliably reachable. Run with -race.
func TestQueuedSink_CloseDuringCircuitOpenRequeue(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		sink := &circuitOpenSink{name: "circuit-open"}
		cfg := QueuedSinkConfig{
			// Small queue so the requeue contends for space and workers keep
			// cycling the same events.
			QueueSize:               4,
			WorkerCount:             4,
			WriteTimeout:            time.Second,
			DropOnFull:              true,
			CircuitBreakerThreshold: 1_000_000, // never open our own breaker
			CircuitBreakerResetTime: time.Hour,
		}
		qs := NewQueuedSink(sink, cfg, zap.NewNop())

		var producers sync.WaitGroup
		stop := make(chan struct{})
		for p := 0; p < 4; p++ {
			producers.Add(1)
			go func() {
				defer producers.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					// EventSessionValidated is non-sensitive, so a full queue
					// drops rather than writing synchronously.
					_ = qs.Write(context.Background(), &Event{
						ID:   "e",
						Type: EventSessionValidated,
					})
				}
			}()
		}

		// Let the workers start cycling events through the requeue branch.
		for sink.calls.Load() < 4 {
			time.Sleep(time.Millisecond)
		}

		// Close concurrently with in-flight requeues. Before the fix this
		// panics with "send on closed channel".
		require.NoError(t, qs.Close())
		close(stop)
		producers.Wait()
	}
}

// TestQueuedSink_WriteAfterCloseReturnsError asserts that a Write racing with
// Close never panics and reports the closed sink instead.
func TestQueuedSink_WriteAfterCloseReturnsError(t *testing.T) {
	sink := newQueuedMockSink("late-write")
	qs := NewQueuedSink(sink, DefaultQueuedSinkConfig(), zap.NewNop())
	require.NoError(t, qs.Close())

	err := qs.Write(context.Background(), &Event{ID: "after-close", Type: EventSessionValidated})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is closed")
}
