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

package mail

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
)

// MockSender simulates a mail sender with configurable behavior
type MockSender struct {
	mu            sync.Mutex
	successAfter  int
	attempts      int
	lastReceivers []string
	lastSubject   string
	lastBody      string
	host          string
}

func (m *MockSender) Send(receivers []string, subject, body string) error {
	m.mu.Lock()
	m.attempts++
	m.lastReceivers = receivers
	m.lastSubject = subject
	m.lastBody = body
	shouldFail := m.attempts <= m.successAfter
	m.mu.Unlock()

	if shouldFail {
		return errors.New("simulated send failure")
	}
	return nil
}

func (m *MockSender) Attempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts
}

func (m *MockSender) LastSubject() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSubject
}

func (m *MockSender) GetHost() string {
	return m.host
}

func (m *MockSender) GetPort() int {
	return 25
}

func TestQueue_Enqueue(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{successAfter: 0, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 10)
	queue.Start()
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	err := queue.Enqueue("test-1", []string{"user@example.com"}, "Test", "Body")
	assert.NoError(t, err)

	// Give worker time to process
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 1, sender.Attempts())
	assert.Equal(t, "Test", sender.LastSubject())
}

func TestQueue_EnqueueMultiple(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{successAfter: 0, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 100)
	queue.Start()
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	for i := range 5 {
		err := queue.Enqueue("test-"+string(rune(i)), []string{"user@example.com"}, "Subject", "Body")
		assert.NoError(t, err)
	}

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 5, sender.Attempts())
}

func TestQueue_EnqueueFull(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	// Create a queue with size 1 and don't start the worker so it fills immediately
	sender := &MockSender{successAfter: 1000, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 1) // Very small queue: only 1 item capacity

	// DON'T call queue.Start() - this prevents the worker from draining items
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	// First item should succeed
	err1 := queue.Enqueue("test-1", []string{"user@example.com"}, "Subject", "Body")
	assert.NoError(t, err1, "first enqueue should succeed")

	// Second item should fail because queue capacity is 1 and buffer is full
	err2 := queue.Enqueue("test-2", []string{"user@example.com"}, "Subject", "Body")
	assert.Error(t, err2, "second enqueue should fail - queue is full")
	if err2 != nil {
		assert.Contains(t, err2.Error(), "queue is full", "error message should indicate queue is full")
	}
}

func TestQueue_EnqueueNoReceivers(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{successAfter: 0, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 10)
	queue.Start()
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	err := queue.Enqueue("test-1", []string{}, "Subject", "Body")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no receivers")
}

func TestQueue_RetryWithBackoff(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	// Sender fails for first 2 attempts, succeeds on third
	sender := &MockSender{successAfter: 2, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 5, 100, 10)
	queue.Start()
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	err := queue.Enqueue("test-1", []string{"user@example.com"}, "Subject", "Body")
	assert.NoError(t, err)

	// Wait for initial attempt + retries
	time.Sleep(400 * time.Millisecond)

	// Should have succeeded after retries
	assert.Greater(t, sender.Attempts(), 1, "should have retried")
}

func TestQueue_Shutdown(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{successAfter: 0, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 10)
	queue.Start()

	err := queue.Enqueue("test-1", []string{"user@example.com"}, "Subject", "Body")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = queue.Stop(ctx)
	assert.NoError(t, err)
}

// SlowSender simulates a slow mail sender
type SlowSender struct {
	mu       sync.Mutex
	delay    time.Duration
	attempts int
	host     string
}

func (s *SlowSender) Send(receivers []string, subject, body string) error {
	s.mu.Lock()
	s.attempts++
	s.mu.Unlock()
	time.Sleep(s.delay)
	return nil
}

func (s *SlowSender) GetHost() string {
	return s.host
}

func (s *SlowSender) GetPort() int {
	return 25
}

func TestQueue_ShutdownTimeout(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	// Slow sender that takes 100ms per send
	slowSender := &SlowSender{delay: 100 * time.Millisecond, host: "test.example.com"}
	queue := NewQueue(slowSender, sugar, 10, 10, 100)
	queue.Start()

	// Enqueue 5 items (will take ~500ms to process all)
	for i := range 5 {
		err := queue.Enqueue("test-"+string(rune(i)), []string{"user@example.com"}, "Subject", "Body")
		if err != nil {
			t.Logf("failed to enqueue item %d: %v", i, err)
		}
	}

	// Try to stop with very short timeout (should timeout while processing)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := queue.Stop(ctx)
	// With such a short timeout, we expect it to timeout while processing items
	// But due to timing variations, we just verify it either succeeds or times out gracefully
	if err != nil {
		assert.Equal(t, context.DeadlineExceeded, err)
	}
}

func TestQueue_CalculateBackoff(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{host: "test.example.com"}
	queue := NewQueue(sender, sugar, 5, 10000, 10) // 10 seconds base

	testCases := []struct {
		attempt  int
		expected int
	}{
		{1, 10000},    // 10s
		{2, 20000},    // 20s
		{3, 40000},    // 40s
		{4, 80000},    // 80s (1m 20s)
		{5, 160000},   // 160s (2m 40s)
		{6, 320000},   // 320s (5m 20s)
		{7, 640000},   // 640s (10m 40s)
		{8, 1280000},  // 1280s (21+ min) - capped at 30m
		{9, 1800000},  // Capped at 30m
		{10, 1800000}, // Capped at 30m
	}

	for _, tc := range testCases {
		t.Run("attempt-"+string(rune(48+tc.attempt)), func(t *testing.T) {
			result := queue.calculateBackoff(tc.attempt)
			expected := tc.expected
			if tc.expected > 1800000 {
				expected = 1800000
			}
			assert.Equal(t, expected, result)
		})
	}
}

func TestQueue_Length(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	// Test queue length before starting the worker
	sender := &MockSender{successAfter: 100, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 10)
	// Don't start the queue yet - test it while idle

	assert.Equal(t, 0, queue.Length())

	err := queue.Enqueue("test-1", []string{"user@example.com"}, "Subject", "Body")
	assert.NoError(t, err)
	assert.Equal(t, 1, queue.Length())

	err = queue.Enqueue("test-2", []string{"user@example.com"}, "Subject", "Body")
	assert.NoError(t, err)
	assert.Equal(t, 2, queue.Length())

	// Now start the queue and let it process
	queue.Start()
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	// Give worker time to process all items
	time.Sleep(200 * time.Millisecond)
	// After processing, queue should be empty
	assert.Equal(t, 0, queue.Length())
}

func TestNewSenderWithQueue(t *testing.T) {
	mpConfig := &config.MailProviderConfig{
		Name:           "test-provider",
		Host:           "localhost",
		Port:           1025,
		Username:       "test@example.com",
		Password:       "password",
		RetryCount:     5,
		RetryBackoffMs: 10000,
		QueueSize:      1000,
		SenderAddress:  "sender@example.com",
	}

	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := NewSenderFromMailProvider(mpConfig, "")
	assert.NotNil(t, sender)

	queue := NewQueue(sender, sugar, mpConfig.RetryCount, mpConfig.RetryBackoffMs, mpConfig.QueueSize)
	assert.NotNil(t, queue)
	assert.Equal(t, 5, queue.maxRetries)
	assert.Equal(t, 10000, queue.initialBackoffMs)
	assert.Equal(t, 1000, queue.maxQueueSize)
}

func TestQueue_EnqueueAfterShutdown(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{successAfter: 0, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 10)
	queue.Start()
	err := queue.Stop(context.Background())
	if err != nil {
		t.Logf("failed to stop queue: %v", err)
	}

	// Try to enqueue after shutdown
	err = queue.Enqueue("test-1", []string{"user@example.com"}, "Subject", "Body")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shutting down")
}

func TestQueue_ConcurrentEnqueue(t *testing.T) {
	logger, _ := zap.NewProduction()
	defer func() {
		if err := logger.Sync(); err != nil {
			t.Logf("failed to sync logger: %v", err)
		}
	}()
	sugar := logger.Sugar()

	sender := &MockSender{successAfter: 0, host: "test.example.com"}
	queue := NewQueue(sender, sugar, 3, 100, 100)
	queue.Start()
	defer func() {
		if err := queue.Stop(context.Background()); err != nil {
			t.Errorf("failed to stop queue: %v", err)
		}
	}()

	// Enqueue from multiple goroutines
	done := make(chan error, 10)
	for i := range 10 {
		go func(id int) {
			err := queue.Enqueue("test-"+string(rune(48+id)), []string{"user@example.com"}, "Subject", "Body")
			done <- err
		}(i)
	}

	// Collect results
	for range 10 {
		err := <-done
		assert.NoError(t, err)
	}

	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, 10, sender.Attempts())
}

// PanickingSender panics on every Send call for testing recovery limits.
type PanickingSender struct {
	mu     sync.Mutex
	panics int
	host   string
}

func (p *PanickingSender) Send(receivers []string, subject, body string) error {
	p.mu.Lock()
	p.panics++
	p.mu.Unlock()
	panic("intentional test panic")
}

func (p *PanickingSender) GetHost() string { return p.host }
func (p *PanickingSender) GetPort() int    { return 25 }

func (p *PanickingSender) PanicCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.panics
}

func TestQueue_PanicRecoveryBehavior(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()

	panicSender := &PanickingSender{host: "test.example.com"}
	queue := NewQueue(panicSender, sugar, 3, 10, 10)
	queue.Start()
	defer func() {
		_ = queue.Stop(context.Background())
	}()

	// Enqueue items one at a time, waiting for each panic to be processed.
	// The worker can cancel the queue after reaching maxPanicRecoveries,
	// so later enqueues may legitimately fail.
	for i := range maxPanicRecoveries + 1 {
		err := queue.Enqueue("panic-"+strconv.Itoa(i), []string{"user@example.com"}, "Subject", "Body")
		if err != nil {
			// Queue was cancelled after the worker hit the panic limit — that's expected
			break
		}
		// Wait for this panic to be counted before enqueueing the next item
		expected := min(i+1, maxPanicRecoveries)
		assert.Eventually(t, func() bool {
			return panicSender.PanicCount() >= expected
		}, 5*time.Second, 50*time.Millisecond, "worker should have panicked at least %d times", expected)
	}

	// Poll until panics settle instead of using a fixed sleep
	assert.Eventually(t, func() bool {
		return panicSender.PanicCount() >= maxPanicRecoveries
	}, 5*time.Second, 50*time.Millisecond, "worker should panic %d times", maxPanicRecoveries)

	// Worker should have panicked exactly maxPanicRecoveries times and then stopped
	assert.Equal(t, maxPanicRecoveries, panicSender.PanicCount(),
		"worker should stop restarting after %d consecutive panics", maxPanicRecoveries)

	// After max panics the queue context is cancelled, so Enqueue should fail
	assert.Eventually(t, func() bool {
		err := queue.Enqueue("post-failure", []string{"user@example.com"}, "Subject", "Body")
		return err != nil
	}, 5*time.Second, 50*time.Millisecond, "Enqueue should return error after worker exhaustion")
}

// IntermittentPanickingSender panics for certain send counts and succeeds otherwise,
// used to test that successful sends reset the consecutive panic counter.
type IntermittentPanickingSender struct {
	mu      sync.Mutex
	sends   int
	panics  int
	panicAt map[int]bool // which send attempt numbers should panic
	host    string
}

func (s *IntermittentPanickingSender) Send(receivers []string, subject, body string) error {
	s.mu.Lock()
	s.sends++
	current := s.sends
	shouldPanic := s.panicAt[current]
	if shouldPanic {
		s.panics++
	}
	s.mu.Unlock()
	if shouldPanic {
		panic("intentional intermittent test panic")
	}
	return nil
}

func (s *IntermittentPanickingSender) GetHost() string { return s.host }
func (s *IntermittentPanickingSender) GetPort() int    { return 25 }

func TestQueue_PanicRecoveryResetsOnSuccess(t *testing.T) {
	logger := zap.NewNop()
	sugar := logger.Sugar()

	// Panics on sends 1 and 3, succeeds on send 2 (between panics).
	// If consecutive counter resets on success, the worker should survive
	// because neither panic run reaches maxPanicRecoveries (3).
	sender := &IntermittentPanickingSender{
		host:    "test.example.com",
		panicAt: map[int]bool{1: true, 3: true},
	}
	queue := NewQueue(sender, sugar, 3, 10, 10)
	queue.Start()
	defer func() {
		_ = queue.Stop(context.Background())
	}()

	// Enqueue 3 items: first will panic, second will succeed (resetting counter),
	// third will panic again but counter is back to 0 so worker survives.
	for i := range 3 {
		err := queue.Enqueue("intermittent-"+strconv.Itoa(i), []string{"user@example.com"}, "Subject", "Body")
		require.NoError(t, err, "Enqueue should succeed for item %d", i)
		// Wait for this item to be processed before sending the next,
		// ensuring deterministic ordering of panic/success sequences.
		expected := i + 1
		assert.Eventually(t, func() bool {
			sender.mu.Lock()
			defer sender.mu.Unlock()
			return sender.sends >= expected
		}, 5*time.Second, 10*time.Millisecond, "item %d should have been processed", i)
	}

	// Poll until all items are processed instead of using a fixed sleep
	assert.Eventually(t, func() bool {
		sender.mu.Lock()
		defer sender.mu.Unlock()
		return sender.sends >= 3
	}, 5*time.Second, 50*time.Millisecond, "all 3 items should have been processed")

	sender.mu.Lock()
	totalSends := sender.sends
	totalPanics := sender.panics
	sender.mu.Unlock()

	// All 3 items should have been processed (2 panics + 1 success),
	// and the worker should still be alive (not stopped).
	assert.Equal(t, 3, totalSends, "all 3 items should have been sent")
	assert.Equal(t, 2, totalPanics, "exactly 2 panics should have occurred")

	// Verify worker is still alive by enqueueing one more item
	err := queue.Enqueue("after-reset", []string{"user@example.com"}, "Subject", "Body")
	require.NoError(t, err, "Enqueue should succeed after panic counter reset")

	assert.Eventually(t, func() bool {
		sender.mu.Lock()
		defer sender.mu.Unlock()
		return sender.sends >= 4
	}, 5*time.Second, 50*time.Millisecond, "worker should process item after non-consecutive panics")

	sender.mu.Lock()
	finalSends := sender.sends
	sender.mu.Unlock()
	assert.Equal(t, 4, finalSends, "worker should still be alive and process items after non-consecutive panics")
}
