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
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// MockKafkaBroker provides a simple mock Kafka broker for testing.
// It accepts connections and records messages without requiring a real Kafka cluster.
type MockKafkaBroker struct {
	listener     net.Listener
	addr         string
	mu           sync.Mutex
	messages     [][]byte
	messageCount atomic.Int64
	closed       atomic.Bool
	connections  atomic.Int64
	wg           sync.WaitGroup
	t            *testing.T
}

// NewMockKafkaBroker creates and starts a mock Kafka broker on a random port.
func NewMockKafkaBroker(t *testing.T) *MockKafkaBroker {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock Kafka broker: %v", err)
	}

	broker := &MockKafkaBroker{
		listener: listener,
		addr:     listener.Addr().String(),
		messages: make([][]byte, 0),
		t:        t,
	}

	broker.wg.Add(1)
	go broker.acceptLoop()

	return broker
}

// Addr returns the address the broker is listening on.
func (b *MockKafkaBroker) Addr() string {
	return b.addr
}

// MessageCount returns the number of messages received.
func (b *MockKafkaBroker) MessageCount() int64 {
	return b.messageCount.Load()
}

// ConnectionCount returns the number of connections received.
func (b *MockKafkaBroker) ConnectionCount() int64 {
	return b.connections.Load()
}

// Messages returns a copy of all received messages.
func (b *MockKafkaBroker) Messages() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := make([][]byte, len(b.messages))
	copy(result, b.messages)
	return result
}

// Close shuts down the mock broker.
func (b *MockKafkaBroker) Close() error {
	if b.closed.Swap(true) {
		return nil // Already closed
	}
	err := b.listener.Close()
	b.wg.Wait()
	return err
}

func (b *MockKafkaBroker) acceptLoop() {
	defer b.wg.Done()

	for !b.closed.Load() {
		conn, err := b.listener.Accept()
		if err != nil {
			if b.closed.Load() {
				return
			}
			continue
		}
		b.connections.Add(1)
		b.wg.Add(1)
		go b.handleConnection(conn)
	}
}

func (b *MockKafkaBroker) handleConnection(conn net.Conn) {
	defer b.wg.Done()
	defer func() { _ = conn.Close() }()

	// Set reasonable timeouts
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return
	}

	buf := make([]byte, 64*1024) // 64KB buffer

	for !b.closed.Load() {
		// Read Kafka request frame (4-byte length prefix)
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}

		msgLen := int(binary.BigEndian.Uint32(buf[:4]))
		if msgLen <= 0 || msgLen > len(buf) {
			continue
		}

		// Read the message body
		if _, err := io.ReadFull(conn, buf[:msgLen]); err != nil {
			return
		}

		// Record the message
		b.mu.Lock()
		msgCopy := make([]byte, msgLen)
		copy(msgCopy, buf[:msgLen])
		b.messages = append(b.messages, msgCopy)
		b.mu.Unlock()
		b.messageCount.Add(1)

		// Send a minimal Kafka response (just correlation ID and success)
		// This is a simplified response that works for basic testing
		response := make([]byte, 8)
		binary.BigEndian.PutUint32(response[0:4], 4) // Response length
		copy(response[4:8], buf[0:4])                // Echo correlation ID
		if _, err := conn.Write(response); err != nil {
			return
		}

		// Reset deadline for next message
		if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}
	}
}

// WaitForMessages waits for at least n messages to be received.
func (b *MockKafkaBroker) WaitForMessages(ctx context.Context, n int64) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if b.MessageCount() >= n {
				return true
			}
		}
	}
}

// WaitForConnections waits for at least n connections to be received.
func (b *MockKafkaBroker) WaitForConnections(ctx context.Context, n int64) bool {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if b.ConnectionCount() >= n {
				return true
			}
		}
	}
}

// Reset clears all recorded messages.
func (b *MockKafkaBroker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.messages = make([][]byte, 0)
	b.messageCount.Store(0)
}
