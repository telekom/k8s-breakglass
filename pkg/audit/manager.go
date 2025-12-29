/*
Copyright 2024.

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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// Manager coordinates audit event creation and distribution.
// Designed for EXTREMELY granular audit trails with non-blocking operation.
type Manager struct {
	sink       Sink
	asyncQueue chan *Event
	logger     *zap.Logger
	wg         sync.WaitGroup
	closed     atomic.Bool

	// Metrics for monitoring
	queuedEvents    atomic.Int64
	droppedEvents   atomic.Int64
	processedEvents atomic.Int64

	// Configuration
	config ManagerConfig

	// Batch processing for high-throughput
	batchSink BatchSink
}

// BatchSink is an optional interface for sinks that support batch writes.
type BatchSink interface {
	Sink
	WriteBatch(ctx context.Context, events []*Event) error
}

// ManagerConfig configures the audit Manager.
type ManagerConfig struct {
	// QueueSize is the size of the async event queue.
	// For extremely granular auditing, use a large queue (100k+).
	// Default: 100000
	QueueSize int

	// WorkerCount is the number of async processing workers.
	// More workers = higher throughput but more CPU.
	// Default: 5
	WorkerCount int

	// BatchSize is the number of events to batch before flushing.
	// Only used with BatchSink implementations.
	// Default: 100
	BatchSize int

	// BatchTimeout is the maximum time to wait before flushing a partial batch.
	// Default: 100ms
	BatchTimeout time.Duration

	// DropOnFull controls behavior when queue is full.
	// If true, new events are dropped silently (non-blocking).
	// If false, events are still dropped but a warning is logged.
	// Default: true (non-blocking)
	DropOnFull bool

	// SampleRate controls event sampling (1.0 = all, 0.1 = 10%).
	// Use for high-volume environments where 100% capture is too expensive.
	// Default: 1.0 (capture all events)
	SampleRate float64

	// HighVolumeEventTypes are sampled at SampleRate.
	// Other events are always captured.
	// Default: empty (all events treated equally)
	HighVolumeEventTypes []EventType

	// WriteTimeout is the timeout for writing to sinks.
	// Default: 5s
	WriteTimeout time.Duration
}

// DefaultManagerConfig returns default configuration for high-throughput.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		QueueSize:    100000, // 100k events buffered
		WorkerCount:  5,
		BatchSize:    100,
		BatchTimeout: 100 * time.Millisecond,
		DropOnFull:   true, // Non-blocking
		SampleRate:   1.0,  // Capture all
		WriteTimeout: 5 * time.Second,
	}
}

// NewManager creates a new audit Manager optimized for non-blocking operation.
func NewManager(sink Sink, cfg ManagerConfig, logger *zap.Logger) *Manager {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 100000
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 5
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 100 * time.Millisecond
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1.0
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}

	m := &Manager{
		sink:       sink,
		asyncQueue: make(chan *Event, cfg.QueueSize),
		logger:     logger.Named("audit-manager"),
		config:     cfg,
	}

	// Check if sink supports batch writes
	if batchSink, ok := sink.(BatchSink); ok {
		m.batchSink = batchSink
	}

	// Start async workers
	for i := 0; i < cfg.WorkerCount; i++ {
		m.wg.Add(1)
		if m.batchSink != nil {
			go m.processBatchQueue(i)
		} else {
			go m.processQueue(i)
		}
	}

	logger.Info("audit manager started",
		zap.Int("queue_size", cfg.QueueSize),
		zap.Int("workers", cfg.WorkerCount),
		zap.Bool("batch_enabled", m.batchSink != nil),
		zap.Float64("sample_rate", cfg.SampleRate))

	return m
}

// Emit sends an audit event asynchronously (non-blocking).
// This method NEVER blocks - if the queue is full, the event is dropped.
func (m *Manager) Emit(ctx context.Context, event *Event) {
	if m.closed.Load() {
		return
	}

	// Apply sampling for high-volume event types
	if m.shouldSample(event.Type) {
		m.droppedEvents.Add(1)
		return
	}

	// Assign ID if not set
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Set default severity if not set
	if event.Severity == "" {
		event.Severity = SeverityForEventType(event.Type)
	}

	// Non-blocking send to async queue
	select {
	case m.asyncQueue <- event:
		m.queuedEvents.Add(1)
	default:
		// Queue is full - drop event (non-blocking)
		m.droppedEvents.Add(1)
		metrics.AuditEventsDropped.Inc()
		if !m.config.DropOnFull {
			m.logger.Warn("audit queue full, dropping event",
				zap.String("event_type", string(event.Type)),
				zap.String("event_id", event.ID))
		}
	}
}

// EmitSync sends an audit event synchronously.
// Use sparingly - for critical events only.
func (m *Manager) EmitSync(ctx context.Context, event *Event) error {
	// Assign ID if not set
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Set default severity if not set
	if event.Severity == "" {
		event.Severity = SeverityForEventType(event.Type)
	}

	return m.sink.Write(ctx, event)
}

// shouldSample returns true if the event should be sampled (dropped).
func (m *Manager) shouldSample(eventType EventType) bool {
	if m.config.SampleRate >= 1.0 {
		return false
	}

	// Check if this is a high-volume event type
	isHighVolume := false
	for _, hvType := range m.config.HighVolumeEventTypes {
		if hvType == eventType {
			isHighVolume = true
			break
		}
	}

	if !isHighVolume && len(m.config.HighVolumeEventTypes) > 0 {
		return false // Always capture non-high-volume events
	}

	// Simple hash-based sampling using event timestamp nanoseconds
	return float64(time.Now().UnixNano()%1000)/1000.0 > m.config.SampleRate
}

// processQueue handles events from the async queue (single-event mode).
func (m *Manager) processQueue(workerID int) {
	defer m.wg.Done()

	for event := range m.asyncQueue {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.WriteTimeout)
		if err := m.sink.Write(ctx, event); err != nil {
			m.logger.Error("failed to write audit event",
				zap.Int("worker", workerID),
				zap.String("event_id", event.ID),
				zap.String("event_type", string(event.Type)),
				zap.Error(err))
			metrics.AuditSinkErrors.WithLabelValues(m.sink.Name()).Inc()
		} else {
			m.processedEvents.Add(1)
			metrics.AuditEventsProcessed.Inc()
		}
		cancel()
	}
}

// processBatchQueue handles events from the async queue using batch writes.
func (m *Manager) processBatchQueue(workerID int) {
	defer m.wg.Done()

	batch := make([]*Event, 0, m.config.BatchSize)
	ticker := time.NewTicker(m.config.BatchTimeout)
	defer ticker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), m.config.WriteTimeout)
		if err := m.batchSink.WriteBatch(ctx, batch); err != nil {
			m.logger.Error("failed to write audit batch",
				zap.Int("worker", workerID),
				zap.Int("batch_size", len(batch)),
				zap.Error(err))
			metrics.AuditSinkErrors.WithLabelValues(m.sink.Name()).Add(float64(len(batch)))
		} else {
			m.processedEvents.Add(int64(len(batch)))
			metrics.AuditEventsProcessed.Add(float64(len(batch)))
		}
		cancel()

		batch = batch[:0] // Reset batch
	}

	for {
		select {
		case event, ok := <-m.asyncQueue:
			if !ok {
				// Channel closed, flush remaining
				flushBatch()
				return
			}
			batch = append(batch, event)
			if len(batch) >= m.config.BatchSize {
				flushBatch()
			}
		case <-ticker.C:
			flushBatch()
		}
	}
}

// Close shuts down the audit manager gracefully.
func (m *Manager) Close() error {
	if m.closed.Swap(true) {
		return nil // Already closed
	}

	close(m.asyncQueue)
	m.wg.Wait()

	m.logger.Info("audit manager stopped",
		zap.Int64("processed", m.processedEvents.Load()),
		zap.Int64("dropped", m.droppedEvents.Load()))

	return m.sink.Close()
}

// Stats returns current audit manager statistics.
func (m *Manager) Stats() ManagerStats {
	return ManagerStats{
		QueuedEvents:    m.queuedEvents.Load(),
		ProcessedEvents: m.processedEvents.Load(),
		DroppedEvents:   m.droppedEvents.Load(),
		QueueLength:     len(m.asyncQueue),
		QueueCapacity:   cap(m.asyncQueue),
	}
}

// ManagerStats contains audit manager statistics.
type ManagerStats struct {
	QueuedEvents    int64
	ProcessedEvents int64
	DroppedEvents   int64
	QueueLength     int
	QueueCapacity   int
}

// --- Helper methods for common events ---

// SessionRequested emits an audit event for session requests.
func (m *Manager) SessionRequested(ctx context.Context, sessionName, escalationName, user, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventSessionRequested,
		Severity: SeverityInfo,
		Actor:    Actor{User: user},
		Target: Target{
			Kind: "BreakglassSession",
			Name: sessionName,
		},
		Details: map[string]interface{}{
			"escalationName": escalationName,
			"reason":         reason,
		},
		RequestContext: &RequestContext{
			SessionName:    sessionName,
			EscalationName: escalationName,
		},
	})
}

// SessionApproved emits an audit event for session approvals.
func (m *Manager) SessionApproved(ctx context.Context, sessionName, escalationName, approver, requestedBy string) {
	m.Emit(ctx, &Event{
		Type:     EventSessionApproved,
		Severity: SeverityInfo,
		Actor:    Actor{User: approver},
		Target: Target{
			Kind: "BreakglassSession",
			Name: sessionName,
		},
		Details: map[string]interface{}{
			"escalationName": escalationName,
			"requestedBy":    requestedBy,
		},
		RequestContext: &RequestContext{
			SessionName:    sessionName,
			EscalationName: escalationName,
		},
	})
}

// SessionDenied emits an audit event for session denials.
func (m *Manager) SessionDenied(ctx context.Context, sessionName, escalationName, denier, requestedBy, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventSessionDenied,
		Severity: SeverityWarning,
		Actor:    Actor{User: denier},
		Target: Target{
			Kind: "BreakglassSession",
			Name: sessionName,
		},
		Details: map[string]interface{}{
			"escalationName": escalationName,
			"requestedBy":    requestedBy,
			"reason":         reason,
		},
		RequestContext: &RequestContext{
			SessionName:    sessionName,
			EscalationName: escalationName,
		},
	})
}

// AccessDecision emits an audit event for authorization decisions.
func (m *Manager) AccessDecision(ctx context.Context, user string, groups []string, resource, name, namespace, cluster, verb string, allowed bool, sessionName string) {
	eventType := EventAccessGranted
	if !allowed {
		eventType = EventAccessDenied
	}

	m.Emit(ctx, &Event{
		Type:     eventType,
		Severity: SeverityForEventType(eventType),
		Actor: Actor{
			User:   user,
			Groups: groups,
		},
		Target: Target{
			Kind:      resource,
			Name:      name,
			Namespace: namespace,
			Cluster:   cluster,
		},
		Details: map[string]interface{}{
			"verb":    verb,
			"allowed": allowed,
		},
		RequestContext: &RequestContext{
			SessionName: sessionName,
		},
	})
}

// PolicyViolation emits an audit event for policy violations.
func (m *Manager) PolicyViolation(ctx context.Context, user string, groups []string, resource, name, namespace, cluster, policyName, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventPolicyViolation,
		Severity: SeverityWarning,
		Actor: Actor{
			User:   user,
			Groups: groups,
		},
		Target: Target{
			Kind:      resource,
			Name:      name,
			Namespace: namespace,
			Cluster:   cluster,
		},
		Details: map[string]interface{}{
			"policyName": policyName,
			"reason":     reason,
		},
	})
}

// DebugSessionCreated emits an audit event for debug session creation.
func (m *Manager) DebugSessionCreated(ctx context.Context, sessionName, user, cluster, templateName string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionCreated,
		Severity: SeverityInfo,
		Actor:    Actor{User: user},
		Target: Target{
			Kind:    "DebugSession",
			Name:    sessionName,
			Cluster: cluster,
		},
		Details: map[string]interface{}{
			"templateName": templateName,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionTerminated emits an audit event for debug session termination.
func (m *Manager) DebugSessionTerminated(ctx context.Context, sessionName, user, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionTerminated,
		Severity: SeverityCritical,
		Actor:    Actor{User: user},
		Target: Target{
			Kind: "DebugSession",
			Name: sessionName,
		},
		Details: map[string]interface{}{
			"reason": reason,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}
