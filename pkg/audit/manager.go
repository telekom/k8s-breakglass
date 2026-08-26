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
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

const maxDebugSessionAuditDetailLength = 256

const maxDebugSessionAuditDetailEntries = 32

const maxDebugSessionAuditDetailDepth = 3

var debugSessionAuditSecretPattern = regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+|bearer\s+|(?:token|password|secret|client_secret)\s*[=:]\s*)[^\s,;]+`)

// SanitizeDebugSessionAuditDetail removes control characters, redacts common
// credential-shaped values, and bounds user-controlled audit detail. Audit
// sinks are intentionally unaware of these policy details; every sink receives
// the same safe event.
func SanitizeDebugSessionAuditDetail(value string) string {
	value = strings.TrimSpace(value)
	value = debugSessionAuditSecretPattern.ReplaceAllString(value, "[REDACTED]")
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len([]rune(value)) > maxDebugSessionAuditDetailLength {
		value = string([]rune(value)[:maxDebugSessionAuditDetailLength])
	}
	return value
}

func isSensitiveDebugSessionDetailKey(key string) bool {
	switch strings.ToLower(key) {
	case "authorization", "body", "command", "credentials", "credential", "env", "environment", "error", "headers", "message", "output", "password", "raw", "reason", "request", "requestbody", "secret", "token":
		return true
	default:
		return false
	}
}

func sanitizeDebugSessionAuditValue(key string, value interface{}, depth int) interface{} {
	if isSensitiveDebugSessionDetailKey(key) {
		return "[REDACTED]"
	}
	if depth >= maxDebugSessionAuditDetailDepth {
		return "[REDACTED]"
	}

	switch typed := value.(type) {
	case string:
		return SanitizeDebugSessionAuditDetail(typed)
	case []string:
		bounded := typed
		if len(bounded) > 16 {
			bounded = bounded[:16]
		}
		result := make([]string, 0, len(bounded))
		for _, item := range bounded {
			result = append(result, SanitizeDebugSessionAuditDetail(item))
		}
		return result
	case map[string]string:
		result := make(map[string]string, min(len(typed), maxDebugSessionAuditDetailEntries))
		count := 0
		for itemKey, itemValue := range typed {
			if count >= maxDebugSessionAuditDetailEntries {
				break
			}
			if isSensitiveDebugSessionDetailKey(itemKey) {
				result[itemKey] = "[REDACTED]"
			} else {
				result[itemKey] = SanitizeDebugSessionAuditDetail(itemValue)
			}
			count++
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{}, min(len(typed), maxDebugSessionAuditDetailEntries))
		count := 0
		for itemKey, itemValue := range typed {
			if count >= maxDebugSessionAuditDetailEntries {
				break
			}
			result[itemKey] = sanitizeDebugSessionAuditValue(itemKey, itemValue, depth+1)
			count++
		}
		return result
	default:
		return value
	}
}

func debugSessionAuditDetails(values map[string]interface{}) map[string]interface{} {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]interface{}, min(len(values), maxDebugSessionAuditDetailEntries))
	count := 0
	for key, value := range values {
		if count >= maxDebugSessionAuditDetailEntries {
			break
		}
		result[key] = sanitizeDebugSessionAuditValue(key, value, 0)
		count++
	}
	return result
}

func sanitizeDebugSessionAuditEvent(event *Event) {
	if event == nil || !strings.HasPrefix(string(event.Type), "debug_session.") {
		return
	}
	event.Actor.User = SanitizeDebugSessionAuditDetail(event.Actor.User)
	event.Actor.IdentityProvider = SanitizeDebugSessionAuditDetail(event.Actor.IdentityProvider)
	event.Actor.SourceIP = SanitizeDebugSessionAuditDetail(event.Actor.SourceIP)
	event.Actor.UserAgent = SanitizeDebugSessionAuditDetail(event.Actor.UserAgent)
	if len(event.Actor.Groups) > 16 {
		event.Actor.Groups = event.Actor.Groups[:16]
	}
	for i := range event.Actor.Groups {
		event.Actor.Groups[i] = SanitizeDebugSessionAuditDetail(event.Actor.Groups[i])
	}
	event.Target.Kind = SanitizeDebugSessionAuditDetail(event.Target.Kind)
	event.Target.Name = SanitizeDebugSessionAuditDetail(event.Target.Name)
	event.Target.Namespace = SanitizeDebugSessionAuditDetail(event.Target.Namespace)
	event.Target.Cluster = SanitizeDebugSessionAuditDetail(event.Target.Cluster)
	event.Target.APIGroup = SanitizeDebugSessionAuditDetail(event.Target.APIGroup)
	event.Details = debugSessionAuditDetails(event.Details)
	if event.RequestContext != nil {
		event.RequestContext.CorrelationID = SanitizeDebugSessionAuditDetail(event.RequestContext.CorrelationID)
		event.RequestContext.SessionName = SanitizeDebugSessionAuditDetail(event.RequestContext.SessionName)
		event.RequestContext.EscalationName = SanitizeDebugSessionAuditDetail(event.RequestContext.EscalationName)
		event.RequestContext.DebugSessionName = SanitizeDebugSessionAuditDetail(event.RequestContext.DebugSessionName)
	}
}

// stableDebugSessionEventID makes retries of the same observed transition
// idempotent for sinks that deduplicate by Event.ID. Details are sanitized
// before they participate in the key, so secrets and raw errors never affect
// or enter the identity.
func stableDebugSessionEventID(event *Event) string {
	if event == nil || !strings.HasPrefix(string(event.Type), "debug_session.") {
		return ""
	}
	payload, err := json.Marshal(struct {
		Type    EventType              `json:"type"`
		Actor   string                 `json:"actor"`
		Target  Target                 `json:"target"`
		Details map[string]interface{} `json:"details,omitempty"`
	}{event.Type, event.Actor.User, event.Target, event.Details})
	if err != nil {
		return ""
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, payload).String()
}

// Manager coordinates audit event creation and distribution.
// Designed for EXTREMELY granular audit trails with non-blocking operation.
type Manager struct {
	sink        Sink
	directSinks []Sink // underlying sinks for true synchronous fallback writes
	asyncQueue  chan *Event
	logger      *zap.Logger
	wg          sync.WaitGroup
	closed      atomic.Bool
	// closeMu guards asyncQueue sends against concurrent Close. Emit/EmitSync
	// hold RLock while sending; Close holds Lock before closing the channel, so
	// no send can race with the channel close.
	closeMu   sync.RWMutex
	stopStats chan struct{} // Signal to stop stats reporter

	// Metrics for monitoring
	queuedEvents               atomic.Int64
	droppedEvents              atomic.Int64
	processedEvents            atomic.Int64
	sensitiveEventsSyncWritten atomic.Int64
	sequence                   atomic.Uint64

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
	// sampleRateConfigured is true when SampleRate was explicitly configured.
	// It preserves the zero-value default while allowing an explicit 0.0 rate.
	sampleRateConfigured bool

	// HighVolumeEventTypes are sampled at SampleRate.
	// Other events are always captured.
	// Default: empty (all events treated equally)
	HighVolumeEventTypes []EventType

	// AlwaysCaptureEventTypes are never sampled (always 100%).
	AlwaysCaptureEventTypes []EventType

	// IncludeEventTypes allows only matching event types. Empty means all.
	IncludeEventTypes []string

	// ExcludeEventTypes blocks matching event types and takes precedence.
	ExcludeEventTypes []string

	// WriteTimeout is the timeout for writing to sinks.
	// Default: 5s
	WriteTimeout time.Duration

	// StatsInterval is how often to log queue/sink stats.
	// Set to 0 to disable periodic stats logging.
	// Default: 30s
	StatsInterval time.Duration

	// DirectSinks are the underlying raw sinks used for true synchronous
	// writes during sensitive-event fallback, bypassing QueuedSink layers.
	// If empty, the fallback writes through the primary sink chain, which may
	// block up to the context timeout and is subject to downstream queue limits.
	DirectSinks []Sink
}

// DefaultManagerConfig returns default configuration for high-throughput.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		QueueSize:     100000, // 100k events buffered
		WorkerCount:   5,
		BatchSize:     100,
		BatchTimeout:  100 * time.Millisecond,
		DropOnFull:    true, // Non-blocking
		SampleRate:    1.0,  // Capture all
		WriteTimeout:  5 * time.Second,
		StatsInterval: 30 * time.Second, // Log stats every 30s
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
	if !cfg.sampleRateConfigured && cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}
	if cfg.SampleRate < 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1.0
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.StatsInterval < 0 {
		cfg.StatsInterval = 0 // Disable stats
	}

	m := &Manager{
		sink:        sink,
		directSinks: cfg.DirectSinks,
		asyncQueue:  make(chan *Event, cfg.QueueSize),
		logger:      logger.Named("audit-manager"),
		config:      cfg,
		stopStats:   make(chan struct{}),
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

	// Start periodic stats reporter if enabled
	if cfg.StatsInterval > 0 {
		go m.statsReporter()
	}

	logger.Info("audit manager started",
		zap.Int("queue_size", cfg.QueueSize),
		zap.Int("workers", cfg.WorkerCount),
		zap.Bool("batch_enabled", m.batchSink != nil),
		zap.Float64("sample_rate", cfg.SampleRate),
		zap.Duration("stats_interval", cfg.StatsInterval))

	return m
}

// Emit sends an audit event asynchronously (non-blocking for non-sensitive events).
// Sensitive events (IsSensitiveEvent) fall back to a synchronous write when the
// queue is full, which may block up to WriteTimeout.
func (m *Manager) Emit(ctx context.Context, event *Event) {
	sanitizeDebugSessionAuditEvent(event)
	if m.closed.Load() {
		return
	}

	if !eventTypeAllowed(event.Type, m.config.IncludeEventTypes, m.config.ExcludeEventTypes) {
		return
	}

	// Apply sampling for high-volume event types
	if m.shouldSample(event.Type) {
		m.droppedEvents.Add(1)
		return
	}

	// Assign ID if not set
	if event.ID == "" {
		event.ID = stableDebugSessionEventID(event)
		if event.ID == "" {
			event.ID = uuid.New().String()
		}
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Sequence == 0 {
		event.Sequence = m.sequence.Add(1)
	}

	// Set default severity if not set
	if event.Severity == "" {
		event.Severity = SeverityForEventType(event.Type)
	}

	// Non-blocking send to async queue.
	// Hold closeMu.RLock so that Close cannot close the channel concurrently.
	m.closeMu.RLock()
	defer m.closeMu.RUnlock()

	// Re-check closed under the lock: Close sets closed=true then acquires
	// closeMu.Lock, so if we see closed=true here the channel is already closed.
	if m.closed.Load() {
		return
	}

	select {
	case m.asyncQueue <- event:
		m.queuedEvents.Add(1)
	default:
		// Queue is full — sensitive events fall back to a synchronous direct write
		// to bypass manager-queue overflow. Per-sink queue drops (QueuedSink
		// queue_full / circuit_open) are not intercepted by this path.
		if IsSensitiveEvent(event.Type) {
			writeCtx, cancel := context.WithTimeout(context.Background(), m.config.WriteTimeout)
			defer cancel()

			writeErr := m.syncWriteDirect(writeCtx, event)
			if writeErr != nil {
				m.logger.Error("failed sync-write of sensitive audit event",
					zap.String("event_type", string(event.Type)),
					zap.String("event_id", event.ID),
					zap.Error(writeErr))
			}

			return
		}

		m.droppedEvents.Add(1)
		metrics.AuditEventsDropped.WithLabelValues(m.sink.Name(), "queue_full").Inc()
		if !m.config.DropOnFull {
			m.logger.Warn("audit queue full, dropping event",
				zap.String("event_type", string(event.Type)),
				zap.String("event_id", event.ID))
		}
	}
}

// syncWriteDirect writes an event synchronously to the direct (unbuffered) sinks.
// If no direct sinks are configured, it falls back to the queued sink.
// Metrics are incremented per-sink on success and failure.
func (m *Manager) syncWriteDirect(ctx context.Context, event *Event) error {
	if len(m.directSinks) == 0 {
		if err := m.sink.Write(ctx, event); err != nil {
			metrics.AuditSinkErrors.WithLabelValues(m.sink.Name(), "sensitive_sync_fallback").Inc()
			return err
		}
		// processedEvents counts enqueue/write attempts that succeeded at this
		// layer; it does not guarantee downstream delivery (the queued sink may
		// still drop the event if its own queue is full or the circuit is open).
		m.processedEvents.Add(1)
		metrics.AuditEventsProcessed.WithLabelValues(m.sink.Name()).Inc()
		m.sensitiveEventsSyncWritten.Add(1)
		metrics.AuditSensitiveEventsSyncWritten.WithLabelValues(m.sink.Name()).Inc()
		return nil
	}
	var errs []error
	anySucceeded := false
	for _, s := range m.directSinks {
		if err := s.Write(ctx, event); err != nil {
			m.logger.Error("direct sink write failed for sensitive event",
				zap.String("sink", s.Name()),
				zap.String("event_id", event.ID),
				zap.Error(err))
			metrics.AuditSinkErrors.WithLabelValues(s.Name(), "sensitive_sync_fallback").Inc()
			errs = append(errs, err)
		} else {
			anySucceeded = true
			// Per-sink Prometheus counter reflects actual sink delivery.
			metrics.AuditEventsProcessed.WithLabelValues(s.Name()).Inc()
			metrics.AuditSensitiveEventsSyncWritten.WithLabelValues(s.Name()).Inc()
		}
	}
	// Increment in-memory counters once per event (not once per sink) so that
	// ManagerStats.ProcessedEvents is not artificially inflated when multiple
	// direct sinks are configured.
	if anySucceeded {
		m.processedEvents.Add(1)
		m.sensitiveEventsSyncWritten.Add(1)
	}
	return errors.Join(errs...)
}

// EmitSync sends an audit event synchronously.
// Use sparingly - for critical events only.
func (m *Manager) EmitSync(ctx context.Context, event *Event) error {
	sanitizeDebugSessionAuditEvent(event)
	if !eventTypeAllowed(event.Type, m.config.IncludeEventTypes, m.config.ExcludeEventTypes) {
		return nil
	}

	// Assign ID if not set
	if event.ID == "" {
		event.ID = stableDebugSessionEventID(event)
		if event.ID == "" {
			event.ID = uuid.New().String()
		}
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Sequence == 0 {
		event.Sequence = m.sequence.Add(1)
	}

	// Set default severity if not set
	if event.Severity == "" {
		event.Severity = SeverityForEventType(event.Type)
	}

	return m.sink.Write(ctx, event)
}

// shouldSample returns true if the event should be sampled (dropped).
func (m *Manager) shouldSample(eventType EventType) bool {
	// Sensitive events are never sampled.
	if IsSensitiveEvent(eventType) {
		return false
	}

	if m.config.SampleRate >= 1.0 {
		return false
	}

	// Always-capture selectors override high-volume sampling.
	for _, acType := range m.config.AlwaysCaptureEventTypes {
		if acType == eventType {
			return false
		}
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

	if m.config.SampleRate <= 0 {
		return true
	}

	// Simple hash-based sampling using event timestamp nanoseconds
	return float64(time.Now().UnixNano()%1000)/1000.0 >= m.config.SampleRate
}

// processQueue handles events from the async queue (single-event mode).
func (m *Manager) processQueue(workerID int) {
	defer m.wg.Done()

	for event := range m.asyncQueue {
		ctx, cancel := context.WithTimeout(context.Background(), m.config.WriteTimeout)
		if err := m.sink.Write(ctx, event); err != nil {
			// Use string representation to avoid noisy stacktraces for transient errors
			m.logger.Error("failed to write audit event",
				zap.Int("worker", workerID),
				zap.String("event_id", event.ID),
				zap.String("event_type", string(event.Type)),
				zap.String("error", err.Error()))
			metrics.AuditSinkErrors.WithLabelValues(m.sink.Name(), "write").Inc()
		} else {
			m.processedEvents.Add(1)
			metrics.AuditEventsProcessed.WithLabelValues(m.sink.Name()).Inc()
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
			// Use string representation to avoid noisy stacktraces for transient errors
			m.logger.Error("failed to write audit batch",
				zap.Int("worker", workerID),
				zap.Int("batch_size", len(batch)),
				zap.String("error", err.Error()))
			metrics.AuditSinkErrors.WithLabelValues(m.sink.Name(), "batch_write").Add(float64(len(batch)))
		} else {
			m.processedEvents.Add(int64(len(batch)))
			metrics.AuditEventsProcessed.WithLabelValues(m.sink.Name()).Add(float64(len(batch)))
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

	// Stop stats reporter
	close(m.stopStats)

	// Acquire the exclusive write lock before closing the channel so that any
	// concurrent Emit holding the read lock finishes its send first.
	m.closeMu.Lock()
	close(m.asyncQueue)
	m.closeMu.Unlock()

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

// statsReporter periodically logs audit manager statistics.
func (m *Manager) statsReporter() {
	ticker := time.NewTicker(m.config.StatsInterval)
	defer ticker.Stop()

	lastProcessed := int64(0)
	lastDropped := int64(0)

	for {
		select {
		case <-m.stopStats:
			return
		case <-ticker.C:
			stats := m.Stats()

			// Calculate deltas since last report
			processedDelta := stats.ProcessedEvents - lastProcessed
			droppedDelta := stats.DroppedEvents - lastDropped

			lastProcessed = stats.ProcessedEvents
			lastDropped = stats.DroppedEvents

			queueUtilization := float64(0)
			if stats.QueueCapacity > 0 {
				queueUtilization = float64(stats.QueueLength) / float64(stats.QueueCapacity) * 100
			}

			// Log at debug level if everything is healthy, info if queue is getting full
			logLevel := m.logger.Debug
			if queueUtilization > 50 {
				logLevel = m.logger.Info
			}
			if queueUtilization > 80 {
				logLevel = m.logger.Warn
			}

			logLevel("audit manager stats",
				zap.Int("queue_length", stats.QueueLength),
				zap.Int("queue_capacity", stats.QueueCapacity),
				zap.Float64("queue_utilization_pct", queueUtilization),
				zap.Int64("total_queued", stats.QueuedEvents),
				zap.Int64("total_processed", stats.ProcessedEvents),
				zap.Int64("total_dropped", stats.DroppedEvents),
				zap.Int64("processed_since_last", processedDelta),
				zap.Int64("dropped_since_last", droppedDelta),
				zap.String("sink_name", m.sink.Name()),
				zap.Bool("batch_enabled", m.batchSink != nil))

			// Update Prometheus metrics for queue depth
			metrics.AuditQueueLength.WithLabelValues(m.sink.Name()).Set(float64(stats.QueueLength))
			metrics.AuditQueueCapacity.WithLabelValues(m.sink.Name()).Set(float64(stats.QueueCapacity))
		}
	}
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
		Details: debugSessionAuditDetails(map[string]interface{}{
			"templateName": templateName,
		}),
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionRecording emits a lifecycle event for a terminal recording.
// CorrelationID is intentionally supplied separately from artifact metadata so
// the event remains useful even when finalization fails.
func (m *Manager) DebugSessionRecording(ctx context.Context, eventType EventType, sessionName, namespace, cluster, correlationID string, details map[string]interface{}) {
	// Whitelist the small metadata contract rather than filtering a caller map.
	// This prevents future sidecars or integrations from accidentally placing
	// recording bytes, credentials, or arbitrary nested data in the audit queue.
	safeDetails := make(map[string]interface{}, 3)
	for _, key := range []string{"format", "retention", "state"} {
		if value, ok := details[key]; ok {
			switch value := value.(type) {
			case string:
				if len(value) <= 128 {
					safeDetails[key] = value
				}
			case bool, int, int32, int64, uint, uint32, uint64:
				safeDetails[key] = value
			}
		}
	}
	m.Emit(ctx, &Event{
		Type:     eventType,
		Severity: SeverityForEventType(eventType),
		Actor:    Actor{User: "system"},
		Target:   Target{Kind: "DebugSession", Name: sessionName, Namespace: namespace, Cluster: cluster},
		Details:  safeDetails,
		RequestContext: &RequestContext{
			CorrelationID:    correlationID,
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
		Details: debugSessionAuditDetails(map[string]interface{}{
			"reason": reason,
		}),
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionFailed emits an audit event when a debug session fails.
func (m *Manager) DebugSessionFailed(ctx context.Context, sessionName, namespace, cluster, reason string, details map[string]interface{}) {
	boundedDetails := debugSessionAuditDetails(details)
	if boundedDetails == nil {
		boundedDetails = make(map[string]interface{})
	}
	boundedDetails["reason"] = SanitizeDebugSessionAuditDetail(reason)
	boundedDetails["cluster"] = SanitizeDebugSessionAuditDetail(cluster)

	m.Emit(ctx, &Event{
		Type:     EventDebugSessionFailed,
		Severity: SeverityCritical,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      "DebugSession",
			Name:      sessionName,
			Namespace: namespace,
		},
		Details: boundedDetails,
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionExpired emits an audit event when a debug session expires.
func (m *Manager) DebugSessionExpired(ctx context.Context, sessionName, namespace, cluster string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionExpired,
		Severity: SeverityWarning,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      "DebugSession",
			Name:      sessionName,
			Namespace: namespace,
		},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"cluster": cluster,
		}),
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionApprovalTimeout emits an audit event when a debug session approval times out.
func (m *Manager) DebugSessionApprovalTimeout(ctx context.Context, sessionName, namespace, cluster string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionApprovalTimeout,
		Severity: SeverityWarning,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      "DebugSession",
			Name:      sessionName,
			Namespace: namespace,
		},
		Details: map[string]interface{}{
			"cluster": cluster,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionBindingUnresolved emits an audit event when a DebugSession names an
// explicit BindingRef that could not be resolved. Because the binding carries the
// approver configuration, this leaves the approval requirement indeterminate and the
// session is NOT activated — it is requeued until the ref resolves or the reference
// is corrected.
func (m *Manager) DebugSessionBindingUnresolved(ctx context.Context, sessionName, namespace, cluster, bindingName, bindingNamespace, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionBindingUnresolved,
		Severity: SeverityWarning,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      "DebugSession",
			Name:      sessionName,
			Namespace: namespace,
		},
		Details: map[string]interface{}{
			"cluster":          cluster,
			"bindingName":      bindingName,
			"bindingNamespace": bindingNamespace,
			"reason":           reason,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionPodFailed emits an audit event when a debug session pod fails.
func (m *Manager) DebugSessionPodFailed(ctx context.Context, sessionName, namespace, podName, podNamespace, reason, message string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionPodFailed,
		Severity: SeverityCritical,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      "Pod",
			Name:      podName,
			Namespace: podNamespace,
		},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"debug_session":  sessionName,
			"session_ns":     namespace,
			"failure_reason": reason,
			"message":        message,
		}),
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionPodRestarted emits an audit event when a debug session pod restarts.
func (m *Manager) DebugSessionPodRestarted(ctx context.Context, sessionName, namespace, podName, podNamespace string, restartCount int32, lastTerminationReason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionPodRestarted,
		Severity: SeverityWarning,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      "Pod",
			Name:      podName,
			Namespace: podNamespace,
		},
		Details: map[string]interface{}{
			"debug_session":           sessionName,
			"session_ns":              namespace,
			"restart_count":           restartCount,
			"last_termination_reason": lastTerminationReason,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionResourceDeployed emits an audit event when debug session resources are deployed.
func (m *Manager) DebugSessionResourceDeployed(ctx context.Context, sessionName, namespace, cluster, resourceKind, resourceName, resourceNamespace string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionResourceDeploy,
		Severity: SeverityInfo,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      resourceKind,
			Name:      resourceName,
			Namespace: resourceNamespace,
		},
		Details: map[string]interface{}{
			"debug_session": sessionName,
			"session_ns":    namespace,
			"cluster":       cluster,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionResourceCleanup emits an audit event when debug session resources are cleaned up.
func (m *Manager) DebugSessionResourceCleanup(ctx context.Context, sessionName, namespace, cluster, resourceKind, resourceName, resourceNamespace string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionResourceCleanup,
		Severity: SeverityInfo,
		Actor:    Actor{User: "system"},
		Target: Target{
			Kind:      resourceKind,
			Name:      resourceName,
			Namespace: resourceNamespace,
		},
		Details: map[string]interface{}{
			"debug_session": sessionName,
			"session_ns":    namespace,
			"cluster":       cluster,
		},
		RequestContext: &RequestContext{
			DebugSessionName: sessionName,
		},
	})
}

// DebugSessionRequested records an accepted API request. Request reasons are
// deliberately treated as untrusted text and are redacted/bounded before they
// reach any sink.
func (m *Manager) DebugSessionRequested(ctx context.Context, sessionName, namespace, user, cluster, templateName, requestedDuration, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionRequested,
		Severity: SeverityInfo,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(user)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace), Cluster: SanitizeDebugSessionAuditDetail(cluster)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"templateRef":       templateName,
			"requestedDuration": requestedDuration,
			"reason":            reason,
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionValidated records that all API-side validation and authorization
// checks passed before the DebugSession object was persisted.
func (m *Manager) DebugSessionValidated(ctx context.Context, sessionName, namespace, user, cluster, templateName string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionValidated,
		Severity: SeverityInfo,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(user)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace), Cluster: SanitizeDebugSessionAuditDetail(cluster)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"templateRef": templateName,
			"outcome":     "passed",
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionValidationFailed records a stable validation category. It does
// not include raw admission errors, request bodies, or template values.
func (m *Manager) DebugSessionValidationFailed(ctx context.Context, sessionName, namespace, user, cluster, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionValidationFailed,
		Severity: SeverityWarning,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(user)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace), Cluster: SanitizeDebugSessionAuditDetail(cluster)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"outcome": "failed",
			"reason":  reason,
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionApproved records an approval decision separately from activation.
func (m *Manager) DebugSessionApproved(ctx context.Context, sessionName, namespace, approver, requestedBy, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionApproved,
		Severity: SeverityInfo,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(approver)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"requestedBy": requestedBy,
			"reason":      reason,
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionRejected records a rejection decision separately from terminal cleanup.
func (m *Manager) DebugSessionRejected(ctx context.Context, sessionName, namespace, rejector, requestedBy, reason string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionRejected,
		Severity: SeverityWarning,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(rejector)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"requestedBy": requestedBy,
			"reason":      reason,
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionRenewed records a successful lifetime extension.
func (m *Manager) DebugSessionRenewed(ctx context.Context, sessionName, namespace, user, cluster string, extension time.Duration, expiresAt time.Time, renewalCount int32) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionRenewed,
		Severity: SeverityInfo,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(user)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace), Cluster: SanitizeDebugSessionAuditDetail(cluster)},
		Details: map[string]interface{}{
			"extension":    extension.String(),
			"expiresAt":    expiresAt.UTC().Format(time.RFC3339),
			"renewalCount": renewalCount,
		},
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionAttached records a participant attachment/join without recording
// terminal command contents or other terminal-recorder data.
func (m *Manager) DebugSessionAttached(ctx context.Context, sessionName, namespace, user, cluster, operation string) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionAttached,
		Severity: SeverityInfo,
		Actor:    Actor{User: SanitizeDebugSessionAuditDetail(user)},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace), Cluster: SanitizeDebugSessionAuditDetail(cluster)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"operation": operation,
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}

// DebugSessionCleanupFailed records a bounded failure category and resource
// count. Raw Kubernetes errors may contain object data and are not forwarded.
func (m *Manager) DebugSessionCleanupFailed(ctx context.Context, sessionName, namespace, cluster, reason string, remaining int) {
	m.Emit(ctx, &Event{
		Type:     EventDebugSessionCleanupFailed,
		Severity: SeverityWarning,
		Actor:    Actor{User: "system"},
		Target:   Target{Kind: "DebugSession", Name: SanitizeDebugSessionAuditDetail(sessionName), Namespace: SanitizeDebugSessionAuditDetail(namespace), Cluster: SanitizeDebugSessionAuditDetail(cluster)},
		Details: debugSessionAuditDetails(map[string]interface{}{
			"reason":    reason,
			"remaining": remaining,
		}),
		RequestContext: &RequestContext{DebugSessionName: sessionName},
	})
}
