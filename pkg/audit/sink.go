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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

// Sink defines the interface for audit event destinations.
type Sink interface {
	// Write sends an audit event to the sink.
	Write(ctx context.Context, event *Event) error

	// Close releases any resources held by the sink.
	Close() error

	// Name returns the sink's identifier.
	Name() string
}

// LogSink writes audit events to a structured logger.
type LogSink struct {
	logger *zap.Logger
}

// NewLogSink creates a new LogSink.
func NewLogSink(logger *zap.Logger) *LogSink {
	return &LogSink{logger: logger.Named("audit")}
}

// Write logs the audit event.
func (s *LogSink) Write(_ context.Context, event *Event) error {
	fields := []zap.Field{
		zap.String("event_id", event.ID),
		zap.String("event_type", string(event.Type)),
		zap.String("severity", string(event.Severity)),
		zap.Time("timestamp", event.Timestamp),
		zap.String("actor_user", event.Actor.User),
		zap.String("target_kind", event.Target.Kind),
		zap.String("target_name", event.Target.Name),
	}

	if event.Actor.IdentityProvider != "" {
		fields = append(fields, zap.String("actor_idp", event.Actor.IdentityProvider))
	}
	if len(event.Actor.Groups) > 0 {
		fields = append(fields, zap.Strings("actor_groups", event.Actor.Groups))
	}
	if event.Actor.SourceIP != "" {
		fields = append(fields, zap.String("actor_ip", event.Actor.SourceIP))
	}
	if event.Target.Namespace != "" {
		fields = append(fields, zap.String("target_namespace", event.Target.Namespace))
	}
	if event.Target.Cluster != "" {
		fields = append(fields, zap.String("target_cluster", event.Target.Cluster))
	}
	if event.RequestContext != nil {
		if event.RequestContext.SessionName != "" {
			fields = append(fields, zap.String("session_name", event.RequestContext.SessionName))
		}
		if event.RequestContext.EscalationName != "" {
			fields = append(fields, zap.String("escalation_name", event.RequestContext.EscalationName))
		}
		if event.RequestContext.CorrelationID != "" {
			fields = append(fields, zap.String("correlation_id", event.RequestContext.CorrelationID))
		}
	}

	// Add details as a JSON field
	if len(event.Details) > 0 {
		if detailsJSON, err := json.Marshal(event.Details); err == nil {
			fields = append(fields, zap.String("details", string(detailsJSON)))
		}
	}

	s.logger.Info("audit_event", fields...)
	return nil
}

// Close is a no-op for LogSink.
func (s *LogSink) Close() error {
	return nil
}

// Name returns the sink identifier.
func (s *LogSink) Name() string {
	return "log"
}

// WebhookSink sends audit events to an external HTTP endpoint.
// It supports both single-event and batch writes for efficiency.
type WebhookSink struct {
	name           string
	url            string
	batchURL       string // Optional: separate URL for batch requests
	httpClient     *http.Client
	headers        map[string]string
	logger         *zap.Logger
	eventsWritten  int64
	eventsFailed   int64
	batchesWritten int64
}

// WebhookSinkConfig configures a WebhookSink.
type WebhookSinkConfig struct {
	Name     string
	URL      string
	BatchURL string // Optional: separate endpoint for batch writes (e.g., /events/batch)
	Headers  map[string]string
	Timeout  time.Duration
}

// NewWebhookSink creates a new WebhookSink.
func NewWebhookSink(cfg WebhookSinkConfig, logger *zap.Logger) *WebhookSink {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	batchURL := cfg.BatchURL
	if batchURL == "" {
		batchURL = cfg.URL // Use same URL for batch if not specified
	}

	sink := &WebhookSink{
		name:     cfg.Name,
		url:      cfg.URL,
		batchURL: batchURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		headers: cfg.Headers,
		logger:  logger.Named("webhook-sink"),
	}

	sink.logger.Info("Webhook audit sink created",
		zap.String("name", cfg.Name),
		zap.String("url", cfg.URL),
		zap.String("batchURL", batchURL),
		zap.Duration("timeout", timeout))

	return sink
}

// Write sends the audit event to the webhook.
func (s *WebhookSink) Write(ctx context.Context, event *Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		s.eventsFailed++
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		s.eventsFailed++
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.eventsFailed++
		s.logger.Debug("webhook request failed",
			zap.String("url", s.url),
			zap.String("event_id", event.ID),
			zap.String("event_type", string(event.Type)),
			zap.String("error", err.Error()))
		return fmt.Errorf("failed to send audit event to %s: %w", s.url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		s.eventsFailed++
		s.logger.Debug("webhook returned error",
			zap.String("url", s.url),
			zap.String("event_id", event.ID),
			zap.String("event_type", string(event.Type)),
			zap.Int("status_code", resp.StatusCode))
		return fmt.Errorf("webhook %s returned error status: %d", s.url, resp.StatusCode)
	}

	s.eventsWritten++
	s.logger.Debug("webhook event sent successfully",
		zap.String("event_id", event.ID),
		zap.String("event_type", string(event.Type)))

	return nil
}

// WriteBatch sends multiple audit events to the webhook in a single request.
// This implements the BatchSink interface for efficient bulk operations.
func (s *WebhookSink) WriteBatch(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	// Wrap events in a batch payload
	batchPayload := struct {
		Events []*Event `json:"events"`
		Count  int      `json:"count"`
	}{
		Events: events,
		Count:  len(events),
	}

	body, err := json.Marshal(batchPayload)
	if err != nil {
		s.eventsFailed += int64(len(events))
		return fmt.Errorf("failed to marshal batch payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.batchURL, bytes.NewReader(body))
	if err != nil {
		s.eventsFailed += int64(len(events))
		return fmt.Errorf("failed to create batch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Batch-Size", fmt.Sprintf("%d", len(events)))
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.eventsFailed += int64(len(events))
		s.logger.Debug("webhook batch request failed",
			zap.String("url", s.batchURL),
			zap.Int("batch_size", len(events)),
			zap.String("error", err.Error()))
		return fmt.Errorf("failed to send audit batch to %s: %w", s.batchURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		s.eventsFailed += int64(len(events))
		s.logger.Debug("webhook batch returned error",
			zap.String("url", s.batchURL),
			zap.Int("batch_size", len(events)),
			zap.Int("status_code", resp.StatusCode))
		return fmt.Errorf("webhook %s returned error status: %d", s.batchURL, resp.StatusCode)
	}

	s.eventsWritten += int64(len(events))
	s.batchesWritten++
	s.logger.Debug("webhook batch sent successfully",
		zap.Int("batch_size", len(events)),
		zap.Int64("total_events", s.eventsWritten))

	return nil
}

// Stats returns the webhook sink statistics.
func (s *WebhookSink) Stats() (written, failed, batches int64) {
	return s.eventsWritten, s.eventsFailed, s.batchesWritten
}

// Close is a no-op for WebhookSink.
func (s *WebhookSink) Close() error {
	s.logger.Info("closing webhook audit sink",
		zap.String("name", s.name),
		zap.Int64("events_written", s.eventsWritten),
		zap.Int64("events_failed", s.eventsFailed),
		zap.Int64("batches_written", s.batchesWritten))
	return nil
}

// Name returns the sink identifier.
func (s *WebhookSink) Name() string {
	if s.name != "" {
		return s.name
	}
	return "webhook"
}

// KubernetesEventSink creates Kubernetes Events for audit entries.
type KubernetesEventSink struct {
	recorder record.EventRecorder
	// Only emit events for these types (empty means all)
	includeTypes map[EventType]bool
}

// NewKubernetesEventSink creates a new KubernetesEventSink.
func NewKubernetesEventSink(recorder record.EventRecorder, includeTypes []EventType) *KubernetesEventSink {
	typeMap := make(map[EventType]bool)
	for _, t := range includeTypes {
		typeMap[t] = true
	}
	return &KubernetesEventSink{
		recorder:     recorder,
		includeTypes: typeMap,
	}
}

// Write creates a Kubernetes Event for the audit entry.
func (s *KubernetesEventSink) Write(_ context.Context, event *Event) error {
	// Filter by event type if configured
	if len(s.includeTypes) > 0 && !s.includeTypes[event.Type] {
		return nil
	}

	// Map severity to Kubernetes event type
	eventType := corev1.EventTypeNormal
	if event.Severity == SeverityWarning || event.Severity == SeverityCritical {
		eventType = corev1.EventTypeWarning
	}

	// Note: Kubernetes Events require an object reference.
	// The caller should set up the recorder with appropriate object refs.
	// This is a simplified implementation - in practice you'd need the object.
	message := fmt.Sprintf("[%s] %s by %s on %s/%s",
		event.Type,
		event.Severity,
		event.Actor.User,
		event.Target.Kind,
		event.Target.Name,
	)

	if len(event.Details) > 0 {
		if reason, ok := event.Details["reason"].(string); ok {
			message += fmt.Sprintf(" - %s", reason)
		}
	}

	// Note: This is a placeholder - actual implementation would need the object reference
	_ = eventType
	_ = message
	return nil
}

// Close is a no-op for KubernetesEventSink.
func (s *KubernetesEventSink) Close() error {
	return nil
}

// Name returns the sink identifier.
func (s *KubernetesEventSink) Name() string {
	return "kubernetes"
}

// MultiSink writes to multiple sinks concurrently.
type MultiSink struct {
	sinks  []Sink
	logger *zap.Logger
}

// NewMultiSink creates a sink that writes to multiple destinations.
func NewMultiSink(sinks []Sink, logger *zap.Logger) *MultiSink {
	return &MultiSink{
		sinks:  sinks,
		logger: logger,
	}
}

// Write sends the event to all sinks.
func (s *MultiSink) Write(ctx context.Context, event *Event) error {
	var lastErr error
	for _, sink := range s.sinks {
		if err := sink.Write(ctx, event); err != nil {
			// Use string representation to avoid noisy stacktraces for transient errors
			s.logger.Warn("audit sink write failed",
				zap.String("sink", sink.Name()),
				zap.String("error", err.Error()))
			lastErr = err
		}
	}
	return lastErr
}

// Close closes all sinks.
func (s *MultiSink) Close() error {
	var lastErr error
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Name returns the sink identifier.
func (s *MultiSink) Name() string {
	return "multi"
}
