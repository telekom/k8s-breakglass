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
type WebhookSink struct {
	name       string
	url        string
	httpClient *http.Client
	headers    map[string]string
	logger     *zap.Logger
}

// WebhookSinkConfig configures a WebhookSink.
type WebhookSinkConfig struct {
	Name    string
	URL     string
	Headers map[string]string
	Timeout time.Duration
}

// NewWebhookSink creates a new WebhookSink.
func NewWebhookSink(cfg WebhookSinkConfig, logger *zap.Logger) *WebhookSink {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &WebhookSink{
		name: cfg.Name,
		url:  cfg.URL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		headers: cfg.Headers,
		logger:  logger,
	}
}

// Write sends the audit event to the webhook.
func (s *WebhookSink) Write(ctx context.Context, event *Event) error {
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send audit event: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Close is a no-op for WebhookSink.
func (s *WebhookSink) Close() error {
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
			s.logger.Warn("audit sink write failed",
				zap.String("sink", sink.Name()),
				zap.Error(err))
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
