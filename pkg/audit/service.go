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

// Package audit provides the audit trail system for the breakglass controller.
// It captures and forwards audit events to configured sinks (Kafka, webhook, log, Kubernetes).
//
// The Service type manages the audit system lifecycle:
//   - Watches AuditConfig changes via the AuditConfigReconciler
//   - Builds and configures sinks based on AuditConfig spec
//   - Provides thread-safe Emit/EmitSync methods for sending audit events
//   - Handles graceful shutdown and sink cleanup
//
// Usage:
//
//	svc := audit.NewService(kubeClient, logger, "breakglass-system")
//	// When AuditConfig is created/updated:
//	svc.Reload(ctx, config)
//	// Emit events:
//	svc.Emit(ctx, &audit.Event{...})
//	// Cleanup:
//	svc.Close()
package audit

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// Service manages the audit system lifecycle, including sink creation and event emission.
// It watches AuditConfig changes and reconfigures the audit manager accordingly.
type Service struct {
	client            client.Client
	logger            *zap.Logger
	mu                sync.RWMutex
	manager           *Manager
	sinks             []Sink
	isolatedMultiSink *IsolatedMultiSink
	enabled           bool
	configNS          string // namespace where secrets are located (controller namespace)
}

// NewService creates a new audit Service.
func NewService(kubeClient client.Client, logger *zap.Logger, controllerNamespace string) *Service {
	return &Service{
		client:   kubeClient,
		logger:   logger.Named("audit-service"),
		enabled:  false,
		configNS: controllerNamespace,
	}
}

// Reload reconfigures the audit system based on the provided AuditConfig.
// If config is nil, auditing is disabled.
// Deprecated: Use ReloadMultiple to aggregate sinks from multiple AuditConfigs.
func (s *Service) Reload(ctx context.Context, config *breakglassv1alpha1.AuditConfig) error {
	if config == nil {
		return s.ReloadMultiple(ctx, nil)
	}
	return s.ReloadMultiple(ctx, []*breakglassv1alpha1.AuditConfig{config})
}

// ReloadMultiple reconfigures the audit system based on multiple AuditConfigs.
// Sinks from all enabled configs are aggregated together.
// If configs is nil or empty, auditing is disabled.
func (s *Service) ReloadMultiple(ctx context.Context, configs []*breakglassv1alpha1.AuditConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close existing sinks
	s.closeSinksLocked()

	// Filter to only enabled configs
	var enabledConfigs []*breakglassv1alpha1.AuditConfig
	for _, cfg := range configs {
		if cfg != nil && cfg.Spec.Enabled {
			enabledConfigs = append(enabledConfigs, cfg)
		}
	}

	if len(enabledConfigs) == 0 {
		s.enabled = false
		s.manager = nil
		s.logger.Info("audit system disabled (no enabled configs)")
		metrics.AuditConfigReloads.WithLabelValues("disabled").Inc()
		return nil
	}

	// Build sinks from ALL enabled configs (aggregate)
	var allSinks []Sink
	var configNames []string
	for _, config := range enabledConfigs {
		sinks, err := s.buildSinks(ctx, config)
		if err != nil {
			s.logger.Error("failed to build audit sinks from config, skipping",
				zap.String("config", config.Name),
				zap.String("error", err.Error()))
			continue
		}
		allSinks = append(allSinks, sinks...)
		configNames = append(configNames, config.Name)
	}

	if len(allSinks) == 0 {
		s.logger.Warn("no audit sinks configured from any AuditConfig, auditing disabled")
		s.enabled = false
		metrics.AuditConfigReloads.WithLabelValues("no_sinks").Inc()
		return nil
	}

	// Use queue config from the first enabled config (or defaults)
	queueSize := 10000 // Per-sink queue size
	workerCount := 2   // Per-sink workers
	dropOnFull := true
	sampleRate := 1.0

	// Use the first config's queue settings as baseline
	if len(enabledConfigs) > 0 {
		config := enabledConfigs[0]
		if config.Spec.Queue != nil {
			if config.Spec.Queue.Size > 0 {
				queueSize = config.Spec.Queue.Size
			}
			if config.Spec.Queue.Workers > 0 {
				workerCount = config.Spec.Queue.Workers
			}
			dropOnFull = config.Spec.Queue.DropOnFull
		}

		if config.Spec.Sampling != nil && config.Spec.Sampling.Rate != "" {
			if rate, err := strconv.ParseFloat(config.Spec.Sampling.Rate, 64); err == nil && rate > 0 && rate <= 1 {
				sampleRate = rate
			}
		}
	}

	// Create isolated multi-sink: each sink gets its own queue for isolation
	// If one sink is slow/blocked, it won't affect other sinks
	queuedSinkCfg := QueuedSinkConfig{
		QueueSize:               queueSize,
		WorkerCount:             workerCount,
		WriteTimeout:            5 * time.Second,
		DropOnFull:              dropOnFull,
		CircuitBreakerThreshold: 5,
		CircuitBreakerResetTime: 30 * time.Second,
	}
	isolatedMultiSink := NewIsolatedMultiSink(allSinks, queuedSinkCfg, s.logger)

	// Create manager config (now simpler since queuing is per-sink)
	managerCfg := ManagerConfig{
		QueueSize:    100000, // Main queue still buffers before broadcasting
		WorkerCount:  5,
		BatchSize:    100,
		BatchTimeout: 100 * time.Millisecond,
		DropOnFull:   dropOnFull,
		SampleRate:   sampleRate,
		WriteTimeout: 5 * time.Second,
	}

	s.manager = NewManager(isolatedMultiSink, managerCfg, s.logger)
	s.sinks = allSinks
	s.isolatedMultiSink = isolatedMultiSink
	s.enabled = true

	// Log detailed configuration summary
	s.logger.Info("audit system configured with aggregated sinks",
		zap.Strings("configs", configNames),
		zap.Int("totalSinks", len(allSinks)),
		zap.Int("queueSize", queueSize),
		zap.Int("workers", workerCount),
		zap.Bool("dropOnFull", dropOnFull),
		zap.Float64("sampleRate", sampleRate))

	// Log individual sink configurations for debugging
	for _, config := range enabledConfigs {
		for _, sinkCfg := range config.Spec.Sinks {
			fields := []zap.Field{
				zap.String("config", config.Name),
				zap.String("name", sinkCfg.Name),
				zap.String("type", string(sinkCfg.Type)),
			}
			switch sinkCfg.Type {
			case breakglassv1alpha1.AuditSinkTypeKafka:
				if sinkCfg.Kafka != nil {
					fields = append(fields,
						zap.Strings("brokers", sinkCfg.Kafka.Brokers),
						zap.String("topic", sinkCfg.Kafka.Topic),
						zap.Bool("tls_enabled", sinkCfg.Kafka.TLS != nil && sinkCfg.Kafka.TLS.Enabled),
						zap.Bool("sasl_enabled", sinkCfg.Kafka.SASL != nil && sinkCfg.Kafka.SASL.Mechanism != ""),
						zap.Int("batch_size", sinkCfg.Kafka.BatchSize),
						zap.Bool("async", sinkCfg.Kafka.Async))
				}
			case breakglassv1alpha1.AuditSinkTypeWebhook:
				if sinkCfg.Webhook != nil {
					fields = append(fields,
						zap.String("url", sinkCfg.Webhook.URL),
						zap.Int("timeout_seconds", sinkCfg.Webhook.TimeoutSeconds),
						zap.Int("batch_size", sinkCfg.Webhook.BatchSize))
				}
			}
			s.logger.Debug("sink configuration loaded", fields...)
		}
	}

	metrics.AuditConfigReloads.WithLabelValues("success").Inc()
	return nil
}

// Emit sends an audit event asynchronously.
func (s *Service) Emit(ctx context.Context, event *Event) {
	s.mu.RLock()
	manager := s.manager
	enabled := s.enabled
	s.mu.RUnlock()

	if !enabled || manager == nil {
		return
	}

	manager.Emit(ctx, event)
}

// EmitSync sends an audit event synchronously (use sparingly).
func (s *Service) EmitSync(ctx context.Context, event *Event) error {
	s.mu.RLock()
	manager := s.manager
	enabled := s.enabled
	s.mu.RUnlock()

	if !enabled || manager == nil {
		return nil
	}

	return manager.EmitSync(ctx, event)
}

// IsEnabled returns whether auditing is currently enabled.
func (s *Service) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// SinkHealth represents the health status of a single audit sink.
type SinkHealth struct {
	Name                string
	Healthy             bool
	CircuitState        string // "closed", "open", "half-open", or "none" for non-network sinks
	ConsecutiveFailures int64
	TotalRequests       int64
	TotalFailures       int64
	TotalRejections     int64
	LastError           string
	LastSuccessTime     time.Time
}

// GetSinkHealth returns health information for all configured sinks.
// This is useful for updating AuditConfig status.
func (s *Service) GetSinkHealth() []SinkHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var health []SinkHealth

	// If using isolated multi-sink (per-sink queues), get health from there
	if s.isolatedMultiSink != nil {
		for _, qh := range s.isolatedMultiSink.Health() {
			circuitState := "closed"
			if qh.CircuitOpen {
				circuitState = "open"
			}
			h := SinkHealth{
				Name:                qh.Name,
				Healthy:             qh.Healthy,
				CircuitState:        circuitState,
				ConsecutiveFailures: int64(qh.ConsecutiveFails),
				TotalRequests:       qh.ProcessedEvents + qh.FailedEvents,
				TotalFailures:       qh.FailedEvents,
				TotalRejections:     qh.DroppedEvents,
				LastError:           qh.LastError,
				LastSuccessTime:     qh.LastSuccessTime,
			}
			health = append(health, h)
		}
		return health
	}

	// Fallback: check individual sinks (legacy path)
	for _, sink := range s.sinks {
		h := SinkHealth{
			Name:         sink.Name(),
			Healthy:      true,
			CircuitState: "none",
		}

		// Check if this is a circuit-breaker wrapped sink
		if cbSink, ok := sink.(*CircuitBreakerSink); ok {
			stats := cbSink.Stats()
			h.Healthy = cbSink.IsHealthy()
			h.CircuitState = stats.State.String()
			h.ConsecutiveFailures = stats.ConsecutiveFails
			h.TotalRequests = stats.TotalRequests
			h.TotalFailures = stats.TotalFailures
			h.TotalRejections = stats.TotalRejections
			if stats.LastError != nil {
				h.LastError = stats.LastError.Error()
			}
		}

		health = append(health, h)
	}

	return health
}

// GetQueuedSinkHealth returns detailed queue health for all isolated sinks.
// This provides more detailed metrics than GetSinkHealth.
func (s *Service) GetQueuedSinkHealth() []QueuedSinkHealth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.isolatedMultiSink == nil {
		return nil
	}

	return s.isolatedMultiSink.Health()
}

// Close shuts down the audit service.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var closeErr error
	if s.manager != nil {
		closeErr = s.manager.Close()
	}
	s.closeSinksLocked()
	s.enabled = false

	s.logger.Info("audit service closed")
	return closeErr
}

// closeSinksLocked closes all sinks. Caller must hold s.mu.
func (s *Service) closeSinksLocked() {
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			s.logger.Warn("failed to close audit sink",
				zap.String("sink", sink.Name()),
				zap.String("error", err.Error()))
		}
	}
	s.sinks = nil
}

// buildSinks creates sinks based on AuditConfig.
func (s *Service) buildSinks(ctx context.Context, config *breakglassv1alpha1.AuditConfig) ([]Sink, error) {
	var sinks []Sink

	for _, sinkCfg := range config.Spec.Sinks {
		sink, err := s.buildSink(ctx, sinkCfg)
		if err != nil {
			s.logger.Warn("failed to build sink, skipping",
				zap.String("name", sinkCfg.Name),
				zap.String("type", string(sinkCfg.Type)),
				zap.String("error", err.Error()))
			continue
		}

		// Wrap network sinks with circuit breaker for resilience
		if sinkCfg.Type == breakglassv1alpha1.AuditSinkTypeKafka || sinkCfg.Type == breakglassv1alpha1.AuditSinkTypeWebhook {
			cbCfg := s.getCircuitBreakerConfig(config, sinkCfg)
			sink = NewCircuitBreakerSink(sink, cbCfg, s.logger)
			s.logger.Info("wrapped sink with circuit breaker",
				zap.String("sink", sinkCfg.Name),
				zap.String("type", string(sinkCfg.Type)),
				zap.Int("failure_threshold", cbCfg.FailureThreshold),
				zap.Duration("open_timeout", cbCfg.OpenTimeout))
		}

		sinks = append(sinks, sink)
	}

	return sinks, nil
}

// getCircuitBreakerConfig returns circuit breaker configuration for a sink.
// Uses defaults with optional overrides from AuditConfig.
func (s *Service) getCircuitBreakerConfig(_ *breakglassv1alpha1.AuditConfig, _ breakglassv1alpha1.AuditSinkConfig) CircuitBreakerConfig {
	// Use sensible defaults - could be extended to read from AuditConfig spec
	cfg := CircuitBreakerConfig{
		FailureThreshold:    5,                // Open after 5 consecutive failures
		SuccessThreshold:    2,                // Close after 2 consecutive successes in half-open
		OpenTimeout:         30 * time.Second, // Wait 30s before probing
		HalfOpenMaxRequests: 1,                // Allow 1 probe request in half-open
		OnStateChange: func(from, to CircuitState) {
			s.logger.Info("audit sink circuit breaker state change",
				zap.String("from", from.String()),
				zap.String("to", to.String()))
			// Metrics are updated inside CircuitBreaker.transitionTo
		},
	}
	return cfg
}

// buildSink creates a single sink based on configuration.
func (s *Service) buildSink(ctx context.Context, sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	switch sinkCfg.Type {
	case breakglassv1alpha1.AuditSinkTypeLog:
		return s.buildLogSink(sinkCfg)

	case breakglassv1alpha1.AuditSinkTypeKafka:
		return s.buildKafkaSink(ctx, sinkCfg)

	case breakglassv1alpha1.AuditSinkTypeWebhook:
		return s.buildWebhookSink(sinkCfg)

	case breakglassv1alpha1.AuditSinkTypeKubernetes:
		return s.buildKubernetesSink(sinkCfg)

	default:
		return nil, fmt.Errorf("unknown sink type: %s", sinkCfg.Type)
	}
}

func (s *Service) buildLogSink(sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	return NewLogSink(s.logger), nil
}

func (s *Service) buildKafkaSink(ctx context.Context, sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	if sinkCfg.Kafka == nil {
		return nil, fmt.Errorf("kafka config required for kafka sink")
	}

	kafkaCfg := KafkaSinkConfig{
		Name:             sinkCfg.Name,
		Brokers:          sinkCfg.Kafka.Brokers,
		Topic:            sinkCfg.Kafka.Topic,
		BatchSize:        sinkCfg.Kafka.BatchSize,
		BatchTimeout:     time.Duration(sinkCfg.Kafka.BatchTimeoutSeconds) * time.Second,
		RequiredAcks:     sinkCfg.Kafka.RequiredAcks,
		CompressionCodec: sinkCfg.Kafka.Compression,
		Async:            sinkCfg.Kafka.Async,
	}

	// Load TLS config if enabled
	if sinkCfg.Kafka.TLS != nil && sinkCfg.Kafka.TLS.Enabled {
		tlsCfg, err := s.buildKafkaTLSConfig(ctx, sinkCfg.Kafka.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		kafkaCfg.TLS = tlsCfg
	}

	// Load SASL config if enabled
	if sinkCfg.Kafka.SASL != nil && sinkCfg.Kafka.SASL.Mechanism != "" {
		saslCfg, err := s.buildKafkaSASLConfig(ctx, sinkCfg.Kafka.SASL)
		if err != nil {
			return nil, fmt.Errorf("failed to build SASL config: %w", err)
		}
		kafkaCfg.SASL = saslCfg
	}

	return NewKafkaSink(kafkaCfg, s.logger)
}

func (s *Service) buildKafkaTLSConfig(ctx context.Context, tlsCfg *breakglassv1alpha1.KafkaTLSSpec) (*KafkaTLSConfig, error) {
	cfg := &KafkaTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
	}

	// Load CA certificate from secret
	if tlsCfg.CASecretRef != nil {
		namespace := tlsCfg.CASecretRef.Namespace
		if namespace == "" {
			namespace = s.configNS
		}
		caData, err := s.getSecretKey(ctx, tlsCfg.CASecretRef.Name, namespace, "ca.crt")
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		cfg.CACert = caData
	}

	// Load client certificate from secret
	if tlsCfg.ClientCertSecretRef != nil {
		namespace := tlsCfg.ClientCertSecretRef.Namespace
		if namespace == "" {
			namespace = s.configNS
		}
		certData, err := s.getSecretKey(ctx, tlsCfg.ClientCertSecretRef.Name, namespace, "tls.crt")
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		keyData, err := s.getSecretKey(ctx, tlsCfg.ClientCertSecretRef.Name, namespace, "tls.key")
		if err != nil {
			return nil, fmt.Errorf("failed to load client key: %w", err)
		}
		cfg.ClientCert = certData
		cfg.ClientKey = keyData
	}

	return cfg, nil
}

func (s *Service) buildKafkaSASLConfig(ctx context.Context, saslCfg *breakglassv1alpha1.KafkaSASLSpec) (*KafkaSASLConfig, error) {
	cfg := &KafkaSASLConfig{
		Mechanism: saslCfg.Mechanism,
	}

	if saslCfg.CredentialsSecretRef.Name != "" {
		namespace := saslCfg.CredentialsSecretRef.Namespace
		if namespace == "" {
			namespace = s.configNS
		}
		username, err := s.getSecretKey(ctx, saslCfg.CredentialsSecretRef.Name, namespace, "username")
		if err != nil {
			return nil, fmt.Errorf("failed to load SASL username: %w", err)
		}
		password, err := s.getSecretKey(ctx, saslCfg.CredentialsSecretRef.Name, namespace, "password")
		if err != nil {
			return nil, fmt.Errorf("failed to load SASL password: %w", err)
		}
		cfg.Username = string(username)
		cfg.Password = string(password)
	}

	return cfg, nil
}

func (s *Service) buildWebhookSink(sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	if sinkCfg.Webhook == nil {
		return nil, fmt.Errorf("webhook config required for webhook sink")
	}

	webhookCfg := WebhookSinkConfig{
		Name:     sinkCfg.Name,
		URL:      sinkCfg.Webhook.URL,
		BatchURL: sinkCfg.Webhook.BatchURL,
		Headers:  sinkCfg.Webhook.Headers,
		Timeout:  time.Duration(sinkCfg.Webhook.TimeoutSeconds) * time.Second,
	}

	return NewWebhookSink(webhookCfg, s.logger), nil
}

func (s *Service) buildKubernetesSink(sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	// Kubernetes event sink - placeholder for now
	return NewLogSink(s.logger.Named("k8s-events")), nil
}

// getSecretKey retrieves a specific key from a Kubernetes secret.
func (s *Service) getSecretKey(ctx context.Context, name, namespace, key string) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := s.client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}

	data, ok := secret.Data[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found in secret %s/%s", key, namespace, name)
	}

	return data, nil
}
