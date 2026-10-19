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

// Service manages the audit system lifecycle:
//   - Watches AuditConfig changes via the AuditConfigReconciler
//   - Builds and configures sinks based on AuditConfig spec
//   - Provides thread-safe Emit/EmitSync methods for sending audit events
//   - Handles graceful shutdown and sink cleanup
//
// Usage:
//
//	svc := audit.NewService(kubeClient, recorder, logger, "breakglass-system")
//	// When AuditConfig is created/updated:
//	svc.Reload(ctx, config)
//	// Emit events:
//	svc.Emit(ctx, &audit.Event{...})
//	// Cleanup:
//	svc.Close()
package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var systemCertPool = x509.SystemCertPool

// reloadBuildTimeout bounds the API reads and sink construction of one reload.
// Tests change it, so they must not run in parallel.
var reloadBuildTimeout = 30 * time.Second

// closeWaitTimeout bounds how long Close waits for previous pipelines that are
// still closing in the background.
const closeWaitTimeout = 10 * time.Second

// Service manages the audit system lifecycle, including sink creation and event emission.
// It watches AuditConfig changes and reconfigures the audit manager accordingly.
type Service struct {
	client   client.Client
	recorder events.EventRecorder
	logger   *zap.Logger
	// mu guards the current pipeline fields below and is held only for field
	// reads and the swap: the authorization webhook takes it for every
	// SubjectAccessReview, so it must never be held across API or sink I/O.
	mu sync.RWMutex
	// reloadMu serializes reloads; sink construction runs under it, not under mu.
	reloadMu sync.Mutex
	// closing tracks previous pipelines that are still closing in the background.
	closing sync.WaitGroup
	// running holds copies of the AuditConfigs the current pipeline was
	// built from; a failed reload keeps the pipeline only while all of them
	// are still enabled with the same spec.
	running            []*breakglassv1alpha1.AuditConfig
	manager            *Manager
	sinks              []Sink
	isolatedMultiSink  *IsolatedMultiSink
	enabled            bool
	configurationState ConfigurationState
	configNS           string // namespace where secrets are located (controller namespace)
}

// ConfigurationState distinguishes intentional audit disablement from a
// configured audit system that cannot currently construct its sinks.
type ConfigurationState string

const (
	ConfigurationDisabled    ConfigurationState = "disabled"
	ConfigurationReady       ConfigurationState = "ready"
	ConfigurationUnavailable ConfigurationState = "unavailable"
)

// NewService creates a new audit Service.
func NewService(kubeClient client.Client, recorder events.EventRecorder, logger *zap.Logger, controllerNamespace string) *Service {
	return &Service{
		client:             kubeClient,
		recorder:           recorder,
		logger:             logger.Named("audit-service"),
		enabled:            false,
		configurationState: ConfigurationUnavailable,
		configNS:           controllerNamespace,
	}
}

// ControllerNamespace is the namespace allowed for audit sink credentials.
func (s *Service) ControllerNamespace() string { return s.configNS }

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
	return s.ReloadMultipleWithAvailability(ctx, configs, false)
}

// ReloadMultipleWithAvailability reloads valid enabled configs. If
// configuredUnavailable is true, at least one enabled AuditConfig was rejected
// before sink construction, so auditing must fail closed instead of appearing
// intentionally disabled.
func (s *Service) ReloadMultipleWithAvailability(ctx context.Context, configs []*breakglassv1alpha1.AuditConfig, configuredUnavailable bool) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	for _, cfg := range configs {
		if cfg != nil && cfg.Spec.Enabled && cfg.Spec.Filtering != nil && cfg.Spec.Filtering.ExcludeNamespaces != nil && len(cfg.Spec.Filtering.ExcludeNamespaces.SelectorTerms) > 0 {
			return fmt.Errorf("audit config %q uses unsupported namespace selector exclusions; use namespace patterns", cfg.Name)
		}
	}

	if configuredUnavailable {
		return s.keepPreviousPipeline(configs, errors.New("one or more enabled AuditConfigs are invalid or unavailable"))
	}

	// Filter to only enabled configs
	var enabledConfigs []*breakglassv1alpha1.AuditConfig
	for _, cfg := range configs {
		if cfg != nil && cfg.Spec.Enabled {
			enabledConfigs = append(enabledConfigs, cfg)
		}
	}

	if len(enabledConfigs) == 0 {
		s.swap(nil, nil, nil, nil, false, ConfigurationDisabled)
		s.logger.Info("audit system disabled (no enabled configs)")
		metrics.AuditConfigReloads.WithLabelValues("disabled").Inc()
		return nil
	}

	// Build sinks from ALL enabled configs (aggregate). This reads Secrets and
	// may dial sinks, so it runs without s.mu and within a bounded time.
	buildCtx, cancel := context.WithTimeout(ctx, reloadBuildTimeout)
	defer cancel()
	var allSinks []Sink
	var sinkQueues []QueuedSinkConfig
	var configNames []string
	for _, config := range enabledConfigs {
		sinks, err := s.buildSinks(buildCtx, config)
		if err != nil {
			for _, built := range allSinks {
				_ = built.Close()
			}
			s.logger.Error("failed to build audit sinks from config",
				zap.String("config", config.Name),
				zap.String("error", err.Error()))
			return s.keepPreviousPipeline(enabledConfigs, fmt.Errorf("build audit sinks from config %q: %w", config.Name, err))
		}
		allSinks = append(allSinks, sinks...)
		for range sinks {
			sinkQueues = append(sinkQueues, queuedConfig(config.Spec.Queue))
		}
		configNames = append(configNames, config.Name)
	}

	if len(allSinks) == 0 {
		s.logger.Error("enabled AuditConfig produced no audit sinks")
		return s.keepPreviousPipeline(enabledConfigs, errors.New("enabled AuditConfig produced no audit sinks"))
	}

	// Use queue config from the first enabled config (or defaults)
	queueSize := 10000 // Per-sink queue size
	workerCount := 2   // Per-sink workers
	dropOnFull := true
	sampleRate := 1.0
	sampleRateConfigured := false
	var highVolume []EventType
	var alwaysCapture []EventType

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
			if config.Spec.Queue.DropOnFull != nil {
				dropOnFull = *config.Spec.Queue.DropOnFull
			}
		}

		if config.Spec.Sampling != nil {
			if config.Spec.Sampling.Rate != "" {
				if rate, err := strconv.ParseFloat(config.Spec.Sampling.Rate, 64); err == nil && rate >= 0 && rate <= 1 {
					sampleRate = rate
					sampleRateConfigured = true
				}
			}
			for _, hv := range config.Spec.Sampling.HighVolumeEventTypes {
				highVolume = append(highVolume, EventType(hv))
			}
			for _, ac := range config.Spec.Sampling.AlwaysCaptureEventTypes {
				alwaysCapture = append(alwaysCapture, EventType(ac))
			}
		}
	}
	includeEventTypes, excludeEventTypes, sharedEventTypeFilters := managerEventTypeFilters(enabledConfigs)
	if !sharedEventTypeFilters {
		s.logger.Debug("manager event-type pre-filter disabled because enabled AuditConfigs use different event-type filters")
	}

	// Create isolated multi-sink: each sink gets its own queue for isolation
	// If one sink is slow/blocked, it won't affect other sinks
	queuedSinkCfg := DefaultQueuedSinkConfig()
	queuedSinkCfg.QueueSize = queueSize
	queuedSinkCfg.WorkerCount = workerCount
	queuedSinkCfg.DropOnFull = dropOnFull
	isolatedMultiSink := NewIsolatedMultiSink(allSinks, queuedSinkCfg, s.logger, sinkQueues...)

	// Create manager config (now simpler since queuing is per-sink)
	managerCfg := ManagerConfig{
		Enrich:                  s.enrichResourceIdentity,
		QueueSize:               100000, // Main queue still buffers before broadcasting
		WorkerCount:             5,
		BatchSize:               100,
		BatchTimeout:            100 * time.Millisecond,
		DropOnFull:              dropOnFull,
		SampleRate:              sampleRate,
		sampleRateConfigured:    sampleRateConfigured,
		HighVolumeEventTypes:    highVolume,
		AlwaysCaptureEventTypes: alwaysCapture,
		IncludeEventTypes:       includeEventTypes,
		ExcludeEventTypes:       excludeEventTypes,
		WriteTimeout:            5 * time.Second,
		// DirectSinks references the same sink instances stored in s.sinks.
		// When this pipeline is replaced, closePipeline closes the Manager
		// (draining its workers and in-flight sync writes) before these sinks.
		DirectSinks: allSinks,
	}

	s.swap(NewManager(isolatedMultiSink, managerCfg, s.logger), allSinks, isolatedMultiSink, enabledConfigs, true, ConfigurationReady)

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
						zap.String("url", redactURL(sinkCfg.Webhook.URL)),
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

func managerEventTypeFilters(configs []*breakglassv1alpha1.AuditConfig) ([]string, []string, bool) {
	if len(configs) == 0 {
		return nil, nil, true
	}

	var include []string
	var exclude []string
	for i, config := range configs {
		var currentInclude []string
		var currentExclude []string
		if config != nil && config.Spec.Filtering != nil {
			currentInclude = config.Spec.Filtering.IncludeEventTypes
			currentExclude = config.Spec.Filtering.ExcludeEventTypes
		}
		if i == 0 {
			include = append([]string(nil), currentInclude...)
			exclude = append([]string(nil), currentExclude...)
			continue
		}
		if !slices.Equal(include, currentInclude) || !slices.Equal(exclude, currentExclude) {
			return nil, nil, false
		}
	}

	return include, exclude, true
}

// Emit sends an audit event asynchronously.
func (s *Service) Emit(ctx context.Context, event *Event) {
	m := s.currentManager()
	if m == nil || m.Emit(ctx, event) {
		return
	}
	// A reload replaced the Manager between the read and the enqueue: hand
	// the event to the new one once instead of losing it.
	if next := s.currentManager(); next != nil && next != m {
		next.Emit(ctx, event)
	}
}

// currentManager returns the enabled Manager without holding s.mu during the
// caller's sink I/O. A Manager replaced by a reload drops or rejects later
// events safely (see Manager.Emit and Manager.EmitSync).
func (s *Service) currentManager() *Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.enabled {
		return nil
	}
	return s.manager
}

// EmitSync sends an audit event synchronously (use sparingly).
func (s *Service) EmitSync(ctx context.Context, event *Event) error {
	m := s.currentManager()
	if m == nil {
		return errors.New("audit service is disabled")
	}
	err := m.EmitSync(ctx, event)
	// A reload replaced the Manager between the read and the write: write to
	// the new one once.
	if errors.Is(err, errManagerClosed) {
		if next := s.currentManager(); next != nil && next != m {
			return next.EmitSync(ctx, event)
		}
	}
	return err
}

// IsEnabled returns whether auditing is currently enabled.
func (s *Service) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// IsConfigured reports whether an enabled AuditConfig intentionally requires
// auditing, including when its configuration or sinks are unavailable.
func (s *Service) IsConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configurationState != ConfigurationDisabled
}

// ConfigurationState returns the state of the running audit pipeline. After a
// failed reload that kept the previous pipeline it stays Ready; the failed
// AuditConfig reports Ready=False through its status.
func (s *Service) ConfigurationState() ConfigurationState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.configurationState
}

// Manager returns the current audit Manager, or nil if auditing is not yet configured.
// The returned pointer reflects the manager at the moment of the call; it may become
// stale if Reload or ReloadMultiple is called subsequently, which can replace the manager.
// Callers that need a stable reference across reloads should re-invoke Manager() each time.
func (s *Service) Manager() *Manager {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.manager
}

// GetStats returns the current audit manager statistics.
// Returns nil if the audit manager is not initialized.
func (s *Service) GetStats() *ManagerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.manager == nil {
		return nil
	}
	stats := s.manager.Stats()
	return &stats
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
			h := SinkHealth{
				Name:                qh.Name,
				Healthy:             qh.Healthy,
				CircuitState:        qh.CircuitState,
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
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	s.mu.Lock()
	oldManager, oldSinks := s.manager, s.sinks
	s.manager, s.sinks, s.isolatedMultiSink = nil, nil, nil
	s.enabled = false
	s.configurationState = ConfigurationDisabled
	s.mu.Unlock()

	closeErr := s.closePipeline(oldManager, oldSinks)
	// Previous pipelines close in the background; a sink whose Close never
	// returns must not hang the process shutdown.
	closed := make(chan struct{})
	go func() { s.closing.Wait(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(closeWaitTimeout):
		s.logger.Warn("audit service closed while previous audit sinks were still closing")
	}
	s.logger.Info("audit service closed")
	return closeErr
}

// swap installs a pipeline (nil to stop auditing) and closes the previous one
// in the background, so readers never wait for a flush to a stalled sink.
// Caller must hold s.reloadMu.
func (s *Service) swap(manager *Manager, sinks []Sink, multi *IsolatedMultiSink, configs []*breakglassv1alpha1.AuditConfig, enabled bool, state ConfigurationState) {
	running := make([]*breakglassv1alpha1.AuditConfig, 0, len(configs))
	for _, cfg := range configs {
		running = append(running, cfg.DeepCopy())
	}
	s.mu.Lock()
	oldManager, oldSinks := s.manager, s.sinks
	s.manager, s.sinks, s.isolatedMultiSink, s.running = manager, sinks, multi, running
	s.enabled = enabled
	s.configurationState = state
	s.mu.Unlock()
	if oldManager == nil && len(oldSinks) == 0 {
		return
	}
	s.closing.Add(1)
	go func() {
		defer s.closing.Done()
		_ = s.closePipeline(oldManager, oldSinks)
	}()
}

// ErrKeptPreviousPipeline marks a failed reload after which the running audit
// pipeline stays active unchanged.
var ErrKeptPreviousPipeline = errors.New("the previous audit pipeline stays active")

// keepPreviousPipeline handles a failed reload of configs. The running
// pipeline keeps auditing only while every AuditConfig it was built from is
// still in configs, enabled and with an unchanged spec, so a disabled,
// deleted or changed configuration (for example a removed sink) never keeps
// running. Otherwise the pipeline is closed and auditing is configured but
// unavailable (fails closed). It returns cause, wrapped with
// ErrKeptPreviousPipeline when the pipeline was kept. Caller must hold
// s.reloadMu.
func (s *Service) keepPreviousPipeline(configs []*breakglassv1alpha1.AuditConfig, cause error) error {
	s.mu.RLock()
	keep := s.enabled && s.manager != nil && runningConfigsUnchanged(s.running, configs)
	names := make([]string, 0, len(s.running))
	for _, cfg := range s.running {
		names = append(names, cfg.Name)
	}
	s.mu.RUnlock()
	if keep {
		s.logger.Warn("audit reload failed; the previous audit pipeline stays active",
			zap.Strings("configs", names), zap.String("error", cause.Error()))
		metrics.AuditConfigReloads.WithLabelValues("kept_previous").Inc()
		return fmt.Errorf("%w: %w", ErrKeptPreviousPipeline, cause)
	}
	s.swap(nil, nil, nil, nil, false, ConfigurationUnavailable)
	return cause
}

// runningConfigsUnchanged reports whether every config of the running
// pipeline is in configs, enabled and with the same spec.
func runningConfigsUnchanged(running, configs []*breakglassv1alpha1.AuditConfig) bool {
	if len(running) == 0 {
		return false
	}
	for _, old := range running {
		found := false
		for _, cfg := range configs {
			if cfg != nil && cfg.Name == old.Name && cfg.Spec.Enabled && equality.Semantic.DeepEqual(cfg.Spec, old.Spec) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// closePipeline closes a Manager (draining its workers and in-flight sync
// writes) before the sinks it writes to. It never runs under s.mu.
func (s *Service) closePipeline(manager *Manager, sinks []Sink) error {
	var closeErr error
	if manager != nil {
		if closeErr = manager.Close(); closeErr != nil {
			s.logger.Warn("failed to close audit manager", zap.String("error", closeErr.Error()))
		}
	}
	for _, sink := range sinks {
		if err := sink.Close(); err != nil {
			s.logger.Warn("failed to close audit sink",
				zap.String("sink", sink.Name()),
				zap.String("error", err.Error()))
		}
	}
	return closeErr
}

// buildSinks creates sinks based on AuditConfig.
func (s *Service) buildSinks(ctx context.Context, config *breakglassv1alpha1.AuditConfig) ([]Sink, error) {
	var sinks []Sink

	for _, sinkCfg := range config.Spec.Sinks {
		sink, err := s.buildSink(ctx, sinkCfg)
		if err != nil {
			for _, built := range sinks {
				_ = built.Close()
			}
			return nil, fmt.Errorf("build audit sink %q: %w", sinkCfg.Name, err)
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

		sink = NewFilteredSink(sink, EventFilterConfig{
			IncludeEventTypes: sinkCfg.EventTypes,
			MinSeverity:       Severity(sinkCfg.MinSeverity),
		})
		if config.Spec.Filtering != nil {
			sink = NewFilteredSink(sink, EventFilterConfig{
				IncludeEventTypes: config.Spec.Filtering.IncludeEventTypes,
				ExcludeEventTypes: config.Spec.Filtering.ExcludeEventTypes,
				IncludeUsers:      config.Spec.Filtering.IncludeUsers,
				ExcludeUsers:      config.Spec.Filtering.ExcludeUsers,
				IncludeNamespaces: config.Spec.Filtering.IncludeNamespaces,
				ExcludeNamespaces: config.Spec.Filtering.ExcludeNamespaces,
				IncludeResources:  config.Spec.Filtering.IncludeResources,
				ExcludeResources:  config.Spec.Filtering.ExcludeResources,
			})
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
		return s.buildWebhookSink(ctx, sinkCfg)

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
		RequiredAcksSet:  true,
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

func (s *Service) buildWebhookSink(ctx context.Context, sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	if sinkCfg.Webhook == nil {
		return nil, fmt.Errorf("webhook config required for webhook sink")
	}

	headers := cloneHeaders(sinkCfg.Webhook.Headers)
	var err error
	headers, err = s.applyWebhookAuth(ctx, sinkCfg.Webhook, headers)
	if err != nil {
		return nil, err
	}

	webhookCfg := WebhookSinkConfig{
		Name:     sinkCfg.Name,
		URL:      sinkCfg.Webhook.URL,
		BatchURL: sinkCfg.Webhook.BatchURL,
		Headers:  headers,
		Timeout:  time.Duration(sinkCfg.Webhook.TimeoutSeconds) * time.Second,
	}

	if sinkCfg.Webhook.TLS != nil {
		tlsCfg, err := s.buildWebhookTLSConfig(ctx, sinkCfg.Webhook.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build webhook TLS config: %w", err)
		}
		webhookCfg.TLS = tlsCfg
	}

	return NewWebhookSink(webhookCfg, s.logger), nil
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	return maps.Clone(headers)
}

func (s *Service) applyWebhookAuth(ctx context.Context, webhookCfg *breakglassv1alpha1.WebhookSinkSpec, headers map[string]string) (map[string]string, error) {
	if webhookCfg.AuthSecretRef == nil || hasAuthorizationHeader(headers) {
		return headers, nil
	}

	namespace := webhookCfg.AuthSecretRef.Namespace
	if err := s.requireControllerNamespace("webhook auth", webhookCfg.AuthSecretRef.Name, namespace); err != nil {
		return nil, err
	}

	secret := &corev1.Secret{}
	if err := s.client.Get(ctx, types.NamespacedName{Name: webhookCfg.AuthSecretRef.Name, Namespace: namespace}, secret); err != nil {
		return nil, fmt.Errorf("failed to get webhook auth secret %s/%s: %w", namespace, webhookCfg.AuthSecretRef.Name, err)
	}

	if headers == nil {
		headers = make(map[string]string, 1)
	}

	if token, ok := secret.Data["token"]; ok {
		headers["Authorization"] = "Bearer " + string(token)
		return headers, nil
	}

	username, hasUsername := secret.Data["username"]
	password, hasPassword := secret.Data["password"]
	if hasUsername && hasPassword {
		credentials := append(append([]byte{}, username...), ':')
		credentials = append(credentials, password...)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString(credentials)
		return headers, nil
	}

	return nil, fmt.Errorf("webhook auth secret %s/%s must contain either token or username/password", namespace, webhookCfg.AuthSecretRef.Name)
}

func (s *Service) requireControllerNamespace(refType, name, namespace string) error {
	if s.configNS == "" {
		return fmt.Errorf("%s secret %q cannot be read because controller namespace is not configured", refType, name)
	}
	if namespace != s.configNS {
		return fmt.Errorf("%s secret %q namespace must be controller namespace %q, got %q", refType, name, s.configNS, namespace)
	}
	return nil
}

func hasAuthorizationHeader(headers map[string]string) bool {
	for key := range headers {
		if strings.EqualFold(key, "Authorization") {
			return true
		}
	}
	return false
}

func (s *Service) buildWebhookTLSConfig(ctx context.Context, tlsCfg *breakglassv1alpha1.WebhookTLSSpec) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify, // #nosec G402 -- Explicit AuditConfig option for private webhook endpoints.
		MinVersion:         tls.VersionTLS12,
	}

	if tlsCfg.CASecretRef == nil {
		return cfg, nil
	}

	namespace := tlsCfg.CASecretRef.Namespace
	if err := s.requireControllerNamespace("webhook CA", tlsCfg.CASecretRef.Name, namespace); err != nil {
		return nil, err
	}

	caData, err := s.getSecretKey(ctx, tlsCfg.CASecretRef.Name, namespace, "ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to load webhook CA certificate: %w", err)
	}

	rootCAs, err := systemCertPool()
	if err != nil && s.logger != nil {
		s.logger.Warn("failed to load system CA pool, using custom webhook CA pool only",
			zap.String("error", err.Error()))
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if ok := rootCAs.AppendCertsFromPEM(caData); !ok {
		return nil, fmt.Errorf("failed to parse webhook CA certificate from secret %s/%s", namespace, tlsCfg.CASecretRef.Name)
	}
	cfg.RootCAs = rootCAs

	return cfg, nil
}

func (s *Service) buildKubernetesSink(sinkCfg breakglassv1alpha1.AuditSinkConfig) (Sink, error) {
	var eventTypes []EventType
	if sinkCfg.Kubernetes != nil {
		for _, et := range sinkCfg.Kubernetes.EventTypes {
			eventTypes = append(eventTypes, EventType(et))
		}
	}
	return NewKubernetesEventSink(s.recorder, eventTypes), nil
}

// getSecretKey retrieves a specific key from a Kubernetes secret.
func (s *Service) getSecretKey(ctx context.Context, name, namespace, key string) ([]byte, error) {
	if err := s.requireControllerNamespace("audit", name, namespace); err != nil {
		return nil, err
	}
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
