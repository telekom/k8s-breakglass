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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// KafkaSinkConfig configures a KafkaSink.
type KafkaSinkConfig struct {
	// Name is the identifier for this sink instance.
	Name string

	// Brokers is the list of Kafka broker addresses.
	Brokers []string

	// Topic is the Kafka topic to write audit events to.
	Topic string

	// TLS configuration for secure connections.
	TLS *KafkaTLSConfig

	// SASL authentication configuration.
	SASL *KafkaSASLConfig

	// BatchSize is the number of messages to batch before flushing.
	// Default: 100
	BatchSize int

	// BatchTimeout is the maximum time to wait before flushing a batch.
	// Default: 1 second
	BatchTimeout time.Duration

	// WriteTimeout is the timeout for writing messages.
	// Default: 10 seconds
	WriteTimeout time.Duration

	// RequiredAcks determines the level of acknowledgment required.
	// -1: all replicas, 0: none, 1: leader only
	// Default: -1 (all replicas)
	RequiredAcks int

	// RequiredAcksSet distinguishes an explicit zero value from an omitted
	// runtime config value.
	RequiredAcksSet bool

	// Async enables asynchronous writes (fire-and-forget).
	// Default: false
	Async bool

	// CompressionCodec for message compression.
	// Valid values: "none", "gzip", "snappy", "lz4", "zstd"
	// Default: "snappy"
	CompressionCodec string
}

// KafkaTLSConfig holds TLS configuration for Kafka connections.
type KafkaTLSConfig struct {
	// Enabled turns on TLS for the Kafka connection.
	Enabled bool

	// CACert is the PEM-encoded CA certificate for verifying the server.
	CACert []byte

	// ClientCert is the PEM-encoded client certificate for mTLS.
	ClientCert []byte

	// ClientKey is the PEM-encoded client private key for mTLS.
	ClientKey []byte

	// InsecureSkipVerify skips server certificate verification.
	// WARNING: Only use for testing.
	InsecureSkipVerify bool
}

// KafkaSASLConfig holds SASL authentication configuration.
type KafkaSASLConfig struct {
	// Mechanism is the SASL mechanism to use.
	// Valid values: "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"
	Mechanism string

	// Username for SASL authentication.
	Username string

	// Password for SASL authentication.
	Password string
}

// KafkaSink writes audit events to a Kafka topic.
type KafkaSink struct {
	name   string
	writer *kafka.Writer
	logger *zap.Logger
	mu     sync.Mutex
	closed bool

	// Metrics tracking (atomic for lock-free access)
	messagesWritten atomic.Int64
	messagesFailed  atomic.Int64
	asyncFailures   atomic.Int64
	batchesSent     atomic.Int64
	connected       atomic.Bool
	lastError       atomic.Value // stores kafkaSinkError
	lastSuccessTime atomic.Value // stores time.Time

	// slot admits one synchronous write at a time. A write cancelled by its
	// context leaves its records inside kafka-go until the writer's own
	// produce attempt ends; the slot stays taken until then (pending reaches
	// zero), so retries during an outage cannot pile up copies in the writer.
	slot    chan struct{}
	pending atomic.Int64
}

// writeToken marks the records of one synchronous write so that
// countingBalancer can tell whether kafka-go submitted them.
type writeToken struct{ balanced atomic.Int64 }

// countingBalancer counts the records kafka-go assigned to a partition.
// WriteMessages submits the records right after balancing the last one, so
// a write whose records were not all balanced submitted none of them.
type countingBalancer struct{ kafka.Balancer }

func (b countingBalancer) Balance(msg kafka.Message, partitions ...int) int {
	partition := b.Balancer.Balance(msg, partitions...)
	if token, ok := msg.WriterData.(*writeToken); ok {
		token.balanced.Add(1)
	}
	return partition
}

// errKafkaWriterBusy reports that the caller's context ended while an
// earlier write, or records it left inside kafka-go, still held the writer.
// It is an ordinary, retryable error.
var errKafkaWriterBusy = errors.New("kafka writer still holds records from an earlier write")

// releasePending marks n records of the current write as completed and frees
// the write slot once none are left.
func (s *KafkaSink) releasePending(n int64) {
	if s.pending.Add(-n) == 0 {
		<-s.slot
	}
}

type kafkaSinkError struct {
	err error
	at  time.Time
}

// NewKafkaSink creates a new KafkaSink.
func NewKafkaSink(cfg KafkaSinkConfig, logger *zap.Logger) (*KafkaSink, error) {
	if len(cfg.Brokers) == 0 {
		metrics.AuditConfigReloads.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("at least one Kafka broker is required")
	}
	if cfg.Topic == "" {
		metrics.AuditConfigReloads.WithLabelValues("error").Inc()
		return nil, fmt.Errorf("Kafka topic is required")
	}

	// Build transport with TLS and SASL
	transport := &kafka.Transport{}

	if cfg.TLS != nil && cfg.TLS.Enabled {
		tlsConfig, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			metrics.AuditConfigReloads.WithLabelValues("error").Inc()
			logger.Error("failed to build Kafka TLS config",
				zap.String("error", err.Error()),
				zap.Strings("brokers", cfg.Brokers))
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		transport.TLS = tlsConfig
	}

	if cfg.SASL != nil && cfg.SASL.Mechanism != "" {
		mechanism, err := buildSASLMechanism(cfg.SASL)
		if err != nil {
			metrics.AuditConfigReloads.WithLabelValues("error").Inc()
			logger.Error("failed to build Kafka SASL mechanism",
				zap.String("error", err.Error()),
				zap.String("mechanism", cfg.SASL.Mechanism))
			return nil, fmt.Errorf("failed to build SASL mechanism: %w", err)
		}
		transport.SASL = mechanism
	}

	// Set defaults
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	batchTimeout := cfg.BatchTimeout
	if batchTimeout <= 0 {
		batchTimeout = time.Second
	}
	if !cfg.Async {
		// Synchronous writes are admitted one at a time (see slot), so no
		// other write can join a partial kafka-go batch while it waits.
		// Waiting for BatchTimeout would only delay the receipt past the
		// queue's write deadline; the queued sink already batches. Flush at
		// once instead.
		batchTimeout = time.Millisecond
	}

	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 10 * time.Second
	}

	requiredAcks := cfg.RequiredAcks
	if requiredAcks == 0 && !cfg.RequiredAcksSet {
		requiredAcks = -1 // Default to all replicas
	}

	compression := kafka.Snappy
	switch cfg.CompressionCodec {
	case "none":
		compression = 0
	case "gzip":
		compression = kafka.Gzip
	case "lz4":
		compression = kafka.Lz4
	case "zstd":
		compression = kafka.Zstd
	case "snappy", "":
		compression = kafka.Snappy
	default:
		logger.Warn("unknown compression codec, defaulting to snappy",
			zap.String("codec", cfg.CompressionCodec))
	}

	writer := &kafka.Writer{
		Addr:                   kafka.TCP(cfg.Brokers...),
		Topic:                  cfg.Topic,
		Balancer:               countingBalancer{&kafka.LeastBytes{}},
		BatchSize:              batchSize,
		BatchTimeout:           batchTimeout,
		WriteTimeout:           writeTimeout,
		RequiredAcks:           kafka.RequiredAcks(requiredAcks),
		Async:                  cfg.Async,
		Compression:            compression,
		Transport:              transport,
		AllowAutoTopicCreation: true,
	}

	sinkName := cfg.Name
	if sinkName == "" {
		sinkName = "kafka"
	}

	sink := &KafkaSink{
		name:   sinkName,
		writer: writer,
		logger: logger.Named("kafka-audit"),
		slot:   make(chan struct{}, 1),
	}
	sink.connected.Store(!cfg.Async)
	if !cfg.Async {
		writer.Completion = func(messages []kafka.Message, _ error) {
			sink.releasePending(int64(len(messages)))
		}
	}
	if cfg.Async {
		writer.Completion = func(messages []kafka.Message, err error) {
			if err == nil {
				sink.messagesWritten.Add(int64(len(messages)))
				sink.lastSuccessTime.Store(time.Now())
				metrics.AuditEventsProcessed.WithLabelValues(sinkName).Add(float64(len(messages)))
				sink.connected.Store(true)
				metrics.AuditSinkConnected.WithLabelValues(sinkName).Set(1)
				return
			}
			sink.messagesFailed.Add(int64(len(messages)))
			sink.asyncFailures.Add(int64(len(messages)))
			sink.connected.Store(false)
			sink.lastError.Store(kafkaSinkError{err: err, at: time.Now()})
			metrics.AuditSinkConnected.WithLabelValues(sinkName).Set(0)
			metrics.AuditSinkErrors.WithLabelValues(sinkName, "async_write").Inc()
			metrics.AuditEventsDropped.WithLabelValues(sinkName, "async_write").Add(float64(len(messages)))
			sink.logger.Error("asynchronous Kafka delivery failed",
				zap.Int("count", len(messages)), zap.Error(err))
		}
	}

	// Initialize metrics
	if cfg.Async {
		metrics.AuditSinkConnected.WithLabelValues(sinkName).Set(0)
	} else {
		metrics.AuditSinkConnected.WithLabelValues(sinkName).Set(1)
	}
	metrics.AuditConfigReloads.WithLabelValues("success").Inc()

	logger.Info("Kafka audit sink created",
		zap.String("name", sinkName),
		zap.Strings("brokers", cfg.Brokers),
		zap.String("topic", cfg.Topic),
		zap.Bool("tls_enabled", cfg.TLS != nil && cfg.TLS.Enabled),
		zap.Bool("sasl_enabled", cfg.SASL != nil && cfg.SASL.Mechanism != ""))

	return sink, nil
}

// classifyKafkaError categorizes Kafka errors for metrics and logging.
func classifyKafkaError(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Check for context errors first (timeout/cancellation)
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}

	// Network errors
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network"
	}

	// DNS/connection errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network"
	}

	// Check error message patterns for Kafka-specific errors
	switch {
	case strings.Contains(errStr, "SASL") || strings.Contains(errStr, "authentication"):
		return "auth"
	case strings.Contains(errStr, "authorization") || strings.Contains(errStr, "ACL"):
		return "authorization"
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "timed out"):
		return "timeout"
	case strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host"):
		return "network"
	case strings.Contains(errStr, "broker") || strings.Contains(errStr, "leader"):
		return "broker"
	case strings.Contains(errStr, "topic"):
		return "topic"
	case strings.Contains(errStr, "TLS") || strings.Contains(errStr, "certificate"):
		return "tls"
	default:
		return "other"
	}
}

// Write sends an audit event to Kafka with comprehensive error handling.
func (s *KafkaSink) Write(ctx context.Context, event *Event) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		metrics.AuditSinkErrors.WithLabelValues(s.name, "closed").Inc()
		return fmt.Errorf("kafka sink is closed")
	}
	s.mu.Unlock()

	start := time.Now()

	// Serialize event to JSON
	value, err := json.Marshal(event)
	if err != nil {
		metrics.AuditSinkErrors.WithLabelValues(s.name, "serialization").Inc()
		s.messagesFailed.Add(1)
		return fmt.Errorf("failed to marshal audit event: %w: %w", ErrSerialization, err)
	}

	// Use event ID as the key for partitioning
	key := []byte(event.ID)

	msg := kafka.Message{
		Key:     key,
		Value:   value,
		Headers: kafkaHeaders(event),
	}

	// Track in-flight messages
	metrics.AuditKafkaMessagesInFlight.WithLabelValues(s.name).Inc()
	defer metrics.AuditKafkaMessagesInFlight.WithLabelValues(s.name).Dec()

	if err := s.writeMessages(ctx, msg); err != nil {
		duration := time.Since(start)
		errorType := classifyKafkaError(err)

		// Update metrics
		if !isRetainedAttempt(ctx) {
			metrics.AuditSinkErrors.WithLabelValues(s.name, errorType).Inc()
		}
		metrics.AuditSinkLatency.WithLabelValues(s.name).Observe(duration.Seconds())
		s.messagesFailed.Add(1)

		// Track connection state
		wasConnected := s.connected.Swap(false)
		if wasConnected {
			metrics.AuditSinkConnected.WithLabelValues(s.name).Set(0)
		}

		// Store last error for diagnostics
		s.lastError.Store(kafkaSinkError{err: err, at: time.Now()})

		// Log with appropriate severity based on error type
		// Use zap.String for error to avoid stacktraces on expected network errors
		baseLogFields := []zap.Field{
			zap.String("error_type", errorType),
			zap.Duration("duration", duration),
			zap.String("event_id", event.ID),
			zap.String("event_type", string(event.Type)),
		}

		switch errorType {
		case "network", "dns", "timeout":
			// Use string representation for transient errors to avoid noisy stacktraces
			s.logger.Warn("Kafka sink temporarily unavailable, event dropped",
				append(baseLogFields, zap.String("error", err.Error()))...)
		case "auth", "authorization":
			// Auth errors are config issues, not bugs - no stacktrace needed
			s.logger.Error("Kafka authentication/authorization failed",
				append(baseLogFields, zap.String("error", err.Error()))...)
		case "tls":
			// TLS errors are config issues, not bugs - no stacktrace needed
			s.logger.Error("Kafka TLS error",
				append(baseLogFields, zap.String("error", err.Error()))...)
		default:
			// Unknown errors - use string to avoid noisy stacktraces
			s.logger.Error("failed to write audit event to Kafka",
				append(baseLogFields, zap.String("error", err.Error()))...)
		}

		return fmt.Errorf("failed to write to Kafka (%s): %w", errorType, err)
	}

	// Success path
	duration := time.Since(start)
	metrics.AuditSinkLatency.WithLabelValues(s.name).Observe(duration.Seconds())
	if !s.writer.Async {
		s.messagesWritten.Add(1)
	}

	// Mark as connected if we weren't before
	if !s.writer.Async && !s.connected.Swap(true) {
		metrics.AuditSinkConnected.WithLabelValues(s.name).Set(1)
		s.logger.Info("Kafka sink connection restored",
			zap.String("name", s.name),
			zap.Duration("duration", duration))
	}

	return nil
}

// Close closes the Kafka writer and cleans up metrics.
func (s *KafkaSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	defer func() {
		s.connected.Store(false)
		metrics.AuditSinkConnected.WithLabelValues(s.name).Set(0)
	}()

	// Update connected metric
	metrics.AuditSinkConnected.WithLabelValues(s.name).Set(0)

	s.logger.Info("closing Kafka audit sink",
		zap.String("name", s.name),
		zap.Int64("messages_written", s.messagesWritten.Load()),
		zap.Int64("messages_failed", s.messagesFailed.Load()),
		zap.Int64("batches_sent", s.batchesSent.Load()))

	if err := s.writer.Close(); err != nil {
		return fmt.Errorf("failed to close Kafka writer: %w", err)
	}
	return nil
}

// Name returns the sink identifier.
func (s *KafkaSink) Name() string {
	return s.name
}

// kafkaHeaders returns the record headers of an event, identical for single
// and batched writes (docs/audit-event-schema.md).
func kafkaHeaders(event *Event) []kafka.Header {
	headers := []kafka.Header{
		{Key: "event-type", Value: []byte(event.Type)},
		{Key: "severity", Value: []byte(event.Severity)},
		{Key: "timestamp", Value: []byte(event.Timestamp.Format(time.RFC3339))},
	}
	if event.SchemaVersion != "" {
		headers = append(headers, kafka.Header{Key: "schema-version", Value: []byte(event.SchemaVersion)})
	}
	if event.Actor.User != "" {
		headers = append(headers, kafka.Header{Key: "actor", Value: []byte(event.Actor.User)})
	}
	if event.RequestContext != nil && event.RequestContext.CorrelationID != "" {
		headers = append(headers, kafka.Header{Key: "correlation-id", Value: []byte(event.RequestContext.CorrelationID)})
	}
	return headers
}

// buildTLSConfig creates a TLS configuration from KafkaTLSConfig.
func buildTLSConfig(cfg *KafkaTLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402 -- explicit audit sink option for test/dev Kafka endpoints
	}

	// Add CA certificate if provided
	if len(cfg.CACert) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(cfg.CACert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Add client certificate if provided (mTLS)
	if len(cfg.ClientCert) > 0 && len(cfg.ClientKey) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// buildSASLMechanism creates a SASL mechanism from KafkaSASLConfig.
func buildSASLMechanism(cfg *KafkaSASLConfig) (sasl.Mechanism, error) {
	switch cfg.Mechanism {
	case "PLAIN":
		return plain.Mechanism{
			Username: cfg.Username,
			Password: cfg.Password,
		}, nil
	case "SCRAM-SHA-256":
		mechanism, err := scram.Mechanism(scram.SHA256, cfg.Username, cfg.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to create SCRAM-SHA-256 mechanism: %w", err)
		}
		return mechanism, nil
	case "SCRAM-SHA-512":
		mechanism, err := scram.Mechanism(scram.SHA512, cfg.Username, cfg.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to create SCRAM-SHA-512 mechanism: %w", err)
		}
		return mechanism, nil
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", cfg.Mechanism)
	}
}

// WriteBatch writes multiple audit events to Kafka in a single batch with comprehensive error handling.
func (s *KafkaSink) WriteBatch(ctx context.Context, events []*Event) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		metrics.AuditSinkErrors.WithLabelValues(s.name, "closed").Inc()
		return fmt.Errorf("kafka sink is closed")
	}
	s.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	start := time.Now()
	messages := make([]kafka.Message, 0, len(events))
	for _, event := range events {
		value, err := json.Marshal(event)
		if err != nil {
			metrics.AuditSinkErrors.WithLabelValues(s.name, "serialization").Inc()
			s.messagesFailed.Add(int64(len(events)))
			return fmt.Errorf("marshal audit batch event %q: %w: %w", event.ID, ErrSerialization, err)
		}

		messages = append(messages, kafka.Message{
			Key:     []byte(event.ID),
			Value:   value,
			Headers: kafkaHeaders(event),
		})
	}

	// Track in-flight messages
	metrics.AuditKafkaMessagesInFlight.WithLabelValues(s.name).Add(float64(len(messages)))
	defer metrics.AuditKafkaMessagesInFlight.WithLabelValues(s.name).Sub(float64(len(messages)))

	if err := s.writeMessages(ctx, messages...); err != nil {
		duration := time.Since(start)
		errorType := classifyKafkaError(err)

		// Update metrics
		if !isRetainedAttempt(ctx) {
			metrics.AuditSinkErrors.WithLabelValues(s.name, errorType).Inc()
		}
		metrics.AuditSinkLatency.WithLabelValues(s.name).Observe(duration.Seconds())
		s.messagesFailed.Add(int64(len(messages)))

		// Track connection state
		wasConnected := s.connected.Swap(false)
		if wasConnected {
			metrics.AuditSinkConnected.WithLabelValues(s.name).Set(0)
		}

		// Store last error
		s.lastError.Store(kafkaSinkError{err: err, at: time.Now()})

		s.logger.Warn("failed to write batch to Kafka",
			zap.String("error", err.Error()),
			zap.String("error_type", errorType),
			zap.Int("batch_size", len(messages)),
			zap.Duration("duration", duration))

		return fmt.Errorf("failed to write batch to Kafka (%s): %w", errorType, err)
	}

	// Success path
	duration := time.Since(start)
	metrics.AuditSinkLatency.WithLabelValues(s.name).Observe(duration.Seconds())
	metrics.AuditKafkaBatchesSent.WithLabelValues(s.name).Inc()
	if !s.writer.Async {
		s.messagesWritten.Add(int64(len(messages)))
	}
	s.batchesSent.Add(1)

	// Mark as connected if we weren't before
	if !s.writer.Async && !s.connected.Swap(true) {
		metrics.AuditSinkConnected.WithLabelValues(s.name).Set(1)
		s.logger.Info("Kafka sink connection restored",
			zap.String("name", s.name),
			zap.Int("batch_size", len(messages)))
	}

	return nil
}

// Stats returns writer statistics.
func (s *KafkaSink) Stats() kafka.WriterStats {
	return s.writer.Stats()
}

// IsConnected returns the current connection state.
func (s *KafkaSink) IsConnected() bool {
	return s.connected.Load()
}

// LastError returns the last error encountered and when it occurred.
func (s *KafkaSink) LastError() (time.Time, error) {
	stored, _ := s.lastError.Load().(kafkaSinkError)
	return stored.at, stored.err
}

// MessageStats returns message statistics for monitoring.
func (s *KafkaSink) MessageStats() (written, failed, batches int64) {
	return s.messagesWritten.Load(), s.messagesFailed.Load(), s.batchesSent.Load()
}

// HealthCheck performs a simple health check by getting writer stats.
// This doesn't send a message but verifies the writer is operational.
func (s *KafkaSink) HealthCheck() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("kafka sink is closed")
	}
	s.mu.Unlock()

	stats := s.writer.Stats()

	// Check if we have recent errors
	if stats.Errors > 0 && !s.connected.Load() {
		lastErrTime, lastErr := s.LastError()
		if lastErr != nil && time.Since(lastErrTime) < time.Minute {
			return fmt.Errorf("kafka sink unhealthy: %w (at %s)", lastErr, lastErrTime.Format(time.RFC3339))
		}
	}

	return nil
}

// writeMessages turns a kafka-go writer panic into an error. kafka-go's
// balancers index the partition list without a length check, so a metadata
// response that lists the topic without partitions panics in the caller's
// goroutine.
func (s *KafkaSink) writeMessages(ctx context.Context, messages ...kafka.Message) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// Retryable: the balancer panic depends on transient metadata.
			s.logger.Error("kafka writer panicked",
				zap.Any("panic", r), zap.ByteString("stack", debug.Stack()))
			err = fmt.Errorf("kafka writer panic: %v", r)
		}
	}()
	if !s.writer.Async && len(messages) > 0 {
		// ponytail: one synchronous write in flight per sink. A healthy write
		// holds the slot only while it runs, so other writers wait for it
		// within their own deadline; per-partition slots if throughput needs
		// concurrent writers.
		select {
		case s.slot <- struct{}{}:
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", errKafkaWriterBusy, ctx.Err())
		}
		token := &writeToken{}
		for i := range messages {
			messages[i].WriterData = token
		}
		s.pending.Store(int64(len(messages)))
		defer func() {
			// kafka-go submits the records only after it balanced all of
			// them; otherwise no completion callback will release them.
			if token.balanced.Load() < int64(len(messages)) {
				s.releasePending(int64(len(messages)))
			}
		}()
	}
	err = s.writer.WriteMessages(ctx, messages...)
	if kafkaRejected(err) {
		err = fmt.Errorf("%w: %w", ErrRejected, err)
	}
	return err
}

// kafkaRejected reports whether the broker or writer refused the records
// themselves: every failed record is too large or invalid. InvalidMessage
// (a CRC mismatch) is temporary in kafka-go and stays retryable.
// ponytail: a batch with some rejected and some delivered records counts the
// whole batch as dropped; per-record accounting if this ever matters.
func kafkaRejected(err error) bool {
	if err == nil {
		return false
	}
	rejected := func(err error) bool {
		return errors.Is(err, kafka.MessageSizeTooLarge) || errors.Is(err, kafka.RecordListTooLarge) ||
			errors.Is(err, kafka.InvalidRecord)
	}
	var writeErrors kafka.WriteErrors
	if !errors.As(err, &writeErrors) {
		return rejected(err)
	}
	for _, e := range writeErrors {
		if e != nil && !rejected(e) {
			return false
		}
	}
	return writeErrors.Count() > 0
}
