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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestKafkaSinkConfig_Validation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name    string
		cfg     KafkaSinkConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			cfg: KafkaSinkConfig{
				Brokers: []string{"localhost:9092"},
				Topic:   "audit-events",
			},
			wantErr: false,
		},
		{
			name: "missing brokers",
			cfg: KafkaSinkConfig{
				Topic: "audit-events",
			},
			wantErr: true,
			errMsg:  "at least one Kafka broker is required",
		},
		{
			name: "missing topic",
			cfg: KafkaSinkConfig{
				Brokers: []string{"localhost:9092"},
			},
			wantErr: true,
			errMsg:  "Kafka topic is required",
		},
		{
			name: "valid with TLS",
			cfg: KafkaSinkConfig{
				Brokers: []string{"kafka:9093"},
				Topic:   "audit-events",
				TLS: &KafkaTLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true,
				},
			},
			wantErr: false,
		},
		{
			name: "valid with SASL PLAIN",
			cfg: KafkaSinkConfig{
				Brokers: []string{"kafka:9092"},
				Topic:   "audit-events",
				SASL: &KafkaSASLConfig{
					Mechanism: "PLAIN",
					Username:  "user",
					Password:  "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid SASL mechanism",
			cfg: KafkaSinkConfig{
				Brokers: []string{"kafka:9092"},
				Topic:   "audit-events",
				SASL: &KafkaSASLConfig{
					Mechanism: "INVALID",
					Username:  "user",
					Password:  "pass",
				},
			},
			wantErr: true,
			errMsg:  "unsupported SASL mechanism",
		},
		{
			name: "valid with all options",
			cfg: KafkaSinkConfig{
				Name:             "full-config",
				Brokers:          []string{"kafka-0:9093", "kafka-1:9093"},
				Topic:            "audit-events",
				BatchSize:        200,
				BatchTimeout:     2 * time.Second,
				WriteTimeout:     15 * time.Second,
				RequiredAcks:     1,
				Async:            true,
				CompressionCodec: "zstd",
				TLS: &KafkaTLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true,
				},
				SASL: &KafkaSASLConfig{
					Mechanism: "SCRAM-SHA-256",
					Username:  "admin",
					Password:  "secret",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, err := NewKafkaSink(tt.cfg, logger)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, sink)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sink)
				err = sink.Close()
				assert.NoError(t, err)
			}
		})
	}
}

func TestKafkaSink_Name(t *testing.T) {
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name     string
		sinkName string
		expected string
	}{
		{
			name:     "custom name",
			sinkName: "my-kafka-sink",
			expected: "my-kafka-sink",
		},
		{
			name:     "default name",
			sinkName: "",
			expected: "kafka",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink, err := NewKafkaSink(KafkaSinkConfig{
				Name:    tt.sinkName,
				Brokers: []string{"localhost:9092"},
				Topic:   "test",
			}, logger)
			require.NoError(t, err)
			defer func() { _ = sink.Close() }()

			assert.Equal(t, tt.expected, sink.Name())
		})
	}
}

func TestBuildTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *KafkaTLSConfig
		wantErr bool
	}{
		{
			name: "minimal TLS",
			cfg: &KafkaTLSConfig{
				Enabled: true,
			},
			wantErr: false,
		},
		{
			name: "with insecure skip verify",
			cfg: &KafkaTLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			wantErr: false,
		},
		{
			name: "invalid CA cert",
			cfg: &KafkaTLSConfig{
				Enabled: true,
				CACert:  []byte("not a valid cert"),
			},
			wantErr: true,
		},
		{
			name: "invalid client cert pair",
			cfg: &KafkaTLSConfig{
				Enabled:    true,
				ClientCert: []byte("not a cert"),
				ClientKey:  []byte("not a key"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsCfg, err := buildTLSConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, tlsCfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsCfg)
			}
		})
	}
}

func TestBuildSASLMechanism(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *KafkaSASLConfig
		wantErr bool
	}{
		{
			name: "PLAIN",
			cfg: &KafkaSASLConfig{
				Mechanism: "PLAIN",
				Username:  "user",
				Password:  "pass",
			},
			wantErr: false,
		},
		{
			name: "SCRAM-SHA-256",
			cfg: &KafkaSASLConfig{
				Mechanism: "SCRAM-SHA-256",
				Username:  "user",
				Password:  "pass",
			},
			wantErr: false,
		},
		{
			name: "SCRAM-SHA-512",
			cfg: &KafkaSASLConfig{
				Mechanism: "SCRAM-SHA-512",
				Username:  "user",
				Password:  "pass",
			},
			wantErr: false,
		},
		{
			name: "unsupported mechanism",
			cfg: &KafkaSASLConfig{
				Mechanism: "OAUTH",
				Username:  "user",
				Password:  "pass",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mechanism, err := buildSASLMechanism(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, mechanism)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mechanism)
			}
		})
	}
}

func TestKafkaSink_DoubleClose(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)

	// First close should succeed
	err = sink.Close()
	assert.NoError(t, err)

	// Second close should be a no-op
	err = sink.Close()
	assert.NoError(t, err)
}

func TestKafkaSink_WriteAfterClose(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)

	err = sink.Close()
	require.NoError(t, err)

	// Write after close should fail
	event := &Event{
		ID:        "test-1",
		Type:      EventSessionRequested,
		Severity:  SeverityInfo,
		Timestamp: time.Now(),
		Actor:     Actor{User: "test@example.com"},
		Target:    Target{Kind: "BreakglassSession", Name: "test"},
	}

	err = sink.Write(context.Background(), event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestKafkaSink_WriteBatchEmpty(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Empty batch should be a no-op
	err = sink.WriteBatch(context.Background(), []*Event{})
	assert.NoError(t, err)
}

// TestKafkaSink_CompressionCodecs tests all compression options
func TestKafkaSink_CompressionCodecs(t *testing.T) {
	logger := zaptest.NewLogger(t)

	codecs := []string{"none", "gzip", "snappy", "lz4", "zstd", "", "unknown"}

	for _, codec := range codecs {
		t.Run("codec_"+codec, func(t *testing.T) {
			sink, err := NewKafkaSink(KafkaSinkConfig{
				Brokers:          []string{"localhost:9092"},
				Topic:            "test",
				CompressionCodec: codec,
			}, logger)
			require.NoError(t, err)
			require.NotNil(t, sink)
			_ = sink.Close()
		})
	}
}

func TestKafkaSink_IsConnected(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Initially connected (optimistic)
	assert.True(t, sink.IsConnected())
}

func TestKafkaSink_MessageStats(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Initially all zeros
	written, failed, batches := sink.MessageStats()
	assert.Equal(t, int64(0), written)
	assert.Equal(t, int64(0), failed)
	assert.Equal(t, int64(0), batches)
}

func TestKafkaSink_LastError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Initially no error
	lastTime, lastErr := sink.LastError()
	assert.Nil(t, lastErr)
	assert.True(t, lastTime.IsZero())
}

func TestKafkaSink_HealthCheck(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Health check on fresh sink should pass
	err = sink.HealthCheck()
	assert.NoError(t, err)
}

func TestKafkaSink_HealthCheckAfterClose(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)

	err = sink.Close()
	require.NoError(t, err)

	// Health check after close should fail
	err = sink.HealthCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestClassifyKafkaError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil error", nil, ""},
		{"context deadline exceeded", context.DeadlineExceeded, "timeout"},
		{"context canceled", context.Canceled, "cancelled"},
		{"timeout in message", fmt.Errorf("connection timed out"), "timeout"},
		{"connection refused", fmt.Errorf("connection refused"), "network"},
		{"no such host", fmt.Errorf("no such host: broker.example.com"), "network"},
		{"SASL error", fmt.Errorf("SASL authentication failed"), "auth"},
		{"authentication error", fmt.Errorf("authentication failed"), "auth"},
		{"authorization error", fmt.Errorf("authorization failed: ACL denied"), "authorization"},
		{"broker error", fmt.Errorf("broker unavailable"), "broker"},
		{"leader error", fmt.Errorf("no leader for partition"), "broker"},
		{"topic error", fmt.Errorf("topic not found"), "topic"},
		{"TLS error", fmt.Errorf("TLS handshake failed"), "tls"},
		{"certificate error", fmt.Errorf("certificate verify failed"), "tls"},
		{"generic error", fmt.Errorf("something went wrong"), "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyKafkaError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKafkaSink_WriteBatchAfterClose(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)

	err = sink.Close()
	require.NoError(t, err)

	// WriteBatch after close should fail
	events := []*Event{
		{
			ID:        "test-1",
			Type:      EventSessionRequested,
			Severity:  SeverityInfo,
			Timestamp: time.Now(),
			Actor:     Actor{User: "test@example.com"},
		},
	}

	err = sink.WriteBatch(context.Background(), events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestKafkaSink_Stats(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Stats should return valid struct
	stats := sink.Stats()
	assert.NotNil(t, stats)
	assert.Equal(t, "test", stats.Topic)
}

func TestKafkaSink_DefaultValues(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test with minimal config - defaults should be applied
	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "test",
		// All other fields are default/zero values
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Verify sink was created with defaults
	assert.Equal(t, "kafka", sink.Name()) // Default name
	assert.True(t, sink.IsConnected())    // Optimistic initial state
}

func TestKafkaSink_CustomName(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Name:    "my-custom-kafka-sink",
		Brokers: []string{"localhost:9092"},
		Topic:   "audit-events",
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	assert.Equal(t, "my-custom-kafka-sink", sink.Name())
}

func TestKafkaSink_MultipleBrokers(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Test with multiple brokers
	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{
			"kafka-0.kafka:9092",
			"kafka-1.kafka:9092",
			"kafka-2.kafka:9092",
		},
		Topic: "test",
	}, logger)
	require.NoError(t, err)
	require.NotNil(t, sink)
	_ = sink.Close()
}

func TestBuildTLSConfig_WithoutCA(t *testing.T) {
	// TLS config without CA cert should still work (uses system CAs)
	cfg := &KafkaTLSConfig{
		Enabled: true,
	}

	tlsCfg, err := buildTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	assert.Nil(t, tlsCfg.RootCAs) // No custom CA, will use system CAs
}

func TestKafkaSink_ContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)

	sink, err := NewKafkaSink(KafkaSinkConfig{
		Brokers:      []string{"localhost:9092"},
		Topic:        "test",
		WriteTimeout: 100 * time.Millisecond, // Short timeout for test
	}, logger)
	require.NoError(t, err)
	defer func() { _ = sink.Close() }()

	// Create an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	event := &Event{
		ID:        "cancelled-test",
		Type:      EventSessionRequested,
		Timestamp: time.Now(),
	}

	// This may or may not error depending on timing, but shouldn't panic
	_ = sink.Write(ctx, event)
}

func TestClassifyKafkaError_WrappedErrors(t *testing.T) {
	// Test that wrapped errors are properly classified
	baseErr := context.DeadlineExceeded
	wrappedErr := fmt.Errorf("operation failed: %w", baseErr)

	result := classifyKafkaError(wrappedErr)
	assert.Equal(t, "timeout", result)
}

func TestKafkaSink_EmptyBrokersList(t *testing.T) {
	logger := zaptest.NewLogger(t)

	_, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: []string{}, // Empty list
		Topic:   "test",
	}, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one Kafka broker is required")
}

func TestKafkaSink_NilBrokersList(t *testing.T) {
	logger := zaptest.NewLogger(t)

	_, err := NewKafkaSink(KafkaSinkConfig{
		Brokers: nil, // Nil list
		Topic:   "test",
	}, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one Kafka broker is required")
}
