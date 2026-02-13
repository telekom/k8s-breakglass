package config

import (
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestParseDurationOrDefault(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		defaultVal time.Duration
		want       time.Duration
	}{
		{
			name:       "empty string returns default",
			value:      "",
			defaultVal: 30 * time.Second,
			want:       30 * time.Second,
		},
		{
			name:       "valid duration string",
			value:      "45s",
			defaultVal: 30 * time.Second,
			want:       45 * time.Second,
		},
		{
			name:       "valid duration in minutes",
			value:      "2m",
			defaultVal: 30 * time.Second,
			want:       2 * time.Minute,
		},
		{
			name:       "valid duration in hours",
			value:      "1h",
			defaultVal: 30 * time.Second,
			want:       time.Hour,
		},
		{
			name:       "invalid duration returns default",
			value:      "not-a-duration",
			defaultVal: 30 * time.Second,
			want:       30 * time.Second,
		},
		{
			name:       "zero duration returns default",
			value:      "0s",
			defaultVal: 30 * time.Second,
			want:       30 * time.Second,
		},
		{
			name:       "negative duration returns default",
			value:      "-5s",
			defaultVal: 30 * time.Second,
			want:       30 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDurationOrDefault(tt.value, tt.defaultVal)
			if got != tt.want {
				t.Errorf("parseDurationOrDefault(%q, %v) = %v, want %v", tt.value, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestServerTimeouts_GetReadTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeouts *ServerTimeouts
		want     time.Duration
	}{
		{
			name:     "default when empty",
			timeouts: &ServerTimeouts{},
			want:     DefaultReadTimeout,
		},
		{
			name:     "custom value",
			timeouts: &ServerTimeouts{ReadTimeout: "45s"},
			want:     45 * time.Second,
		},
		{
			name:     "invalid falls back to default",
			timeouts: &ServerTimeouts{ReadTimeout: "bad"},
			want:     DefaultReadTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeouts.GetReadTimeout(); got != tt.want {
				t.Errorf("GetReadTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerTimeouts_GetReadHeaderTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeouts *ServerTimeouts
		want     time.Duration
	}{
		{
			name:     "default when empty",
			timeouts: &ServerTimeouts{},
			want:     DefaultReadHeaderTimeout,
		},
		{
			name:     "custom value",
			timeouts: &ServerTimeouts{ReadHeaderTimeout: "5s"},
			want:     5 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeouts.GetReadHeaderTimeout(); got != tt.want {
				t.Errorf("GetReadHeaderTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerTimeouts_GetWriteTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeouts *ServerTimeouts
		want     time.Duration
	}{
		{
			name:     "default when empty",
			timeouts: &ServerTimeouts{},
			want:     DefaultWriteTimeout,
		},
		{
			name:     "custom value",
			timeouts: &ServerTimeouts{WriteTimeout: "90s"},
			want:     90 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeouts.GetWriteTimeout(); got != tt.want {
				t.Errorf("GetWriteTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerTimeouts_GetIdleTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeouts *ServerTimeouts
		want     time.Duration
	}{
		{
			name:     "default when empty",
			timeouts: &ServerTimeouts{},
			want:     DefaultIdleTimeout,
		},
		{
			name:     "custom value",
			timeouts: &ServerTimeouts{IdleTimeout: "3m"},
			want:     3 * time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeouts.GetIdleTimeout(); got != tt.want {
				t.Errorf("GetIdleTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerTimeouts_GetMaxHeaderBytes(t *testing.T) {
	tests := []struct {
		name     string
		timeouts *ServerTimeouts
		want     int
	}{
		{
			name:     "default when zero",
			timeouts: &ServerTimeouts{},
			want:     DefaultMaxHeaderBytes,
		},
		{
			name:     "custom value",
			timeouts: &ServerTimeouts{MaxHeaderBytes: 2 << 20},
			want:     2 << 20,
		},
		{
			name:     "negative falls back to default",
			timeouts: &ServerTimeouts{MaxHeaderBytes: -1},
			want:     DefaultMaxHeaderBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeouts.GetMaxHeaderBytes(); got != tt.want {
				t.Errorf("GetMaxHeaderBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_GetServerTimeouts(t *testing.T) {
	t.Run("nil timeouts returns empty struct", func(t *testing.T) {
		s := Server{}
		got := s.GetServerTimeouts()
		if got == nil {
			t.Fatal("GetServerTimeouts() returned nil")
		}
		// Should still produce defaults
		if got.GetReadTimeout() != DefaultReadTimeout {
			t.Errorf("expected default ReadTimeout %v, got %v", DefaultReadTimeout, got.GetReadTimeout())
		}
	})

	t.Run("non-nil timeouts returned as-is", func(t *testing.T) {
		custom := &ServerTimeouts{ReadTimeout: "5s"}
		s := Server{Timeouts: custom}
		got := s.GetServerTimeouts()
		if got != custom {
			t.Error("expected same pointer to be returned")
		}
		if got.GetReadTimeout() != 5*time.Second {
			t.Errorf("expected 5s, got %v", got.GetReadTimeout())
		}
	})
}

func TestServer_GetShutdownTimeout(t *testing.T) {
	tests := []struct {
		name string
		s    Server
		want time.Duration
	}{
		{
			name: "default when empty",
			s:    Server{},
			want: DefaultShutdownTimeout,
		},
		{
			name: "custom value",
			s:    Server{ShutdownTimeout: "60s"},
			want: 60 * time.Second,
		},
		{
			name: "invalid falls back to default",
			s:    Server{ShutdownTimeout: "invalid"},
			want: DefaultShutdownTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.GetShutdownTimeout(); got != tt.want {
				t.Errorf("GetShutdownTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerTimeouts_YAMLRoundTrip(t *testing.T) {
	// Verify that loading a config with timeouts actually populates the struct
	yamlConfig := `
server:
  listenAddress: ":8080"
  timeouts:
    readTimeout: "45s"
    writeTimeout: "90s"
    idleTimeout: "3m"
    readHeaderTimeout: "15s"
    maxHeaderBytes: 2097152
  shutdownTimeout: "60s"
`
	var cfg Config
	if err := yamlUnmarshalForTest([]byte(yamlConfig), &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if cfg.Server.Timeouts == nil {
		t.Fatal("Timeouts is nil after unmarshal")
	}
	if got := cfg.Server.Timeouts.GetReadTimeout(); got != 45*time.Second {
		t.Errorf("ReadTimeout = %v, want 45s", got)
	}
	if got := cfg.Server.Timeouts.GetWriteTimeout(); got != 90*time.Second {
		t.Errorf("WriteTimeout = %v, want 90s", got)
	}
	if got := cfg.Server.Timeouts.GetIdleTimeout(); got != 3*time.Minute {
		t.Errorf("IdleTimeout = %v, want 3m", got)
	}
	if got := cfg.Server.Timeouts.GetReadHeaderTimeout(); got != 15*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 15s", got)
	}
	if got := cfg.Server.Timeouts.GetMaxHeaderBytes(); got != 2097152 {
		t.Errorf("MaxHeaderBytes = %v, want 2097152", got)
	}
	if got := cfg.Server.GetShutdownTimeout(); got != 60*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 60s", got)
	}
}

func TestServerTimeouts_DefaultConstants(t *testing.T) {
	// Verify default constants have expected values
	if DefaultReadTimeout != 30*time.Second {
		t.Errorf("DefaultReadTimeout = %v, want 30s", DefaultReadTimeout)
	}
	if DefaultReadHeaderTimeout != 10*time.Second {
		t.Errorf("DefaultReadHeaderTimeout = %v, want 10s", DefaultReadHeaderTimeout)
	}
	if DefaultWriteTimeout != 60*time.Second {
		t.Errorf("DefaultWriteTimeout = %v, want 60s", DefaultWriteTimeout)
	}
	if DefaultIdleTimeout != 120*time.Second {
		t.Errorf("DefaultIdleTimeout = %v, want 120s", DefaultIdleTimeout)
	}
	if DefaultMaxHeaderBytes != 1<<20 {
		t.Errorf("DefaultMaxHeaderBytes = %v, want %v", DefaultMaxHeaderBytes, 1<<20)
	}
	if DefaultShutdownTimeout != 30*time.Second {
		t.Errorf("DefaultShutdownTimeout = %v, want 30s", DefaultShutdownTimeout)
	}
}

func TestServerTimeouts_NilReceiver(t *testing.T) {
	// All getter methods must be safe to call on a nil *ServerTimeouts receiver.
	var nilTimeouts *ServerTimeouts

	if got := nilTimeouts.GetReadTimeout(); got != DefaultReadTimeout {
		t.Errorf("nil.GetReadTimeout() = %v, want %v", got, DefaultReadTimeout)
	}
	if got := nilTimeouts.GetReadHeaderTimeout(); got != DefaultReadHeaderTimeout {
		t.Errorf("nil.GetReadHeaderTimeout() = %v, want %v", got, DefaultReadHeaderTimeout)
	}
	if got := nilTimeouts.GetWriteTimeout(); got != DefaultWriteTimeout {
		t.Errorf("nil.GetWriteTimeout() = %v, want %v", got, DefaultWriteTimeout)
	}
	if got := nilTimeouts.GetIdleTimeout(); got != DefaultIdleTimeout {
		t.Errorf("nil.GetIdleTimeout() = %v, want %v", got, DefaultIdleTimeout)
	}
	if got := nilTimeouts.GetMaxHeaderBytes(); got != DefaultMaxHeaderBytes {
		t.Errorf("nil.GetMaxHeaderBytes() = %v, want %v", got, DefaultMaxHeaderBytes)
	}
}

// yamlUnmarshalForTest wraps yaml.Unmarshal for test use.
func yamlUnmarshalForTest(data []byte, v interface{}) error {
	return yaml.Unmarshal(data, v)
}
