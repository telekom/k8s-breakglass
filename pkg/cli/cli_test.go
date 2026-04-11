package cli

import (
	"crypto/tls"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestGetEnvString(t *testing.T) {
	t.Setenv("BREAKGLASS_TEST_ENV", "custom-value")

	if got := getEnvString("BREAKGLASS_TEST_ENV", "default"); got != "custom-value" {
		t.Fatalf("expected env override, got %s", got)
	}

	if got := getEnvString("BREAKGLASS_UNKNOWN_ENV", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %s", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	t.Setenv("BREAKGLASS_BOOL_TRUE", "true")
	if !getEnvBool("BREAKGLASS_BOOL_TRUE", false) {
		t.Fatal("expected true when env variable explicitly true")
	}

	t.Setenv("BREAKGLASS_BOOL_ONE", "1")
	if !getEnvBool("BREAKGLASS_BOOL_ONE", false) {
		t.Fatal("expected true for numeric string 1")
	}

	t.Setenv("BREAKGLASS_BOOL_FALSE", "false")
	if getEnvBool("BREAKGLASS_BOOL_FALSE", true) {
		t.Fatal("expected false when env variable explicitly false")
	}

	t.Setenv("BREAKGLASS_BOOL_INVALID", "sometimes")
	if !getEnvBool("BREAKGLASS_BOOL_INVALID", true) {
		t.Fatal("expected fallback default when env value invalid")
	}

	if getEnvBool("BREAKGLASS_BOOL_MISSING", false) {
		t.Fatal("expected default false when env missing")
	}
}

func TestGetEnvBool_AllTrueVariants(t *testing.T) {
	trueValues := []string{"true", "TRUE", "True", "1", "yes", "YES", "Yes"}
	for _, val := range trueValues {
		t.Run(val, func(t *testing.T) {
			t.Setenv("TEST_BOOL", val)
			assert.True(t, getEnvBool("TEST_BOOL", false), "expected true for %q", val)
		})
	}
}

func TestGetEnvBool_AllFalseVariants(t *testing.T) {
	falseValues := []string{"false", "FALSE", "False", "0", "no", "NO", "No"}
	for _, val := range falseValues {
		t.Run(val, func(t *testing.T) {
			t.Setenv("TEST_BOOL", val)
			assert.False(t, getEnvBool("TEST_BOOL", true), "expected false for %q", val)
		})
	}
}

func TestDisableHTTP2(t *testing.T) {
	cfg := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	DisableHTTP2(cfg)

	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected HTTP/1.1 only, got %v", cfg.NextProtos)
	}
}

func TestDisableHTTP2_EmptyConfig(t *testing.T) {
	cfg := &tls.Config{}
	DisableHTTP2(cfg)

	assert.Len(t, cfg.NextProtos, 1)
	assert.Equal(t, "http/1.1", cfg.NextProtos[0])
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		defaultVal  time.Duration
		expected    time.Duration
		expectError bool
	}{
		{
			name:       "valid duration 10m",
			value:      "10m",
			defaultVal: 5 * time.Minute,
			expected:   10 * time.Minute,
		},
		{
			name:       "valid duration 1h",
			value:      "1h",
			defaultVal: 5 * time.Minute,
			expected:   1 * time.Hour,
		},
		{
			name:       "valid duration 30s",
			value:      "30s",
			defaultVal: 5 * time.Minute,
			expected:   30 * time.Second,
		},
		{
			name:       "empty value uses default",
			value:      "",
			defaultVal: 5 * time.Minute,
			expected:   5 * time.Minute,
		},
		{
			name:        "invalid duration uses default",
			value:       "invalid",
			defaultVal:  5 * time.Minute,
			expected:    5 * time.Minute,
			expectError: true,
		},
		{
			name:        "numeric without unit uses default",
			value:       "100",
			defaultVal:  5 * time.Minute,
			expected:    5 * time.Minute,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDuration("test-flag", tt.value, tt.defaultVal)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseEscalationStatusUpdateInterval(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	tests := []struct {
		name     string
		interval string
		expected time.Duration
	}{
		{
			name:     "valid 15m",
			interval: "15m",
			expected: 15 * time.Minute,
		},
		{
			name:     "valid 1h",
			interval: "1h",
			expected: 1 * time.Hour,
		},
		{
			name:     "invalid uses default",
			interval: "invalid",
			expected: 10 * time.Minute, // DefaultEscalationStatusUpdateInterval
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseEscalationStatusUpdateInterval(tt.interval, logger)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseClusterConfigCheckInterval(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()

	tests := []struct {
		name     string
		interval string
		expected time.Duration
	}{
		{
			name:     "valid 5m",
			interval: "5m",
			expected: 5 * time.Minute,
		},
		{
			name:     "valid 30m",
			interval: "30m",
			expected: 30 * time.Minute,
		},
		{
			name:     "invalid uses default",
			interval: "bad",
			expected: 10 * time.Minute, // DefaultClusterConfigCheckInterval
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseClusterConfigCheckInterval(tt.interval, logger)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_Print(t *testing.T) {
	logger := zaptest.NewLogger(t).Sugar()
	config := &Config{
		Debug:                true,
		MetricsAddr:          ":8081",
		MetricsSecure:        true,
		ProbeAddr:            ":8082",
		EnableLeaderElection: true,
		LeaderElectNamespace: "default",
		LeaderElectID:        "breakglass.telekom.io",
		EnableHTTP2:          false,
		EnableWebhooks:       true,
		EnableFrontend:       true,
		EnableAPI:            true,
		EnableCleanup:        true,
		Webhook: WebhookConfig{
			BindAddr:       ":9443",
			CertPath:       "/certs",
			CertName:       "tls.crt",
			CertKey:        "tls.key",
			SvcName:        "breakglass-webhook",
			CertGeneration: true,
			MetricsAddr:    ":8083",
			MetricsSecure:  false,
		},
		ConfigPath:                 "./config.yaml",
		BreakglassNamespace:        "breakglass-system",
		DisableEmail:               false,
		ClusterConfigCheckInterval: "10m",
		EscalationStatusUpdateInt:  "15m",
	}

	// This should not panic
	config.Print(logger)
}

func TestConfig_DefaultValues(t *testing.T) {
	config := &Config{}

	// Verify zero values
	assert.False(t, config.Debug)
	assert.Empty(t, config.MetricsAddr)
	assert.False(t, config.MetricsSecure)
	assert.False(t, config.EnableLeaderElection)
	assert.False(t, config.EnableWebhooks)
	assert.False(t, config.EnableFrontend)
	assert.False(t, config.EnableAPI)
	assert.False(t, config.EnableCleanup)
}

func TestWebhookConfig_DefaultValues(t *testing.T) {
	config := WebhookConfig{}

	assert.Empty(t, config.BindAddr)
	assert.Empty(t, config.CertPath)
	assert.Empty(t, config.SvcName)
	assert.False(t, config.CertGeneration)
	assert.False(t, config.MetricsSecure)
}

func TestDisableSessionRateLimit_DefaultIsFalse(t *testing.T) {
	config := &Config{}
	assert.False(t, config.DisableSessionRateLimit, "DisableSessionRateLimit should default to false")
}

func TestDisableSessionRateLimit_EnvVar(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "true")
	got := getEnvBool("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", false)
	assert.True(t, got, "BREAKGLASS_DISABLE_SESSION_RATE_LIMIT=true should parse as true")
}

func TestDisableSessionRateLimit_EnvVarFalse(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "false")
	got := getEnvBool("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", true)
	assert.False(t, got, "BREAKGLASS_DISABLE_SESSION_RATE_LIMIT=false should parse as false")
}

func TestDisableSessionRateLimit_EmptyEnvVar(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "")
	got := getEnvBool("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", false)
	assert.False(t, got, "BREAKGLASS_DISABLE_SESSION_RATE_LIMIT unset should default to false")
}

// parseWithArgs resets the global flag.CommandLine, sets os.Args to the provided
// arguments, and calls Parse(). It restores os.Args and flag.CommandLine on return.
// This is the only safe way to test Parse() (which calls flag.Parse() on the global
// flag.CommandLine) without spawning a subprocess.
func parseWithArgs(t *testing.T, args []string) *Config {
	t.Helper()

	origArgs := os.Args
	origFlagCommandLine := flag.CommandLine

	t.Cleanup(func() {
		os.Args = origArgs
		flag.CommandLine = origFlagCommandLine
	})

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	os.Args = append([]string{os.Args[0]}, args...)

	return Parse()
}

func TestParse_DisableSessionRateLimit_Default(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "")

	cfg := parseWithArgs(t, []string{})

	assert.False(t, cfg.DisableSessionRateLimit,
		"DisableSessionRateLimit should be false when neither flag nor env var is set")
}

func TestParse_DisableSessionRateLimit_Flag(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "")

	cfg := parseWithArgs(t, []string{"--disable-session-rate-limit"})

	assert.True(t, cfg.DisableSessionRateLimit,
		"DisableSessionRateLimit should be true when --disable-session-rate-limit flag is passed")
}

func TestParse_DisableSessionRateLimit_EnvVar(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "true")

	cfg := parseWithArgs(t, []string{})

	assert.True(t, cfg.DisableSessionRateLimit,
		"DisableSessionRateLimit should be true when BREAKGLASS_DISABLE_SESSION_RATE_LIMIT=true")
}

func TestParse_DisableSessionRateLimit_FlagOverridesEnv(t *testing.T) {
	t.Setenv("BREAKGLASS_DISABLE_SESSION_RATE_LIMIT", "false")

	cfg := parseWithArgs(t, []string{"--disable-session-rate-limit"})

	assert.True(t, cfg.DisableSessionRateLimit,
		"CLI flag --disable-session-rate-limit should override BREAKGLASS_DISABLE_SESSION_RATE_LIMIT=false")
}
