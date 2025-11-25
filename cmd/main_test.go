package main

import (
	"crypto/tls"
	"testing"
)

func TestSetupLogger_DebugMode(t *testing.T) {
	// debug true should return a non-nil logger
	logger := setupLogger(true)
	if logger == nil {
		t.Fatalf("expected non-nil logger for debug mode")
	}
	// best-effort flush
	_ = logger.Sync()
}

func TestSetupLogger_ProductionMode(t *testing.T) {
	// debug false should return a non-nil logger
	logger := setupLogger(false)
	if logger == nil {
		t.Fatalf("expected non-nil logger for production mode")
	}
	_ = logger.Sync()
}

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

func TestDisableHTTP2(t *testing.T) {
	cfg := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	disableHTTP2(cfg)

	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatalf("expected HTTP/1.1 only, got %v", cfg.NextProtos)
	}
}
