package utils

import (
	"testing"
)

func TestSetupLogger_DebugMode(t *testing.T) {
	// debug true should return a non-nil logger
	logger, _ := SetupLogger(true)
	if logger == nil {
		t.Fatalf("expected non-nil logger for debug mode")
	}
	// best-effort flush
	_ = logger.Sync()
}

func TestSetupLogger_ProductionMode(t *testing.T) {
	// debug false should return a non-nil logger
	logger, _ := SetupLogger(false)
	if logger == nil {
		t.Fatalf("expected non-nil logger for production mode")
	}
	_ = logger.Sync()
}
