package breakglass

import (
	"os"
	"testing"
	"time"
)

func TestGetDebugSessionRetentionPeriod_Default(t *testing.T) {
	t.Setenv("DEBUG_SESSION_RETENTION_PERIOD", "")
	got := getDebugSessionRetentionPeriod()
	want := 168 * time.Hour
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestGetDebugSessionRetentionPeriod_Valid(t *testing.T) {
	t.Setenv("DEBUG_SESSION_RETENTION_PERIOD", "24h")
	got := getDebugSessionRetentionPeriod()
	want := 24 * time.Hour
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestGetDebugSessionRetentionPeriod_InvalidFallsBack(t *testing.T) {
	// Use os.Setenv to ensure behavior is consistent even without testing.T.Setenv.
	original := os.Getenv("DEBUG_SESSION_RETENTION_PERIOD")
	t.Cleanup(func() {
		_ = os.Setenv("DEBUG_SESSION_RETENTION_PERIOD", original)
	})
	_ = os.Setenv("DEBUG_SESSION_RETENTION_PERIOD", "not-a-duration")

	got := getDebugSessionRetentionPeriod()
	want := 168 * time.Hour
	if got != want {
		t.Fatalf("expected %v, got %v", want, got)
	}
}
