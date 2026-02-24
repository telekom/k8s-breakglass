package utils

import (
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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

func TestCreateScheme(t *testing.T) {
	// Create scheme once and reuse across all subtests for better performance
	scheme, err := CreateScheme()
	if err != nil {
		t.Fatalf("CreateScheme() error = %v", err)
	}
	if scheme == nil {
		t.Fatal("CreateScheme() returned nil scheme")
	}

	t.Run("scheme contains corev1 types", func(t *testing.T) {
		// Check that corev1.Secret is known to the scheme
		gvk := corev1.SchemeGroupVersion.WithKind("Secret")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize corev1.Secret")
		}
	})

	t.Run("scheme contains v1alpha1 types", func(t *testing.T) {
		// Check that BreakglassSession is known to the scheme
		gvk := breakglassv1alpha1.GroupVersion.WithKind("BreakglassSession")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize BreakglassSession")
		}
	})

	t.Run("scheme contains IdentityProvider type", func(t *testing.T) {
		gvk := breakglassv1alpha1.GroupVersion.WithKind("IdentityProvider")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize IdentityProvider")
		}
	})

	t.Run("scheme contains ClusterConfig type", func(t *testing.T) {
		gvk := breakglassv1alpha1.GroupVersion.WithKind("ClusterConfig")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize ClusterConfig")
		}
	})

	t.Run("scheme contains BreakglassEscalation type", func(t *testing.T) {
		gvk := breakglassv1alpha1.GroupVersion.WithKind("BreakglassEscalation")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize BreakglassEscalation")
		}
	})

	t.Run("scheme contains DenyPolicy type", func(t *testing.T) {
		gvk := breakglassv1alpha1.GroupVersion.WithKind("DenyPolicy")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize DenyPolicy")
		}
	})

	t.Run("scheme contains MailProvider type", func(t *testing.T) {
		gvk := breakglassv1alpha1.GroupVersion.WithKind("MailProvider")
		if !scheme.Recognizes(gvk) {
			t.Errorf("scheme does not recognize MailProvider")
		}
	})
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		// Standard Go durations
		{"empty string", "", 0, false},
		{"seconds", "30s", 30 * time.Second, false},
		{"minutes", "5m", 5 * time.Minute, false},
		{"hours", "2h", 2 * time.Hour, false},
		{"combined hms", "1h30m45s", time.Hour + 30*time.Minute + 45*time.Second, false},

		// Day units
		{"one day", "1d", 24 * time.Hour, false},
		{"seven days", "7d", 7 * 24 * time.Hour, false},
		{"ninety days", "90d", 90 * 24 * time.Hour, false},
		{"days and hours", "1d12h", 36 * time.Hour, false},
		{"days hours minutes", "2d6h30m", 2*24*time.Hour + 6*time.Hour + 30*time.Minute, false},

		// Edge cases
		{"zero days", "0d", 0, false},
		{"zero hours", "0h", 0, false},

		// Invalid durations
		{"invalid format", "invalid", 0, true},
		{"wrong units", "2days", 0, true},
		{"negative", "-1d", 0, true},
		{"invalid after days", "1dinvalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the canonical ParseDuration in api/v1alpha1 package
			got, err := breakglassv1alpha1.ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseDuration(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
