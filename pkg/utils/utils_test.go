package utils

import (
	"errors"
	"path"
	"testing"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
)

func TestSetupLoggerLevels(t *testing.T) {
	for _, debug := range []bool{false, true} {
		name := "production"
		if debug {
			name = "development"
		}
		t.Run(name, func(t *testing.T) {
			logger, err := SetupLogger(debug)
			if err != nil {
				t.Fatalf("SetupLogger(%t): %v", debug, err)
			}
			t.Cleanup(func() { _ = logger.Sync() }) // Standard streams may not support Sync.
			if logger.Core().Enabled(zap.DebugLevel) != debug {
				t.Fatal("development/production debug-level defaults changed")
			}
			for _, level := range []zapcore.Level{zap.InfoLevel, zap.WarnLevel, zap.ErrorLevel} {
				if !logger.Core().Enabled(level) {
					t.Fatalf("expected %s to be enabled", level.String())
				}
			}
		})
	}
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

func TestNamespaceSelectorBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		op     breakglassv1alpha1.NamespaceSelectorOperator
		values []string
		labels map[string]string
		want   bool
	}{
		{"in missing", breakglassv1alpha1.NamespaceSelectorOpIn, []string{""}, nil, false},
		{"in empty value", breakglassv1alpha1.NamespaceSelectorOpIn, []string{""}, map[string]string{"env": ""}, true},
		{"in nil values", breakglassv1alpha1.NamespaceSelectorOpIn, nil, map[string]string{"env": "prod"}, false},
		{"star is literal", breakglassv1alpha1.NamespaceSelectorOpIn, []string{"*"}, map[string]string{"env": "prod"}, false},
		{"literal star matches", breakglassv1alpha1.NamespaceSelectorOpIn, []string{"*"}, map[string]string{"env": "*"}, true},
		{"not in missing", breakglassv1alpha1.NamespaceSelectorOpNotIn, []string{""}, nil, true},
		{"not in empty value", breakglassv1alpha1.NamespaceSelectorOpNotIn, []string{""}, map[string]string{"env": ""}, false},
		{"not in nil values", breakglassv1alpha1.NamespaceSelectorOpNotIn, nil, map[string]string{"env": "prod"}, true},
		{"exists missing", breakglassv1alpha1.NamespaceSelectorOpExists, nil, nil, false},
		{"exists empty value", breakglassv1alpha1.NamespaceSelectorOpExists, nil, map[string]string{"env": ""}, true},
		{"does not exist", breakglassv1alpha1.NamespaceSelectorOpDoesNotExist, nil, nil, true},
		{"unknown fails closed", "Unknown", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matcher := NewNamespaceMatcher(&breakglassv1alpha1.NamespaceFilter{
				SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{{
					MatchExpressions: []breakglassv1alpha1.NamespaceSelectorRequirement{{Key: "env", Operator: tc.op, Values: tc.values}},
				}},
			})
			if got := matcher.MatchesWithLabels("app", tc.labels); got != tc.want {
				t.Fatalf("MatchesWithLabels = %t, want %t", got, tc.want)
			}
			if matcher.Matches("app") {
				t.Fatal("name-only matching must not evaluate label selectors")
			}
			if tc.labels == nil && matcher.MatchesWithLabels("app", map[string]string{}) != tc.want {
				t.Fatal("nil and empty label maps must have the same semantics")
			}
		})
	}
}

func TestGlobMatchBoundaries(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		value   string
		want    bool
		bad     bool
	}{
		{"*", "team/admin", true, false},
		{"team/*", "team/admin", true, false},
		{"team/*", "team/admin/nested", false, false},
		{"a*[", "different", false, true},
		{`a\b`, `a\b`, true, false},
	} {
		t.Run(tc.pattern+":"+tc.value, func(t *testing.T) {
			got, err := GlobMatch(tc.pattern, tc.value)
			if got != tc.want || errors.Is(err, path.ErrBadPattern) != tc.bad {
				t.Fatalf("GlobMatch(%q, %q) = (%t, %v); want (%t, badPattern=%t)", tc.pattern, tc.value, got, err, tc.want, tc.bad)
			}
		})
	}
}

func TestGlobMatchGroupsSkipsInvalidPatterns(t *testing.T) {
	if !GlobMatchGroups([]string{"[", "ops-*"}, []string{"dev", "ops-admin"}) {
		t.Fatal("group matching must skip invalid patterns and find a later match")
	}
}
