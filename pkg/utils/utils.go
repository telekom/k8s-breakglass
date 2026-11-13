package utils

import (
	"fmt"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CreateScheme creates and returns a runtime scheme with all necessary types registered.
// This includes standard Kubernetes types and all custom breakglass CRDs.
// The same scheme instance should be reused for all Kubernetes clients to ensure consistency.
func CreateScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	// Add standard Kubernetes types (core API)
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add corev1 to scheme: %w", err)
	}

	if err := coordinationv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add coordinationv1 to scheme: %w", err)
	}

	// Add events.k8s.io/v1 types for SSA-backed event queries
	if err := eventsv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add eventsv1 to scheme: %w", err)
	}

	// Add custom breakglass CRD types (v1alpha1)
	if err := breakglassv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add v1alpha1 CRDs to scheme: %w", err)
	}

	return scheme, nil
}

// logLevels are the accepted --log-level values.
var logLevels = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

// SetupLogger creates the application logger for a level (debug, info, warn,
// error) and a format. The "json" format is zap's production profile and the
// "console" format its development profile (human-readable; DPanic panics),
// so ("info", "json") is the default output and ("debug", "console") the
// output of the deprecated --debug flag.
// Stacktraces are only added for DPanic level and above to reduce log noise
// during normal error handling (transient network errors, etc.).
func SetupLogger(level, format string) (*zap.Logger, error) {
	var cfg zap.Config
	switch format {
	case "json":
		cfg = zap.NewProductionConfig()
	case "console":
		cfg = zap.NewDevelopmentConfig()
	default:
		return nil, fmt.Errorf("invalid log format %q: must be json or console", format)
	}
	lvl, ok := logLevels[level]
	if !ok {
		return nil, fmt.Errorf("invalid log level %q: must be debug, info, warn or error", level)
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.StacktraceKey = "" // Disable stacktrace field entirely
	logger, err := cfg.Build(zap.AddStacktrace(zap.DPanicLevel))
	if err != nil {
		return nil, fmt.Errorf("unable to create logger (level %s, format %s): %w", level, format, err)
	}
	return logger, nil
}
