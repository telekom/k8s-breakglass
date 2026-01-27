package utils

import (
	"fmt"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
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

	// Add events.k8s.io/v1 types for SSA-backed event queries
	if err := eventsv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add eventsv1 to scheme: %w", err)
	}

	// Add custom breakglass CRD types (v1alpha1)
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add v1alpha1 CRDs to scheme: %w", err)
	}

	return scheme, nil
}

// SetupLogger creates and configures a zap logger for the application.
// If debug is true, it uses development mode; otherwise production mode.
// Stacktraces are only added for DPanic level and above to reduce log noise
// during normal error handling (transient network errors, etc.).
func SetupLogger(debug bool) (*zap.Logger, error) {
	var logger *zap.Logger
	var err error
	if debug {
		// Development config with stacktraces only for DPanic+
		cfg := zap.NewDevelopmentConfig()
		cfg.EncoderConfig.StacktraceKey = "" // Disable stacktrace field entirely
		logger, err = cfg.Build(
			zap.AddStacktrace(zap.DPanicLevel), // Only add stacktraces for DPanic+
		)
	} else {
		// Production config with stacktraces only for DPanic+
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.StacktraceKey = "" // Disable stacktrace field entirely
		logger, err = cfg.Build(
			zap.AddStacktrace(zap.DPanicLevel), // Only add stacktraces for DPanic+
		)
	}
	if err != nil {
		return nil, fmt.Errorf("unable to create logger (debug: %t): %w", debug, err)
	}
	return logger, nil
}
