// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// recordSessionActivity asynchronously updates the session's activity tracking
// fields (LastActivityAt, AccessCount) and emits Prometheus metrics.
// It runs in a goroutine to avoid blocking the authorization webhook response.
func recordSessionActivity(ctx context.Context, sesManager *breakglass.SessionManager, clusterName, sessionName string, log *zap.SugaredLogger) {
	now := time.Now()

	// Emit metrics immediately (non-blocking)
	metrics.SessionActivityTotal.WithLabelValues(clusterName, sessionName).Inc()
	metrics.SessionLastActivityTimestamp.WithLabelValues(clusterName, sessionName).Set(float64(now.Unix()))

	// Update session status asynchronously
	go func() {
		// Use a fresh context to avoid cancellation from the parent request
		updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := updateSessionActivityStatus(updateCtx, sesManager, sessionName, now, log); err != nil {
			metrics.SessionActivityUpdateErrors.WithLabelValues(clusterName, sessionName).Inc()
			if log != nil {
				log.With("error", err, "session", sessionName, "cluster", clusterName).Warn("Failed to update session activity status")
			}
		}
	}()
}

// updateSessionActivityStatus fetches the current session, updates the activity
// fields, and writes the status back. It performs an atomic read-modify-write
// to avoid losing concurrent updates.
func updateSessionActivityStatus(ctx context.Context, sesManager *breakglass.SessionManager, sessionName string, now time.Time, log *zap.SugaredLogger) error {
	if sesManager == nil {
		return fmt.Errorf("session manager is nil")
	}

	current, err := sesManager.GetBreakglassSessionByName(ctx, sessionName)
	if err != nil {
		return fmt.Errorf("failed to get session %s: %w", sessionName, err)
	}

	// Update the activity fields
	nowMeta := metav1.NewTime(now)
	current.Status.LastActivityAt = &nowMeta
	current.Status.AccessCount++

	return sesManager.UpdateBreakglassSessionStatus(ctx, current)
}

// RecordSessionActivityFunc is the function type for recording session activity.
// This allows injection of a mock for testing.
type RecordSessionActivityFunc func(ctx context.Context, sesManager *breakglass.SessionManager, clusterName, sessionName string, log *zap.SugaredLogger)

// defaultRecordSessionActivity is the package-level reference used by WebhookController.
// It can be overridden in tests.
var defaultRecordSessionActivity RecordSessionActivityFunc = recordSessionActivity

// setRecordSessionActivityFunc overrides the activity recorder for testing.
// Returns a cleanup function that restores the original.
func setRecordSessionActivityFunc(fn RecordSessionActivityFunc) func() {
	old := defaultRecordSessionActivity
	defaultRecordSessionActivity = fn
	return func() { defaultRecordSessionActivity = old }
}

// SessionActivityRecorder is an interface for recording session activity.
// It is used to allow mocking in tests.
type SessionActivityRecorder interface {
	// RecordActivity records that an authorization was allowed via the given session.
	RecordActivity(ctx context.Context, clusterName, sessionName string)
}

// defaultSessionActivityRecorder implements SessionActivityRecorder using the real implementation.
type defaultSessionActivityRecorder struct {
	sesManager *breakglass.SessionManager
	log        *zap.SugaredLogger
}

// RecordActivity records session activity using the real implementation.
func (r *defaultSessionActivityRecorder) RecordActivity(ctx context.Context, clusterName, sessionName string) {
	recordSessionActivity(ctx, r.sesManager, clusterName, sessionName, r.log)
}

// noopSessionActivityRecorder is a no-op implementation for when activity tracking is not needed.
type noopSessionActivityRecorder struct{}

// RecordActivity is a no-op.
func (r *noopSessionActivityRecorder) RecordActivity(_ context.Context, _, _ string) {}

// newSessionActivityRecorder creates the appropriate recorder based on configuration.
func newSessionActivityRecorder(sesManager *breakglass.SessionManager, log *zap.SugaredLogger) SessionActivityRecorder {
	if sesManager == nil {
		return &noopSessionActivityRecorder{}
	}
	return &defaultSessionActivityRecorder{
		sesManager: sesManager,
		log:        log,
	}
}
