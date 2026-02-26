/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package breakglass

import (
	"context"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// maxStatusUpdateRetries is the maximum number of status update attempts
// before giving up on transitioning a session to IdleExpired.
const maxStatusUpdateRetries = 3

// ExpireIdleSessions sets state to IdleExpired for approved sessions that have been idle
// longer than their configured spec.idleTimeout. A session is idle when no authorization
// request has been recorded since the session was approved (or since the last activity if any).
//
// Sessions without spec.idleTimeout are skipped. Sessions where
// status.lastActivity has not been set (no webhook requests recorded yet)
// are also skipped, since idleness cannot be reliably determined.
//
// The provided context controls cancellation; callers should pass a bounded
// context (e.g., with DefaultCleanupOperationTimeout) so that the function
// exits promptly during operator shutdown.
func (wc *BreakglassSessionController) ExpireIdleSessions(ctx context.Context) {
	sessions, err := wc.sessionManager.GetSessionsByState(ctx, breakglassv1alpha1.SessionStateApproved)
	if err != nil {
		wc.log.Errorw("error listing breakglass sessions for idle expiry", "error", err)
		return
	}

	for _, ses := range sessions {
		// Check for context cancellation between sessions to exit promptly during shutdown.
		select {
		case <-ctx.Done():
			wc.log.Infow("Context cancelled during idle session expiry", "error", ctx.Err())
			return
		default:
		}

		if ses.Spec.IdleTimeout == "" {
			continue
		}

		idleTimeout, err := breakglassv1alpha1.ParseDuration(ses.Spec.IdleTimeout)
		if err != nil {
			wc.log.Warnw("invalid idleTimeout on session, skipping",
				"session", ses.Name,
				"idleTimeout", ses.Spec.IdleTimeout,
				"error", err)
			continue
		}

		// Determine the idle baseline: last activity timestamp.
		// If lastActivity has never been set (activity tracking is disabled or
		// no requests have been recorded yet), we cannot reliably determine
		// idleness, so skip this session.
		if ses.Status.LastActivity == nil || ses.Status.LastActivity.IsZero() {
			// Session has idleTimeout but no activity recorded yet. This is normal for
			// newly-approved sessions that haven't been used, or when enableActivityTracking
			// is disabled. Log at debug to avoid noisy logs on every cleanup cycle.
			if ses.Status.ActivityCount == 0 {
				wc.log.Debugw("Skipping idle check: no activity recorded yet",
					"session", ses.Name,
					"idleTimeout", ses.Spec.IdleTimeout)
			}
			continue
		}
		baseline := ses.Status.LastActivity.Time

		idleSince := time.Since(baseline)
		if idleSince < idleTimeout {
			continue
		}

		wc.log.Infow("Expiring session due to idle timeout",
			"session", ses.Name,
			"idleTimeout", ses.Spec.IdleTimeout,
			"idleSince", idleSince.Round(time.Second),
			"lastActivity", baseline)

		// Prepare status transition
		ses.Status.State = breakglassv1alpha1.SessionStateIdleExpired
		ses.SetCondition(newIdleCondition(idleSince, ses.Spec.IdleTimeout))
		ses.Status.ReasonEnded = "idleTimeout"

		// Ensure we have correct metadata for the API update.
		// Re-validate idle condition after refetch to avoid TOCTOU race where
		// activity was recorded between our initial check and this point.
		if stored, gerr := wc.sessionManager.GetBreakglassSessionByName(ctx, ses.Name); gerr == nil {
			ses.Namespace = stored.Namespace
			ses.ResourceVersion = stored.ResourceVersion
			// If the session was already transitioned to a terminal state by another
			// controller replica, skip idle expiry to avoid overwriting the reason.
			if stored.Status.State != breakglassv1alpha1.SessionStateApproved {
				wc.log.Infow("Session already transitioned after refetch; skipping idle expiry",
					"session", ses.Name, "currentState", stored.Status.State)
				continue
			}
			// Re-validate: if the stored session's lastActivity is more recent, it may no longer be idle
			if stored.Status.LastActivity != nil && !stored.Status.LastActivity.IsZero() {
				refreshedIdle := time.Since(stored.Status.LastActivity.Time)
				if refreshedIdle < idleTimeout {
					wc.log.Infow("Session no longer idle after refetch; skipping expiry",
						"session", ses.Name,
						"refreshedIdleSince", refreshedIdle.Round(time.Second))
					continue
				}
			}
		} else {
			wc.log.Debugw("could not refetch session before idle status update; will attempt update anyway",
				"session", ses.Name, "error", gerr)
		}

		// Persist the status change with retry on conflict (following ExpireApprovedSessions pattern)
		var lastErr error
		idleExpireSucceeded := false
		for attempt := 0; attempt < maxStatusUpdateRetries; attempt++ {
			if err := wc.sessionManager.UpdateBreakglassSessionStatus(ctx, ses); err == nil {
				lastErr = nil
				idleExpireSucceeded = true
				metrics.SessionIdleExpired.WithLabelValues(ses.Spec.Cluster).Inc()
				wc.emitSessionExpiredAuditEvent(ctx, &ses, "idleTimeout")
				break
			} else {
				lastErr = fmt.Errorf("status update attempt %d failed: %w", attempt+1, err)
				wc.log.Warnw("failed to update idle-expired session status (will retry)",
					"session", ses.Name, "attempt", attempt+1, "error", err)

				if updated, gerr := wc.sessionManager.GetBreakglassSessionByName(ctx, ses.Name); gerr == nil {
					// If the session was already transitioned to a terminal state by another process,
					// do not overwrite it — just stop retrying.
					if updated.Status.State != breakglassv1alpha1.SessionStateApproved {
						wc.log.Infow("Session already transitioned by another process; skipping idle expiry",
							"session", ses.Name, "currentState", updated.Status.State)
						lastErr = nil
						break
					}
					updated.Status.State = ses.Status.State
					updated.Status.Conditions = ses.Status.Conditions
					updated.Status.ReasonEnded = ses.Status.ReasonEnded
					ses = updated
				} else {
					wc.log.Errorw("failed to refetch session after failed idle status update",
						"session", ses.Name, "error", gerr)
					break
				}
				// Brief context-aware delay before retry to allow the API server
				// to process concurrent writes and reduce conflict pressure on
				// the next status update attempt.
				select {
				case <-ctx.Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
		}
		if lastErr != nil {
			wc.log.Errorw("failed to update idle-expired session after retries",
				"session", ses.Name, "error", lastErr)
		} else if idleExpireSucceeded {
			wc.sendSessionIdleExpiredEmail(ses)
		}
	}
}

// sendSessionIdleExpiredEmail sends a notification when a session is expired due to idle timeout.
func (wc *BreakglassSessionController) sendSessionIdleExpiredEmail(session breakglassv1alpha1.BreakglassSession) {
	if wc.disableEmail || wc.mailService == nil || !wc.mailService.IsEnabled() {
		return
	}

	// Determine a human-readable session start time for the notification.
	// Fallback order: actualStartTime → approvedAt → current time.
	// ActualStartTime is metav1.Time (value type, not *metav1.Time pointer),
	// so .IsZero() is the correct "not set" check — no nil deref possible.
	var startedAt string
	switch {
	case !session.Status.ActualStartTime.IsZero():
		startedAt = session.Status.ActualStartTime.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	case !session.Status.ApprovedAt.IsZero():
		startedAt = session.Status.ApprovedAt.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	default:
		startedAt = time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	}

	params := mail.SessionExpiredMailParams{
		SubjectEmail:     session.Spec.User,
		RequestedRole:    session.Spec.GrantedGroup,
		Cluster:          session.Spec.Cluster,
		Username:         session.Spec.User,
		SessionID:        session.Name,
		StartedAt:        startedAt,
		ExpiredAt:        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		ExpirationReason: fmt.Sprintf("Session was idle for longer than %s", session.Spec.IdleTimeout),
		BrandingName:     wc.config.Frontend.BrandingName,
	}

	body, err := mail.RenderSessionExpired(params)
	if err != nil {
		wc.log.Errorw("failed to render idle-expired session email",
			"session", session.Name,
			"error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Session Idle Expired: %s", wc.config.Frontend.BrandingName, session.Name)
	if err := wc.mailService.Enqueue(session.Name, []string{session.Spec.User}, subject, body); err != nil {
		wc.log.Errorw("failed to enqueue idle-expired session email",
			"session", session.Name,
			"error", err)
	}
}

// newIdleCondition builds a standard Idle condition for idle-expired sessions.
// This helper avoids duplicating the condition construction across the idle expiry
// code and any future callers.
func newIdleCondition(idleSince time.Duration, idleTimeout string) metav1.Condition {
	return metav1.Condition{
		Type:               string(breakglassv1alpha1.SessionConditionTypeIdle),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             "IdleTimeout",
		Message:            fmt.Sprintf("Session expired after %s of inactivity (idle timeout: %s).", idleSince.Round(time.Second), idleTimeout),
	}
}
