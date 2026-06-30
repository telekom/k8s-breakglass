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

// ExpireApprovedSessions sets state to Expired for approved sessions that have passed ExpiresAt
func (wc *BreakglassSessionController) ExpireApprovedSessions() {
	// Use indexed query to fetch only approved sessions
	sessions, err := wc.sessionManager.GetSessionsByState(context.Background(), breakglassv1alpha1.SessionStateApproved)
	if err != nil {
		wc.log.Error("error listing breakglass sessions for approved expiry", err)
		return
	}
	for _, ses := range sessions {
		if IsSessionExpired(ses) {
			// Log intent and timestamps for easier debugging
			now := time.Now()
			wc.log.Infow("Expiring approved session due to reached ExpiresAt", "session", ses.Name, "expiresAt", ses.Status.ExpiresAt.Time, "now", now)

			updated, applied, err := wc.updateSessionStatusIfCurrent(
				context.Background(),
				ses,
				breakglassv1alpha1.SessionStateApproved,
				IsSessionExpired,
				func(current *breakglassv1alpha1.BreakglassSession) {
					current.Status.State = breakglassv1alpha1.SessionStateExpired
					current.SetCondition(metav1.Condition{
						Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
						Status:             metav1.ConditionTrue,
						LastTransitionTime: metav1.Now(),
						Reason:             "ExpiredByTime",
						Message:            "Session expired because its ExpiresAt has been reached.",
					})
					current.Status.ReasonEnded = "timeExpired"
					retainFor := ParseRetainFor(current.Spec, wc.log)
					current.Status.RetainedUntil = metav1.NewTime(now.Add(retainFor))
				},
			)
			if err != nil {
				wc.log.Errorw("failed to update expired session status", "session", ses.Name, "error", err)
				continue
			}
			if !applied {
				wc.log.Infow("Session no longer approved or expired after refetch; skipping time expiry",
					"session", ses.Name,
					"currentState", updated.Status.State,
				)
				continue
			}

			metrics.SessionExpired.WithLabelValues(updated.Spec.Cluster).Inc()
			wc.emitSessionExpiredAuditEvent(context.Background(), &updated, "timeExpired")
			wc.sendSessionExpiredEmail(updated, "timeExpired")
		}
	}
}

// sendSessionExpiredEmail sends a notification when a session expires
func (wc *BreakglassSessionController) sendSessionExpiredEmail(session breakglassv1alpha1.BreakglassSession, expirationReason string) {
	if wc.disableEmail || wc.mailService == nil || !wc.mailService.IsEnabled() {
		return
	}

	reasonText := "Session expired"
	switch expirationReason {
	case "timeExpired":
		reasonText = "Session validity period has ended"
	case "approvalTimeout":
		reasonText = "Session approval timed out before being approved"
	}

	params := mail.SessionExpiredMailParams{
		SubjectEmail:     session.Spec.User,
		RequestedRole:    session.Spec.GrantedGroup,
		Cluster:          session.Spec.Cluster,
		Username:         session.Spec.User,
		SessionID:        session.Name,
		StartedAt:        session.Status.ActualStartTime.Time.Format("2006-01-02 15:04:05 UTC"),
		ExpiredAt:        time.Now().Format("2006-01-02 15:04:05 UTC"),
		ExpirationReason: reasonText,
		BrandingName:     wc.config.Frontend.BrandingName,
	}

	body, err := mail.RenderSessionExpired(params)
	if err != nil {
		wc.log.Errorw("failed to render session expired email",
			"session", session.Name,
			"namespace", session.Namespace,
			"error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Session Expired: %s", wc.config.Frontend.BrandingName, session.Name)
	if err := wc.mailService.Enqueue(session.Name, []string{session.Spec.User}, subject, body); err != nil {
		wc.log.Errorw("failed to enqueue session expired email",
			"session", session.Name,
			"namespace", session.Namespace,
			"error", err)
	}
}
