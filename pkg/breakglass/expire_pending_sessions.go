package breakglass

import (
	"context"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"

	// ExpirePendingSessions sets state to Timeout for pending sessions that have expired (approval timeout)

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (wc *BreakglassSessionController) ExpirePendingSessions() {
	// Use indexed query to fetch only pending sessions (matching ExpireApprovedSessions pattern)
	sessions, err := wc.sessionManager.GetSessionsByState(context.Background(), breakglassv1alpha1.SessionStatePending)
	if err != nil {
		wc.log.Error("error listing breakglass sessions for pending expiry", err)
		return
	}
	for _, ses := range sessions {
		if IsSessionApprovalTimedOut(ses) {
			wc.log.Infow("Expiring pending session due to approval timeout", "session", ses.Name)
			ses.Status.State = breakglassv1alpha1.SessionStateTimeout

			// Set RetainedUntil for timeout sessions
			retainFor := ParseRetainFor(ses.Spec, wc.log)
			ses.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))

			ses.Status.Conditions = append(ses.Status.Conditions, metav1.Condition{
				Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "ApprovalTimeout",
				Message:            "Session approval timed out.",
			})
			if err := wc.sessionManager.UpdateBreakglassSessionStatus(context.Background(), ses); err == nil {
				// count the session as expired when status update succeeds
				metrics.SessionExpired.WithLabelValues(ses.Spec.Cluster).Inc()
				// Emit audit event for approval timeout
				wc.emitSessionExpiredAuditEvent(context.Background(), &ses, "approvalTimeout")
				// Send expiration email for approval timeout
				wc.sendSessionExpiredEmail(ses, "approvalTimeout")
			} else {
				wc.log.Errorw("failed to update session status while expiring pending session", "error", err)
			}
		}
	}
}
