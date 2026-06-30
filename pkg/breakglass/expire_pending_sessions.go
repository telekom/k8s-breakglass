package breakglass

import (
	"context"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExpirePendingSessions sets state to Timeout for pending sessions that have expired (approval timeout).
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
			now := time.Now()
			updated, applied, err := wc.updateSessionStatusIfCurrent(
				context.Background(),
				ses,
				breakglassv1alpha1.SessionStatePending,
				IsSessionApprovalTimedOut,
				func(current *breakglassv1alpha1.BreakglassSession) {
					current.Status.State = breakglassv1alpha1.SessionStateTimeout
					retainFor := ParseRetainFor(current.Spec, wc.log)
					current.Status.RetainedUntil = metav1.NewTime(now.Add(retainFor))
					current.Status.ReasonEnded = "approvalTimeout"
					current.SetCondition(metav1.Condition{
						Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
						Status:             metav1.ConditionTrue,
						LastTransitionTime: metav1.Now(),
						Reason:             "ApprovalTimeout",
						Message:            "Session approval timed out.",
					})
				},
			)
			if err != nil {
				wc.log.Errorw("failed to update session status while expiring pending session", "error", err)
				continue
			}
			if !applied {
				wc.log.Infow("Session no longer pending or timed out after refetch; skipping approval timeout",
					"session", ses.Name,
					"currentState", updated.Status.State,
				)
				continue
			}

			metrics.SessionExpired.WithLabelValues(updated.Spec.Cluster).Inc()
			wc.emitSessionExpiredAuditEvent(context.Background(), &updated, "approvalTimeout")
			wc.sendSessionExpiredEmail(updated, "approvalTimeout")
		}
	}
}

// Fixes issue #944
