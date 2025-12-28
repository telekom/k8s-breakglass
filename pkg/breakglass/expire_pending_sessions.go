package breakglass

import (
	"context"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"

	// ExpirePendingSessions sets state to Timeout for pending sessions that have expired (approval timeout)

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (wc *BreakglassSessionController) ExpirePendingSessions() {
	sessions, err := wc.sessionManager.GetAllBreakglassSessions(context.Background())
	if err != nil {
		wc.log.Error("error listing breakglass sessions for pending expiry", err)
		return
	}
	for _, ses := range sessions {
		if IsSessionApprovalTimedOut(ses) {
			wc.log.Infow("Expiring pending session due to approval timeout", "session", ses.Name)
			ses.Status.State = telekomv1alpha1.SessionStateTimeout

			// Set RetainedUntil for timeout sessions (same logic as other terminal states)
			retainFor := DefaultRetainForDuration
			if ses.Spec.RetainFor != "" {
				if d, err := time.ParseDuration(ses.Spec.RetainFor); err == nil && d > 0 {
					retainFor = d
				} else {
					wc.log.Warnw("Invalid RetainFor in session spec; falling back to default", "value", ses.Spec.RetainFor, "error", err)
				}
			}
			ses.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))

			ses.Status.Conditions = append(ses.Status.Conditions, metav1.Condition{
				Type:               string(telekomv1alpha1.SessionConditionTypeExpired),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "ApprovalTimeout",
				Message:            "Session approval timed out.",
			})
			if err := wc.sessionManager.UpdateBreakglassSessionStatus(context.Background(), ses); err == nil {
				// count the session as expired when status update succeeds
				metrics.SessionExpired.WithLabelValues(ses.Spec.Cluster).Inc()
			} else {
				wc.log.Errorw("failed to update session status while expiring pending session", "error", err)
			}
		}
	}
}
