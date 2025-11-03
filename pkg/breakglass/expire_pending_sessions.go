package breakglass

import (
	"context"

	telekomv1alpha1 "github.com/telekom/das-schiff-breakglass/api/v1alpha1"

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
			ses.Status.Conditions = append(ses.Status.Conditions, metav1.Condition{
				Type:               string(telekomv1alpha1.SessionConditionTypeExpired),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "ApprovalTimeout",
				Message:            "Session approval timed out.",
			})
			_ = wc.sessionManager.UpdateBreakglassSessionStatus(context.Background(), ses)
		}
	}
}
