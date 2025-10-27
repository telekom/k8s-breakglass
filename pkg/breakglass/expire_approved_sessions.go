package breakglass

import (
	"context"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExpireApprovedSessions sets state to Expired for approved sessions that have passed ExpiresAt
func (wc *BreakglassSessionController) ExpireApprovedSessions() {
	sessions, err := wc.sessionManager.GetAllBreakglassSessions(context.Background())
	if err != nil {
		wc.log.Error("error listing breakglass sessions for approved expiry", err)
		return
	}
	for _, ses := range sessions {
		if ses.Status.State == telekomv1alpha1.SessionStateApproved && IsSessionExpired(ses) {
			wc.log.Infow("Expiring approved session due to reached ExpiresAt", "session", ses.Name)
			ses.Status.State = telekomv1alpha1.SessionStateExpired
			ses.Status.Conditions = append(ses.Status.Conditions, metav1.Condition{
				Type:               string(telekomv1alpha1.SessionConditionTypeExpired),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "ExpiredByTime",
				Message:            "Session expired because its ExpiresAt has been reached.",
			})
			// Try to persist the status change. Use UpdateBreakglassSession which works with fake client
			if err := wc.sessionManager.UpdateBreakglassSession(context.Background(), ses); err != nil {
				wc.log.Errorw("failed to update expired session", "session", ses.Name, "error", err)
			}
		}
	}
}
