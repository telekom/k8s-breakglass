package breakglass

import (
	"context"

	"time"

	"github.com/pkg/errors"
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
			// Log intent and timestamps for easier debugging
			now := time.Now()
			wc.log.Infow("Expiring approved session due to reached ExpiresAt", "session", ses.Name, "expiresAt", ses.Status.ExpiresAt.Time, "now", now)

			// Prepare status transition
			ses.Status.State = telekomv1alpha1.SessionStateExpired
			ses.Status.Conditions = append(ses.Status.Conditions, metav1.Condition{
				Type:               string(telekomv1alpha1.SessionConditionTypeExpired),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "ExpiredByTime",
				Message:            "Session expired because its ExpiresAt has been reached.",
			})
			// set short reason for UI consumption
			ses.Status.ReasonEnded = "timeExpired"

			// Ensure we have the correct namespace/resourceVersion from the stored object before updating status.
			if stored, gerr := wc.sessionManager.GetBreakglassSessionByName(context.Background(), ses.Name); gerr == nil {
				// copy any necessary metadata so client can locate the object
				ses.Namespace = stored.Namespace
				ses.ResourceVersion = stored.ResourceVersion
			} else {
				// If we cannot refetch, log and proceed; Update may still fail and will be retried below
				wc.log.Debugw("could not refetch session before status update; will attempt update anyway", "session", ses.Name, "error", gerr)
			}

			// Persist the status change using Status().Update and retry on conflict with a few attempts.
			var lastErr error
			for attempt := 0; attempt < 3; attempt++ {
				if err := wc.sessionManager.UpdateBreakglassSessionStatus(context.Background(), ses); err == nil {
					lastErr = nil
					break
				} else {
					lastErr = errors.Wrapf(err, "status update attempt %d failed", attempt+1)
					wc.log.Warnw("failed to update expired session status (will retry)", "session", ses.Name, "attempt", attempt+1, "error", err)

					// On conflict or other recoverable errors, re-fetch the latest object and reapply status changes
					if updated, gerr := wc.sessionManager.GetBreakglassSessionByName(context.Background(), ses.Name); gerr == nil {
						// copy status changes onto updated object and retry
						updated.Status.State = ses.Status.State
						updated.Status.Conditions = ses.Status.Conditions
						updated.Status.ReasonEnded = ses.Status.ReasonEnded
						ses = updated
					} else {
						// If we cannot re-fetch, short-circuit and surface error
						wc.log.Errorw("failed to refetch session after failed status update", "session", ses.Name, "error", gerr)
						break
					}
					// small backoff between retries
					time.Sleep(200 * time.Millisecond)
				}
			}
			if lastErr != nil {
				wc.log.Errorw("failed to update expired session after retries", "session", ses.Name, "error", lastErr)
				// Fallback: try a full object update if Status().Update did not succeed.
				if ferr := wc.sessionManager.UpdateBreakglassSession(context.Background(), ses); ferr == nil {
					wc.log.Infow("fallback full update succeeded after status update failures", "session", ses.Name)
				} else {
					wc.log.Errorw("fallback full update failed", "session", ses.Name, "error", ferr)
				}
			}
		}
	}
}
