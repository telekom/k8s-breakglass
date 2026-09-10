package breakglass

import (
	"context"
	"errors"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ExpireApprovedSessions sets state to Expired for approved sessions that have passed ExpiresAt
func (wc *BreakglassSessionController) ExpireApprovedSessions(ctxs ...context.Context) {
	ctx := optionalCleanupContext(ctxs...)
	if err := ctx.Err(); err != nil {
		wc.log.Infow("skipping approved session expiry because context is cancelled", "error", err)
		return
	}
	wc.drainExpiryNotifications(ctx, breakglassv1alpha1.SessionStateExpired)
	// Use indexed query to fetch only approved sessions
	sessions, err := wc.sessionManager.GetSessionsByState(ctx, breakglassv1alpha1.SessionStateApproved)
	if err != nil {
		wc.log.Error("error listing breakglass sessions for approved expiry", err)
		return
	}
	for _, ses := range sessions {
		if err := ctx.Err(); err != nil {
			wc.log.Infow("stopping approved session expiry because context is cancelled", "error", err)
			return
		}
		if IsSessionExpired(ses) {
			// Log intent and timestamps for easier debugging
			now := time.Now()
			wc.log.Infow("Expiring approved session due to reached ExpiresAt", "session", ses.Name, "expiresAt", ses.Status.ExpiresAt.Time, "now", now)

			updated, applied, err := wc.updateSessionStatusIfCurrent(
				ctx,
				ses,
				breakglassv1alpha1.SessionStateApproved,
				IsSessionExpired,
				func(current *breakglassv1alpha1.BreakglassSession) {
					transitionTime := metav1.NewTime(now.UTC())
					current.Status.ExpiresAt = utils.ClampBreakglassSessionExpiry(current.Status.ExpiresAt, now)
					current.Status.State = breakglassv1alpha1.SessionStateExpired
					current.SetCondition(metav1.Condition{
						Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
						Status:             metav1.ConditionTrue,
						LastTransitionTime: transitionTime,
						Reason:             "ExpiredByTime",
						Message:            "Session expired because its ExpiresAt has been reached.",
					})
					current.Status.ReasonEnded = "timeExpired"
					retainFor := ParseRetainFor(current.Spec, wc.log)
					current.Status.RetainedUntil = metav1.NewTime(now.Add(retainFor))
					wc.setExpiryNotificationIntent(current, transitionTime)
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
			wc.emitSessionExpiredAuditEvent(ctx, &updated, "timeExpired")
			if err := wc.enqueueExpiryNotification(ctx, updated); err != nil {
				wc.log.Errorw("failed to enqueue approved session expiry notification",
					"session", updated.Name, "namespace", updated.Namespace, "error", err)
			}
		}
	}
}

// sendSessionExpiredEmail sends a notification when a session expires
func (wc *BreakglassSessionController) sendSessionExpiredEmail(session breakglassv1alpha1.BreakglassSession, expirationReason string) error {
	if wc.disableEmail {
		return errors.New("expiry email is intentionally disabled")
	}
	if wc.mailService == nil || !wc.mailService.IsEnabled() {
		return errors.New("expiry email service is unavailable")
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
		ExpiredAt:        expiryNotificationTime(session).Format("2006-01-02 15:04:05 UTC"),
		ExpirationReason: reasonText,
		BrandingName:     wc.config.Frontend.BrandingName,
	}

	body, err := mail.RenderSessionExpired(params)
	if err != nil {
		wc.log.Errorw("failed to render session expired email",
			"session", session.Name,
			"namespace", session.Namespace,
			"error", err)
		return fmt.Errorf("render session expired email: %w", err)
	}

	subject := fmt.Sprintf("[%s] Session Expired: %s", wc.config.Frontend.BrandingName, session.Name)
	if err := wc.mailService.Enqueue(session.Name, []string{session.Spec.User}, subject, body); err != nil {
		wc.log.Errorw("failed to enqueue session expired email",
			"session", session.Name,
			"namespace", session.Namespace,
			"error", err)
		return fmt.Errorf("enqueue session expired email: %w", err)
	}
	return nil
}

func (wc *BreakglassSessionController) setExpiryNotificationIntent(session *breakglassv1alpha1.BreakglassSession, transitionTime metav1.Time) {
	session.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent),
		Status:             metav1.ConditionFalse,
		Reason:             "PendingEnqueue",
		Message:            "Expiry email enqueue is pending.",
		LastTransitionTime: transitionTime,
	})
}

func expiryNotificationTime(session breakglassv1alpha1.BreakglassSession) time.Time {
	condition := session.GetCondition(string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent))
	if condition != nil && !condition.LastTransitionTime.IsZero() {
		return condition.LastTransitionTime.Time.UTC()
	}
	return time.Now().UTC()
}

func (wc *BreakglassSessionController) drainExpiryNotifications(ctx context.Context, state breakglassv1alpha1.BreakglassSessionState) {
	sessions, err := wc.sessionManager.GetSessionsByState(ctx, state)
	if err != nil {
		wc.log.Errorw("failed to list sessions with pending expiry notifications", "state", state, "error", err)
		return
	}
	for i := range sessions {
		condition := sessions[i].GetCondition(string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent))
		if condition == nil || condition.Status != metav1.ConditionFalse {
			continue
		}
		if wc.disableEmail {
			if err := wc.acknowledgeExpiryNotification(ctx, sessions[i], condition, "NotificationsDisabled",
				"Expiry email was not enqueued because notifications are intentionally disabled."); err != nil {
				wc.log.Errorw("failed to acknowledge disabled expiry notification",
					"session", sessions[i].Name, "namespace", sessions[i].Namespace, "error", err)
			}
			continue
		}
		if err := wc.enqueueExpiryNotification(ctx, sessions[i]); err != nil {
			wc.log.Errorw("failed to retry session expiry notification enqueue",
				"session", sessions[i].Name, "namespace", sessions[i].Namespace, "error", err)
		}
	}
}

func (wc *BreakglassSessionController) enqueueExpiryNotification(ctx context.Context, session breakglassv1alpha1.BreakglassSession) error {
	condition := session.GetCondition(string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent))
	if condition == nil || condition.Status != metav1.ConditionFalse {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if wc.disableEmail {
		return wc.acknowledgeExpiryNotification(ctx, session, condition, "NotificationsDisabled",
			"Expiry email was not enqueued because notifications are intentionally disabled.")
	}
	if err := wc.sendSessionExpiredEmail(session, session.Status.ReasonEnded); err != nil {
		return err
	}
	return wc.acknowledgeExpiryNotification(ctx, session, condition, "QueueAccepted",
		"Expiry email was accepted by the in-memory queue for best-effort asynchronous delivery.")
}

func (wc *BreakglassSessionController) acknowledgeExpiryNotification(
	ctx context.Context,
	session breakglassv1alpha1.BreakglassSession,
	condition *metav1.Condition,
	reason string,
	message string,
) error {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var current breakglassv1alpha1.BreakglassSession
		if err := wc.sessionManager.Reader().Get(ctx, client.ObjectKeyFromObject(&session), &current); err != nil {
			return err
		}
		currentCondition := current.GetCondition(string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent))
		if currentCondition == nil || currentCondition.Status == metav1.ConditionTrue {
			return nil
		}
		if currentCondition.Reason != condition.Reason || !currentCondition.LastTransitionTime.Equal(&condition.LastTransitionTime) {
			return errors.New("expiry notification enqueue intent changed before acknowledgement")
		}
		base := current.DeepCopy()
		current.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.SessionConditionTypeExpiryNotificationIntent),
			Status:             metav1.ConditionTrue,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: condition.LastTransitionTime,
		})
		return wc.sessionManager.Client.Status().Patch(ctx, &current,
			client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("acknowledge expiry notification enqueue intent: %w", err)
	}
	return nil
}
