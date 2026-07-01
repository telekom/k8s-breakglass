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
	"errors"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type scheduledSessionStateChangedError struct {
	name  string
	state breakglassv1alpha1.BreakglassSessionState
}

func (e *scheduledSessionStateChangedError) Error() string {
	return fmt.Sprintf("session state changed to %s", e.state)
}

// ScheduledSessionActivator handles activation of scheduled sessions.
// When a session's ScheduledStartTime is reached, it transitions from WaitingForScheduledTime to Approved
// and becomes available for use (RBAC group is applied).
type ScheduledSessionActivator struct {
	log            *zap.SugaredLogger
	sessionManager *SessionManager
	mailService    MailEnqueuer
	auditService   AuditEmitter
	brandingName   string
	disableEmail   bool
}

// NewScheduledSessionActivator creates a new activator instance
func NewScheduledSessionActivator(log *zap.SugaredLogger, sessionManager *SessionManager) *ScheduledSessionActivator {
	return &ScheduledSessionActivator{
		log:            log,
		sessionManager: sessionManager,
	}
}

// WithMailService sets the mail service for sending activation notifications
func (ssa *ScheduledSessionActivator) WithMailService(mailService MailEnqueuer, brandingName string, disableEmail bool) *ScheduledSessionActivator {
	ssa.mailService = mailService
	ssa.brandingName = brandingName
	ssa.disableEmail = disableEmail
	return ssa
}

// WithAuditService sets the audit service for scheduled activation events.
func (ssa *ScheduledSessionActivator) WithAuditService(auditService AuditEmitter) *ScheduledSessionActivator {
	ssa.auditService = auditService
	return ssa
}

// ActivateScheduledSessions checks sessions in WaitingForScheduledTime state.
// Sessions whose ScheduledStartTime has arrived transition to Approved so the RBAC group can be applied.
// Sessions that can no longer be valid are expired instead of being activated late.
func (ssa *ScheduledSessionActivator) ActivateScheduledSessions() {
	ctx := context.Background()

	// Use indexed query to fetch only sessions waiting for scheduled time
	sessions, err := ssa.sessionManager.GetSessionsByState(ctx, breakglassv1alpha1.SessionStateWaitingForScheduledTime)
	if err != nil {
		ssa.log.Errorw("error listing sessions for scheduled activation", "error", err)
		return
	}

	now := time.Now()
	for _, ses := range sessions {
		listedMissingScheduledTime := ses.Spec.ScheduledStartTime == nil || ses.Spec.ScheduledStartTime.IsZero()
		if !listedMissingScheduledTime && now.Before(ses.Spec.ScheduledStartTime.Time) {
			// Not yet time for this session; avoid a live read until the cached
			// scheduledStartTime says this session may need a state transition.
			continue
		}

		operation := "activation"
		if listedMissingScheduledTime {
			operation = "expiry"
		}
		current, ok := ssa.currentWaitingScheduledSession(ctx, ses, operation)
		if !ok {
			continue
		}
		ses = current

		// Sanity check: session should have a scheduledStartTime
		if ses.Spec.ScheduledStartTime == nil || ses.Spec.ScheduledStartTime.IsZero() {
			ssa.log.Errorw("expiring session in WaitingForScheduledTime state with no ScheduledStartTime",
				"session", ses.Name,
				"namespace", ses.Namespace)
			ssa.expireScheduledSession(ctx, ses, now, "missingScheduledStartTime", "MissingScheduledStartTime", "Session expired: WaitingForScheduledTime with no ScheduledStartTime set")
			continue
		}

		scheduledTime := ses.Spec.ScheduledStartTime.Time
		if now.Before(scheduledTime) {
			// Live state moved the scheduled start into the future after the list read.
			continue
		}
		if !ses.Status.ExpiresAt.IsZero() && !now.Before(ses.Status.ExpiresAt.Time) {
			ssa.log.Infow("Expiring scheduled session whose validity ended before activation",
				"session", ses.Name,
				"namespace", ses.Namespace,
				"scheduledStartTime", scheduledTime,
				"expiresAt", ses.Status.ExpiresAt.Time,
				"now", now)
			ssa.expireScheduledSession(ctx, ses, now, "scheduledSessionExpiredBeforeActivation", "ScheduledSessionExpiredBeforeActivation", "Session expired before its scheduled activation was processed")
			continue
		}

		// Time to activate!
		ssa.log.Infow("Activating scheduled session",
			"session", ses.Name,
			"namespace", ses.Namespace,
			"scheduledStartTime", scheduledTime,
			"now", now)

		// Transition to Approved state
		ses.Status.State = breakglassv1alpha1.SessionStateApproved
		ses.Status.ActualStartTime = metav1.Now()

		// Add condition for audit trail
		ses.SetCondition(metav1.Condition{
			Type:               "ScheduledStartTimeReached",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "ActivationTriggered",
			Message:            "Session activated at scheduled start time",
		})

		// Update session status in cluster
		if err := ssa.updateWaitingScheduledSessionStatus(ctx, ses); err != nil {
			if apierrors.IsConflict(err) {
				ssa.log.Infow("skipping scheduled session activation because state changed before update",
					"session", ses.Name, "namespace", ses.Namespace, "error", err)
			} else {
				ssa.log.Errorw("failed to activate scheduled session",
					"session", ses.Name,
					"namespace", ses.Namespace,
					"error", err)
			}
			continue
		}

		ssa.log.Infow("Successfully activated scheduled session",
			"session", ses.Name,
			"namespace", ses.Namespace,
			"actualStartTime", ses.Status.ActualStartTime.Time)

		// Record metric for successful activation
		metrics.SessionActivated.WithLabelValues(ses.Spec.Cluster).Inc()

		ssa.emitSessionActivatedAuditEvent(ses)

		// Send activation notification email
		ssa.sendSessionActivatedEmail(ses)

		// RBAC group will now be applied by the authorization controller
		// (same mechanism as immediate sessions)
	}
}

func (ssa *ScheduledSessionActivator) updateWaitingScheduledSessionStatus(
	ctx context.Context,
	session breakglassv1alpha1.BreakglassSession,
) error {
	key := client.ObjectKeyFromObject(&session)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := breakglassv1alpha1.BreakglassSession{}
		if err := ssa.sessionManager.Reader().Get(ctx, key, &current); err != nil {
			return err
		}
		if current.Status.State != breakglassv1alpha1.SessionStateWaitingForScheduledTime {
			return &scheduledSessionStateChangedError{name: current.Name, state: current.Status.State}
		}

		base := current.DeepCopy()
		applyScheduledSessionStatusTransition(&current, session)
		patch := client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})
		return ssa.sessionManager.Client.Status().Patch(ctx, &current, patch)
	})
	if err == nil {
		return nil
	}
	var stateChanged *scheduledSessionStateChangedError
	if errors.As(err, &stateChanged) {
		return apierrors.NewConflict(schema.GroupResource{
			Group:    breakglassv1alpha1.GroupVersion.Group,
			Resource: "breakglasssessions",
		}, stateChanged.name, stateChanged)
	}
	return err
}

func applyScheduledSessionStatusTransition(current *breakglassv1alpha1.BreakglassSession, desired breakglassv1alpha1.BreakglassSession) {
	current.Status.State = desired.Status.State
	current.Status.ObservedGeneration = current.Generation
	if !desired.Status.ActualStartTime.IsZero() {
		current.Status.ActualStartTime = desired.Status.ActualStartTime
	}
	if desired.Status.State == breakglassv1alpha1.SessionStateExpired {
		current.Status.ReasonEnded = desired.Status.ReasonEnded
		current.Status.ExpiresAt = desired.Status.ExpiresAt
		current.Status.RetainedUntil = desired.Status.RetainedUntil
	}
	for _, condition := range desired.Status.Conditions {
		switch condition.Type {
		case "ScheduledStartTimeReached", string(breakglassv1alpha1.SessionConditionTypeExpired):
			meta.SetStatusCondition(&current.Status.Conditions, condition)
		}
	}
}

func (ssa *ScheduledSessionActivator) expireScheduledSession(ctx context.Context, session breakglassv1alpha1.BreakglassSession, now time.Time, reasonEnded, conditionReason, message string) {
	session.Status.State = breakglassv1alpha1.SessionStateExpired
	session.Status.ReasonEnded = reasonEnded
	if session.Status.ExpiresAt.IsZero() || now.Before(session.Status.ExpiresAt.Time) {
		session.Status.ExpiresAt = metav1.NewTime(now)
	}
	retainFor := ParseRetainFor(session.Spec, ssa.log)
	session.Status.RetainedUntil = metav1.NewTime(now.Add(retainFor))
	session.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             conditionReason,
		Message:            message,
	})
	if err := ssa.updateWaitingScheduledSessionStatus(ctx, session); err != nil {
		if apierrors.IsConflict(err) {
			ssa.log.Infow("skipping scheduled session expiry because state changed before update",
				"session", session.Name, "namespace", session.Namespace, "reason", reasonEnded, "error", err)
		} else {
			ssa.log.Errorw("failed to expire scheduled session",
				"session", session.Name, "namespace", session.Namespace, "reason", reasonEnded, "error", err)
		}
		return
	}
	metrics.SessionExpired.WithLabelValues(session.Spec.Cluster).Inc()
}

func (ssa *ScheduledSessionActivator) currentWaitingScheduledSession(
	ctx context.Context,
	listed breakglassv1alpha1.BreakglassSession,
	operation string,
) (breakglassv1alpha1.BreakglassSession, bool) {
	current := breakglassv1alpha1.BreakglassSession{}
	if err := ssa.sessionManager.Reader().Get(ctx, client.ObjectKey{Name: listed.Name, Namespace: listed.Namespace}, &current); err != nil {
		if apierrors.IsNotFound(err) {
			ssa.log.Infow("skipping scheduled session "+operation+" because live session was deleted",
				"session", listed.Name,
				"namespace", listed.Namespace)
		} else {
			ssa.log.Errorw("skipping scheduled session "+operation+" because live session could not be read",
				"session", listed.Name,
				"namespace", listed.Namespace,
				"error", err)
		}
		return listed, false
	}
	if current.Status.State != breakglassv1alpha1.SessionStateWaitingForScheduledTime {
		ssa.log.Infow("skipping scheduled session "+operation+" because state changed",
			"session", current.Name,
			"namespace", current.Namespace,
			"state", current.Status.State)
		return current, false
	}
	return current, true
}

func (ssa *ScheduledSessionActivator) emitSessionActivatedAuditEvent(session breakglassv1alpha1.BreakglassSession) {
	if ssa.auditService == nil || !ssa.auditService.IsEnabled() {
		return
	}

	ssa.auditService.Emit(context.Background(), &audit.Event{
		Type:      audit.EventSessionActivated,
		Severity:  audit.SeverityInfo,
		Timestamp: time.Now().UTC(),
		Actor: audit.Actor{
			User: "system",
		},
		Target: audit.Target{
			Kind:      "BreakglassSession",
			Name:      session.Name,
			Namespace: session.Namespace,
			Cluster:   session.Spec.Cluster,
		},
		RequestContext: &audit.RequestContext{
			SessionName:    session.Name,
			EscalationName: session.Spec.GrantedGroup,
		},
		Details: map[string]interface{}{
			"message":            "Scheduled session activated",
			"cluster":            session.Spec.Cluster,
			"grantedGroup":       session.Spec.GrantedGroup,
			"state":              string(session.Status.State),
			"scheduledStartTime": session.Spec.ScheduledStartTime,
			"actualStartTime":    session.Status.ActualStartTime,
		},
	})
}

// sendSessionActivatedEmail sends a notification when a scheduled session becomes active
func (ssa *ScheduledSessionActivator) sendSessionActivatedEmail(session breakglassv1alpha1.BreakglassSession) {
	if ssa.disableEmail || ssa.mailService == nil || !ssa.mailService.IsEnabled() {
		return
	}

	params := mail.SessionActivatedMailParams{
		SubjectEmail:   session.Spec.User,
		RequestedRole:  session.Spec.GrantedGroup,
		Cluster:        session.Spec.Cluster,
		Username:       session.Spec.User,
		SessionID:      session.Name,
		ActivatedAt:    session.Status.ActualStartTime.Time.Format("2006-01-02 15:04:05 UTC"),
		ExpirationTime: session.Status.ExpiresAt.Time.Format("2006-01-02 15:04:05 UTC"),
		ApproverEmail:  session.Status.Approver,
		IDPName:        session.Spec.IdentityProviderName,
		IDPIssuer:      session.Spec.IdentityProviderIssuer,
		BrandingName:   ssa.brandingName,
	}

	body, err := mail.RenderSessionActivated(params)
	if err != nil {
		ssa.log.Errorw("failed to render session activated email",
			"session", session.Name,
			"namespace", session.Namespace,
			"error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Session Activated: %s", ssa.brandingName, session.Name)
	if err := ssa.mailService.Enqueue(session.Name, []string{session.Spec.User}, subject, body); err != nil {
		ssa.log.Errorw("failed to enqueue session activated email",
			"session", session.Name,
			"namespace", session.Namespace,
			"error", err)
	}
}
