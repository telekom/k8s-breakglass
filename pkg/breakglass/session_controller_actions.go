package breakglass

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// handleWithdrawMyRequest allows the session requester to withdraw their own pending request
func (wc *BreakglassSessionController) handleWithdrawMyRequest(c *gin.Context) {
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)

	sessionName := c.Param("name")
	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		reqLog.Error("error while getting breakglass session", zap.Error(err))
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(c, "session not found")
		} else {
			apiresponses.RespondInternalError(c, "get session", err, reqLog)
		}
		return
	}

	// Only allow the original requester to withdraw
	requesterEmail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.Error("error getting user identity email", zap.Error(err))
		apiresponses.RespondInternalError(c, "extract email from token", err, reqLog)
		return
	}
	if bs.Spec.User != requesterEmail {
		// User is authenticated but not the session owner - return 403 Forbidden
		apiresponses.RespondForbidden(c, "only the session requester can withdraw")
		return
	}

	// Only allow withdrawal if session is still pending
	if !IsSessionPendingApproval(bs) {
		apiresponses.RespondBadRequest(c, "Session is not pending and cannot be withdrawn")
		return
	}

	// Set status to Withdrawn
	// IMPORTANT: Do NOT clear existing timestamps (ApprovedAt, ExpiresAt, etc.)
	// We want to preserve history. Only set state and withdrawal-specific timestamp.
	bs.Status.WithdrawnAt = metav1.Now() // Record when withdrawn
	bs.Status.State = breakglassv1alpha1.SessionStateWithdrawn
	// short reason for UI
	bs.Status.ReasonEnded = "withdrawn"
	// clear approver info for withdrawn sessions
	bs.Status.Approver = ""
	bs.Status.Approvers = nil

	// Set RetainedUntil for withdrawn sessions
	retainFor := ParseRetainFor(bs.Spec, reqLog)
	bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))

	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(breakglassv1alpha1.SessionConditionTypeCanceled),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
		Message:            "Session withdrawn by requester",
	})

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		reqLog.Error("error while updating breakglass session", zap.Error(err))
		if apierrors.IsConflict(err) {
			apiresponses.RespondConflict(c, "session update conflict, please retry")
		} else if apierrors.IsInvalid(err) {
			apiresponses.RespondUnprocessableEntity(c, err.Error())
		} else {
			apiresponses.RespondInternalError(c, "update session status", err, reqLog)
		}
		return
	}

	// Emit audit event for session withdrawal by requester
	wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionWithdrawn, &bs, requesterEmail, "Session withdrawn by requester")

	c.JSON(http.StatusOK, bs)
}

// handleDropMySession allows the session requester (owner) to drop their own session.
// This differs from withdraw: drop permits removing either pending or approved sessions by owner.
func (wc *BreakglassSessionController) handleDropMySession(c *gin.Context) {
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)

	sessionName := c.Param("name")
	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		reqLog.Error("error while getting breakglass session", zap.Error(err))
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(c, "session not found")
		} else {
			apiresponses.RespondInternalError(c, "get session", err, reqLog)
		}
		return
	}

	// Only allow the original requester to drop
	requesterEmail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.Error("error getting user identity email", zap.Error(err))
		apiresponses.RespondInternalError(c, "extract email from token", err, reqLog)
		return
	}
	if bs.Spec.User != requesterEmail {
		// User is authenticated but not the session owner - return 403 Forbidden
		apiresponses.RespondForbidden(c, "only the session requester can drop")
		return
	}

	// If approved -> mark as Expired and set RetainedUntil appropriately (owner requested termination)
	if bs.Status.State == breakglassv1alpha1.SessionStateApproved && !bs.Status.ApprovedAt.IsZero() {
		// Approved session dropped - transition to Expired
		// IMPORTANT: Do NOT clear existing timestamps. We want to preserve history.
		bs.Status.ExpiresAt = metav1.NewTime(time.Now())
		bs.Status.State = breakglassv1alpha1.SessionStateExpired
		bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
			Message:            "Session dropped by owner",
		})
		bs.Status.ReasonEnded = "dropped"

		// Set RetainedUntil for expired sessions
		retainFor := ParseRetainFor(bs.Spec, reqLog)
		bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))
	} else {
		// Pending or other state -> behave like withdraw
		// IMPORTANT: Do NOT clear existing timestamps. We want to preserve history.
		bs.Status.WithdrawnAt = metav1.Now() // Record when withdrawn
		bs.Status.State = breakglassv1alpha1.SessionStateWithdrawn
		bs.Status.Approver = ""
		bs.Status.Approvers = nil

		// Set RetainedUntil for withdrawn sessions
		retainFor := ParseRetainFor(bs.Spec, reqLog)
		bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))

		bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
			Type:               string(breakglassv1alpha1.SessionConditionTypeCanceled),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
			Message:            "Session dropped by owner",
		})
		bs.Status.ReasonEnded = "withdrawn"
	}

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		reqLog.Error("error while updating breakglass session", zap.Error(err))
		if apierrors.IsConflict(err) {
			apiresponses.RespondConflict(c, "session update conflict, please retry")
		} else if apierrors.IsInvalid(err) {
			apiresponses.RespondUnprocessableEntity(c, err.Error())
		} else {
			apiresponses.RespondInternalError(c, "update session status", err, reqLog)
		}
		return
	}

	// Emit audit event for session dropped by owner
	wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionDropped, &bs, requesterEmail, "Session dropped by owner")

	c.JSON(http.StatusOK, bs)
}

// handleApproverCancel allows an approver to cancel/terminate a running (approved) session.
// This endpoint is intended for approvers to immediately end an active session (set to Expired).
func (wc *BreakglassSessionController) handleApproverCancel(c *gin.Context) {
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)

	sessionName := c.Param("name")
	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		reqLog.Error("error while getting breakglass session", zap.Error(err))
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(c, "session not found")
		} else {
			apiresponses.RespondInternalError(c, "get session", err, reqLog)
		}
		return
	}

	// Only approvers can cancel via this endpoint
	if !wc.isSessionApprover(c, bs) {
		// User is authenticated but not an approver - return 403 Forbidden
		apiresponses.RespondForbidden(c, "only approvers can cancel sessions")
		return
	}

	// Only allow cancellation of active/approved sessions
	if bs.Status.State != breakglassv1alpha1.SessionStateApproved || bs.Status.ApprovedAt.IsZero() {
		apiresponses.RespondBadRequest(c, "Session is not active/approved and cannot be canceled by approver")
		return
	}

	// Transition to expired immediately
	// IMPORTANT: Do NOT clear existing timestamps. We want to preserve history.
	bs.Status.ExpiresAt = metav1.NewTime(time.Now())
	bs.Status.State = breakglassv1alpha1.SessionStateExpired

	// Set RetainedUntil for expired sessions
	retainFor := ParseRetainFor(bs.Spec, reqLog)
	bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))

	// record approver who canceled
	approverEmail, _ := wc.identityProvider.GetEmail(c)
	if approverEmail != "" {
		bs.Status.Approver = approverEmail
		// append if not present
		bs.Status.Approvers = addIfNotPresent(bs.Status.Approvers, approverEmail)
	}

	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(breakglassv1alpha1.SessionConditionTypeExpired),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
		Message:            "Session canceled by approver",
	})
	bs.Status.ReasonEnded = "canceled"

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		reqLog.Error("error while updating breakglass session", zap.Error(err))
		if apierrors.IsConflict(err) {
			apiresponses.RespondConflict(c, "session update conflict, please retry")
		} else if apierrors.IsInvalid(err) {
			apiresponses.RespondUnprocessableEntity(c, err.Error())
		} else {
			apiresponses.RespondInternalError(c, "update session status", err, reqLog)
		}
		return
	}

	// Emit audit event for session revocation by approver
	wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionRevoked, &bs, approverEmail, "Session canceled by approver")

	c.JSON(http.StatusOK, bs)
}

// formatDuration converts a time.Duration to a human-readable string (e.g., "2 hours", "30 minutes")
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0"
	}

	// Handle days
	if d >= 24*time.Hour {
		days := d / (24 * time.Hour)
		remainder := d % (24 * time.Hour)
		if remainder == 0 {
			if days == 1 {
				return "1 day"
			}
			return fmt.Sprintf("%d days", days)
		}
		hours := remainder / time.Hour
		if hours == 0 {
			if days == 1 {
				return "1 day"
			}
			return fmt.Sprintf("%d days", days)
		}
		if days == 1 {
			if hours == 1 {
				return "1 day 1 hour"
			}
			return fmt.Sprintf("1 day %d hours", hours)
		}
		if hours == 1 {
			return fmt.Sprintf("%d days 1 hour", days)
		}
		return fmt.Sprintf("%d days %d hours", days, hours)
	}

	// Handle hours
	if d >= time.Hour {
		hours := d / time.Hour
		remainder := d % time.Hour
		if remainder == 0 {
			if hours == 1 {
				return "1 hour"
			}
			return fmt.Sprintf("%d hours", hours)
		}
		mins := remainder / time.Minute
		if mins == 0 {
			if hours == 1 {
				return "1 hour"
			}
			return fmt.Sprintf("%d hours", hours)
		}
		if hours == 1 {
			if mins == 1 {
				return "1 hour 1 minute"
			}
			return fmt.Sprintf("1 hour %d minutes", mins)
		}
		if mins == 1 {
			return fmt.Sprintf("%d hours 1 minute", hours)
		}
		return fmt.Sprintf("%d hours %d minutes", hours, mins)
	}

	// Handle minutes
	if d >= time.Minute {
		mins := d / time.Minute
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}

	// Handle seconds (rarely used but for completeness)
	secs := d / time.Second
	if secs == 1 {
		return "1 second"
	}
	return fmt.Sprintf("%d seconds", secs)
}

func (wc *BreakglassSessionController) sendOnRequestEmail(bs breakglassv1alpha1.BreakglassSession,
	requestEmail,
	requestUsername string,
	approvers []string,
	approverGroupsToShow []string, // The specific approver group(s) to display in this email
	matchedEscalation *breakglassv1alpha1.BreakglassEscalation,
) error {
	// Guard: validate approvers list
	if len(approvers) == 0 {
		wc.log.Errorw("Cannot send breakglass request email: approvers list is empty",
			"session", bs.Name,
			"cluster", bs.Spec.Cluster,
			"group", bs.Spec.GrantedGroup,
			"requestUsername", requestUsername,
			"requestEmail", requestEmail)
		return fmt.Errorf("cannot send email: no approvers available")
	}

	subject := fmt.Sprintf("Cluster %q user %q is requesting breakglass group assignment %q", bs.Spec.Cluster, bs.Spec.User, bs.Spec.GrantedGroup)

	wc.log.Debugw("Rendering breakglass session request email",
		"session", bs.Name,
		"subject", subject,
		"approverId", len(approvers),
		"approvers", approvers,
		"requestEmail", requestEmail,
		"requestUsername", requestUsername)

	// Calculate scheduling information and duration for email
	scheduledStartTimeStr := ""
	calculatedExpiresAtStr := ""
	formattedDurationStr := ""
	requestedAtStr := time.Now().Format("2006-01-02 15:04:05 MST")

	if bs.Spec.ScheduledStartTime != nil {
		scheduledStartTimeStr = bs.Spec.ScheduledStartTime.Format("2006-01-02 15:04:05 MST")

		// Calculate expiry time from scheduled start time using spec.MaxValidFor
		expiryTime := bs.Spec.ScheduledStartTime.Time
		if bs.Spec.MaxValidFor != "" {
			if d, err := breakglassv1alpha1.ParseDuration(bs.Spec.MaxValidFor); err == nil && d > 0 {
				expiryTime = bs.Spec.ScheduledStartTime.Add(d)
				formattedDurationStr = formatDuration(d)
			}
		} else {
			// Default to 1 hour if not specified
			expiryTime = bs.Spec.ScheduledStartTime.Add(1 * time.Hour)
			formattedDurationStr = "1 hour"
		}
		calculatedExpiresAtStr = expiryTime.Format("2006-01-02 15:04:05 MST")
	} else {
		// Immediate session: calculate duration from MaxValidFor
		if bs.Spec.MaxValidFor != "" {
			if d, err := breakglassv1alpha1.ParseDuration(bs.Spec.MaxValidFor); err == nil && d > 0 {
				formattedDurationStr = formatDuration(d)
				calculatedExpiresAtStr = time.Now().Add(d).Format("2006-01-02 15:04:05 MST")
			}
		} else {
			// Default to 1 hour
			formattedDurationStr = "1 hour"
			calculatedExpiresAtStr = time.Now().Add(1 * time.Hour).Format("2006-01-02 15:04:05 MST")
		}
	}

	// Use the provided approver groups to display
	// These are specific to this email (e.g., just "group-a" for members of group-a)
	wc.log.Debugw("Using provided approver groups for email",
		"approverGroupsToShow", approverGroupsToShow,
		"session", bs.Name)

	// Build TimeRemaining string for UI/UX
	timeRemaining := ""
	var expiryTime time.Time
	if bs.Spec.ScheduledStartTime != nil {
		expiryTime = bs.Spec.ScheduledStartTime.Time
		if bs.Spec.MaxValidFor != "" {
			if d, err := breakglassv1alpha1.ParseDuration(bs.Spec.MaxValidFor); err == nil && d > 0 {
				expiryTime = bs.Spec.ScheduledStartTime.Add(d)
			}
		} else {
			expiryTime = bs.Spec.ScheduledStartTime.Add(1 * time.Hour)
		}
	} else {
		// Immediate session
		expiryTime = time.Now()
		if bs.Spec.MaxValidFor != "" {
			if d, err := breakglassv1alpha1.ParseDuration(bs.Spec.MaxValidFor); err == nil && d > 0 {
				expiryTime = time.Now().Add(d)
			}
		} else {
			expiryTime = time.Now().Add(1 * time.Hour)
		}
	}
	remainingDuration := time.Until(expiryTime)
	if remainingDuration > 0 {
		timeRemaining = formatDuration(remainingDuration)
	}

	// Build RequestedApprovalGroups string
	requestedApprovalGroupsStr := ""
	if matchedEscalation != nil && len(matchedEscalation.Spec.Approvers.Groups) > 0 {
		groupNames := matchedEscalation.Spec.Approvers.Groups
		if len(groupNames) == 1 {
			requestedApprovalGroupsStr = groupNames[0]
		} else {
			requestedApprovalGroupsStr = strings.Join(groupNames, " OR ")
		}
	}

	body, err := mail.RenderBreakglassSessionRequest(mail.RequestBreakglassSessionMailParams{
		SubjectEmail:            requestEmail,
		SubjectFullName:         requestUsername,
		RequestingUsername:      requestUsername,
		RequestedCluster:        bs.Spec.Cluster,
		RequestedUsername:       bs.Spec.User,
		RequestedGroup:          bs.Spec.GrantedGroup,
		RequestReason:           bs.Spec.RequestReason,
		ScheduledStartTime:      scheduledStartTimeStr,
		CalculatedExpiresAt:     calculatedExpiresAtStr,
		FormattedDuration:       formattedDurationStr,
		RequestedAt:             requestedAtStr,
		ApproverGroups:          approverGroupsToShow,
		RequestedApprovalGroups: requestedApprovalGroupsStr,
		TimeRemaining:           timeRemaining,
		URL:                     fmt.Sprintf("%s/session/%s/approve", wc.config.Frontend.BaseURL, bs.Name),
		BrandingName: func() string {
			if wc.config.Frontend.BrandingName != "" {
				return wc.config.Frontend.BrandingName
			}
			return "Breakglass"
		}(),
	})
	if err != nil {
		wc.log.Errorw("failed to render email template",
			"session", bs.Name,
			"error", err,
			"recipients", len(approvers),
			"subject", subject)
		return err
	}

	wc.log.Debugw("Email template rendered successfully",
		"session", bs.Name,
		"bodyLength", len(body),
		"recipientCount", len(approvers),
		"recipients", approvers,
		"subject", subject)

	// Use mail service (preferred) or mail queue for non-blocking async sending
	sessionID := fmt.Sprintf("session-%s", bs.Name)
	if wc.mailService != nil && wc.mailService.IsEnabled() {
		if err := wc.mailService.Enqueue(sessionID, approvers, subject, body); err != nil {
			wc.log.Warnw("Failed to enqueue session request email via mail service",
				"session", bs.Name,
				"recipientCount", len(approvers),
				"recipients", approvers,
				"subject", subject,
				"error", err)
			return err
		}
		wc.log.Infow("Breakglass session request email queued",
			"session", bs.Name,
			"recipientCount", len(approvers),
			"recipients", approvers,
			"subject", subject)
		return nil
	}

	// Fallback to legacy mailQueue
	if wc.mailQueue != nil {
		if err := wc.mailQueue.Enqueue(sessionID, approvers, subject, body); err != nil {
			wc.log.Warnw("Failed to enqueue session request email (will not retry)",
				"session", bs.Name,
				"recipientCount", len(approvers),
				"recipients", approvers,
				"subject", subject,
				"error", err)
			// Don't fall back to synchronous send - if queue is configured but failing,
			// synchronous send would likely fail too. Just log and continue.
			return err
		}
		wc.log.Infow("Breakglass session request email queued",
			"session", bs.Name,
			"recipientCount", len(approvers),
			"recipients", approvers,
			"subject", subject)
		return nil
	}

	// Fallback to synchronous send if mail sender is configured (for legacy/test compatibility)
	// Note: In production, mailService should be used via WithMailService() which sets wc.mailService
	// This fallback is primarily for tests that set wc.mail directly to a FakeMailSender
	if wc.mail != nil {
		if err := wc.mail.Send(approvers, subject, body); err != nil {
			wc.log.Errorw("failed to send request email",
				"session", bs.Name,
				"recipientCount", len(approvers),
				"recipients", approvers,
				"subject", subject,
				"error", err)
			return err
		}
		wc.log.Infow("Breakglass session request email sent",
			"session", bs.Name,
			"recipientCount", len(approvers),
			"recipients", approvers,
			"subject", subject)
		return nil
	}

	// No mail service, queue, or sender configured - email notifications are disabled
	wc.log.Warnw("No mail provider configured - email notification skipped",
		"session", bs.Name,
		"recipientCount", len(approvers),
		"recipients", approvers,
		"subject", subject)
	return nil
}

// sendOnRequestEmailsByGroup sends separate emails for each approver group, where each email shows
// only the specific group that matched. This allows approvers to understand which group they're
// being notified on behalf of.
func (wc *BreakglassSessionController) sendOnRequestEmailsByGroup(
	log *zap.SugaredLogger,
	bs breakglassv1alpha1.BreakglassSession,
	requestEmail, requestUsername string,
	filteredApprovers []string,
	approversByGroup map[string][]string, // map[groupName][]approverEmails
	matchedEscalation *breakglassv1alpha1.BreakglassEscalation,
) {
	if matchedEscalation == nil {
		log.Warnw("Cannot send emails by group: matched escalation is nil", "session", bs.Name)
		return
	}

	log.Debugw("Sending emails per approver group",
		"session", bs.Name,
		"totalApprovers", len(filteredApprovers),
		"groupCount", len(approversByGroup))

	// Build a map of approver email -> groups they belong to (across ALL groups)
	// This ensures we send one email per approver, showing all their groups
	approverToGroups := make(map[string][]string)

	// For each configured approver group, collect which groups each approver belongs to
	for _, groupName := range matchedEscalation.Spec.Approvers.Groups {
		groupMembers := approversByGroup[groupName]

		// Filter the group members to only include those in filteredApprovers
		for _, member := range groupMembers {
			for _, filtered := range filteredApprovers {
				if member == filtered {
					// Record this approver -> group mapping
					approverToGroups[member] = append(approverToGroups[member], groupName)
					break
				}
			}
		}
	}

	// Send one email to each approver, showing all groups they belong to
	for approver, groups := range approverToGroups {
		log.Debugw("Sending email for approver",
			"session", bs.Name,
			"approver", approver,
			"groupCount", len(groups),
			"groups", groups)

		// Send email with ALL groups this approver belongs to
		if err := wc.sendOnRequestEmail(bs, requestEmail, requestUsername, []string{approver}, groups, matchedEscalation); err != nil {
			log.Warnw("Failed to send email for approver",
				"session", bs.Name,
				"approver", approver,
				"groupCount", len(groups),
				"groups", groups,
				"error", err)
			// Continue with other approvers even if one fails
		}
	}

	// Also send emails to explicit users (those not in any group)
	explicitUsers := approversByGroup["_explicit_users"]
	if len(explicitUsers) > 0 {
		// Filter explicit users to only include those in filteredApprovers
		var approversForExplicit []string
		for _, user := range explicitUsers {
			for _, filtered := range filteredApprovers {
				if user == filtered {
					approversForExplicit = append(approversForExplicit, user)
					break
				}
			}
		}

		if len(approversForExplicit) > 0 {
			log.Debugw("Sending email for explicit users",
				"session", bs.Name,
				"recipientCount", len(approversForExplicit))

			// Send email with no specific group (since these are explicit users)
			if err := wc.sendOnRequestEmail(bs, requestEmail, requestUsername, approversForExplicit, []string{}, matchedEscalation); err != nil {
				log.Warnw("Failed to send email for explicit users",
					"session", bs.Name,
					"recipientCount", len(approversForExplicit),
					"error", err)
			}
		}
	}
}

// filterExcludedNotificationRecipients filters out users/groups that are in the escalation's NotificationExclusions
func (wc *BreakglassSessionController) filterExcludedNotificationRecipients(
	log *zap.SugaredLogger,
	approvers []string,
	escalation *breakglassv1alpha1.BreakglassEscalation,
) []string {
	log.Debugw("filterExcludedNotificationRecipients called",
		"approverCount", len(approvers),
		"approvers", approvers,
		"escalationNil", escalation == nil,
		"hasNotificationExclusions", escalation != nil && escalation.Spec.NotificationExclusions != nil)

	if escalation == nil || escalation.Spec.NotificationExclusions == nil {
		log.Debugw("No notification exclusions configured",
			"escalationNil", escalation == nil)
		return approvers
	}

	exclusions := escalation.Spec.NotificationExclusions
	log.Infow("Notification exclusions configured",
		"excludedUserCount", len(exclusions.Users),
		"excludedUsers", exclusions.Users,
		"excludedGroupCount", len(exclusions.Groups),
		"excludedGroups", exclusions.Groups)

	// Build set of excluded users for O(1) lookup
	excludedUsers := make(map[string]bool)
	for _, user := range exclusions.Users {
		excludedUsers[user] = true
	}
	log.Debugw("Built excluded users set",
		"directExcludedUserCount", len(excludedUsers),
		"directExcludedUsers", exclusions.Users)

	// Get members of excluded groups
	excludedGroupMembers := make(map[string]bool)
	if len(exclusions.Groups) > 0 && wc.escalationManager != nil && wc.escalationManager.GetResolver() != nil {
		// Use a timeout context to prevent hanging on slow group resolution
		ctx, cancel := context.WithTimeout(context.Background(), APIContextTimeout)
		defer cancel()
		resolvedGroupsCount := 0
		totalMembersCount := 0

		for _, group := range exclusions.Groups {
			log.Debugw("Attempting to resolve excluded group members",
				"group", group)
			members, err := wc.escalationManager.GetResolver().Members(ctx, group)
			if err != nil {
				log.Warnw("Failed to resolve members of excluded group",
					"group", group,
					"error", err,
					"errorType", fmt.Sprintf("%T", err))
				continue
			}
			log.Infow("Successfully resolved excluded group members",
				"group", group,
				"memberCount", len(members),
				"members", members)
			resolvedGroupsCount++
			totalMembersCount += len(members)
			for _, member := range members {
				excludedGroupMembers[member] = true
			}
		}

		excludedGroupMembersList := make([]string, 0, len(excludedGroupMembers))
		for m := range excludedGroupMembers {
			excludedGroupMembersList = append(excludedGroupMembersList, m)
		}
		log.Infow("Excluded group resolution summary",
			"resolvedGroupCount", resolvedGroupsCount,
			"totalGroupMemberCount", totalMembersCount,
			"uniqueExcludedGroupMembers", len(excludedGroupMembers),
			"excludedGroupMemberList", excludedGroupMembersList)
	} else {
		resolverNil := wc.escalationManager != nil && wc.escalationManager.GetResolver() == nil
		log.Debugw("Cannot resolve excluded group members",
			"groupCount", len(exclusions.Groups),
			"escalationManagerNil", wc.escalationManager == nil,
			"resolverNil", resolverNil)
	}

	// Filter approvers
	filtered := []string{}
	excludedApprovers := []string{}
	for _, approver := range approvers {
		isExcluded := excludedUsers[approver] || excludedGroupMembers[approver]
		if isExcluded {
			excludedApprovers = append(excludedApprovers, approver)
		} else {
			filtered = append(filtered, approver)
		}
	}

	log.Infow("Filtering results",
		"originalApproverCount", len(approvers),
		"originalApprovers", approvers,
		"visibleApproverCount", len(filtered),
		"visibleApprovers", filtered,
		"excludedApproverCount", len(excludedApprovers),
		"excludedApproversFiltered", excludedApprovers,
		"totalDirectExcluded", len(excludedUsers),
		"totalGroupMembersExcluded", len(excludedGroupMembers))

	return filtered
}

// filterHiddenFromUIRecipients filters out users/groups that are marked as hidden from UI in the escalation.
// Hidden groups are used as fallback approvers but are not displayed in the UI or sent notifications.
func (wc *BreakglassSessionController) filterHiddenFromUIRecipients(
	log *zap.SugaredLogger,
	approvers []string,
	escalation *breakglassv1alpha1.BreakglassEscalation,
) []string {
	hiddenFromUICount := 0
	if escalation != nil {
		hiddenFromUICount = len(escalation.Spec.Approvers.HiddenFromUI)
	}
	log.Debugw("filterHiddenFromUIRecipients called",
		"approverCount", len(approvers),
		"approvers", approvers,
		"escalationNil", escalation == nil,
		"hiddenFromUICount", hiddenFromUICount)

	if escalation == nil || len(escalation.Spec.Approvers.HiddenFromUI) == 0 {
		log.Debugw("No hidden approvers configured, returning all approvers",
			"escalationNil", escalation == nil,
			"hiddenCount", hiddenFromUICount)
		return approvers
	}

	log.Infow("Hidden approvers configured",
		"hiddenItems", escalation.Spec.Approvers.HiddenFromUI,
		"hiddenItemCount", len(escalation.Spec.Approvers.HiddenFromUI))

	// Build set of hidden users for O(1) lookup
	hiddenUsers := make(map[string]bool)
	for _, user := range escalation.Spec.Approvers.HiddenFromUI {
		hiddenUsers[user] = true
	}
	log.Debugw("Built hidden users set",
		"directHiddenUserCount", len(hiddenUsers),
		"directHiddenUsers", escalation.Spec.Approvers.HiddenFromUI)

	// Get members of hidden groups
	hiddenGroupMembers := make(map[string]bool)
	if wc.escalationManager != nil && wc.escalationManager.GetResolver() != nil {
		// Use a timeout context to prevent hanging on slow group resolution
		ctx, cancel := context.WithTimeout(context.Background(), APIContextTimeout)
		defer cancel()
		resolvedGroupsCount := 0
		totalMembersCount := 0

		for _, group := range escalation.Spec.Approvers.HiddenFromUI {
			log.Debugw("Attempting to resolve hidden item as group",
				"item", group)
			members, err := wc.escalationManager.GetResolver().Members(ctx, group)
			if err != nil {
				// This might be a user, not a group - just continue
				log.Debugw("Failed to resolve members of hidden item (treating as individual user)",
					"item", group,
					"error", err,
					"errorType", fmt.Sprintf("%T", err))
				continue
			}
			log.Infow("Successfully resolved hidden group members",
				"group", group,
				"memberCount", len(members),
				"members", members)
			resolvedGroupsCount++
			totalMembersCount += len(members)
			for _, member := range members {
				hiddenGroupMembers[member] = true
			}
		}

		log.Infow("Hidden group resolution summary",
			"resolvedGroupCount", resolvedGroupsCount,
			"totalGroupMemberCount", totalMembersCount,
			"uniqueHiddenGroupMembers", len(hiddenGroupMembers),
			"hiddenGroupMemberList", func() []string {
				members := make([]string, 0, len(hiddenGroupMembers))
				for m := range hiddenGroupMembers {
					members = append(members, m)
				}
				return members
			}())
	} else {
		log.Warnw("Cannot resolve hidden group members - resolver not available",
			"escalationManagerNil", wc.escalationManager == nil,
			"resolverNil", wc.escalationManager != nil && wc.escalationManager.GetResolver() == nil)
	}

	// Filter approvers - only include those not in hidden lists
	filtered := []string{}
	hiddenApprovers := []string{}
	for _, approver := range approvers {
		isHidden := hiddenUsers[approver] || hiddenGroupMembers[approver]
		if isHidden {
			hiddenApprovers = append(hiddenApprovers, approver)
		} else {
			filtered = append(filtered, approver)
		}
	}

	log.Infow("Filtering results",
		"originalApproverCount", len(approvers),
		"originalApprovers", approvers,
		"visibleApproverCount", len(filtered),
		"visibleApprovers", filtered,
		"hiddenApproverCount", len(hiddenApprovers),
		"hiddenApproversFiltered", hiddenApprovers,
		"totalDirectHidden", len(hiddenUsers),
		"totalGroupMembersHidden", len(hiddenGroupMembers))

	return filtered
}
