package debug

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/jsonutil"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionAPIController) handleJoinDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	username, ok := requireDebugSessionUsername(ctx)
	if !ok {
		return
	}
	if rejectUnexpectedDebugActionBody(ctx) {
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check session is active
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("cannot join session in state '%s'", session.Status.State))
		return
	}
	if isDebugSessionExpired(session, time.Now()) {
		apiresponses.RespondBadRequest(ctx, "cannot join expired session")
		return
	}

	// Get email from context (set by auth middleware from "email" claim)
	userEmail := ""
	if email, exists := ctx.Get("email"); exists && email != nil {
		if emailStr, ok := email.(string); ok {
			userEmail = emailStr
		}
	}

	for _, p := range session.Status.Participants {
		if p.User == username {
			apiresponses.RespondConflict(ctx, "user already joined this session")
			return
		}
	}

	if !isTerminalSharingEnabledForJoin(session) {
		apiresponses.RespondForbidden(ctx, "terminal sharing is not enabled for this session")
		return
	}

	if !isInvitedDebugSessionParticipant(session, username, userEmail) {
		apiresponses.RespondForbidden(ctx, "user is not invited to join this debug session")
		return
	}

	// Check max participants if configured
	if session.Status.ResolvedTemplate != nil &&
		session.Status.ResolvedTemplate.TerminalSharing != nil &&
		session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants > 0 {
		maxParticipants := int(session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants)
		if len(session.Status.Participants) >= maxParticipants {
			apiresponses.RespondForbidden(ctx, "maximum participants reached")
			return
		}
	}

	role := breakglassv1alpha1.ParticipantRoleViewer

	// Get display name from context (set by auth middleware from "name" claim)
	displayName := ""
	if dn, exists := ctx.Get("displayName"); exists && dn != nil {
		if dnStr, ok := dn.(string); ok {
			displayName = dnStr
		}
	}

	// Add participant
	now := metav1.Now()
	session.Status.Participants = append(session.Status.Participants, breakglassv1alpha1.DebugSessionParticipant{
		User:        username,
		Email:       userEmail,
		DisplayName: displayName,
		Role:        role,
		JoinedAt:    now,
	})

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to add participant", "session", name, "user", username, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to join session")
		return
	}

	reqLog.Infow("User joined debug session", "session", name, "user", username, "role", role)
	metrics.DebugSessionParticipants.WithLabelValues(session.Spec.Cluster, name).Set(float64(len(session.Status.Participants)))

	ctx.JSON(http.StatusOK, gin.H{"message": "successfully joined session", "role": role})
}

// handleRenewDebugSession extends the session duration
func (c *DebugSessionAPIController) handleRenewDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	var req RenewDebugSessionRequest
	if err := decodeDebugJSONStrict(ctx.Request.Body, &req); err != nil {
		apiresponses.RespondBadRequest(ctx, "invalid request body: "+err.Error())
		return
	}
	if err := validateRenewDebugSessionRequest(req); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Parse extension duration (supports day units like "1d")
	extendBy, err := breakglassv1alpha1.ParseDuration(req.ExtendBy)
	if err != nil {
		apiresponses.RespondBadRequest(ctx, "invalid duration format")
		return
	}

	// Validate duration is positive
	if extendBy <= 0 {
		apiresponses.RespondBadRequest(ctx, "extension duration must be positive")
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	if !canRenewDebugSession(session, identity) {
		apiresponses.RespondForbidden(ctx, "only requester or active owner/participant roles can renew")
		return
	}

	// Check session is active
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("cannot renew session in state '%s'", session.Status.State))
		return
	}
	if isDebugSessionExpired(session, time.Now()) {
		apiresponses.RespondBadRequest(ctx, "cannot renew expired session")
		return
	}

	// Extend the expiration
	if session.Status.ExpiresAt == nil {
		apiresponses.RespondBadRequest(ctx, "session has no expiration time")
		return
	}
	newExpiry := metav1.NewTime(session.Status.ExpiresAt.Add(extendBy))

	// Check renewal constraints
	if session.Status.ResolvedTemplate != nil && session.Status.ResolvedTemplate.Constraints != nil {
		constraints := session.Status.ResolvedTemplate.Constraints

		// Check if renewals are allowed (defaults to true if not set)
		if constraints.AllowRenewal != nil && !*constraints.AllowRenewal {
			apiresponses.RespondForbidden(ctx, "session renewals are not allowed by template")
			return
		}

		// Check max renewals (nil means use default of 3, 0 means no renewals allowed)
		if constraints.MaxRenewals != nil {
			maxRenewals := *constraints.MaxRenewals
			if maxRenewals == 0 || session.Status.RenewalCount >= maxRenewals {
				apiresponses.RespondForbidden(ctx, fmt.Sprintf("maximum renewals (%d) reached", maxRenewals))
				return
			}
		} else {
			// Default max renewals is 3
			if session.Status.RenewalCount >= 3 {
				apiresponses.RespondForbidden(ctx, "maximum renewals (3) reached")
				return
			}
		}

		// Check total duration would not exceed max
		if constraints.MaxDuration != "" {
			maxDur, err := breakglassv1alpha1.ParseDuration(constraints.MaxDuration)
			if err == nil {
				if session.Status.StartsAt == nil {
					apiresponses.RespondBadRequest(ctx, "session has no start time")
					return
				}
				if newExpiry.Time.After(session.Status.StartsAt.Add(maxDur)) {
					apiresponses.RespondForbidden(ctx, fmt.Sprintf("extension would exceed maximum duration of %s", constraints.MaxDuration))
					return
				}
			}
		}
	}

	session.Status.ExpiresAt = &newExpiry
	session.Status.RenewalCount++

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to renew session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to renew session")
		return
	}

	reqLog.Infow("Debug session renewed",
		"session", name,
		"extendBy", extendBy,
		"newExpiry", newExpiry.Time,
		"renewalCount", session.Status.RenewalCount)

	ctx.JSON(http.StatusOK, gin.H{
		"message":      "session renewed successfully",
		"newExpiresAt": newExpiry.Time,
		"renewalCount": session.Status.RenewalCount,
	})
}

func canRenewDebugSession(session *breakglassv1alpha1.DebugSession, identity debugSessionReadIdentity) bool {
	if debugSessionIdentityMatches(identity, session.Spec.RequestedBy, session.Spec.RequestedByEmail) {
		return true
	}
	for _, participant := range session.Status.Participants {
		if participant.LeftAt != nil || !debugSessionIdentityMatches(identity, participant.User, participant.Email) {
			continue
		}
		if participant.Role == breakglassv1alpha1.ParticipantRoleOwner ||
			participant.Role == breakglassv1alpha1.ParticipantRoleParticipant {
			return true
		}
	}
	return false
}

func isDebugSessionExpired(session *breakglassv1alpha1.DebugSession, now time.Time) bool {
	return session != nil && session.Status.ExpiresAt != nil && !session.Status.ExpiresAt.Time.After(now)
}

func rejectUnexpectedDebugActionBody(ctx *gin.Context) bool {
	if err := jsonutil.RequireEmptyBody(ctx.Request.Body); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return true
	}
	return false
}

func isTerminalSharingEnabledForJoin(session *breakglassv1alpha1.DebugSession) bool {
	if session == nil {
		return false
	}
	if session.Status.TerminalSharing != nil {
		return session.Status.TerminalSharing.Enabled
	}
	return session.Status.ResolvedTemplate != nil &&
		session.Status.ResolvedTemplate.TerminalSharing != nil &&
		session.Status.ResolvedTemplate.TerminalSharing.Enabled
}

func isInvitedDebugSessionParticipant(session *breakglassv1alpha1.DebugSession, username, email string) bool {
	if session == nil {
		return false
	}
	for _, invited := range session.Spec.InvitedParticipants {
		if strings.EqualFold(invited, username) || (email != "" && strings.EqualFold(invited, email)) {
			return true
		}
	}
	return false
}

// handleTerminateDebugSession terminates a debug session early
func (c *DebugSessionAPIController) handleTerminateDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	username, ok := requireDebugSessionUsername(ctx)
	if !ok {
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check if user is allowed to terminate (owner or admin)
	// For now, only the owner can terminate
	if session.Spec.RequestedBy != username {
		apiresponses.RespondForbidden(ctx, "only the session owner can terminate")
		return
	}

	// Check session can be terminated
	if session.Status.State == breakglassv1alpha1.DebugSessionStateTerminated ||
		session.Status.State == breakglassv1alpha1.DebugSessionStateExpired ||
		session.Status.State == breakglassv1alpha1.DebugSessionStateFailed {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is already in terminal state '%s'", session.Status.State))
		return
	}
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("cannot terminate session in state '%s'", session.Status.State))
		return
	}
	if isDebugSessionExpired(session, time.Now()) {
		apiresponses.RespondBadRequest(ctx, "cannot terminate expired session")
		return
	}
	if rejectUnexpectedDebugActionBody(ctx) {
		return
	}

	// Mark as terminated
	session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Terminated by %s", username)

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to terminate session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to terminate session")
		return
	}

	// Emit audit event for session termination
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionTerminated, session, username, "Debug session terminated by user")

	reqLog.Infow("Debug session terminated", "session", name, "user", username)
	metrics.DebugSessionsTerminated.WithLabelValues(session.Spec.Cluster, "user_terminated").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleApproveDebugSession approves a pending debug session
func (c *DebugSessionAPIController) handleApproveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	username, ok := requireDebugSessionUsername(ctx)
	if !ok {
		return
	}

	var req ApprovalRequest
	if err := decodeDebugJSONStrict(ctx.Request.Body, &req); err != nil {
		if !errors.Is(err, jsonutil.ErrEmptyBody) {
			reqLog.Warnw("Failed to parse ApproveDebugSession request", "error", err)
			apiresponses.RespondBadRequest(ctx, "invalid request body: "+err.Error())
			return
		}
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check session is pending approval
	if session.Status.State != breakglassv1alpha1.DebugSessionStatePendingApproval {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not pending approval (state: %s)", session.Status.State))
		return
	}
	if debugSessionApprovalDecisionRecorded(session) {
		apiresponses.RespondConflict(ctx, "debug session approval has already been decided")
		return
	}

	// Check if user is authorized to approve (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	currentUserEmail := ""
	if email, exists := ctx.Get("email"); exists && email != nil {
		currentUserEmail, _ = email.(string)
	}
	if !c.isUserIdentityAuthorizedToApprove(apiCtx, session, username, currentUserEmail, userGroups) {
		apiresponses.RespondForbidden(ctx, "user is not authorized to approve this session")
		return
	}

	if timedOut, reason := debugSessionApprovalTimedOut(session, time.Now()); timedOut {
		if err := c.failTimedOutDebugSessionApproval(apiCtx, session, currentUser.(string), reason); err != nil {
			if apierrors.IsConflict(err) {
				apiresponses.RespondConflict(ctx, "debug session approval has already been decided")
				return
			}
			reqLog.Errorw("Failed to mark timed-out debug session approval", "session", name, "error", err)
			apiresponses.RespondInternalErrorSimple(ctx, "failed to update timed-out debug session")
			return
		}
		apiresponses.RespondConflict(ctx, reason)
		return
	}

	if req.Reason != "" {
		req.Reason = breakglass.SanitizeReasonText(req.Reason)
	}
	if err := validateDebugApprovalReason(req.Reason, session.Spec.ApprovalReasonConfig, false); err != nil {
		reqLog.Warnw("Debug session approval reason is invalid", "session", name, "error", err)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Mark as approved
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.ApprovedBy = username
	session.Status.Approval.ApprovedAt = &now
	session.Status.Approval.Reason = req.Reason

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to approve session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to approve session")
		return
	}

	// Send approval email to requester
	c.sendDebugSessionApprovalEmail(apiCtx, session)

	// Emit audit event for session approval
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionStarted, session, username, "Debug session approved")

	reqLog.Infow("Debug session approved", "session", name, "approver", username)
	metrics.DebugSessionApproved.WithLabelValues(session.Spec.Cluster, "user").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleRejectDebugSession rejects a pending debug session
func (c *DebugSessionAPIController) handleRejectDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	username, ok := requireDebugSessionUsername(ctx)
	if !ok {
		return
	}

	var req ApprovalRequest
	if err := decodeDebugJSONStrict(ctx.Request.Body, &req); err != nil {
		if !errors.Is(err, jsonutil.ErrEmptyBody) {
			reqLog.Warnw("Failed to parse RejectDebugSession request", "error", err)
			apiresponses.RespondBadRequest(ctx, "invalid request body: "+err.Error())
			return
		}
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check session is pending approval
	if session.Status.State != breakglassv1alpha1.DebugSessionStatePendingApproval {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not pending approval (state: %s)", session.Status.State))
		return
	}
	if debugSessionApprovalDecisionRecorded(session) {
		apiresponses.RespondConflict(ctx, "debug session approval has already been decided")
		return
	}

	// Check if user is authorized to reject (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	currentUserEmail := ""
	if email, exists := ctx.Get("email"); exists && email != nil {
		currentUserEmail, _ = email.(string)
	}
	if !c.isUserIdentityAuthorizedToApprove(apiCtx, session, username, currentUserEmail, userGroups) {
		apiresponses.RespondForbidden(ctx, "user is not authorized to reject this session")
		return
	}

	if timedOut, reason := debugSessionApprovalTimedOut(session, time.Now()); timedOut {
		if err := c.failTimedOutDebugSessionApproval(apiCtx, session, currentUser.(string), reason); err != nil {
			if apierrors.IsConflict(err) {
				apiresponses.RespondConflict(ctx, "debug session approval has already been decided")
				return
			}
			reqLog.Errorw("Failed to mark timed-out debug session rejection", "session", name, "error", err)
			apiresponses.RespondInternalErrorSimple(ctx, "failed to update timed-out debug session")
			return
		}
		apiresponses.RespondConflict(ctx, reason)
		return
	}

	sanitizedReason := req.Reason
	if req.Reason != "" {
		sanitizedReason = breakglass.SanitizeReasonText(req.Reason)
	}
	req.Reason = sanitizedReason
	if err := validateDebugApprovalReason(sanitizedReason, session.Spec.ApprovalReasonConfig, true); err != nil {
		reqLog.Warnw("Debug session rejection reason is invalid", "session", name, "error", err)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Mark as rejected
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.RejectedBy = username
	session.Status.Approval.RejectedAt = &now
	session.Status.Approval.Reason = sanitizedReason

	// Move to terminated state
	session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Rejected by %s: %s", username, sanitizedReason)

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to reject session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to reject session")
		return
	}

	// Send rejection email to requester
	c.sendDebugSessionRejectionEmail(apiCtx, session)

	// Emit audit event for session rejection
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionTerminated, session, username, fmt.Sprintf("Debug session rejected: %s", req.Reason))

	reqLog.Infow("Debug session rejected", "session", name, "rejector", username, "reason", req.Reason)
	metrics.DebugSessionRejected.WithLabelValues(session.Spec.Cluster, "user_rejected").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

func debugSessionApprovalTimedOut(session *breakglassv1alpha1.DebugSession, now time.Time) (bool, string) {
	if session.CreationTimestamp.IsZero() {
		return false, ""
	}
	if debugSessionApprovalDecisionRecorded(session) {
		return false, ""
	}

	timeout := breakglass.DebugSessionApprovalTimeout
	if !session.CreationTimestamp.Add(timeout).Before(now) {
		return false, ""
	}

	return true, fmt.Sprintf("Approval timed out after %s", timeout)
}

func debugSessionApprovalDecisionRecorded(session *breakglassv1alpha1.DebugSession) bool {
	return session.Status.Approval != nil &&
		(session.Status.Approval.ApprovedAt != nil || session.Status.Approval.RejectedAt != nil)
}

func debugSessionApprovalDecisionConflict(session *breakglassv1alpha1.DebugSession) error {
	return apierrors.NewConflict(schema.GroupResource{
		Group:    breakglassv1alpha1.GroupVersion.Group,
		Resource: "debugsessions",
	}, session.Name, errors.New("debug session approval has already been decided"))
}

func (c *DebugSessionAPIController) failTimedOutDebugSessionApproval(ctx context.Context, session *breakglassv1alpha1.DebugSession, actor, reason string) error {
	latest := &breakglassv1alpha1.DebugSession{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKeyFromObject(session), latest); err != nil {
		return fmt.Errorf("load latest debug session before approval timeout: %w", err)
	}

	if debugSessionApprovalDecisionRecorded(latest) {
		return debugSessionApprovalDecisionConflict(latest)
	}
	if timedOut, latestReason := debugSessionApprovalTimedOut(latest, time.Now()); !timedOut {
		return debugSessionApprovalDecisionConflict(latest)
	} else if reason == "" {
		reason = latestReason
	}

	latest.Status.State = breakglassv1alpha1.DebugSessionStateFailed
	latest.Status.Message = reason

	if err := c.client.Status().Update(ctx, latest); err != nil {
		if apierrors.IsConflict(err) {
			return err
		}
		return fmt.Errorf("mark debug session approval timed out: %w", err)
	}

	session.Status = latest.Status
	c.sendDebugSessionFailedEmail(ctx, latest, reason)
	if c.shouldEmitAudit(latest) {
		c.emitDebugSessionAuditEvent(ctx, audit.EventDebugSessionApprovalTimeout, latest, actor, reason)
	}
	metrics.DebugSessionsFailed.WithLabelValues(latest.Spec.Cluster, latest.Spec.TemplateRef).Inc()
	return nil
}

// handleLeaveDebugSession allows a participant to leave a session
func (c *DebugSessionAPIController) handleLeaveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	username, ok := requireDebugSessionUsername(ctx)
	if !ok {
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	if rejectUnexpectedDebugActionBody(ctx) {
		return
	}

	// Find the participant
	participantIndex := -1
	for i := range session.Status.Participants {
		if session.Status.Participants[i].User == username {
			participantIndex = i
			break
		}
	}

	if participantIndex == -1 {
		apiresponses.RespondNotFoundSimple(ctx, "user is not a participant in this session")
		return
	}
	if session.Status.Participants[participantIndex].Role == breakglassv1alpha1.ParticipantRoleOwner {
		apiresponses.RespondForbidden(ctx, "session owner cannot leave; use terminate instead")
		return
	}

	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("cannot leave session in state '%s'", session.Status.State))
		return
	}
	if isDebugSessionExpired(session, time.Now()) {
		apiresponses.RespondBadRequest(ctx, "cannot leave expired session")
		return
	}

	now := metav1.Now()
	session.Status.Participants[participantIndex].LeftAt = &now

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to leave session", "session", name, "user", username, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to leave session")
		return
	}

	reqLog.Infow("User left debug session", "session", name, "user", username)
	// Update active participant count (exclude those who left)
	activeCount := 0
	for _, p := range session.Status.Participants {
		if p.LeftAt == nil {
			activeCount++
		}
	}
	metrics.DebugSessionParticipants.WithLabelValues(session.Spec.Cluster, name).Set(float64(activeCount))

	ctx.JSON(http.StatusOK, gin.H{"message": "successfully left session"})
}

// DebugSessionTemplateResponse represents a template in API responses
