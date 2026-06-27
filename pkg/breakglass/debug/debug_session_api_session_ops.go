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
)

func (c *DebugSessionAPIController) handleJoinDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	var req JoinDebugSessionRequest
	if err := decodeDebugJSONStrict(ctx.Request.Body, &req); err != nil {
		// Allow an empty body — default to viewer role.
		// Reject malformed JSON with 400 to surface client bugs.
		if !errors.Is(err, jsonutil.ErrEmptyBody) {
			apiresponses.RespondBadRequest(ctx, "invalid request body: "+err.Error())
			return
		}
		req.Role = string(breakglassv1alpha1.ParticipantRoleViewer)
	}
	if req.Role == "" {
		req.Role = string(breakglassv1alpha1.ParticipantRoleViewer)
	}

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
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

	// Check if user already joined
	username, ok := currentUser.(string)
	if !ok {
		apiresponses.RespondInternalErrorSimple(ctx, "invalid user context type")
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

	// Determine role
	role := breakglassv1alpha1.ParticipantRoleViewer
	if req.Role == string(breakglassv1alpha1.ParticipantRoleParticipant) {
		apiresponses.RespondForbidden(ctx, "participant role requires owner assignment")
		return
	}
	if req.Role != string(breakglassv1alpha1.ParticipantRoleViewer) {
		apiresponses.RespondBadRequest(ctx, "invalid participant role")
		return
	}

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

	// Get current user for authorization check
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	username := currentUser.(string)

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

	// Check if user is owner or participant
	isOwnerOrParticipant := session.Spec.RequestedBy == username
	if !isOwnerOrParticipant {
		for _, p := range session.Status.Participants {
			if p.User == username {
				isOwnerOrParticipant = true
				break
			}
		}
	}
	if !isOwnerOrParticipant {
		apiresponses.RespondForbidden(ctx, "only session owner or participants can renew")
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

func isDebugSessionExpired(session *breakglassv1alpha1.DebugSession, now time.Time) bool {
	return session != nil && session.Status.ExpiresAt != nil && !session.Status.ExpiresAt.Time.After(now)
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

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
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
	if session.Spec.RequestedBy != currentUser.(string) {
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

	// Mark as terminated
	session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Terminated by %s", currentUser)

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to terminate session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to terminate session")
		return
	}

	// Emit audit event for session termination
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionTerminated, session, currentUser.(string), "Debug session terminated by user")

	reqLog.Infow("Debug session terminated", "session", name, "user", currentUser)
	metrics.DebugSessionsTerminated.WithLabelValues(session.Spec.Cluster, "user_terminated").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleApproveDebugSession approves a pending debug session
func (c *DebugSessionAPIController) handleApproveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
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

	// Check if user is authorized to approve (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	if !c.isUserAuthorizedToApprove(apiCtx, session, currentUser.(string), userGroups) {
		apiresponses.RespondForbidden(ctx, "user is not authorized to approve this session")
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
	session.Status.Approval.ApprovedBy = currentUser.(string)
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
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionStarted, session, currentUser.(string), "Debug session approved")

	reqLog.Infow("Debug session approved", "session", name, "approver", currentUser)
	metrics.DebugSessionApproved.WithLabelValues(session.Spec.Cluster, "user").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleRejectDebugSession rejects a pending debug session
func (c *DebugSessionAPIController) handleRejectDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
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

	// Check if user is authorized to reject (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	if !c.isUserAuthorizedToApprove(apiCtx, session, currentUser.(string), userGroups) {
		apiresponses.RespondForbidden(ctx, "user is not authorized to reject this session")
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
	session.Status.Approval.RejectedBy = currentUser.(string)
	session.Status.Approval.RejectedAt = &now
	session.Status.Approval.Reason = sanitizedReason

	// Move to terminated state
	session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Rejected by %s: %s", currentUser, sanitizedReason)

	if err := breakglass.ApplyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to reject session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to reject session")
		return
	}

	// Send rejection email to requester
	c.sendDebugSessionRejectionEmail(apiCtx, session)

	// Emit audit event for session rejection
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionTerminated, session, currentUser.(string), fmt.Sprintf("Debug session rejected: %s", req.Reason))

	reqLog.Infow("Debug session rejected", "session", name, "rejector", currentUser, "reason", req.Reason)
	metrics.DebugSessionRejected.WithLabelValues(session.Spec.Cluster, "user_rejected").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleLeaveDebugSession allows a participant to leave a session
func (c *DebugSessionAPIController) handleLeaveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
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

	// Find the participant
	username := currentUser.(string)
	found := false
	now := metav1.Now()
	for i := range session.Status.Participants {
		if session.Status.Participants[i].User == username {
			// Check if owner - owners cannot leave
			if session.Status.Participants[i].Role == breakglassv1alpha1.ParticipantRoleOwner {
				apiresponses.RespondForbidden(ctx, "session owner cannot leave; use terminate instead")
				return
			}
			// Mark as left
			session.Status.Participants[i].LeftAt = &now
			found = true
			break
		}
	}

	if !found {
		apiresponses.RespondNotFoundSimple(ctx, "user is not a participant in this session")
		return
	}

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
