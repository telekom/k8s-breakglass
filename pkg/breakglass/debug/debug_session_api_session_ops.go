package debug

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
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
	if err := ctx.ShouldBindJSON(&req); err != nil {
		// Allow empty body (EOF) — default to viewer role.
		// Reject malformed JSON with 400 to surface client bugs.
		if !errors.Is(err, io.EOF) {
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

	// Check if user already joined
	username := currentUser.(string)
	for _, p := range session.Status.Participants {
		if p.User == username {
			apiresponses.RespondConflict(ctx, "user already joined this session")
			return
		}
	}

	// Check max participants if configured
	if session.Status.ResolvedTemplate != nil &&
		session.Status.ResolvedTemplate.TerminalSharing != nil &&
		session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants > 0 {
		if int32(len(session.Status.Participants)) >= session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants {
			apiresponses.RespondForbidden(ctx, "maximum participants reached")
			return
		}
	}

	// Determine role
	role := breakglassv1alpha1.ParticipantRoleViewer
	if req.Role == string(breakglassv1alpha1.ParticipantRoleParticipant) {
		role = breakglassv1alpha1.ParticipantRoleParticipant
	}

	// Get display name from context (set by auth middleware from "name" claim)
	displayName := ""
	if dn, exists := ctx.Get("displayName"); exists && dn != nil {
		if dnStr, ok := dn.(string); ok {
			displayName = dnStr
		}
	}

	// Get email from context (set by auth middleware from "email" claim)
	userEmail := ""
	if email, exists := ctx.Get("email"); exists && email != nil {
		if emailStr, ok := email.(string); ok {
			userEmail = emailStr
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
	if err := ctx.ShouldBindJSON(&req); err != nil {
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
			if err == nil && session.Status.StartsAt != nil {
				currentDuration := time.Since(session.Status.StartsAt.Time)
				if currentDuration+extendBy > maxDur {
					apiresponses.RespondForbidden(ctx, fmt.Sprintf("extension would exceed maximum duration of %s", constraints.MaxDuration))
					return
				}
			}
		}
	}

	// Extend the expiration
	if session.Status.ExpiresAt == nil {
		apiresponses.RespondBadRequest(ctx, "session has no expiration time")
		return
	}

	newExpiry := metav1.NewTime(session.Status.ExpiresAt.Add(extendBy))
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

	var req ApprovalRequest
	_ = ctx.ShouldBindJSON(&req) // Optional body

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

	// Mark as approved
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.ApprovedBy = currentUser.(string)
	session.Status.Approval.ApprovedAt = &now
	// Sanitize approval reason to prevent injection attacks
	if req.Reason != "" {
		sanitized, err := breakglass.SanitizeReasonText(req.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize approval reason, using empty string", "error", err)
			session.Status.Approval.Reason = "" // Use empty string as safe fallback
		} else {
			session.Status.Approval.Reason = sanitized
		}
	} else {
		session.Status.Approval.Reason = req.Reason
	}

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

	var req ApprovalRequest
	_ = ctx.ShouldBindJSON(&req) // Optional body with reason

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

	// Mark as rejected
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.RejectedBy = currentUser.(string)
	session.Status.Approval.RejectedAt = &now
	// Sanitize rejection reason to prevent injection attacks
	sanitizedReason := req.Reason
	if req.Reason != "" {
		var err error
		sanitizedReason, err = breakglass.SanitizeReasonText(req.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize rejection reason, using empty string", "error", err)
			sanitizedReason = "" // Use empty string as safe fallback
		}
	}
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
