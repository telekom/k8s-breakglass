package breakglass

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (wc *BreakglassSessionController) setSessionStatus(c *gin.Context, sesCondition breakglassv1alpha1.BreakglassSessionConditionType) {
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

	// Attempt to decode optional approver reason from the request body (for approve/reject)
	var approverPayload struct {
		Reason string `json:"reason,omitempty"`
	}
	// Ignore errors; payload is optional. Guard against nil Request.Body which can occur in tests/clients.
	if c.Request != nil && c.Request.Body != nil {
		if err := decodeJSONStrict(c.Request.Body, &approverPayload); err != nil {
			if !errors.Is(err, io.EOF) {
				reqLog.Debugw("Failed to decode optional approver payload (using empty values)", "error", err)
			}
		}
	}
	// Sanitize approver reason to prevent injection attacks
	if approverPayload.Reason != "" {
		sanitized, err := SanitizeReasonText(approverPayload.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize approver reason, using empty string", "error", err)
			approverPayload.Reason = "" // Use empty string as safe fallback
		} else {
			approverPayload.Reason = sanitized
		}
	}

	var lastCondition metav1.Condition
	if l := len(bs.Status.Conditions); l > 0 {
		lastCondition = bs.Status.Conditions[l-1]
	}

	// If the session already has the same last condition, return conflict to avoid repeated transitions.
	if lastCondition.Type == string(sesCondition) {
		c.JSON(http.StatusConflict, struct {
			Error   string                               `json:"error"`
			Code    string                               `json:"code"`
			Session breakglassv1alpha1.BreakglassSession `json:"session"`
		}{
			Error:   "session already in requested state",
			Code:    "CONFLICT",
			Session: bs,
		})
		return
	}

	// Different actions have different preconditions:
	// - Approve and Reject must only be executed when the session is pending.
	// - Other actions should be blocked only when the session is already in a true terminal state
	//   (Rejected, Withdrawn, Expired, Timeout). Approved is intentionally not part of that list
	//   because approved sessions may later transition to expired/dropped by owner or canceled by approver.
	currState := bs.Status.State
	if sesCondition == breakglassv1alpha1.SessionConditionTypeApproved || sesCondition == breakglassv1alpha1.SessionConditionTypeRejected {
		if currState != breakglassv1alpha1.SessionStatePending {
			c.JSON(http.StatusBadRequest, struct {
				Error   string                               `json:"error"`
				Code    string                               `json:"code"`
				Session breakglassv1alpha1.BreakglassSession `json:"session"`
			}{
				Error:   fmt.Sprintf("session must be pending to perform %s; current state: %s", sesCondition, currState),
				Code:    "BAD_REQUEST",
				Session: bs,
			})
			return
		}
	} else {
		if currState == breakglassv1alpha1.SessionStateRejected || currState == breakglassv1alpha1.SessionStateWithdrawn || currState == breakglassv1alpha1.SessionStateExpired || currState == breakglassv1alpha1.SessionStateTimeout || currState == breakglassv1alpha1.SessionStateIdleExpired {
			c.JSON(http.StatusBadRequest, struct {
				Error   string                               `json:"error"`
				Code    string                               `json:"code"`
				Session breakglassv1alpha1.BreakglassSession `json:"session"`
			}{
				Error:   fmt.Sprintf("session is in terminal state %s and cannot be modified", currState),
				Code:    "BAD_REQUEST",
				Session: bs,
			})
			return
		}
	}

	// Authorization: determine whether the caller is allowed to perform the action.
	// Allow the session requester to reject their own pending session. For reject actions only,
	// if the caller is the original requester and the session is still pending, bypass the approver check.
	allowOwnerReject := false
	if sesCondition == breakglassv1alpha1.SessionConditionTypeRejected {
		if requesterEmail, err := wc.identityProvider.GetEmail(c); err == nil {
			if requesterEmail == bs.Spec.User && IsSessionPendingApproval(bs) {
				allowOwnerReject = true
			}
		}
	}

	if !allowOwnerReject {
		authResult := wc.checkApprovalAuthorization(c, bs)
		if !authResult.Allowed {
			// Use appropriate HTTP status code based on denial reason:
			// - 401 for authentication failures (can't identify user)
			// - 403 for authorization failures (user identified but not allowed)
			switch authResult.Reason {
			case ApprovalDenialUnauthenticated:
				apiresponses.RespondUnauthorizedWithMessage(c, authResult.Message)
			case ApprovalDenialSelfApprovalBlocked:
				apiresponses.RespondForbidden(c, authResult.Message)
			case ApprovalDenialDomainNotAllowed:
				apiresponses.RespondForbidden(c, authResult.Message)
			case ApprovalDenialNotAnApprover:
				apiresponses.RespondForbidden(c, authResult.Message)
			case ApprovalDenialNoMatchingEscalation:
				apiresponses.RespondForbidden(c, authResult.Message)
			default:
				// Fallback for unknown reasons
				apiresponses.RespondForbidden(c, "Access denied")
			}
			return
		}
	}

	switch sesCondition {
	case breakglassv1alpha1.SessionConditionTypeApproved:
		// Clear any previous rejection timestamp so the approved state is canonical.
		bs.Status.RejectedAt = metav1.Time{}
		bs.Status.ApprovedAt = metav1.Now()

		// Determine expiry based on session spec MaxValidFor if provided, otherwise use default
		validFor := ParseMaxValidFor(bs.Spec, reqLog)

		// Determine retention based on session spec RetainFor if provided, otherwise use default
		retainFor := ParseRetainFor(bs.Spec, reqLog)

		bs.Status.TimeoutAt = metav1.Time{} // Clear approval timeout

		// Check if session has a scheduled start time
		if bs.Spec.ScheduledStartTime != nil && !bs.Spec.ScheduledStartTime.IsZero() {
			// Scheduled session: enter WaitingForScheduledTime state
			// RBAC group will NOT be applied until activation time is reached
			bs.Status.State = breakglassv1alpha1.SessionStateWaitingForScheduledTime
			// Calculate expiry and retention from ScheduledStartTime, not from now
			bs.Status.ExpiresAt = metav1.NewTime(bs.Spec.ScheduledStartTime.Add(validFor))
			bs.Status.RetainedUntil = metav1.NewTime(bs.Spec.ScheduledStartTime.Add(validFor).Add(retainFor))
			// ActualStartTime will be set during activation
			bs.Status.ActualStartTime = metav1.Time{}
			reqLog.Infow("Session approved with scheduled start time",
				"session", bs.Name,
				"scheduledStartTime", bs.Spec.ScheduledStartTime.Time,
				"expiresAt", bs.Status.ExpiresAt.Time,
			)
		} else {
			// Immediate session: activate now (original behavior)
			bs.Status.State = breakglassv1alpha1.SessionStateApproved
			bs.Status.ActualStartTime = metav1.Now() // For consistency
			// Calculate expiry and retention from now
			bs.Status.ExpiresAt = metav1.NewTime(bs.Status.ApprovedAt.Add(validFor))
			bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))
			// RBAC group is immediately applied (via webhook or controller)
			reqLog.Infow("Session approved and activated immediately",
				"session", bs.Name,
				"expiresAt", bs.Status.ExpiresAt.Time,
			)
		}
		// record approver
		approverEmail, _ := wc.identityProvider.GetEmail(c)
		if approverEmail != "" {
			bs.Status.Approver = approverEmail
			// append to approvers history if not already present
			bs.Status.Approvers = addIfNotPresent(bs.Status.Approvers, approverEmail)
		}
		// store approver reason if provided
		if strings.TrimSpace(approverPayload.Reason) != "" {
			bs.Status.ApprovalReason = approverPayload.Reason
		}
	case breakglassv1alpha1.SessionConditionTypeRejected:
		// IMPORTANT: Do NOT clear existing timestamps. We want to preserve history.
		// Only set state and rejection-specific timestamp.
		bs.Status.RejectedAt = metav1.Now()
		bs.Status.State = breakglassv1alpha1.SessionStateRejected
		bs.Status.ReasonEnded = "rejected"

		// Set RetainedUntil for rejected sessions
		retainFor := ParseRetainFor(bs.Spec, reqLog)
		bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))

		// record approver (rejector)
		rejectorEmail, _ := wc.identityProvider.GetEmail(c)
		if rejectorEmail != "" {
			bs.Status.Approver = rejectorEmail
			bs.Status.Approvers = addIfNotPresent(bs.Status.Approvers, rejectorEmail)
		}
		// store approver reason if provided
		if strings.TrimSpace(approverPayload.Reason) != "" {
			bs.Status.ApprovalReason = approverPayload.Reason
		}
	case breakglassv1alpha1.SessionConditionTypeIdle:
		reqLog.Error("error setting session status to idle which should be only initial state")
		apiresponses.RespondBadRequest(c, "cannot set session status to idle (initial state only)")
		return
	default:
		reqLog.Error("unknown session condition type", zap.String("type", string(sesCondition)))
		apiresponses.RespondBadRequest(c, fmt.Sprintf("unknown session condition type: %s", sesCondition))
		return
	}

	username, _ := wc.identityProvider.GetEmail(c)
	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(sesCondition),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
		Message:            fmt.Sprintf("User %q set session to %s", username, sesCondition),
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

	// Get approver identity for audit events
	approver := wc.identityProvider.GetUsername(c)
	if approver == "" {
		if email, err := wc.identityProvider.GetEmail(c); err == nil {
			approver = email
		}
	}

	// Track metrics for session lifecycle events
	switch sesCondition {
	case breakglassv1alpha1.SessionConditionTypeApproved:
		metrics.SessionApproved.WithLabelValues(bs.Spec.Cluster).Inc()
		// Track if session was approved with specific IDP
		if bs.Spec.IdentityProviderName != "" {
			metrics.SessionApprovedWithIDP.WithLabelValues(bs.Spec.IdentityProviderName).Inc()
		}
		// Also track if it was a scheduled session that got approved
		if bs.Spec.ScheduledStartTime != nil && !bs.Spec.ScheduledStartTime.IsZero() {
			metrics.SessionScheduled.WithLabelValues(bs.Spec.Cluster).Inc()
		}

		// Emit audit event for session approval
		wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionApproved, &bs, approver, "Session approved")

		// Send approval notification email to requester
		if !wc.disableEmail && bs.Spec.User != "" && (wc.mailService != nil && wc.mailService.IsEnabled() || wc.mailQueue != nil) {
			wc.sendSessionApprovalEmail(reqLog, bs)
		}
	case breakglassv1alpha1.SessionConditionTypeRejected:
		metrics.SessionRejected.WithLabelValues(bs.Spec.Cluster).Inc()
		// Emit audit event for session rejection
		wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionRejected, &bs, approver, "Session rejected")

		// Send rejection notification email to requester
		if !wc.disableEmail && bs.Spec.User != "" && (wc.mailService != nil && wc.mailService.IsEnabled() || wc.mailQueue != nil) {
			wc.sendSessionRejectionEmail(reqLog, bs)
		}
	}

	c.JSON(http.StatusOK, bs)
}

func (wc *BreakglassSessionController) getActiveBreakglassSession(ctx context.Context,
	username,
	clustername,
	group string,
) (breakglassv1alpha1.BreakglassSession, error) {
	selector := fields.SelectorFromSet(
		fields.Set{
			"spec.cluster":      clustername,
			"spec.user":         username,
			"spec.grantedGroup": group,
		},
	)
	wc.log.Debugw("Querying for active breakglass session", "user", username, "cluster", clustername, "group", group)
	sessions, err := wc.sessionManager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		wc.log.Error("Failed to list sessions for getActiveBreakglassSession", zap.Error(err))
		return breakglassv1alpha1.BreakglassSession{}, fmt.Errorf("failed to list sessions: %w", err)
	}

	validSessions := make([]breakglassv1alpha1.BreakglassSession, 0, len(sessions))
	for _, ses := range sessions {
		if !IsSessionActive(ses) {
			continue
		}
		wc.log.Debugw("Found active session candidate", "session", ses.Name)
		validSessions = append(validSessions, ses)
	}

	if len(validSessions) == 0 {
		wc.log.Infow("No active breakglass session found", "user", username, "cluster", clustername, "group", group)
		return breakglassv1alpha1.BreakglassSession{}, ErrSessionNotFound
	} else if len(validSessions) > 1 {
		wc.log.Error("There is more than a single active breakglass session; this should not happen",
			zap.Int("num_sessions", len(validSessions)),
			zap.String("user_data", fmt.Sprintf("%#v", ClusterUserGroup{
				Clustername: clustername,
				Username:    username,
				GroupName:   group,
			})))
	}
	wc.log.Infow("Returning active breakglass session", "session", validSessions[0].Name)
	return validSessions[0], nil
}

// checkSessionLimits verifies that creating a new session won't exceed session limits.
// Limits are resolved in order of precedence:
// 1. Escalation override (sessionLimitsOverride.unlimited = true disables limits)
// 2. Escalation override (sessionLimitsOverride.maxActiveSessionsPerUser and/or maxActiveSessionsTotal)
// 3. IDP group override (sessionLimits.groupOverrides[].unlimited or maxActiveSessionsPerUser)
// 4. IDP default (sessionLimits.maxActiveSessionsPerUser)
//
// Note: maxActiveSessionsTotal is only available at escalation level, not IDP level.
// Per-user limits are checked globally across all escalations; total limits are per-escalation.
// Returns nil if the session can be created, or an error describing the limit violation.
func (wc *BreakglassSessionController) checkSessionLimits(
	ctx context.Context,
	escalation *breakglassv1alpha1.BreakglassEscalation,
	idpName string,
	userIdentifier string,
	userGroups []string,
	log *zap.SugaredLogger,
) error {
	// 1. Check escalation-level override first
	if escalation.Spec.SessionLimitsOverride != nil {
		override := escalation.Spec.SessionLimitsOverride
		if override.Unlimited {
			log.Debugw("Session limits disabled via escalation override (unlimited)",
				"escalation", escalation.Name)
			return nil
		}
		// Check per-user limit from escalation override
		if override.MaxActiveSessionsPerUser != nil {
			limit := *override.MaxActiveSessionsPerUser
			log.Debugw("Using escalation-level per-user session limit override",
				"escalation", escalation.Name,
				"maxPerUser", limit)
			if err := wc.checkUserSessionCount(ctx, userIdentifier, limit, "escalation override", log); err != nil {
				return err
			}
		}
		// Check total limit from escalation override
		if override.MaxActiveSessionsTotal != nil {
			limit := *override.MaxActiveSessionsTotal
			log.Debugw("Using escalation-level total session limit override",
				"escalation", escalation.Name,
				"maxTotal", limit)
			if err := wc.checkTotalSessionCount(ctx, escalation, limit, "escalation override", log); err != nil {
				return err
			}
		}
		// Only return early if escalation has per-user override (which replaces IDP per-user limits).
		// If only MaxActiveSessionsTotal is set, fall through to check IDP per-user limits,
		// since total and per-user limits are orthogonal concerns.
		if override.MaxActiveSessionsPerUser != nil {
			return nil
		}
	}

	// 2. Look up IDP limits if idpName is set
	if idpName == "" {
		log.Debugw("No IDP name set, skipping IDP-level session limits")
		return nil
	}

	idp := &breakglassv1alpha1.IdentityProvider{}
	if err := wc.sessionManager.Client.Get(ctx, client.ObjectKey{Name: idpName}, idp); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warnw("IdentityProvider not found — session limits cannot be enforced; verify the IDP resource exists",
				"idp", idpName)
			return nil
		}
		return fmt.Errorf("failed to get IdentityProvider: %w", err)
	}

	// No session limits configured on IDP
	if idp.Spec.SessionLimits == nil {
		log.Debugw("No session limits configured on IDP", "idp", idpName)
		return nil
	}

	// 3. Check IDP group overrides (first matching group wins)
	// Uses glob pattern matching (e.g., "platform-*" matches "platform-team")
GroupOverrideLoop:
	for _, groupOverride := range idp.Spec.SessionLimits.GroupOverrides {
		for _, userGroup := range userGroups {
			// Use glob pattern matching for flexible group specifications
			matched, err := utils.GlobMatch(groupOverride.Group, userGroup)
			if err != nil {
				// Invalid glob pattern - log warning and skip this override
				log.Warnw("Invalid glob pattern in IDP group override, skipping",
					"idp", idpName,
					"pattern", groupOverride.Group,
					"error", err)
				continue GroupOverrideLoop
			}
			if matched {
				log.Debugw("Matched IDP group override",
					"idp", idpName,
					"pattern", groupOverride.Group,
					"matchedGroup", userGroup,
					"unlimited", groupOverride.Unlimited)
				if groupOverride.Unlimited {
					return nil
				}
				if groupOverride.MaxActiveSessionsPerUser != nil {
					return wc.checkUserSessionCount(ctx, userIdentifier, *groupOverride.MaxActiveSessionsPerUser, fmt.Sprintf("IDP group override (%s)", groupOverride.Group), log)
				}
				// Group matched but no specific limit set, fall through to IDP default
				// Use labeled break to exit BOTH loops (first matching group wins)
				break GroupOverrideLoop
			}
		}
	}

	// 4. Apply IDP default limit
	if idp.Spec.SessionLimits.MaxActiveSessionsPerUser != nil {
		return wc.checkUserSessionCount(ctx, userIdentifier, *idp.Spec.SessionLimits.MaxActiveSessionsPerUser, "IDP default", log)
	}

	log.Debugw("No session limit applicable", "idp", idpName, "escalation", escalation.Name)
	return nil
}

// checkUserSessionCount counts active sessions for a user and checks against a limit.
// Uses the spec.user field index for efficient lookup when available.
func (wc *BreakglassSessionController) checkUserSessionCount(
	ctx context.Context,
	userIdentifier string,
	limit int32,
	source string,
	log *zap.SugaredLogger,
) error {
	// Use indexed query to fetch only sessions for this user
	sessionList, err := wc.sessionManager.GetUserBreakglassSessions(ctx, userIdentifier)
	if err != nil {
		return fmt.Errorf("failed to list sessions for user: %w", err)
	}

	// Count active sessions for this user (across ALL escalations)
	var userActive int32
	for i := range sessionList {
		session := &sessionList[i]
		if !IsSessionActive(*session) {
			continue
		}
		userActive++
	}

	log.Debugw("Session count for user",
		"user", userIdentifier,
		"activeCount", userActive,
		"limit", limit,
		"source", source)

	if userActive >= limit {
		return fmt.Errorf("session limit reached: maximum %d active sessions per user allowed (%s)", limit, source)
	}

	return nil
}

// checkTotalSessionCount counts total active sessions for an escalation and checks against a limit.
// Sessions are counted by matching owner reference to ensure sessions created by different
// escalations that grant the same group are not incorrectly counted together.
// Optimized: only lists sessions in states that can be active (Pending, Approved) instead of all sessions.
func (wc *BreakglassSessionController) checkTotalSessionCount(
	ctx context.Context,
	escalation *breakglassv1alpha1.BreakglassEscalation,
	limit int32,
	source string,
	log *zap.SugaredLogger,
) error {
	// Optimization: only list sessions in potentially active states (Pending and Approved)
	// rather than listing all sessions and filtering out terminal states.
	// This reduces data transfer from etcd significantly in clusters with many expired sessions.
	pendingSessions, err := wc.sessionManager.GetSessionsByState(ctx, breakglassv1alpha1.SessionStatePending)
	if err != nil {
		return fmt.Errorf("failed to list pending sessions: %w", err)
	}
	approvedSessions, err := wc.sessionManager.GetSessionsByState(ctx, breakglassv1alpha1.SessionStateApproved)
	if err != nil {
		return fmt.Errorf("failed to list approved sessions: %w", err)
	}

	// Count active sessions for this specific escalation (by matching owner reference UID)
	// This ensures sessions from different escalations that grant the same group are counted separately.
	var totalActive int32
	for i := range pendingSessions {
		session := &pendingSessions[i]
		if !isOwnedByEscalation(session, escalation) {
			continue
		}
		if !IsSessionActive(*session) {
			continue
		}
		totalActive++
	}
	for i := range approvedSessions {
		session := &approvedSessions[i]
		if !isOwnedByEscalation(session, escalation) {
			continue
		}
		if !IsSessionActive(*session) {
			continue
		}
		totalActive++
	}

	log.Debugw("Total session count for escalation",
		"escalation", escalation.Name,
		"escalationUID", escalation.UID,
		"activeCount", totalActive,
		"limit", limit,
		"source", source)

	if totalActive >= limit {
		return fmt.Errorf("session limit reached: maximum %d total active sessions allowed (%s)", limit, source)
	}

	return nil
}

func (wc *BreakglassSessionController) handleApproveBreakglassSession(c *gin.Context) {
	wc.setSessionStatus(c, breakglassv1alpha1.SessionConditionTypeApproved)
}

func (wc *BreakglassSessionController) handleRejectBreakglassSession(c *gin.Context) {
	wc.setSessionStatus(c, breakglassv1alpha1.SessionConditionTypeRejected)
}

// handleGetBreakglassSessionStatus handles GET /status for breakglass session
func (wc *BreakglassSessionController) handleGetBreakglassSessionStatus(c *gin.Context) {
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)
	reqLog.Debug("Handling GET /status for breakglass session")
	// Use background context with timeout instead of request context to prevent
	// "context canceled" errors when client closes connection during rapid refreshes.
	// The Kubernetes API List operation needs to complete even if the HTTP client
	// disconnects, otherwise users see errors on rapid tab switches in the UI.
	// We use a timeout to prevent indefinite hangs. Timeout is configurable via APIContextTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), APIContextTimeout)
	defer cancel()

	// Support server-side filtering when cluster/user/group query params are provided
	// to avoid fetching all sessions when unnecessary.
	clusterQ := c.Query("cluster")
	userQ := c.Query("user")
	groupQ := c.Query("group")
	// Support token-based validation (frontend uses ?token=<name>) to validate an approval link
	if token := c.Query("token"); token != "" {
		// Try to load session by metadata.name (token is treated as session name)
		ses, err := wc.sessionManager.GetBreakglassSessionByName(ctx, token)
		if err != nil {
			reqLog.Debugw("Token validation: session not found", "token", token, "error", err)
			c.JSON(http.StatusNotFound, struct {
				Valid bool `json:"valid"`
			}{Valid: false})
			return
		}
		canApprove := wc.isSessionApprover(c, ses)
		alreadyActive := IsSessionActive(ses)
		valid := true
		if IsSessionExpired(ses) || ses.Status.State == breakglassv1alpha1.SessionStateWithdrawn || ses.Status.State == breakglassv1alpha1.SessionStateRejected {
			valid = false
		}
		c.JSON(http.StatusOK, gin.H{"canApprove": canApprove, "alreadyActive": alreadyActive, "valid": valid})
		return
	}

	var sessions []breakglassv1alpha1.BreakglassSession
	var err error
	if clusterQ != "" || userQ != "" || groupQ != "" {
		// Build field selector from provided params
		fs := fields.Set{}
		if clusterQ != "" {
			fs["spec.cluster"] = clusterQ
		}
		if userQ != "" {
			fs["spec.user"] = userQ
		}
		if groupQ != "" {
			fs["spec.grantedGroup"] = groupQ
		}
		selector := fields.SelectorFromSet(fs)
		reqLog.Debugw("Using field selector for sessions query", "selector", selector.String())
		sessions, err = wc.sessionManager.GetBreakglassSessionsWithSelector(ctx, selector)
	} else {
		sessions, err = wc.sessionManager.GetAllBreakglassSessions(ctx)
	}
	if err != nil {
		reqLog.Error("Error getting breakglass sessions", zap.Error(err))
		apiresponses.RespondInternalError(c, "list sessions", err, reqLog)
		return
	}

	// Ownership filters
	includeMine := ParseBoolQuery(c.Query("mine"), false)
	includeApprover := ParseBoolQuery(c.Query("approver"), true)
	includeApprovedByMe := ParseBoolQuery(c.Query("approvedByMe"), false)
	activeOnly := ParseBoolQuery(c.Query("activeOnly"), false)
	stateFilters := normalizeStateFilters(c)
	statePredicates := buildStateFilterPredicates(stateFilters)

	var userEmail string
	if includeMine || includeApprovedByMe {
		userEmail, err = wc.identityProvider.GetEmail(c)
		if err != nil {
			reqLog.Error("Error getting user identity email", zap.Error(err))
			apiresponses.RespondInternalError(c, "extract email from token", err, reqLog)
			return
		}
	}

	authIdentifiers := []string{}
	if includeMine {
		authIdentifiers = collectAuthIdentifiers(userEmail, wc.identityProvider.GetUsername(c), wc.identityProvider.GetIdentity(c))
		if len(authIdentifiers) == 0 {
			reqLog.Error("No authenticated identity claims found for session ownership filtering")
			apiresponses.RespondUnauthorizedWithMessage(c, "user identity not found")
			return
		}
	}

	filtered := make([]breakglassv1alpha1.BreakglassSession, 0, len(sessions))
	for _, ses := range sessions {
		isMine := matchesAuthIdentifier(ses.Spec.User, authIdentifiers)
		var isApprover bool
		if includeApprover {
			isApprover = wc.isSessionApprover(c, ses)
		}
		hasApproved := false
		if includeApprovedByMe {
			hasApproved = userHasApprovedSession(ses, userEmail)
		}

		include := false
		if includeMine && isMine {
			include = true
		}
		if includeApprover && isApprover {
			include = true
		}
		if includeApprovedByMe && hasApproved {
			include = true
		}
		if !includeMine && !includeApprover && !includeApprovedByMe {
			include = isMine || isApprover || hasApproved
		}
		if !include {
			continue
		}

		if len(statePredicates) > 0 {
			matched := false
			for _, predicate := range statePredicates {
				if predicate(ses) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		if activeOnly && !IsSessionActive(ses) {
			continue
		}

		filtered = append(filtered, ses)
	}

	// Enrich sessions with approvalReason from matching escalations
	enriched := wc.enrichSessionsWithApprovalReason(ctx, filtered, reqLog)

	reqLog.Infow("Returning filtered breakglass sessions", "count", len(enriched))
	c.JSON(http.StatusOK, enriched)
}

// SessionApprovalMeta contains authorization metadata for a session
type SessionApprovalMeta struct {
	CanApprove   bool   `json:"canApprove"`
	CanReject    bool   `json:"canReject"`
	IsRequester  bool   `json:"isRequester"`
	IsApprover   bool   `json:"isApprover"`
	DenialReason string `json:"denialReason,omitempty"`
	SessionState string `json:"sessionState"`
	StateMessage string `json:"stateMessage,omitempty"`
}

// EnrichedSessionResponse wraps a session with additional metadata from the escalation config
type EnrichedSessionResponse struct {
	breakglassv1alpha1.BreakglassSession
	// ApprovalReason contains the escalation's approval reason configuration (if any)
	// Now sourced from session.Spec.ApprovalReasonConfig (snapshot at creation time)
	ApprovalReason *ReasonConfigInfo `json:"approvalReason,omitempty"`
}

// enrichSessionsWithApprovalReason adds the approvalReason config from the session's stored snapshot.
// Sessions now store reason configs at creation time, so no escalation lookup is needed.
func (wc *BreakglassSessionController) enrichSessionsWithApprovalReason(_ context.Context, sessions []breakglassv1alpha1.BreakglassSession, _ *zap.SugaredLogger) []EnrichedSessionResponse {
	result := make([]EnrichedSessionResponse, 0, len(sessions))

	for i := range sessions {
		ses := sessions[i]
		dropK8sInternalFieldsSession(&ses)

		enriched := EnrichedSessionResponse{
			BreakglassSession: ses,
		}

		// Use the session's stored approval reason config (snapshot from escalation at creation time)
		if ses.Spec.ApprovalReasonConfig != nil {
			enriched.ApprovalReason = &ReasonConfigInfo{
				Mandatory:   ses.Spec.ApprovalReasonConfig.Mandatory,
				Description: ses.Spec.ApprovalReasonConfig.Description,
			}
		}

		result = append(result, enriched)
	}

	return result
}

// getSessionApprovalMeta determines the user's authorization status for a session
func (wc *BreakglassSessionController) getSessionApprovalMeta(c *gin.Context, session breakglassv1alpha1.BreakglassSession) SessionApprovalMeta {
	reqLog := system.GetReqLogger(c, wc.log)
	meta := SessionApprovalMeta{
		SessionState: string(session.Status.State),
	}

	// Get user email
	email, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.Warnw("Failed to get user email for approval meta", "error", err)
		meta.DenialReason = "Unable to verify your identity"
		return meta
	}

	// Check if user is the requester
	meta.IsRequester = email == session.Spec.User

	// Check session state first
	switch session.Status.State {
	case breakglassv1alpha1.SessionStateApproved:
		meta.StateMessage = "This session has already been approved"
		if session.Status.Approver != "" {
			meta.StateMessage += " by " + session.Status.Approver
		}
		return meta
	case breakglassv1alpha1.SessionStateRejected:
		meta.StateMessage = "This session has already been rejected"
		if session.Status.Approver != "" {
			meta.StateMessage += " by " + session.Status.Approver
		}
		return meta
	case breakglassv1alpha1.SessionStateWithdrawn:
		meta.StateMessage = "This session has been withdrawn by the requester"
		return meta
	case breakglassv1alpha1.SessionStateExpired:
		meta.StateMessage = "This session has expired"
		return meta
	case breakglassv1alpha1.SessionStateTimeout:
		meta.StateMessage = "This session has timed out waiting for approval"
		return meta
	case breakglassv1alpha1.SessionStateIdleExpired:
		meta.StateMessage = "This session was expired due to inactivity"
		return meta
	}

	// Session is pending - check if user can approve
	if session.Status.State != breakglassv1alpha1.SessionStatePending {
		meta.DenialReason = fmt.Sprintf("Session is in unexpected state: %s", session.Status.State)
		return meta
	}

	// Check if user is an approver (use detailed authorization check for specific denial reasons)
	authResult := wc.checkApprovalAuthorization(c, session)
	meta.IsApprover = authResult.Allowed

	if meta.IsApprover {
		meta.CanApprove = true
		meta.CanReject = true
		reqLog.Debugw("User is authorized to approve/reject session",
			"session", session.Name, "user", email, "isRequester", meta.IsRequester)
	} else {
		// Use the specific denial reason from the authorization check
		meta.DenialReason = authResult.Message
		reqLog.Debugw("User is not authorized to approve session",
			"session", session.Name, "user", email, "reason", authResult.Reason, "message", authResult.Message)
	}

	// Requester can always reject their own pending session (withdraw equivalent)
	if meta.IsRequester && session.Status.State == breakglassv1alpha1.SessionStatePending {
		meta.CanReject = true
	}

	return meta
}

// handleGetBreakglassSessionByName handles GET /breakglassSessions/:name and returns a single session
// It includes authorization metadata to help the frontend display appropriate UI/errors
func (wc *BreakglassSessionController) handleGetBreakglassSessionByName(c *gin.Context) {
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)

	sessionName := c.Param("name")
	reqLog.Infow("Handling GET /breakglassSessions/:name", "session", sessionName)

	ses, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		reqLog.Warnw("Session not found", "session", sessionName, "error", err)
		c.JSON(http.StatusNotFound, struct {
			Error   string `json:"error"`
			Code    string `json:"code"`
			Session string `json:"session"`
		}{
			Error:   "session not found",
			Code:    "NOT_FOUND",
			Session: sessionName,
		})
		return
	}

	// Get authorization metadata
	approvalMeta := wc.getSessionApprovalMeta(c, ses)
	reqLog.Infow("Session retrieved with approval metadata",
		"session", sessionName,
		"state", ses.Status.State,
		"canApprove", approvalMeta.CanApprove,
		"isApprover", approvalMeta.IsApprover,
		"isRequester", approvalMeta.IsRequester,
		"denialReason", approvalMeta.DenialReason)

	// Return a single session object with metadata
	dropK8sInternalFieldsSession(&ses)
	c.JSON(http.StatusOK, gin.H{
		"session":      ses,
		"approvalMeta": approvalMeta,
	})
}
