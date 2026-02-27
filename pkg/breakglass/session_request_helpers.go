package breakglass

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/naming"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// authenticatedIdentity holds the authenticated user's identity fields
// (email, username) resolved from the request JWT context.
type authenticatedIdentity struct {
	email    string
	emailErr error
	username string
}

// escalationResolutionResult holds the outputs of resolving escalations and approvers
// for a session creation request.
type escalationResolutionResult struct {
	matchedEscalation    *breakglassv1alpha1.BreakglassEscalation
	possibleGroups       []string
	allApprovers         []string
	approversByGroup     map[string][]string
	selectedDenyPolicies []string
}

// sessionCreateParams bundles the inputs needed for session creation and persistence.
type sessionCreateParams struct {
	spec           breakglassv1alpha1.BreakglassSessionSpec
	request        BreakglassSessionRequest
	userIdentifier string
	matchedEsc     *breakglassv1alpha1.BreakglassEscalation
	userGroups     []string
	username       string
}

// resolveAuthenticatedIdentity extracts identity claims from the request context,
// validates that at least one identifier is present, and enforces username matching.
// Modifies request.Username in-place when it is empty.
// Returns (*authenticatedIdentity, ok); writes HTTP error and returns ok=false on failure.
func (wc *BreakglassSessionController) resolveAuthenticatedIdentity(
	c *gin.Context, request *BreakglassSessionRequest, reqLog *zap.SugaredLogger,
) (*authenticatedIdentity, bool) {
	authEmail, emailErr := wc.identityProvider.GetEmail(c)
	authUsername := wc.identityProvider.GetUsername(c)
	authUserID := wc.identityProvider.GetIdentity(c)
	authIdentifiers := collectAuthIdentifiers(authEmail, authUsername, authUserID)
	if len(authIdentifiers) == 0 {
		reqLog.Error("No authenticated identity claims found in request context")
		apiresponses.RespondUnauthorizedWithMessage(c, "user identity not found")
		return nil, false
	}
	if request.Username == "" {
		// default to authenticated identity to avoid spoofing
		request.Username = firstNonEmpty(authEmail, authUsername, authUserID)
	} else if !matchesAuthIdentifier(request.Username, authIdentifiers) {
		reqLog.Warnw("Request username does not match authenticated identity",
			"requestUsername", request.Username,
			"authIdentifiers", authIdentifiers)
		apiresponses.RespondForbidden(c, "user identity mismatch")
		return nil, false
	}
	return &authenticatedIdentity{
		email:    authEmail,
		emailErr: emailErr,
		username: authUsername,
	}, true
}

// resolveUserGroups extracts user groups from the JWT token claims, falling back
// to cluster-based group resolution, and strips OIDC prefixes when configured.
// Returns (userGroups, ok); writes an HTTP error response and returns ok=false on failure.
func (wc *BreakglassSessionController) resolveUserGroups(
	c *gin.Context, ctx context.Context, cug ClusterUserGroup,
	globalCfg *config.Config, reqLog *zap.SugaredLogger,
) ([]string, bool) {
	var userGroups []string
	if raw, exists := c.Get("groups"); exists { // trace raw token groups before any normalization
		if arr, ok := raw.([]string); ok {
			reqLog.With("rawTokenGroups", arr, "rawTokenGroupCount", len(arr)).Debug("Extracted raw token groups from JWT claims")
		}
	}
	if tg, exists := c.Get("groups"); exists {
		if arr, ok := tg.([]string); ok {
			userGroups = append(userGroups, arr...)
		}
	}
	if len(userGroups) == 0 { // fallback to cluster lookup
		var gerr error
		userGroups, gerr = wc.getUserGroupsFn(ctx, cug)
		if gerr != nil {
			reqLog.With("error", gerr).Error("Failed to retrieve user groups for escalation determination")
			apiresponses.RespondInternalError(c, "extract user groups", gerr, reqLog)
			return nil, false
		}
	}
	// Strip OIDC prefixes if configured (cluster retrieval might include them; token groups usually not)
	if globalCfg != nil && len(globalCfg.Kubernetes.OIDCPrefixes) > 0 {
		userGroups = StripOIDCPrefixes(userGroups, globalCfg.Kubernetes.OIDCPrefixes)
	}
	return userGroups, true
}

// fetchMatchingEscalations retrieves escalations matching the cluster and user groups.
// Logs diagnostic information when no escalations are found.
// Returns (escalations, ok); writes HTTP error and returns ok=false on failure.
func (wc *BreakglassSessionController) fetchMatchingEscalations(
	c *gin.Context, ctx context.Context, cug ClusterUserGroup,
	userGroups []string, reqLog *zap.SugaredLogger,
) ([]breakglassv1alpha1.BreakglassEscalation, bool) {
	escalations, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(ctx, cug.Clustername, userGroups)
	if err != nil {
		reqLog.Errorw("Error getting breakglass escalations", "error", err)
		apiresponses.RespondInternalError(c, "extract cluster breakglass escalation information", err, reqLog)
		return nil, false
	}
	// We already filtered by cluster & user groups; treat these as possible escalations.
	// Note: Do NOT call dropK8sInternalFieldsEscalation here - we need the UID for owner references.
	// The UID stripping is only for API response serialization, not for internal processing.
	if len(escalations) == 0 {
		// Provide extra debug information in logs to help e2e diagnosis when no escalations are found
		rawGroups, _ := c.Get("groups")
		reqLog.Warnw("No escalation groups found for user",
			"user", cug.Username, "requestedGroup", cug.GroupName,
			"cluster", cug.Clustername, "resolvedUserGroups", userGroups, "rawTokenGroups", rawGroups)
		// Also log any escalations that exist for the cluster for visibility
		if escList, listErr := wc.escalationManager.GetClusterBreakglassEscalations(ctx, cug.Clustername); listErr == nil {
			names := make([]string, 0, len(escList))
			for _, e := range escList {
				names = append(names, e.Name)
			}
			reqLog.Debugw("Cluster escalations (for visibility)", "cluster", cug.Clustername, "escalations", names)
		}
		// User is authenticated but not authorized for this group - return 403 Forbidden
		apiresponses.RespondForbidden(c, "user not authorized for requested group")
		return nil, false
	}
	reqLog.Debugw("Possible escalations found", "user", cug.Username, "cluster", cug.Clustername, "count", len(escalations))
	return escalations, true
}

// collectApproversFromEscalations performs a single pass over filtered escalations to
// collect possible groups, find the matched escalation for the requested group,
// and gather deduplicated approvers from explicit users and resolved group members.
func (wc *BreakglassSessionController) collectApproversFromEscalations(
	ctx context.Context, possibleEscals []breakglassv1alpha1.BreakglassEscalation,
	requestedGroup string, reqLog *zap.SugaredLogger,
) *escalationResolutionResult {
	result := &escalationResolutionResult{
		possibleGroups:   make([]string, 0, len(possibleEscals)),
		approversByGroup: make(map[string][]string),
		allApprovers:     []string{},
	}

	reqLog.Debugw("Starting approver resolution from escalations",
		"escalationCount", len(possibleEscals),
		"requestedGroup", requestedGroup)

	for i := range possibleEscals {
		p := &possibleEscals[i]
		result.possibleGroups = append(result.possibleGroups, p.Spec.EscalatedGroup)
		reqLog.Debugw("Processing escalation for approver resolution",
			"escalationName", p.Name,
			"escalatedGroup", p.Spec.EscalatedGroup,
			"explicitUserCount", len(p.Spec.Approvers.Users),
			"approverGroupCount", len(p.Spec.Approvers.Groups))

		// Always check if this is the matched escalation first (needed for deny policies)
		isMatchedEscalation := p.Spec.EscalatedGroup == requestedGroup && result.matchedEscalation == nil
		if isMatchedEscalation {
			result.matchedEscalation = p
			result.selectedDenyPolicies = append(result.selectedDenyPolicies, p.Spec.DenyPolicyRefs...)
			reqLog.Debugw("Matched escalation found during approver collection",
				"escalationName", result.matchedEscalation.Name,
				"escalatedGroup", result.matchedEscalation.Spec.EscalatedGroup,
				"denyPolicyCount", len(result.selectedDenyPolicies))
		}

		// Check total approvers limit before processing this escalation's approvers
		if len(result.allApprovers) >= MaxTotalApprovers {
			// If we've already found the matched escalation, break out entirely
			// to avoid unnecessary work and log spam
			if result.matchedEscalation != nil {
				reqLog.Infow("Total approvers limit reached and matched escalation found, stopping",
					"limit", MaxTotalApprovers,
					"matchedEscalation", result.matchedEscalation.Name)
				break
			}
			// Otherwise continue looking for the matched escalation (but skip approver resolution)
			reqLog.Debugw("Total approvers limit reached, skipping approver resolution for escalation",
				"limit", MaxTotalApprovers,
				"skippedEscalation", p.Name)
			continue
		}

		// Add explicit users (deduplicated) - track them under special key
		for _, user := range p.Spec.Approvers.Users {
			if len(result.allApprovers) >= MaxTotalApprovers {
				reqLog.Warnw("Total approvers limit reached while adding explicit users",
					"limit", MaxTotalApprovers,
					"escalation", p.Name)
				break
			}
			before := len(result.allApprovers)
			result.allApprovers = addIfNotPresent(result.allApprovers, user)
			if len(result.allApprovers) > before {
				// Explicit users are tracked separately
				result.approversByGroup["_explicit_users"] = addIfNotPresent(result.approversByGroup["_explicit_users"], user)
				reqLog.Debugw("Added explicit approver user",
					"user", user,
					"escalation", p.Name,
					"totalApproversNow", len(result.allApprovers))
			}
		}

		// Resolve and add group members (deduplicated)
		wc.resolveAndAddGroupMembers(ctx, p, result, reqLog)

		// Break outer loop if we've reached the maximum total approvers AND
		// we've already found the matched escalation. If matchedEsc is nil,
		// let the loop continue — the top-of-loop check will skip approver
		// resolution but still identify the matched escalation.
		if len(result.allApprovers) >= MaxTotalApprovers && result.matchedEscalation != nil {
			reqLog.Infow("Maximum total approvers limit reached, stopping escalation processing",
				"limit", MaxTotalApprovers,
				"matchedEscalation", result.matchedEscalation.Name)
			break
		}
	}

	// Note: individual approvers are logged at Debug level above; this Info log
	// emits only counts. The full approver list is logged at Info level later in
	// sendSessionNotifications for notification audit purposes.
	reqLog.Infow("Completed approver resolution from escalations",
		"totalApproversCollected", len(result.allApprovers),
		"approverGroupsCount", len(result.approversByGroup),
		"requestedGroup", requestedGroup)

	return result
}

// resolveAndAddGroupMembers resolves members for each approver group in an escalation
// and adds them to the resolution result, respecting per-group and total approver limits.
func (wc *BreakglassSessionController) resolveAndAddGroupMembers(
	ctx context.Context, p *breakglassv1alpha1.BreakglassEscalation,
	result *escalationResolutionResult, reqLog *zap.SugaredLogger,
) {
	for _, group := range p.Spec.Approvers.Groups {
		// Check total approvers limit before processing this group
		if len(result.allApprovers) >= MaxTotalApprovers {
			reqLog.Warnw("Total approvers limit reached, skipping remaining groups",
				"limit", MaxTotalApprovers,
				"skippedGroup", group,
				"escalation", p.Name)
			break
		}

		reqLog.Debugw("Resolving approver group members",
			"group", group,
			"escalation", p.Name)

		var members []string
		var err error

		// Multi-IDP mode: use deduplicated members from status if available
		if len(p.Spec.AllowedIdentityProvidersForApprovers) > 0 && p.Status.ApproverGroupMembers != nil {
			if statusMembers, ok := p.Status.ApproverGroupMembers[group]; ok {
				members = statusMembers
				reqLog.Debugw("Using deduplicated members from status (multi-IDP mode)",
					"group", group,
					"escalation", p.Name,
					"memberCount", len(members))
			} else {
				reqLog.Debugw("No members found in status for group (multi-IDP mode)",
					"group", group,
					"escalation", p.Name)
				continue
			}
		} else {
			// Legacy mode: resolve from single IDP
			if wc.escalationManager != nil && wc.escalationManager.GetResolver() != nil {
				members, err = wc.escalationManager.GetResolver().Members(ctx, group)
				if err != nil {
					reqLog.Warnw("Failed to resolve approver group members", "group", group, "error", err)
					// Continue with other groups even if one fails
					continue
				}
			}
		}

		// Apply per-group member limit to prevent resource exhaustion
		if len(members) > MaxApproverGroupMembers {
			reqLog.Warnw("Approver group has too many members, truncating",
				"group", group,
				"escalation", p.Name,
				"originalCount", len(members),
				"limit", MaxApproverGroupMembers)
			members = members[:MaxApproverGroupMembers]
		}

		// Log member count (after truncation) to avoid PII leakage for large groups.
		// Only log individual members at Debug level when the group is small enough.
		if len(members) <= 20 {
			reqLog.Debugw("Resolved approver group members",
				"group", group,
				"escalation", p.Name,
				"memberCount", len(members),
				"members", members)
		} else {
			reqLog.Debugw("Resolved approver group members",
				"group", group,
				"escalation", p.Name,
				"memberCount", len(members))
		}

		// Calculate how many more approvers we can add
		remainingCapacity := MaxTotalApprovers - len(result.allApprovers)
		if remainingCapacity == 0 {
			reqLog.Warnw("No remaining capacity for approvers, skipping group",
				"group", group,
				"escalation", p.Name,
				"totalApproversLimit", MaxTotalApprovers)
			break
		}
		if remainingCapacity < len(members) {
			reqLog.Warnw("Truncating members to fit within total approvers limit",
				"group", group,
				"escalation", p.Name,
				"originalCount", len(members),
				"truncatedTo", remainingCapacity,
				"totalApproversLimit", MaxTotalApprovers)
			members = members[:remainingCapacity]
		}

		countBefore := len(result.allApprovers)
		for _, member := range members {
			result.allApprovers = addIfNotPresent(result.allApprovers, member)
			// Track member as belonging to this group
			result.approversByGroup[group] = addIfNotPresent(result.approversByGroup[group], member)
		}
		countAdded := len(result.allApprovers) - countBefore
		reqLog.Debugw("Added group members to approvers",
			"group", group,
			"escalation", p.Name,
			"newMembersAdded", countAdded,
			"totalApproversNow", len(result.allApprovers))
	}
}

// checkDuplicateSession checks for an existing active session and responds with
// an appropriate conflict status if one is found.
// Returns true when no conflicting session exists and creation can proceed.
func (wc *BreakglassSessionController) checkDuplicateSession(
	c *gin.Context, ctx context.Context,
	userIdentifier, clustername, groupName string,
	reqLog *zap.SugaredLogger,
) bool {
	ses, err := wc.getActiveBreakglassSession(ctx, userIdentifier, clustername, groupName)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			reqLog.Errorw("Error getting breakglass sessions", "error", err)
			apiresponses.RespondInternalError(c, "extract breakglass session information", err, reqLog)
			return false
		}
		return true // no existing session found
	}

	// A matching session exists; decide response based on its canonical state.
	reqLog.Infow("Existing session found",
		"session", ses.Name, "cluster", clustername,
		"user", userIdentifier, "group", groupName, "state", ses.Status.State)
	// Remove k8s internal fields before returning session in API response
	dropK8sInternalFieldsSession(&ses)

	// Approved session -> explicit "already approved" error
	if ses.Status.State == breakglassv1alpha1.SessionStateApproved || !ses.Status.ApprovedAt.IsZero() {
		c.JSON(http.StatusConflict, gin.H{"error": "already approved", "session": ses})
		return false
	}

	// Pending (requested but not yet approved/rejected) -> "already requested" with linked session
	if IsSessionPendingApproval(ses) {
		c.JSON(http.StatusConflict, gin.H{"error": "already requested", "session": ses})
		return false
	}

	// Fallback: session exists but in another terminal state (e.g. timeout) — return generic conflict with session
	c.JSON(http.StatusConflict, gin.H{"error": "session exists", "session": ses})
	return false
}

// resolveUserIdentifierClaim determines the user identifier from the token based on
// the configured claim type (ClusterConfig override > Global config > default).
// Returns (userIdentifier, clusterConfig, ok); writes HTTP error on failure.
func (wc *BreakglassSessionController) resolveUserIdentifierClaim(
	c *gin.Context, ctx context.Context, request BreakglassSessionRequest,
	globalCfg *config.Config, reqLog *zap.SugaredLogger,
) (string, *breakglassv1alpha1.ClusterConfig, bool) {
	// Determine the user identifier claim.
	// This ensures the session's spec.User matches what the spoke cluster's OIDC sends in SAR.
	// Priority: ClusterConfig > Global config
	var userIdentifierClaim breakglassv1alpha1.UserIdentifierClaimType
	if globalCfg != nil {
		userIdentifierClaim = globalCfg.GetUserIdentifierClaim()
	}

	// Check ClusterConfig for per-cluster override
	var clusterConfig *breakglassv1alpha1.ClusterConfig
	if wc.clusterConfigManager != nil {
		var ccErr error
		clusterConfig, ccErr = wc.clusterConfigManager.GetClusterConfigByName(ctx, request.Clustername)
		if ccErr != nil {
			reqLog.Debugw("Could not fetch cluster config for user identifier claim",
				"cluster", request.Clustername,
				"error", ccErr)
		} else if clusterConfig.Spec.UserIdentifierClaim != "" {
			userIdentifierClaim = clusterConfig.GetUserIdentifierClaim()
			reqLog.Debugw("Using cluster-specific userIdentifierClaim",
				"cluster", request.Clustername,
				"userIdentifierClaim", userIdentifierClaim)
		}
	}

	// Get the user identifier based on the configured claim type
	userIdentifier, err := wc.identityProvider.GetUserIdentifier(c, userIdentifierClaim)
	if err != nil {
		reqLog.Errorw("Error getting user identifier from token",
			"error", err,
			"userIdentifierClaim", userIdentifierClaim)
		apiresponses.RespondInternalError(c, fmt.Sprintf("extract user identifier (%s) from token", userIdentifierClaim), err, reqLog)
		return "", nil, false
	}
	reqLog.Debugw("Resolved user identifier for session",
		"userIdentifier", userIdentifier,
		"userIdentifierClaim", userIdentifierClaim,
		"requestUsername", request.Username)

	return userIdentifier, clusterConfig, true
}

// buildSessionSpec constructs the BreakglassSessionSpec from the request, matched escalation,
// and cluster configuration. Handles IDP tracking fields, custom duration validation, and
// scheduled start time parsing.
// Returns (spec, ok); writes HTTP error and returns ok=false on validation failures.
func (wc *BreakglassSessionController) buildSessionSpec(
	c *gin.Context, request BreakglassSessionRequest,
	userIdentifier string, matchedEsc *breakglassv1alpha1.BreakglassEscalation,
	clusterConfig *breakglassv1alpha1.ClusterConfig, selectedDenyPolicies []string,
	reqLog *zap.SugaredLogger,
) (breakglassv1alpha1.BreakglassSessionSpec, bool) {
	// Initialize session spec and populate duration fields from matched escalation when available
	spec := breakglassv1alpha1.BreakglassSessionSpec{
		Cluster:        request.Clustername,
		User:           userIdentifier, // Use the identifier based on ClusterConfig's userIdentifierClaim
		GrantedGroup:   request.GroupName,
		DenyPolicyRefs: selectedDenyPolicies,
		RequestReason:  request.Reason,
	}

	// Multi-IDP: Populate IDP tracking fields from authentication middleware
	if idpName, exists := c.Get("identity_provider_name"); exists {
		if name, ok := idpName.(string); ok && name != "" {
			spec.IdentityProviderName = name
		}
	}
	if issuer, exists := c.Get("issuer"); exists {
		if iss, ok := issuer.(string); ok && iss != "" {
			spec.IdentityProviderIssuer = iss
		}
	}

	if matchedEsc == nil {
		return spec, true
	}

	// copy relevant duration-related fields from escalation spec to session spec
	spec.MaxValidFor = matchedEsc.Spec.MaxValidFor
	spec.RetainFor = matchedEsc.Spec.RetainFor
	spec.IdleTimeout = matchedEsc.Spec.IdleTimeout

	// Copy reason configurations as snapshots so session is self-contained
	// This avoids needing to look up the escalation later
	if matchedEsc.Spec.RequestReason != nil {
		spec.RequestReasonConfig = matchedEsc.Spec.RequestReason.DeepCopy()
	}
	if matchedEsc.Spec.ApprovalReason != nil {
		spec.ApprovalReasonConfig = matchedEsc.Spec.ApprovalReason.DeepCopy()
	}

	// Determine AllowIDPMismatch flag: set to true when neither escalation nor cluster have IDP restrictions
	// This ensures backward compatibility for single-IDP deployments
	escalationHasIDPRestriction := len(matchedEsc.Spec.AllowedIdentityProviders) > 0
	clusterHasIDPRestriction := false

	// Use the already-fetched clusterConfig for IDP restriction check (avoid duplicate fetch)
	if clusterConfig != nil {
		clusterHasIDPRestriction = len(clusterConfig.Spec.IdentityProviderRefs) > 0
		reqLog.Debugw("Using already-fetched cluster config for IDP restriction check",
			"cluster", request.Clustername,
			"clusterHasIDPRestriction", clusterHasIDPRestriction,
			"escalationHasIDPRestriction", escalationHasIDPRestriction)
	} else {
		reqLog.Debugw("Cluster config not available for IDP check (will default to false for restriction)",
			"cluster", request.Clustername)
	}

	// AllowIDPMismatch=true means: ignore IDP checks during authorization
	// This is set when BOTH escalation and cluster have no IDP restrictions
	// This enables backward compatibility for deployments not using multi-IDP
	spec.AllowIDPMismatch = !escalationHasIDPRestriction && !clusterHasIDPRestriction
	reqLog.Debugw("Set AllowIDPMismatch flag for session",
		"allowIDPMismatch", spec.AllowIDPMismatch,
		"escalationHasIDPRestriction", escalationHasIDPRestriction,
		"clusterHasIDPRestriction", clusterHasIDPRestriction)

	// Validate and apply custom duration if provided
	if request.Duration > 0 {
		// Parse max allowed duration from string (e.g., "1h", "3600s", "7d")
		d, err := breakglassv1alpha1.ParseDuration(matchedEsc.Spec.MaxValidFor)
		if err != nil {
			reqLog.Warnw("Failed to parse MaxValidFor duration", "error", err, "value", matchedEsc.Spec.MaxValidFor)
			apiresponses.RespondInternalError(c, "parse escalation duration configuration", err, reqLog)
			return breakglassv1alpha1.BreakglassSessionSpec{}, false
		}
		maxAllowed := int64(d.Seconds())
		if err := request.ValidateDuration(maxAllowed); err != nil {
			reqLog.Warnw("Duration validation failed", "error", err, "requestedDuration", request.Duration, "maxAllowed", maxAllowed)
			apiresponses.RespondUnprocessableEntity(c, "invalid duration: "+err.Error())
			return breakglassv1alpha1.BreakglassSessionSpec{}, false
		}
		// Convert custom duration to Go duration string (e.g., "1h30m")
		customDuration := time.Duration(request.Duration) * time.Second
		spec.MaxValidFor = customDuration.String()
		reqLog.Debugw("Custom duration applied", "duration", request.Duration, "defaultMaxValidFor", matchedEsc.Spec.MaxValidFor, "customMaxValidFor", spec.MaxValidFor)
	}

	// Store scheduled start time if provided
	if request.ScheduledStartTime != "" {
		// Parse ISO 8601 datetime
		scheduledTime, err := time.Parse(time.RFC3339, request.ScheduledStartTime)
		if err != nil {
			reqLog.Warnw("Failed to parse scheduledStartTime", "error", err, "value", request.ScheduledStartTime)
			apiresponses.RespondUnprocessableEntity(c, "invalid scheduledStartTime format (expected ISO 8601)")
			return breakglassv1alpha1.BreakglassSessionSpec{}, false
		}

		// Ensure scheduled time is in the future
		now := time.Now()
		if scheduledTime.Before(now) {
			reqLog.Warnw("scheduledStartTime is in the past",
				"requestedTime", request.ScheduledStartTime,
				"parsedUTC", scheduledTime.Format(time.RFC3339),
				"nowUTC", now.Format(time.RFC3339),
				"nowLocal", now.Local().Format(time.RFC3339),
				"parsedLocal", scheduledTime.Local().Format(time.RFC3339),
				"timeDiffSeconds", now.Unix()-scheduledTime.Unix())
			apiresponses.RespondUnprocessableEntity(c, "scheduledStartTime must be in the future")
			return breakglassv1alpha1.BreakglassSessionSpec{}, false
		}

		spec.ScheduledStartTime = &metav1.Time{Time: scheduledTime}
		reqLog.Debugw("Scheduled start time set",
			"scheduledStartTimeISO", request.ScheduledStartTime,
			"scheduledTimeUTC", scheduledTime.Format(time.RFC3339),
			"scheduledTimeLocal", scheduledTime.Local().Format(time.RFC3339),
			"nowUTC", now.Format(time.RFC3339),
			"secondsInFuture", scheduledTime.Unix()-now.Unix())
	}

	return spec, true
}

// createAndPersistSession builds the BreakglassSession object (labels, ownerRefs),
// checks session limits, persists it to the API server, and sets the initial status.
// Returns (session, ok); writes HTTP error and returns ok=false on failure.
func (wc *BreakglassSessionController) createAndPersistSession(
	c *gin.Context, ctx context.Context, params sessionCreateParams,
	reqLog *zap.SugaredLogger,
) (*breakglassv1alpha1.BreakglassSession, bool) {
	bs := breakglassv1alpha1.BreakglassSession{Spec: params.spec}
	// Add labels to sessions so label selectors can operate when field indices are unavailable
	if bs.Labels == nil {
		bs.Labels = map[string]string{}
	}
	// Sanitize label values to conform to Kubernetes label restrictions (RFC1123-ish)
	bs.Labels["breakglass.t-caas.telekom.com/cluster"] = naming.ToRFC1123Label(params.request.Clustername)
	bs.Labels["breakglass.t-caas.telekom.com/user"] = naming.ToRFC1123Label(params.userIdentifier) // Use resolved identifier, not request.Username
	bs.Labels["breakglass.t-caas.telekom.com/group"] = naming.ToRFC1123Label(params.request.GroupName)
	// Ensure session is created in the same namespace as the matched escalation
	if params.matchedEsc != nil {
		reqLog.Debugw("Matched escalation found during session creation; attaching ownerRef",
			"escalationName", params.matchedEsc.Name, "escalationUID", params.matchedEsc.UID, "escalationNamespace", params.matchedEsc.Namespace)
		bs.Namespace = params.matchedEsc.Namespace
		// Attach owner reference so the session can be linked back to its escalation
		// This allows other components (webhook/controller) to resolve the escalation
		// via the session's OwnerReferences.
		bs.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassEscalation",
			Name:       params.matchedEsc.Name,
			UID:        params.matchedEsc.UID,
			// Controller and BlockOwnerDeletion are optional; set Controller=true for clarity.
			Controller: func() *bool { b := true; return &b }(),
		}}
		reqLog.Debugw("OwnerReference prepared for session create", "ownerRefs", bs.OwnerReferences)
	} else {
		reqLog.Debugw("No matching escalation found during session creation; no ownerRef will be attached", "requestedGroup", params.request.GroupName, "cluster", params.request.Clustername)
	}

	// If no escalation was matched, reject creation: sessions must be tied to an escalation
	if params.matchedEsc == nil {
		reqLog.Warnw("Refusing to create session without matched escalation", "user", params.userIdentifier, "cluster", params.request.Clustername, "group", params.request.GroupName)
		apiresponses.RespondForbidden(c, "no escalation found for requested group")
		return nil, false
	}

	// Check session limits (IDP-level with escalation overrides)
	if err := wc.checkSessionLimits(ctx, params.matchedEsc, params.spec.IdentityProviderName, params.userIdentifier, params.userGroups, reqLog); err != nil {
		reqLog.Warnw("Session limit check failed", "error", err, "escalation", params.matchedEsc.Name, "user", params.userIdentifier)
		// Distinguish infrastructure errors (500) from user-facing limit errors (422).
		switch {
		case apierrors.IsNotFound(err),
			apierrors.IsForbidden(err),
			apierrors.IsUnauthorized(err),
			apierrors.IsTimeout(err),
			apierrors.IsServerTimeout(err),
			apierrors.IsTooManyRequests(err),
			apierrors.IsInternalError(err),
			errors.Is(err, context.DeadlineExceeded),
			errors.Is(err, context.Canceled):
			apiresponses.RespondInternalError(c, "check session limits", err, reqLog)
		default:
			apiresponses.RespondUnprocessableEntity(c, err.Error())
		}
		return nil, false
	}

	// Generate RFC1123-safe name parts for cluster and group
	safeCluster := naming.ToRFC1123Subdomain(params.request.Clustername)
	safeGroup := naming.ToRFC1123Subdomain(params.request.GroupName)
	bs.GenerateName = fmt.Sprintf("%s-%s-", safeCluster, safeGroup)
	if err := wc.sessionManager.AddBreakglassSession(ctx, &bs); err != nil {
		reqLog.Errorw("error while adding breakglass session", "error", err)
		reason := "internal_error"
		if apierrors.IsInvalid(err) {
			reason = "invalid"
			apiresponses.RespondUnprocessableEntity(c, err.Error())
		} else if apierrors.IsForbidden(err) {
			reason = "forbidden"
			apiresponses.RespondForbidden(c, err.Error())
		} else if apierrors.IsBadRequest(err) {
			reason = "bad_request"
			apiresponses.RespondBadRequest(c, err.Error())
		} else {
			apiresponses.RespondInternalError(c, "create session", err, reqLog)
		}
		metrics.SessionCreateFailed.WithLabelValues(params.request.Clustername, reason).Inc()
		return nil, false
	}
	// Note: bs already has its Name populated by AddBreakglassSession (passed as pointer).
	// Do not try to fetch it again as this can race with informer cache population.
	// Instead, reuse the bs object that was created.

	// Get approval timeout from escalation spec using helper
	approvalTimeout := ParseApprovalTimeout(params.matchedEsc.Spec, reqLog)
	if params.matchedEsc.Spec.ApprovalTimeout != "" {
		reqLog.Debugw("Using approval timeout from escalation spec", "approvalTimeout", approvalTimeout)
	}

	// Compute retained-until at creation so sessions always expose when they will be cleaned up.
	retainFor := ParseRetainFor(params.spec, reqLog)

	bs.Status = breakglassv1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(retainFor)),
		TimeoutAt:     metav1.NewTime(time.Now().Add(approvalTimeout)), // Approval timeout
		State:         breakglassv1alpha1.SessionStatePending,
		Conditions: []metav1.Condition{{
			Type:               string(breakglassv1alpha1.SessionConditionTypeIdle),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
			Message:            fmt.Sprintf("User %q requested session.", params.username),
		}},
	}

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(ctx, bs); err != nil {
		reqLog.Errorw("error while updating breakglass session", "error", err)
		apiresponses.RespondInternalError(c, "update session status", err, reqLog)
		return nil, false
	}

	return &bs, true
}

// sendSessionNotifications sends email notifications to approvers when a session is
// created. It triggers a background group sync, filters excluded and hidden recipients,
// then sends per-group notification emails.
func (wc *BreakglassSessionController) sendSessionNotifications(
	bs breakglassv1alpha1.BreakglassSession, matchedEsc *breakglassv1alpha1.BreakglassEscalation,
	allApprovers []string, approversByGroup map[string][]string,
	authEmail, username string, reqLog *zap.SugaredLogger,
) {
	if wc.disableEmail {
		reqLog.Debug("Email sending disabled via --disable-email flag")
		return
	}
	if matchedEsc.Spec.DisableNotifications != nil && *matchedEsc.Spec.DisableNotifications {
		reqLog.Infow("Email sending disabled for this escalation via DisableNotifications",
			"escalationName", matchedEsc.Name,
			"cluster", bs.Spec.Cluster,
			"grantedGroup", bs.Spec.GrantedGroup)
		return
	}

	reqLog.Infow("Resolved approvers from escalation (explicit users + group members)",
		"approverCount", len(allApprovers),
		"approvers", allApprovers,
		"cluster", bs.Spec.Cluster,
		"grantedGroup", bs.Spec.GrantedGroup)

	reqLog.Debugw("About to send breakglass request email",
		"approvalsRequired", len(allApprovers),
		"approvers", allApprovers,
		"requestorEmail", authEmail,
		"requestorUsername", username,
		"grantedGroup", bs.Spec.GrantedGroup,
		"cluster", bs.Spec.Cluster)

	if len(allApprovers) == 0 {
		reqLog.Warnw("No approvers resolved for email notification; cannot send email with empty recipients",
			"escalation", bs.Spec.GrantedGroup,
			"cluster", bs.Spec.Cluster,
			"requestorEmail", authEmail,
			"requestorUsername", username)
		return
	}

	// Trigger a group sync before sending email (but still send based on current status)
	if wc.escalationManager != nil && wc.escalationManager.GetResolver() != nil {
		// Capture the request-scoped logger (which contains cid) so background logs
		// emitted during group sync include the same correlation id.
		goroutineLog := reqLog.With("cluster", bs.Spec.Cluster)
		go func(log *zap.SugaredLogger) {
			// Use a timeout context for background work to prevent goroutine leaks
			ctx, cancel := context.WithTimeout(context.Background(), APIContextTimeout)
			defer cancel()
			// Run a sync for all approver groups in the escalation(s) for this request
			escalations, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(ctx, bs.Spec.Cluster, []string{})
			if err != nil {
				log.Warnw("Failed to list escalations for group sync", "error", err)
				return
			}

			// Deduplicate groups across all escalations to avoid syncing the same group multiple times
			groupsToSync := make(map[string]bool)
			for _, esc := range escalations {
				for _, g := range esc.Spec.Approvers.Groups {
					groupsToSync[g] = true
				}
			}

			if len(groupsToSync) == 0 {
				log.Debugw("No approver groups found to sync", "cluster", bs.Spec.Cluster, "escalationCount", len(escalations))
				return
			}

			log.Debugw("Syncing approver groups", "cluster", bs.Spec.Cluster, "groupCount", len(groupsToSync))
			for g := range groupsToSync {
				members, merr := wc.escalationManager.GetResolver().Members(ctx, g)
				if merr != nil {
					log.Warnw("Group member resolution failed during sync", "group", g, "error", merr)
					continue
				}
				log.Debugw("Resolved group members for sync", "group", g, "count", len(members))
			}
		}(goroutineLog)
	}

	// Filter out excluded users/groups and hidden groups from approvers list
	reqLog.Debugw("About to filter approvers",
		"escalationName", matchedEsc.Name,
		"preFilterApproverCount", len(allApprovers),
		"preFilterApprovers", allApprovers)

	filteredApprovers := wc.filterExcludedNotificationRecipients(reqLog, allApprovers, matchedEsc)
	reqLog.Debugw("After filterExcludedNotificationRecipients",
		"postExcludeApproverCount", len(filteredApprovers),
		"postExcludeApprovers", filteredApprovers,
		"excludedCount", len(allApprovers)-len(filteredApprovers))

	filteredApprovers = wc.filterHiddenFromUIRecipients(reqLog, filteredApprovers, matchedEsc)
	reqLog.Debugw("After filterHiddenFromUIRecipients",
		"postHiddenFilterApproverCount", len(filteredApprovers),
		"postHiddenFilterApprovers", filteredApprovers,
		"hiddenFilteredOutCount", len(allApprovers)-len(filteredApprovers))

	if len(filteredApprovers) == 0 {
		reqLog.Infow("All approvers excluded from notifications via NotificationExclusions or HiddenFromUI",
			"escalationName", matchedEsc.Name,
			"originalApproverCount", len(allApprovers))
		return
	}

	// Send separate emails per approver group
	// Each email shows only the specific group that matched
	wc.sendOnRequestEmailsByGroup(reqLog, bs, authEmail, username, filteredApprovers, approversByGroup, matchedEsc)
}
