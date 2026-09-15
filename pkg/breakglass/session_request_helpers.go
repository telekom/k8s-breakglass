package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/naming"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"github.com/telekom/k8s-breakglass/pkg/system"
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

func (wc *BreakglassSessionController) validateClusterIdentityProvider(c *gin.Context, ctx context.Context, cluster string) bool {
	if wc.clusterConfigManager == nil || !wc.clusterConfigManager.hasClient() {
		return true
	}
	cc, err := wc.clusterConfigManager.GetClusterConfigByName(ctx, cluster)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return true
		}
		apiresponses.RespondInternalError(c, "resolve cluster identity provider policy", err, wc.log)
		return false
	}
	if cc == nil || len(cc.Spec.IdentityProviderRefs) == 0 {
		return true
	}
	if !slices.Contains(cc.Spec.IdentityProviderRefs, c.GetString("identity_provider_name")) {
		apiresponses.RespondForbidden(c, "identity provider is not allowed for this cluster")
		return false
	}
	return true
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

type duplicateSessionConflictResponse struct {
	Error   string                               `json:"error"`
	Code    string                               `json:"code"`
	Session breakglassv1alpha1.BreakglassSession `json:"session"`
}

func respondDuplicateSessionConflict(c *gin.Context, message string, ses breakglassv1alpha1.BreakglassSession) {
	c.JSON(http.StatusConflict, duplicateSessionConflictResponse{Error: message, Code: "CONFLICT", Session: ses})
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
	// tokenGroupsPresent distinguishes "the JWT carried a groups/realm_access
	// claim" (even if it resolved to zero groups) from "the JWT carried no
	// group information at all". Only the latter should fall back to
	// cluster-based group resolution; a token that legitimately asserts zero
	// groups must not be treated the same as one with no group claim.
	raw, tokenGroupsPresent := c.Get("groups")
	if tokenGroupsPresent { // trace raw token groups before any normalization
		if arr, ok := raw.([]string); ok {
			reqLog.With("rawTokenGroups", system.RedactSlice(arr), "rawTokenGroupCount", len(arr)).Debug("Extracted raw token groups from JWT claims")
			userGroups = append(userGroups, arr...)
		}
	}
	if !tokenGroupsPresent { // fallback to cluster lookup only when the token carried no group information
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
		reqLog.Warnw("No escalation groups found for user",
			"user", cug.Username, "requestedGroup", system.RedactGroupName(cug.GroupName),
			"cluster", cug.Clustername, "resolvedUserGroups", system.RedactSlice(userGroups))
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

	// Phase 5.5: Apply Rule 11: block unready escalations from session requests.
	// This ensures that "Not Ready" clusters cannot be used for sessions even if they exist.
	readyEscalations := make([]breakglassv1alpha1.BreakglassEscalation, 0, len(escalations))
	for _, e := range escalations {
		if e.IsReady() {
			readyEscalations = append(readyEscalations, e)
		}
	}
	if len(readyEscalations) == 0 {
		reqLog.Warnw("Requested escalation exists but is not ready", "cluster", cug.Clustername, "group", cug.GroupName)
		apiresponses.RespondForbidden(c, "requested cluster/escalation is not ready")
		return nil, false
	}
	escalations = readyEscalations

	if !wc.isRequestedClusterConfigReady(ctx, cug.Clustername, reqLog) {
		apiresponses.RespondForbidden(c, "requested ClusterConfig is not ready or is ambiguous")
		return nil, false
	}

	reqLog.Debugw("Possible escalations found", "user", cug.Username, "cluster", cug.Clustername, "count", len(escalations))
	return escalations, true
}

func (wc *BreakglassSessionController) isRequestedClusterConfigReady(ctx context.Context, clusterName string, reqLog *zap.SugaredLogger) bool {
	if wc.clusterConfigManager == nil || !wc.clusterConfigManager.hasClient() {
		return true
	}

	clusterConfig, err := wc.clusterConfigManager.GetClusterConfigByName(ctx, clusterName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reqLog.Debugw("No ClusterConfig found while enforcing session readiness; preserving legacy escalation-based matching",
				"cluster", clusterName,
				"error", err)
			return true
		}
		reqLog.Warnw("Failed to resolve ClusterConfig while enforcing session readiness; blocking request",
			"cluster", clusterName,
			"error", err)
		return false
	}
	if IsClusterConfigReady(clusterConfig) {
		return true
	}

	reqLog.Warnw("Requested ClusterConfig is not ready", "cluster", clusterName)
	return false
}

// collectApproversFromEscalations selects the requested escalation and gathers
// deduplicated approvers from its explicit users and resolved group members.
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
		"requestedGroup", system.RedactGroupName(requestedGroup))

	// Select the escalation first. Notification recipients belong to the
	// requested escalation only; collecting from every eligible escalation can
	// disclose unrelated escalation requests.
	for i := range possibleEscals {
		p := &possibleEscals[i]
		if !p.IsReady() {
			continue
		}
		result.possibleGroups = append(result.possibleGroups, p.Spec.EscalatedGroup)
		if result.matchedEscalation == nil && p.Spec.EscalatedGroup == requestedGroup {
			result.matchedEscalation = p
			result.selectedDenyPolicies = append(result.selectedDenyPolicies, p.Spec.DenyPolicyRefs...)
		}
	}

	for i := range possibleEscals {
		p := &possibleEscals[i]
		if !p.IsReady() {
			reqLog.Debugw("Skipping unready escalation during approver resolution", "escalationName", p.Name)
			continue
		}
		if p != result.matchedEscalation {
			continue
		}
		reqLog.Debugw("Processing escalation for approver resolution",
			"escalationName", p.Name,
			"escalatedGroup", system.RedactGroupName(p.Spec.EscalatedGroup),
			"explicitUserCount", len(p.Spec.Approvers.Users),
			"approverGroupCount", len(p.Spec.Approvers.Groups))

		reqLog.Debugw("Matched escalation selected for approver resolution",
			"escalationName", result.matchedEscalation.Name,
			"escalatedGroup", system.RedactGroupName(result.matchedEscalation.Spec.EscalatedGroup),
			"denyPolicyCount", len(result.selectedDenyPolicies))

		// Check total approvers limit before processing this escalation's approvers
		if len(result.allApprovers) >= MaxTotalApprovers {
			reqLog.Infow("Total approvers limit reached and matched escalation found, stopping",
				"limit", MaxTotalApprovers,
				"matchedEscalation", result.matchedEscalation.Name)
			break
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

		// Stop once the matched escalation reaches the notification cap.
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
		"requestedGroup", system.RedactGroupName(requestedGroup))

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
				"group", system.RedactGroupName(group),
				"escalation", p.Name)
			break
		}

		reqLog.Debugw("Resolving approver group members",
			"group", system.RedactGroupName(group),
			"escalation", p.Name)

		var members []string
		var err error

		if len(notificationApproverProviders(p)) > 0 {
			var known bool
			members, known = restrictedNotificationGroupMembers(p, group)
			if !known {
				continue
			}
		} else {
			// Legacy mode: resolve from single IDP
			if wc.escalationManager != nil && wc.escalationManager.GetResolver() != nil {
				members, err = wc.escalationManager.GetResolver().Members(ctx, group)
				if err != nil {
					reqLog.Warnw("Failed to resolve approver group members", "group", system.RedactGroupName(group), "error", err)
					// Continue with other groups even if one fails
					continue
				}
			} else {
				continue // No authoritative membership was resolved.
			}
		}

		// Keep complete membership, including known-empty groups, for exclusions.
		// Recipient caps below must not make overlapping excluded members visible.
		result.approversByGroup[group] = members

		// Cap notification candidates; privacy snapshots remain complete.
		if len(members) > MaxApproverGroupMembers {
			reqLog.Warnw("Approver group has too many members, truncating",
				"group", system.RedactGroupName(group),
				"escalation", p.Name,
				"originalCount", len(members),
				"limit", MaxApproverGroupMembers)
			members = members[:MaxApproverGroupMembers]
		}

		// Log member count (after truncation) to avoid PII leakage for large groups.
		// Only log individual members at Debug level when the group is small enough.
		if len(members) <= 20 {
			reqLog.Debugw("Resolved approver group members",
				"group", system.RedactGroupName(group),
				"escalation", p.Name,
				"memberCount", len(members))
		} else {
			reqLog.Debugw("Resolved approver group members",
				"group", system.RedactGroupName(group),
				"escalation", p.Name,
				"memberCount", len(members))
		}

		// Calculate how many more approvers we can add
		remainingCapacity := MaxTotalApprovers - len(result.allApprovers)
		if remainingCapacity == 0 {
			reqLog.Warnw("No remaining capacity for approvers, skipping group",
				"group", system.RedactGroupName(group),
				"escalation", p.Name,
				"totalApproversLimit", MaxTotalApprovers)
			break
		}
		if remainingCapacity < len(members) {
			reqLog.Warnw("Truncating members to fit within total approvers limit",
				"group", system.RedactGroupName(group),
				"escalation", p.Name,
				"originalCount", len(members),
				"truncatedTo", remainingCapacity,
				"totalApproversLimit", MaxTotalApprovers)
			members = members[:remainingCapacity]
		}

		countBefore := len(result.allApprovers)
		for _, member := range members {
			result.allApprovers = addIfNotPresent(result.allApprovers, member)
		}
		countAdded := len(result.allApprovers) - countBefore
		reqLog.Debugw("Added group members to approvers",
			"group", system.RedactGroupName(group),
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
		"user", userIdentifier, "group", system.RedactGroupName(groupName), "state", ses.Status.State)
	// Remove k8s internal fields before returning session in API response
	dropK8sInternalFieldsSession(&ses)

	// Approved session -> explicit "already approved" error
	if ses.Status.State == breakglassv1alpha1.SessionStateApproved || !ses.Status.ApprovedAt.IsZero() {
		respondDuplicateSessionConflict(c, "already approved", ses)
		return false
	}

	// Pending (requested but not yet approved/rejected) -> "already requested" with linked session
	if IsSessionPendingApproval(ses) {
		respondDuplicateSessionConflict(c, "already requested", ses)
		return false
	}

	// Fallback: session exists but in another terminal state (e.g. timeout) — return generic conflict with session
	respondDuplicateSessionConflict(c, "session exists", ses)
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
	if wc.clusterConfigManager != nil && wc.clusterConfigManager.hasClient() {
		var ccErr error
		clusterConfig, ccErr = wc.clusterConfigManager.GetClusterConfigByName(ctx, request.Clustername)
		if ccErr != nil {
			if !apierrors.IsNotFound(ccErr) {
				apiresponses.RespondInternalError(c, "resolve cluster user identifier policy", ccErr, reqLog)
				return "", nil, false
			}
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
	escalationHasIDPRestriction := len(matchedEsc.Spec.AllowedIdentityProviders) > 0 ||
		len(matchedEsc.Spec.AllowedIdentityProvidersForRequests) > 0
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
		reqLog.Debugw("Matched escalation found during session creation",
			"escalationName", params.matchedEsc.Name, "escalationUID", params.matchedEsc.UID, "escalationNamespace", params.matchedEsc.Namespace)
		bs.Namespace = params.matchedEsc.Namespace
		if params.matchedEsc.UID == "" {
			err := fmt.Errorf("matched escalation %s/%s has no UID", params.matchedEsc.Namespace, params.matchedEsc.Name)
			reqLog.Errorw("Refusing to create session for matched escalation without UID",
				"error", err, "escalationName", params.matchedEsc.Name, "escalationNamespace", params.matchedEsc.Namespace)
			apiresponses.RespondInternalError(c, "resolve matched escalation identity", err, reqLog)
			return nil, false
		}
		// Attach owner reference so the session can be linked back to its escalation.
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
		reqLog.Debugw("No matching escalation found during session creation; no ownerRef will be attached", "requestedGroup", system.RedactGroupName(params.request.GroupName), "cluster", params.request.Clustername)
	}

	// If no escalation was matched, reject creation: sessions must be tied to an escalation
	if params.matchedEsc == nil {
		reqLog.Warnw("Refusing to create session without matched escalation", "user", params.userIdentifier, "cluster", params.request.Clustername, "group", system.RedactGroupName(params.request.GroupName))
		apiresponses.RespondForbidden(c, "no escalation found for requested group")
		return nil, false
	}

	// Check session limits (IDP-level with escalation overrides) before creating a provisional object.
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
	if wc.sessionManager.quotaEnabled {
		groups, err := json.Marshal(params.userGroups)
		if err != nil {
			apiresponses.RespondInternalError(c, "encode admission groups", err, reqLog)
			return nil, false
		}
		bs.Annotations = map[string]string{quotas.AdmissionAnnotation: quotas.Pending, "breakglass.t-caas.telekom.com/quota-user-groups": string(groups)}
	}
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

	if err := wc.sessionManager.admitSession(ctx, &bs); err != nil {
		// A failed/ambiguous admission remains provisional and cannot be approved.
		// Its durable reservation is never released by an HTTP worker timeout.
		if errors.Is(err, quotas.ErrFull) {
			apiresponses.RespondConflict(c, "session quota reached")
		} else {
			apiresponses.RespondInternalError(c, "reserve session quota", err, reqLog)
		}
		return nil, false
	}

	// Get approval timeout from escalation spec using helper
	approvalTimeout := ParseApprovalTimeout(params.matchedEsc.Spec, reqLog)
	if params.matchedEsc.Spec.ApprovalTimeout != "" {
		reqLog.Debugw("Using approval timeout from escalation spec", "approvalTimeout", approvalTimeout)
	}

	bs.Status = breakglassv1alpha1.BreakglassSessionStatus{
		TimeoutAt: metav1.NewTime(time.Now().UTC().Add(approvalTimeout)), // Approval timeout
		State:     breakglassv1alpha1.SessionStatePending,
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
			"group", system.RedactGroupName(bs.Spec.GrantedGroup))
		return
	}

	reqLog.Infow("Resolved approvers from escalation (explicit users + group members)",
		"approverCount", len(allApprovers),
		"cluster", bs.Spec.Cluster,
		"group", system.RedactGroupName(bs.Spec.GrantedGroup))

	reqLog.Debugw("About to send breakglass request email",
		"approvalsRequired", len(allApprovers),
		"requestorEmail", authEmail,
		"requestorUsername", username,
		"group", system.RedactGroupName(bs.Spec.GrantedGroup),
		"cluster", bs.Spec.Cluster)

	if len(allApprovers) == 0 {
		reqLog.Warnw("No approvers resolved for email notification; cannot send email with empty recipients",
			"group", system.RedactGroupName(bs.Spec.GrantedGroup),
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
					log.Warnw("Group member resolution failed during sync", "group", system.RedactGroupName(g), "error", merr)
					continue
				}
				log.Debugw("Resolved group members for sync", "group", system.RedactGroupName(g), "count", len(members))
			}
		}(goroutineLog)
	}

	// Filter out excluded users/groups and hidden groups from approvers list
	reqLog.Debugw("About to filter approvers",
		"escalationName", matchedEsc.Name,
		"preFilterApproverCount", len(allApprovers))

	filteredApprovers, exclusionsSuppressed := wc.filterExcludedNotificationRecipients(reqLog, allApprovers, approversByGroup, matchedEsc)
	if exclusionsSuppressed {
		reqLog.Warnw("Suppressing session request notifications because excluded-group membership could not be resolved",
			"escalationName", matchedEsc.Name,
			"originalApproverCount", len(allApprovers))
		return
	}
	reqLog.Debugw("After filterExcludedNotificationRecipients",
		"postExcludeApproverCount", len(filteredApprovers),
		"excludedCount", len(allApprovers)-len(filteredApprovers))

	preHiddenApproverCount := len(filteredApprovers)
	filteredApprovers, hiddenSuppressed := wc.filterHiddenFromUIRecipients(reqLog, filteredApprovers, approversByGroup, matchedEsc)
	if hiddenSuppressed {
		reqLog.Warnw("Suppressing session request notifications because hidden-group membership could not be resolved",
			"escalationName", matchedEsc.Name,
			"originalApproverCount", len(allApprovers))
		return
	}
	reqLog.Debugw("After filterHiddenFromUIRecipients",
		"postHiddenFilterApproverCount", len(filteredApprovers),
		"hiddenFilteredOutCount", preHiddenApproverCount-len(filteredApprovers))

	if len(filteredApprovers) == 0 {
		reqLog.Infow("No approvers remain eligible for session request notifications after configured exclusions and hidden approvers",
			"escalationName", matchedEsc.Name,
			"originalApproverCount", len(allApprovers))
		return
	}

	// Send recipient notifications with all matching groups from bounded snapshots.
	wc.sendOnRequestEmailsByGroup(reqLog, bs, authEmail, username, filteredApprovers, approversByGroup, matchedEsc)
}

// notificationApproverProviders follows role-specific, then legacy restrictions.
func notificationApproverProviders(escalation *breakglassv1alpha1.BreakglassEscalation) []string {
	if len(escalation.Spec.AllowedIdentityProvidersForApprovers) > 0 {
		return escalation.Spec.AllowedIdentityProvidersForApprovers
	}
	return escalation.Spec.AllowedIdentityProviders
}

// restrictedNotificationGroupMembers never substitutes aggregate/default-provider
// membership for an unresolved allowed provider. Empty resolved groups are known.
func restrictedNotificationGroupMembers(escalation *breakglassv1alpha1.BreakglassEscalation, group string) ([]string, bool) {
	var members []string
	seen := make(map[string]bool)
	for _, provider := range notificationApproverProviders(escalation) {
		providerMembers, known := escalation.Status.IDPGroupMemberships[provider][group]
		if !known {
			return nil, false
		}
		for _, member := range providerMembers {
			if !seen[member] {
				seen[member] = true
				members = append(members, member)
			}
		}
	}
	return members, true
}
