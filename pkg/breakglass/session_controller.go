package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/naming"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	MonthDuration            = time.Hour * 24 * 30
	WeekDuration             = time.Hour * 24 * 7
	DefaultValidForDuration  = time.Hour
	DefaultRetainForDuration = MonthDuration
	APIContextTimeout        = 30 * time.Second // Timeout for API operations like session listing

	// MaxApproverGroupMembers limits the number of members resolved from a single approver group.
	// This prevents resource exhaustion from malicious or misconfigured groups with millions of members.
	// A warning is logged when truncation occurs.
	// NOTE: If you change this constant, also update the documentation in:
	//   - docs/configuration-reference.md (Approver Resolution Limits section)
	MaxApproverGroupMembers = 1000

	// MaxTotalApprovers limits the total number of unique approvers collected across all groups.
	// This provides an overall cap regardless of how many groups are configured. When this limit is
	// exceeded, additional approvers are ignored and a warning is logged to prevent resource exhaustion.
	// NOTE: If you change this constant, also update the documentation in:
	//   - docs/configuration-reference.md (Approver Resolution Limits section)
	MaxTotalApprovers = 5000
)

var ErrSessionNotFound error = errors.New("session not found")

// ApprovalCheckResult encapsulates the result of checking whether a user can approve a session.
// It provides specific denial reasons to enable proper error responses (401 vs 403) and user-friendly messages.
type ApprovalCheckResult struct {
	// Allowed is true if the user is authorized to approve/reject the session.
	Allowed bool
	// Reason describes why approval was denied (empty if Allowed is true).
	Reason ApprovalDenialReason
	// Message is a human-readable explanation for the denial.
	Message string
}

// ApprovalDenialReason categorizes why a user cannot approve a session.
type ApprovalDenialReason string

const (
	// ApprovalDenialNone indicates approval is allowed.
	ApprovalDenialNone ApprovalDenialReason = ""
	// ApprovalDenialUnauthenticated indicates the user's identity could not be verified.
	ApprovalDenialUnauthenticated ApprovalDenialReason = "UNAUTHENTICATED"
	// ApprovalDenialSelfApprovalBlocked indicates self-approval is blocked for this escalation/cluster.
	ApprovalDenialSelfApprovalBlocked ApprovalDenialReason = "SELF_APPROVAL_BLOCKED"
	// ApprovalDenialDomainNotAllowed indicates the approver's email domain is not in the allowed list.
	ApprovalDenialDomainNotAllowed ApprovalDenialReason = "DOMAIN_NOT_ALLOWED"
	// ApprovalDenialNotAnApprover indicates the user is not in any approver group/list for matching escalations.
	ApprovalDenialNotAnApprover ApprovalDenialReason = "NOT_AN_APPROVER"
	// ApprovalDenialNoMatchingEscalation indicates no escalation was found for the session's granted group.
	ApprovalDenialNoMatchingEscalation ApprovalDenialReason = "NO_MATCHING_ESCALATION"
)

// BreakglassSessionRequest is defined in clusteruser.go and includes an optional Reason field.

type BreakglassSessionController struct {
	log               *zap.SugaredLogger
	config            config.Config
	configPath        string               // Path to breakglass config file for OIDC prefix stripping
	configLoader      *config.CachedLoader // Cached config loader to avoid disk reads per request
	sessionManager    *SessionManager
	escalationManager EscalationLookup
	middleware        gin.HandlerFunc
	identityProvider  IdentityProvider
	mail              mail.Sender
	mailQueue         *mail.Queue
	mailService       MailEnqueuer
	auditService      AuditEmitter
	getUserGroupsFn   GetUserGroupsFunction
	disableEmail      bool
	ccProvider        interface {
		GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
	}
	clusterConfigManager *ClusterConfigManager

	// inFlightCreates prevents TOCTOU race conditions during session creation.
	// Without this guard, two concurrent requests for the same (cluster, user, group)
	// triple could both pass the duplicate check and create duplicate sessions.
	// The map key is "cluster/user/group". Effective for single-replica deployments;
	// multi-replica setups should additionally rely on webhook-based uniqueness enforcement.
	// Must be a pointer so it survives value-receiver method copies.
	inFlightCreates *sync.Map
}

// MailEnqueuer is an interface for enqueueing emails
type MailEnqueuer interface {
	Enqueue(sessionID string, recipients []string, subject, body string) error
	IsEnabled() bool
}

// AuditEmitter is an interface for emitting audit events
type AuditEmitter interface {
	Emit(ctx context.Context, event *audit.Event)
	IsEnabled() bool
}

// IsSessionPendingApproval returns true if the session is in Pending state (state-first validation)
// State takes absolute priority over timestamps. Terminal states (Rejected, Withdrawn, Expired, Timeout)
// are never pending, regardless of timestamp values.
func IsSessionPendingApproval(session breakglassv1alpha1.BreakglassSession) bool {
	// CRITICAL: Check STATE FIRST - terminal states are never pending
	if session.Status.State == breakglassv1alpha1.SessionStateRejected ||
		session.Status.State == breakglassv1alpha1.SessionStateWithdrawn ||
		session.Status.State == breakglassv1alpha1.SessionStateExpired ||
		session.Status.State == breakglassv1alpha1.SessionStateIdleExpired ||
		session.Status.State == breakglassv1alpha1.SessionStateTimeout {
		return false
	}

	// CRITICAL: Only Pending state is pending (not WaitingForScheduledTime or Approved)
	if session.Status.State != breakglassv1alpha1.SessionStatePending {
		return false
	}

	// Now verify timeout status (secondary check after state verification)
	// If TimeoutAt is set and has passed, session is in timeout state (not pending)
	if !session.Status.TimeoutAt.IsZero() && time.Now().After(session.Status.TimeoutAt.Time) {
		return false
	}

	return true
}

func (BreakglassSessionController) BasePath() string {
	return "breakglassSessions"
}

func (wc *BreakglassSessionController) Register(rg *gin.RouterGroup) error {
	// RESTful endpoints for breakglass sessions (no leading slash)
	rg.GET("", InstrumentedHandler("handleGetBreakglassSessionStatus", wc.handleGetBreakglassSessionStatus))           // List/filter sessions
	rg.GET(":name", InstrumentedHandler("handleGetBreakglassSessionByName", wc.handleGetBreakglassSessionByName))      // Get single session by name
	rg.POST("", InstrumentedHandler("handleRequestBreakglassSession", wc.handleRequestBreakglassSession))              // Create session
	rg.POST(":name/approve", InstrumentedHandler("handleApproveBreakglassSession", wc.handleApproveBreakglassSession)) // Approve session
	rg.POST(":name/reject", InstrumentedHandler("handleRejectBreakglassSession", wc.handleRejectBreakglassSession))    // Reject session
	rg.POST(":name/withdraw", InstrumentedHandler("handleWithdrawMyRequest", wc.handleWithdrawMyRequest))              // Withdraw session (by requester)
	rg.POST(":name/drop", InstrumentedHandler("handleDropMySession", wc.handleDropMySession))                          // Drop session (owner can drop active or pending)
	rg.POST(":name/cancel", InstrumentedHandler("handleApproverCancel", wc.handleApproverCancel))                      // Approver cancels a running/approved session
	return nil
}

// decodeJSONStrict decodes JSON from an io.Reader into dest with DisallowUnknownFields
// enabled. This ensures that requests with unknown/typo'd field names are rejected
// rather than silently ignored, helping catch client bugs and typos early.
// It also ensures that the body contains exactly one JSON value and no trailing
// non-whitespace content.
func decodeJSONStrict(r io.Reader, dest interface{}) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dest); err != nil {
		return err
	}

	// Ensure there is no extra non-whitespace data after the first JSON value.
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected extra JSON input")
		}
		return err
	}

	return nil
}

// validateSessionRequest validates the session request input
func (wc *BreakglassSessionController) validateSessionRequest(request BreakglassSessionRequest) error {
	if request.Clustername == "" {
		return errors.New("cluster is required")
	}
	if request.Username == "" {
		return errors.New("user is required")
	}
	if request.GroupName == "" {
		return errors.New("group is required")
	}
	return nil
}

// addIfNotPresent appends value to the slice only if it's not already present.
// Uses slices.Contains for efficiency.
func addIfNotPresent[T comparable](slice []T, value T) []T {
	if !slices.Contains(slice, value) {
		slice = append(slice, value)
	}
	return slice
}

func (wc *BreakglassSessionController) handleRequestBreakglassSession(c *gin.Context) {
	// Get correlation ID for consistent logging
	// request-scoped logger (includes cid, method, path)
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)
	reqLog.Info("Processing breakglass session request")

	var request BreakglassSessionRequest
	if err := decodeJSONStrict(c.Request.Body, &request); err != nil {
		reqLog.With("error", err).Error("Failed to decode JSON request body")
		apiresponses.RespondUnprocessableEntity(c, "failed to decode JSON request body (invalid JSON or unknown fields)")
		return
	}

	// Debug: log decoded request to help trace missing or malformed fields in e2e
	reqLog.Debugw("Decoded breakglass session request", "request", request)

	// Resolve authenticated identities and enforce request user matching
	authEmail, emailErr := wc.identityProvider.GetEmail(c)
	authUsername := wc.identityProvider.GetUsername(c)
	authUserID := wc.identityProvider.GetIdentity(c)
	authIdentifiers := collectAuthIdentifiers(authEmail, authUsername, authUserID)
	if len(authIdentifiers) == 0 {
		reqLog.Error("No authenticated identity claims found in request context")
		apiresponses.RespondUnauthorizedWithMessage(c, "user identity not found")
		return
	}
	if request.Username == "" {
		// default to authenticated identity to avoid spoofing
		request.Username = firstNonEmpty(authEmail, authUsername, authUserID)
	} else if !matchesAuthIdentifier(request.Username, authIdentifiers) {
		reqLog.Warnw("Request username does not match authenticated identity",
			"requestUsername", request.Username,
			"authIdentifiers", authIdentifiers)
		apiresponses.RespondForbidden(c, "user identity mismatch")
		return
	}

	if err := wc.validateSessionRequest(request); err != nil {
		reqLog.With("error", err, "request", request).Warn("Invalid session request parameters")
		apiresponses.RespondUnprocessableEntity(c, "missing input request data: "+err.Error())
		return
	}

	// Sanitize reason field to prevent injection attacks
	if err := request.SanitizeReason(); err != nil {
		reqLog.With("error", err).Warn("Reason field sanitization failed")
		apiresponses.RespondUnprocessableEntity(c, "invalid reason: "+err.Error())
		return
	}

	ctx := c.Request.Context()
	cug := ClusterUserGroup{
		Clustername: request.Clustername,
		Username:    request.Username,
		GroupName:   request.GroupName,
	}
	reqLog = reqLog.With("cluster", cug.Clustername, "user", cug.Username, "group", cug.GroupName)
	reqLog.Info("Validated session request parameters")

	// Load global config via cached loader (avoids disk reads per request)
	var globalCfg *config.Config
	if wc.configLoader != nil {
		if cfg, cerr := wc.configLoader.Get(); cerr == nil {
			globalCfg = &cfg
		} else {
			reqLog.With("error", fmt.Errorf("cached config load failed: %w", cerr)).Debug("Continuing without global config")
		}
	}

	// Resolve user groups: prefer token groups, fallback to cluster-based resolution
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
			return
		}
	}
	// Strip OIDC prefixes if configured (cluster retrieval might include them; token groups usually not)
	if globalCfg != nil && len(globalCfg.Kubernetes.OIDCPrefixes) > 0 {
		userGroups = StripOIDCPrefixes(userGroups, globalCfg.Kubernetes.OIDCPrefixes)
	}

	escalations, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(ctx, cug.Clustername, userGroups)
	if err != nil {
		reqLog.Errorw("Error getting breakglass escalations", "error", err)
		apiresponses.RespondInternalError(c, "extract cluster breakglass escalation information", err, reqLog)
		return
	}
	// We already filtered by cluster & user groups; treat these as possible escalations.
	possibleEscals := escalations
	// Note: Do NOT call dropK8sInternalFieldsEscalation here - we need the UID for owner references.
	// The UID stripping is only for API response serialization, not for internal processing.
	if len(possibleEscals) == 0 {
		// Provide extra debug information in logs to help e2e diagnosis when no escalations are found
		rawGroups, _ := c.Get("groups")
		reqLog.Warnw("No escalation groups found for user", "user", cug.Username, "requestedGroup", cug.GroupName, "cluster", cug.Clustername, "resolvedUserGroups", userGroups, "rawTokenGroups", rawGroups)
		// Also log any escalations that exist for the cluster for visibility
		if escList, err := wc.escalationManager.GetClusterBreakglassEscalations(ctx, cug.Clustername); err == nil {
			names := make([]string, 0, len(escList))
			for _, e := range escList {
				names = append(names, e.Name)
			}
			reqLog.Debugw("Cluster escalations (for visibility)", "cluster", cug.Clustername, "escalations", names)
		}
		// User is authenticated but not authorized for this group - return 403 Forbidden
		apiresponses.RespondForbidden(c, "user not authorized for requested group")
		return
	} else {
		reqLog.Debugw("Possible escalations found", "user", cug.Username, "cluster", cug.Clustername, "count", len(possibleEscals))
	}

	// Single pass: collect available groups, approvers, and find matched escalation
	possible := make([]string, 0, len(possibleEscals))
	// Track approvers by group: map[groupName][]approverEmails
	approversByGroup := make(map[string][]string)
	allApprovers := []string{} // Deduplicated list of all approvers for filtering
	selectedDenyPolicies := []string{}
	var matchedEsc *breakglassv1alpha1.BreakglassEscalation

	reqLog.Debugw("Starting approver resolution from escalations",
		"escalationCount", len(possibleEscals),
		"requestedGroup", request.GroupName)

	for i := range possibleEscals {
		p := &possibleEscals[i]
		possible = append(possible, p.Spec.EscalatedGroup)
		reqLog.Debugw("Processing escalation for approver resolution",
			"escalationName", p.Name,
			"escalatedGroup", p.Spec.EscalatedGroup,
			"explicitUserCount", len(p.Spec.Approvers.Users),
			"approverGroupCount", len(p.Spec.Approvers.Groups))

		// Always check if this is the matched escalation first (needed for deny policies)
		isMatchedEscalation := p.Spec.EscalatedGroup == request.GroupName && matchedEsc == nil
		if isMatchedEscalation {
			matchedEsc = p
			selectedDenyPolicies = append(selectedDenyPolicies, p.Spec.DenyPolicyRefs...)
			reqLog.Debugw("Matched escalation found during approver collection",
				"escalationName", matchedEsc.Name,
				"escalatedGroup", matchedEsc.Spec.EscalatedGroup,
				"denyPolicyCount", len(selectedDenyPolicies))
		}

		// Check total approvers limit before processing this escalation's approvers
		if len(allApprovers) >= MaxTotalApprovers {
			// If we've already found the matched escalation, break out entirely
			// to avoid unnecessary work and log spam
			if matchedEsc != nil {
				reqLog.Infow("Total approvers limit reached and matched escalation found, stopping",
					"limit", MaxTotalApprovers,
					"matchedEscalation", matchedEsc.Name)
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
			if len(allApprovers) >= MaxTotalApprovers {
				reqLog.Warnw("Total approvers limit reached while adding explicit users",
					"limit", MaxTotalApprovers,
					"escalation", p.Name)
				break
			}
			before := len(allApprovers)
			allApprovers = addIfNotPresent(allApprovers, user)
			if len(allApprovers) > before {
				// Explicit users are tracked separately
				approversByGroup["_explicit_users"] = addIfNotPresent(approversByGroup["_explicit_users"], user)
				reqLog.Debugw("Added explicit approver user",
					"user", user,
					"escalation", p.Name,
					"totalApproversNow", len(allApprovers))
			}
		}

		// Resolve and add group members (deduplicated)
		for _, group := range p.Spec.Approvers.Groups {
			// Check total approvers limit before processing this group
			if len(allApprovers) >= MaxTotalApprovers {
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
			remainingCapacity := MaxTotalApprovers - len(allApprovers)
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

			countBefore := len(allApprovers)
			for _, member := range members {
				allApprovers = addIfNotPresent(allApprovers, member)
				// Track member as belonging to this group
				approversByGroup[group] = addIfNotPresent(approversByGroup[group], member)
			}
			countAdded := len(allApprovers) - countBefore
			reqLog.Debugw("Added group members to approvers",
				"group", group,
				"escalation", p.Name,
				"newMembersAdded", countAdded,
				"totalApproversNow", len(allApprovers))
		}

		// Break outer loop if we've reached the maximum total approvers AND
		// we've already found the matched escalation. If matchedEsc is nil,
		// let the loop continue — the top-of-loop check will skip approver
		// resolution but still identify the matched escalation.
		if len(allApprovers) >= MaxTotalApprovers && matchedEsc != nil {
			reqLog.Infow("Maximum total approvers limit reached, stopping escalation processing",
				"limit", MaxTotalApprovers,
				"matchedEscalation", matchedEsc.Name)
			break
		}
	}

	// Note: individual approvers not logged to reduce PII exposure
	reqLog.Infow("Completed approver resolution from escalations",
		"totalApproversCollected", len(allApprovers),
		"approverGroupsCount", len(approversByGroup),
		"requestedGroup", request.GroupName)

	if !slices.Contains(possible, request.GroupName) {
		reqLog.Warnw("User not authorized for group", "user", request.Username, "group", request.GroupName)
		// User is authenticated but not authorized for this group - return 403 Forbidden
		apiresponses.RespondForbidden(c, "user not authorized for requested group")
		return
	}
	if matchedEsc != nil && matchedEsc.Spec.RequestReason != nil && matchedEsc.Spec.RequestReason.Mandatory {
		if strings.TrimSpace(request.Reason) == "" {
			reqLog.Warnw("Missing required request reason", "group", request.GroupName)
			apiresponses.RespondUnprocessableEntity(c, "missing required request reason")
			return
		}
	}

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
		return
	}
	reqLog.Debugw("Resolved user identifier for session",
		"userIdentifier", userIdentifier,
		"userIdentifierClaim", userIdentifierClaim,
		"requestUsername", request.Username)

	// Guard against TOCTOU race: serialize concurrent session creation requests
	// for the same (cluster, user, group) triple so the duplicate check below
	// cannot be bypassed by a second request arriving before the first creates
	// the session in the API server.
	if wc.inFlightCreates != nil {
		createKey := request.Clustername + "/" + userIdentifier + "/" + request.GroupName
		if _, loaded := wc.inFlightCreates.LoadOrStore(createKey, true); loaded {
			reqLog.Infow("Concurrent session creation already in-flight, returning conflict",
				"cluster", request.Clustername, "user", userIdentifier, "group", request.GroupName)
			c.JSON(http.StatusConflict, gin.H{"error": "session creation already in progress"})
			return
		}
		defer wc.inFlightCreates.Delete(createKey)
	}

	ses, err := wc.getActiveBreakglassSession(ctx,
		userIdentifier, request.Clustername, request.GroupName)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			reqLog.Errorw("Error getting breakglass sessions", "error", err)
			apiresponses.RespondInternalError(c, "extract breakglass session information", err, reqLog)
			return
		}
	} else {
		// A matching session exists; decide response based on its canonical state.
		reqLog.Infow("Existing session found", "session", ses.Name, "cluster", request.Clustername, "user", userIdentifier, "group", request.GroupName, "state", ses.Status.State)
		// Remove k8s internal fields before returning session in API response
		dropK8sInternalFieldsSession(&ses)

		// Approved session -> explicit "already approved" error
		if ses.Status.State == breakglassv1alpha1.SessionStateApproved || !ses.Status.ApprovedAt.IsZero() {
			c.JSON(http.StatusConflict, gin.H{"error": "already approved", "session": ses})
			return
		}

		// Pending (requested but not yet approved/rejected) -> "already requested" with linked session
		if IsSessionPendingApproval(ses) {
			c.JSON(http.StatusConflict, gin.H{"error": "already requested", "session": ses})
			return
		}

		// Fallback: session exists but in another terminal state (e.g. timeout) — return generic conflict with session
		c.JSON(http.StatusConflict, gin.H{"error": "session exists", "session": ses})
		return
	}

	if authEmail == "" {
		reqLog.Errorw("Error getting user identity email", "error", emailErr)
		apiresponses.RespondInternalError(c, "extract email from token", emailErr, reqLog)
		return
	}
	username := wc.identityProvider.GetUsername(c)

	reqLog.Debugw("Session creation initiated by user",
		"requestorEmail", authEmail,
		"requestorUsername", username,
		"requestedGroup", request.GroupName,
		"requestedCluster", request.Clustername)

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

	if matchedEsc != nil {
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
				return
			}
			maxAllowed := int64(d.Seconds())
			if err := request.ValidateDuration(maxAllowed); err != nil {
				reqLog.Warnw("Duration validation failed", "error", err, "requestedDuration", request.Duration, "maxAllowed", maxAllowed)
				apiresponses.RespondUnprocessableEntity(c, "invalid duration: "+err.Error())
				return
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
				return
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
				return
			}

			spec.ScheduledStartTime = &metav1.Time{Time: scheduledTime}
			reqLog.Debugw("Scheduled start time set",
				"scheduledStartTimeISO", request.ScheduledStartTime,
				"scheduledTimeUTC", scheduledTime.Format(time.RFC3339),
				"scheduledTimeLocal", scheduledTime.Local().Format(time.RFC3339),
				"nowUTC", now.Format(time.RFC3339),
				"secondsInFuture", scheduledTime.Unix()-now.Unix())
		}
	}

	bs := breakglassv1alpha1.BreakglassSession{Spec: spec}
	// Add labels to sessions so label selectors can operate when field indices are unavailable
	if bs.Labels == nil {
		bs.Labels = map[string]string{}
	}
	// Sanitize label values to conform to Kubernetes label restrictions (RFC1123-ish)
	bs.Labels["breakglass.t-caas.telekom.com/cluster"] = naming.ToRFC1123Label(request.Clustername)
	bs.Labels["breakglass.t-caas.telekom.com/user"] = naming.ToRFC1123Label(userIdentifier) // Use resolved identifier, not request.Username
	bs.Labels["breakglass.t-caas.telekom.com/group"] = naming.ToRFC1123Label(request.GroupName)
	// Ensure session is created in the same namespace as the matched escalation
	if matchedEsc != nil {
		reqLog.Debugw("Matched escalation found during session creation; attaching ownerRef",
			"escalationName", matchedEsc.Name, "escalationUID", matchedEsc.UID, "escalationNamespace", matchedEsc.Namespace)
		bs.Namespace = matchedEsc.Namespace
		// Attach owner reference so the session can be linked back to its escalation
		// This allows other components (webhook/controller) to resolve the escalation
		// via the session's OwnerReferences.
		bs.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: breakglassv1alpha1.GroupVersion.String(),
			Kind:       "BreakglassEscalation",
			Name:       matchedEsc.Name,
			UID:        matchedEsc.UID,
			// Controller and BlockOwnerDeletion are optional; set Controller=true for clarity.
			Controller: func() *bool { b := true; return &b }(),
		}}
		reqLog.Debugw("OwnerReference prepared for session create", "ownerRefs", bs.OwnerReferences)
	} else {
		reqLog.Debugw("No matching escalation found during session creation; no ownerRef will be attached", "requestedGroup", request.GroupName, "cluster", request.Clustername)
	}

	// If no escalation was matched, reject creation: sessions must be tied to an escalation
	if matchedEsc == nil {
		reqLog.Warnw("Refusing to create session without matched escalation", "user", userIdentifier, "cluster", request.Clustername, "group", request.GroupName)
		apiresponses.RespondUnauthorizedWithMessage(c, "no escalation found for requested group")
		return
	}

	// Check session limits (IDP-level with escalation overrides)
	if err := wc.checkSessionLimits(ctx, matchedEsc, spec.IdentityProviderName, userIdentifier, userGroups, reqLog); err != nil {
		reqLog.Warnw("Session limit check failed", "error", err, "escalation", matchedEsc.Name, "user", userIdentifier)
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
		return
	}

	// Generate RFC1123-safe name parts for cluster and group
	safeCluster := naming.ToRFC1123Subdomain(request.Clustername)
	safeGroup := naming.ToRFC1123Subdomain(request.GroupName)
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
		metrics.SessionCreateFailed.WithLabelValues(request.Clustername, reason).Inc()
		return
	}
	// Note: bs already has its Name populated by AddBreakglassSession (passed as pointer).
	// Do not try to fetch it again as this can race with informer cache population.
	// Instead, reuse the bs object that was created.

	// Get approval timeout from escalation spec using helper
	approvalTimeout := ParseApprovalTimeout(matchedEsc.Spec, reqLog)
	if matchedEsc.Spec.ApprovalTimeout != "" {
		reqLog.Debugw("Using approval timeout from escalation spec", "approvalTimeout", approvalTimeout)
	}

	// Compute retained-until at creation so sessions always expose when they will be cleaned up.
	retainFor := ParseRetainFor(spec, reqLog)

	bs.Status = breakglassv1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(retainFor)),
		TimeoutAt:     metav1.NewTime(time.Now().Add(approvalTimeout)), // Approval timeout
		State:         breakglassv1alpha1.SessionStatePending,
		Conditions: []metav1.Condition{{
			Type:               string(breakglassv1alpha1.SessionConditionTypeIdle),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(breakglassv1alpha1.SessionConditionReasonEditedByApprover),
			Message:            fmt.Sprintf("User %q requested session.", username),
		}},
	}

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(ctx, bs); err != nil {
		reqLog.Errorw("error while updating breakglass session", "error", err)
		apiresponses.RespondInternalError(c, "update session status", err, reqLog)
		return
	}

	if wc.disableEmail {
		reqLog.Debug("Email sending disabled via --disable-email flag")
	} else if matchedEsc.Spec.DisableNotifications != nil && *matchedEsc.Spec.DisableNotifications {
		reqLog.Infow("Email sending disabled for this escalation via DisableNotifications",
			"escalationName", matchedEsc.Name,
			"cluster", bs.Spec.Cluster,
			"grantedGroup", bs.Spec.GrantedGroup)
	} else {
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
		} else {
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
			} else {
				// Send separate emails per approver group
				// Each email shows only the specific group that matched
				wc.sendOnRequestEmailsByGroup(reqLog, bs, authEmail, username, filteredApprovers, approversByGroup, matchedEsc)
			}
		}
	}

	// Emit audit event for session creation
	wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionRequested, &bs, request.Username, "Session requested")

	reqLog.Debugw("Session created", "user", request.Username, "cluster", request.Clustername, "group", request.GroupName, "generatedName", bs.Name)
	c.JSON(http.StatusCreated, bs)
}
