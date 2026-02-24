package breakglass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
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
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	escalationManager *EscalationManager
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
	rg.GET("", instrumentedHandler("handleGetBreakglassSessionStatus", wc.handleGetBreakglassSessionStatus))           // List/filter sessions
	rg.GET(":name", instrumentedHandler("handleGetBreakglassSessionByName", wc.handleGetBreakglassSessionByName))      // Get single session by name
	rg.POST("", instrumentedHandler("handleRequestBreakglassSession", wc.handleRequestBreakglassSession))              // Create session
	rg.POST(":name/approve", instrumentedHandler("handleApproveBreakglassSession", wc.handleApproveBreakglassSession)) // Approve session
	rg.POST(":name/reject", instrumentedHandler("handleRejectBreakglassSession", wc.handleRejectBreakglassSession))    // Reject session
	rg.POST(":name/withdraw", instrumentedHandler("handleWithdrawMyRequest", wc.handleWithdrawMyRequest))              // Withdraw session (by requester)
	rg.POST(":name/drop", instrumentedHandler("handleDropMySession", wc.handleDropMySession))                          // Drop session (owner can drop active or pending)
	rg.POST(":name/cancel", instrumentedHandler("handleApproverCancel", wc.handleApproverCancel))                      // Approver cancels a running/approved session
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
		userGroups = stripOIDCPrefixes(userGroups, globalCfg.Kubernetes.OIDCPrefixes)
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
	includeMine := parseBoolQuery(c.Query("mine"), false)
	includeApprover := parseBoolQuery(c.Query("approver"), true)
	includeApprovedByMe := parseBoolQuery(c.Query("approvedByMe"), false)
	activeOnly := parseBoolQuery(c.Query("activeOnly"), false)
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

// checkApprovalAuthorization performs a detailed check of whether the current user can approve/reject a session.
// It returns an ApprovalCheckResult with specific denial reasons instead of a simple boolean.
func (wc *BreakglassSessionController) checkApprovalAuthorization(c *gin.Context, session breakglassv1alpha1.BreakglassSession) ApprovalCheckResult {
	reqLog := system.GetReqLogger(c, wc.log)

	email, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.Error("Error getting user identity", zap.Error(err))
		return ApprovalCheckResult{
			Allowed: false,
			Reason:  ApprovalDenialUnauthenticated,
			Message: "Unable to verify user identity",
		}
	}
	reqLog.Debugw("Approver identity verified", "email", email, "cluster", session.Spec.Cluster)
	ctx := c.Request.Context()
	approverID := ClusterUserGroup{Username: email, Clustername: session.Spec.Cluster}

	// Base defaults for escalation evaluation
	var baseBlockSelfApproval bool
	var baseAllowedApproverDomains []string

	// Gather approver groups with caching
	cacheKey := "approverGroups_" + email
	var approverGroups []string
	if cached, ok := c.Get(cacheKey); ok {
		approverGroups = cached.([]string)
	} else {
		var gerr error
		approverGroups, gerr = wc.getUserGroupsFn(ctx, approverID)
		if raw, ok := c.Get("groups"); ok {
			if arr, ok2 := raw.([]string); ok2 && len(arr) > 0 {
				approverGroups = arr
			}
		} else if gerr != nil {
			reqLog.Errorw("[E2E-DEBUG] Approver group error", "error", gerr)
			return ApprovalCheckResult{
				Allowed: false,
				Reason:  ApprovalDenialUnauthenticated,
				Message: "Unable to retrieve user groups",
			}
		}
		c.Set(cacheKey, approverGroups)
	}

	escalations, err := wc.escalationManager.GetClusterBreakglassEscalations(ctx, session.Spec.Cluster)
	if err != nil {
		reqLog.Error("Error listing cluster escalations for approval", zap.Error(err))
		return ApprovalCheckResult{
			Allowed: false,
			Reason:  ApprovalDenialNoMatchingEscalation,
			Message: "Error retrieving escalation configuration",
		}
	}

	// Track the most specific denial reason encountered during evaluation.
	// Priority: SelfApprovalBlocked > DomainNotAllowed > NotAnApprover > NoMatchingEscalation
	var mostSpecificDenial ApprovalCheckResult
	foundMatchingEscalation := false

	reqLog.Debugw("Approver evaluation context", "session", session.Name, "sessionGrantedGroup", session.Spec.GrantedGroup, "candidateEscalationCount", len(escalations), "approverEmail", email)
	for _, esc := range escalations {
		if esc.Spec.EscalatedGroup != session.Spec.GrantedGroup {
			continue
		}
		foundMatchingEscalation = true
		reqLog.Debugw("Evaluating matching escalation", "escalation", esc.Name, "users", len(esc.Spec.Approvers.Users), "groups", len(esc.Spec.Approvers.Groups))

		// Determine effective settings for this escalation
		effectiveBlockSelf := baseBlockSelfApproval
		effectiveAllowedDomains := baseAllowedApproverDomains
		if wc.clusterConfigManager != nil {
			if cc, cerr := wc.clusterConfigManager.GetClusterConfigInNamespace(c.Request.Context(), esc.Namespace, session.Spec.Cluster); cerr == nil && cc != nil {
				effectiveBlockSelf = cc.Spec.BlockSelfApproval
				effectiveAllowedDomains = cc.Spec.AllowedApproverDomains
			} else if cerr != nil {
				reqLog.Debugw("No ClusterConfig found in escalation namespace, continuing with defaults", "cluster", session.Spec.Cluster, "namespace", esc.Namespace, "error", cerr)
			}
		}
		if esc.Spec.BlockSelfApproval != nil {
			effectiveBlockSelf = *esc.Spec.BlockSelfApproval
		}
		if len(esc.Spec.AllowedApproverDomains) > 0 {
			effectiveAllowedDomains = esc.Spec.AllowedApproverDomains
		}

		// Check self-approval restriction
		if effectiveBlockSelf && email == session.Spec.User {
			reqLog.Debugw("Self-approval blocked by escalation/cluster setting", "escalation", esc.Name, "approver", email)
			// Track this as the most specific denial (highest priority)
			mostSpecificDenial = ApprovalCheckResult{
				Allowed: false,
				Reason:  ApprovalDenialSelfApprovalBlocked,
				Message: "Self-approval is not allowed for this cluster/escalation. Please ask another approver to approve your request.",
			}
			continue
		}

		// Check domain restrictions
		if len(effectiveAllowedDomains) > 0 {
			allowed := false
			for _, domain := range effectiveAllowedDomains {
				if strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain)) {
					allowed = true
					break
				}
			}
			if !allowed {
				reqLog.Warnw("Approver email does not match allowed domains for escalation", "escalation", esc.Name, "approver", email, "allowedDomains", effectiveAllowedDomains)
				// Only update if we haven't seen a more specific denial (self-approval blocked)
				if mostSpecificDenial.Reason != ApprovalDenialSelfApprovalBlocked {
					mostSpecificDenial = ApprovalCheckResult{
						Allowed: false,
						Reason:  ApprovalDenialDomainNotAllowed,
						Message: fmt.Sprintf("Your email domain is not in the list of allowed approver domains: %v", effectiveAllowedDomains),
					}
				}
				continue
			}
		}

		// Direct user approver check
		if slices.Contains(esc.Spec.Approvers.Users, email) {
			reqLog.Debugw("User is session approver (direct user)", "session", session.Name, "escalation", esc.Name, "user", email)
			return ApprovalCheckResult{Allowed: true}
		}

		// Multi-IDP aware group checking
		approverGroupsToCheck := esc.Spec.Approvers.Groups
		var dedupMembers []string

		if len(esc.Spec.AllowedIdentityProvidersForApprovers) > 0 && esc.Status.ApproverGroupMembers != nil {
			for _, g := range approverGroupsToCheck {
				if members, ok := esc.Status.ApproverGroupMembers[g]; ok {
					dedupMembers = append(dedupMembers, members...)
					reqLog.Debugw("Using deduplicated members from multi-IDP status",
						"escalation", esc.Name, "group", g, "memberCount", len(members))
				}
			}

			for _, member := range dedupMembers {
				if strings.EqualFold(member, email) {
					reqLog.Debugw("User is session approver (multi-IDP deduplicated group member)",
						"session", session.Name, "escalation", esc.Name, "member", email)
					return ApprovalCheckResult{Allowed: true}
				}
			}
		} else {
			for _, g := range approverGroupsToCheck {
				if slices.Contains(approverGroups, g) {
					reqLog.Debugw("User is session approver (legacy group)", "session", session.Name, "escalation", esc.Name, "group", g)
					return ApprovalCheckResult{Allowed: true}
				}
			}
		}

		// Not an approver for this escalation
		if len(esc.Spec.AllowedIdentityProvidersForApprovers) > 0 {
			reqLog.Debugw("Escalation found but user not in deduplicated approvers (continuing)",
				"session", session.Name, "escalation", esc.Name, "user", email, "dedupMemberCount", len(dedupMembers))
		} else {
			reqLog.Debugw("Escalation found but user not in approvers (continuing)",
				"session", session.Name, "escalation", esc.Name, "user", email, "userGroups", approverGroups, "approverUsers", esc.Spec.Approvers.Users, "approverGroups", esc.Spec.Approvers.Groups)
		}
		// Track not-an-approver as lowest priority denial
		if mostSpecificDenial.Reason == ApprovalDenialNone {
			mostSpecificDenial = ApprovalCheckResult{
				Allowed: false,
				Reason:  ApprovalDenialNotAnApprover,
				Message: "You are not in an approver group for this escalation",
			}
		}
	}

	// Return the most specific denial reason found, or no-matching-escalation if none found
	if !foundMatchingEscalation {
		reqLog.Debugw("No escalation with matching granted group for approval", "session", session.Name, "grantedGroup", session.Spec.GrantedGroup, "approverEmail", email, "approverGroups", approverGroups)
		return ApprovalCheckResult{
			Allowed: false,
			Reason:  ApprovalDenialNoMatchingEscalation,
			Message: "No matching escalation found for the session's granted group",
		}
	}

	return mostSpecificDenial
}

// isSessionApprover returns true if the current user is authorized to approve/reject the session.
// For detailed denial reasons, use checkApprovalAuthorization instead.
func (wc *BreakglassSessionController) isSessionApprover(c *gin.Context, session breakglassv1alpha1.BreakglassSession) bool {
	result := wc.checkApprovalAuthorization(c, session)
	return result.Allowed
}

// IsSessionRetained checks if a session should be removed (retainedUntil passed)
func IsSessionRetained(session breakglassv1alpha1.BreakglassSession) bool {
	if session.Status.RetainedUntil.IsZero() {
		return false
	}
	return time.Now().After(session.Status.RetainedUntil.Time)
}

func collectAuthIdentifiers(email, username, userID string) []string {
	identifiers := make([]string, 0, 3)
	if email != "" {
		identifiers = append(identifiers, email)
	}
	if username != "" {
		identifiers = append(identifiers, username)
	}
	if userID != "" {
		identifiers = append(identifiers, userID)
	}
	return identifiers
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func matchesAuthIdentifier(value string, identifiers []string) bool {
	if value == "" {
		return false
	}
	for _, id := range identifiers {
		if id == "" {
			continue
		}
		if strings.EqualFold(id, value) {
			return true
		}
	}
	return false
}

// IsSessionRejected returns true if session is in Rejected state (state-first validation)
func IsSessionRejected(session breakglassv1alpha1.BreakglassSession) bool {
	// CRITICAL: Check STATE FIRST - state is the ultimate truth
	return session.Status.State == breakglassv1alpha1.SessionStateRejected
}

// IsSessionWithdrawn returns true if session is in Withdrawn state (state-first validation)
func IsSessionWithdrawn(session breakglassv1alpha1.BreakglassSession) bool {
	// CRITICAL: Check STATE FIRST - state is the ultimate truth
	return session.Status.State == breakglassv1alpha1.SessionStateWithdrawn
}

// IsSessionExpired returns true if session is in Expired state OR (state is Approved AND ExpiresAt passed).
// State-first: Check terminal Expired state first, then timestamp for Approved state.
func IsSessionExpired(session breakglassv1alpha1.BreakglassSession) bool {
	// CRITICAL: Check STATE FIRST
	// If state is explicitly Expired, it is definitely expired
	if session.Status.State == breakglassv1alpha1.SessionStateExpired {
		return true
	}

	// For Approved state, check if the timestamp has passed (timestamp is secondary check)
	if session.Status.State == breakglassv1alpha1.SessionStateApproved {
		return !session.Status.ExpiresAt.Time.IsZero() && time.Now().After(session.Status.ExpiresAt.Time)
	}

	// All other states (terminal or non-Approved) are not considered expired by this function
	// Expired state is explicitly set via Status.State
	return false
}

func IsSessionValid(session breakglassv1alpha1.BreakglassSession) bool {
	// CRITICAL: Check terminal states FIRST. State is the ultimate truth.
	// Even if timestamps suggest validity, terminal states are never valid.
	if session.Status.State == breakglassv1alpha1.SessionStateRejected ||
		session.Status.State == breakglassv1alpha1.SessionStateWithdrawn ||
		session.Status.State == breakglassv1alpha1.SessionStateExpired ||
		session.Status.State == breakglassv1alpha1.SessionStateIdleExpired ||
		session.Status.State == breakglassv1alpha1.SessionStateTimeout {
		return false
	}

	// Session is not valid if it's in WaitingForScheduledTime state
	// (i.e., scheduled but not yet activated)
	if session.Status.State == breakglassv1alpha1.SessionStateWaitingForScheduledTime {
		return false
	}

	// Session is not valid if it has a scheduled start time in the future
	if session.Spec.ScheduledStartTime != nil && !session.Spec.ScheduledStartTime.IsZero() {
		if time.Now().Before(session.Spec.ScheduledStartTime.Time) {
			return false
		}
	}

	// Only now check if it has expired based on ExpiresAt timestamp
	// But only for approved sessions (which should have ExpiresAt set)
	if session.Status.State == breakglassv1alpha1.SessionStateApproved && IsSessionExpired(session) {
		return false
	}

	return true
}

// IsSessionActive returns if session can be approved or was already approved
// A session is active if it's valid and not in a terminal state.
// State is the primary determinant; timestamps are secondary validators.
func IsSessionActive(session breakglassv1alpha1.BreakglassSession) bool {
	// CRITICAL: Check terminal states FIRST. State is the ultimate truth.
	if session.Status.State == breakglassv1alpha1.SessionStateRejected ||
		session.Status.State == breakglassv1alpha1.SessionStateWithdrawn ||
		session.Status.State == breakglassv1alpha1.SessionStateExpired ||
		session.Status.State == breakglassv1alpha1.SessionStateIdleExpired ||
		session.Status.State == breakglassv1alpha1.SessionStateTimeout {
		return false
	}

	// Use general validity check for other state-based rules
	return IsSessionValid(session)
}

// isOwnedByEscalation checks if a session is owned by the given escalation by matching
// the owner reference UID. This ensures sessions from different escalations that grant
// the same group are counted separately.
func isOwnedByEscalation(session *breakglassv1alpha1.BreakglassSession, escalation *breakglassv1alpha1.BreakglassEscalation) bool {
	for _, ownerRef := range session.GetOwnerReferences() {
		if ownerRef.UID == escalation.UID {
			return true
		}
	}
	return false
}

func NewBreakglassSessionController(log *zap.SugaredLogger,
	cfg config.Config,
	sessionManager *SessionManager,
	escalationManager *EscalationManager,
	middleware gin.HandlerFunc,
	configPath string,
	ccProvider interface {
		GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
	},
	clusterConfigClient client.Client,
	disableEmail ...bool,
) *BreakglassSessionController {
	ip := KeycloakIdentityProvider{log: log}

	// Check if disableEmail flag is provided
	disableEmailFlag := false
	if len(disableEmail) > 0 {
		disableEmailFlag = disableEmail[0]
	}

	// NOTE: mail field is left nil by default. Use WithMailService() to configure email sending
	// via the MailProvider CRD (preferred), or WithQueue() for legacy queue support.
	// Tests can set mail directly via struct initialization with &FakeMailSender{}.

	ctrl := &BreakglassSessionController{
		log:                  log,
		config:               cfg,
		sessionManager:       sessionManager,
		escalationManager:    escalationManager,
		middleware:           middleware,
		identityProvider:     ip,
		mail:                 nil, // Do not create stub sender; use mailService via WithMailService()
		mailQueue:            nil,
		disableEmail:         disableEmailFlag,
		configPath:           configPath,
		configLoader:         config.NewCachedLoader(configPath, 5*time.Second), // Cache config, check file every 5s
		ccProvider:           ccProvider,
		clusterConfigManager: NewClusterConfigManager(clusterConfigClient, WithClusterConfigLogger(log)),
		inFlightCreates:      &sync.Map{},
	}

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		if ctrl.ccProvider != nil {
			if rc, err := ctrl.ccProvider.GetRESTConfig(ctx, cug.Clustername); err == nil && rc != nil {
				remote := rest.CopyConfig(rc)
				remote.Impersonate = rest.ImpersonationConfig{UserName: cug.Username}
				client, cerr := kubernetes.NewForConfig(remote)
				if cerr != nil {
					return nil, fmt.Errorf("remote client construction failed: %w", cerr)
				}
				res, rerr := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
				if rerr != nil {
					return nil, fmt.Errorf("remote SelfSubjectReview failed: %w", rerr)
				}
				ui := res.Status.UserInfo
				groups := ui.Groups
				// Use cached config loader for OIDC prefix stripping
				if ctrl.configLoader != nil {
					if cfgLoaded, lerr := ctrl.configLoader.Get(); lerr == nil && len(cfgLoaded.Kubernetes.OIDCPrefixes) > 0 {
						groups = stripOIDCPrefixes(groups, cfgLoaded.Kubernetes.OIDCPrefixes)
					}
				}
				log.Debugw("Resolved user groups via spoke cluster rest.Config", "cluster", cug.Clustername, "user", cug.Username, "groups", groups)
				return groups, nil
			}
			log.Debugw("Falling back to legacy GetUserGroupsWithConfig (kube context)", "cluster", cug.Clustername)
		}
		return GetUserGroupsWithConfig(ctx, cug, ctrl.configPath)
	}

	return ctrl
}

// sendSessionApprovalEmail sends an approval notification to the requester
func (wc *BreakglassSessionController) sendSessionApprovalEmail(log *zap.SugaredLogger, session breakglassv1alpha1.BreakglassSession) {
	// Check if mail is available (either via service or legacy queue)
	mailEnabled := (wc.mailService != nil && wc.mailService.IsEnabled()) || wc.mailQueue != nil
	if !mailEnabled {
		log.Warnw("mail not available, cannot send approval email", "session", session.Name)
		return
	}

	brandingName := "Breakglass"
	if wc.config.Frontend.BrandingName != "" {
		brandingName = wc.config.Frontend.BrandingName
	}

	// Determine if this is a scheduled session
	isScheduled := session.Spec.ScheduledStartTime != nil && !session.Spec.ScheduledStartTime.IsZero()

	// Determine activation time (either now or scheduled time)
	activationTime := time.Now().Format("2006-01-02 15:04:05")
	if isScheduled {
		activationTime = session.Spec.ScheduledStartTime.Format("2006-01-02 15:04:05")
	}

	// Prepare email parameters with comprehensive approval info
	params := mail.ApprovedMailParams{
		SubjectFullName: session.Spec.User,
		SubjectEmail:    session.Spec.User,
		RequestedRole:   session.Spec.GrantedGroup,
		ApproverFullName: func() string {
			// Try to extract approver name from email or use as-is
			if session.Status.Approver != "" {
				return session.Status.Approver
			}
			return "Approver"
		}(),
		ApproverEmail: session.Status.Approver,
		BrandingName:  brandingName,

		// Tracking and scheduling information
		ApprovedAt:     time.Now().Format("2006-01-02 15:04:05"),
		ActivationTime: activationTime,
		ExpirationTime: session.Status.ExpiresAt.Format("2006-01-02 15:04:05"),
		IsScheduled:    isScheduled,
		SessionID:      session.Name,
		Cluster:        session.Spec.Cluster,
		Username:       session.Spec.User,
		ApprovalReason: "", // Could be populated from session.Status.ApprovalReason if available

		// IDP information for multi-IDP setups
		IDPName:   session.Spec.IdentityProviderName,
		IDPIssuer: session.Spec.IdentityProviderIssuer,
	}

	// Render the approval email body using the enhanced template
	body, err := mail.RenderApproved(params)
	if err != nil {
		log.Errorw("failed to render approval email template", "error", err, "session", session.Name)
		return
	}

	// Enqueue the email for sending via mail service (preferred) or legacy queue
	subject := fmt.Sprintf("Breakglass Access Approved - %s on %s", session.Spec.GrantedGroup, session.Spec.Cluster)
	sessionID := "session-approval-" + session.Name
	recipients := []string{session.Spec.User}

	// Prefer mail service if available
	if wc.mailService != nil && wc.mailService.IsEnabled() {
		if err := wc.mailService.Enqueue(sessionID, recipients, subject, body); err != nil {
			log.Errorw("failed to enqueue approval email via mail service", "error", err, "session", session.Name, "to", session.Spec.User)
			return
		}
		log.Infow("approval email enqueued for sending", "session", session.Name, "to", session.Spec.User)
		return
	}

	// Fallback to legacy queue
	if wc.mailQueue != nil {
		if err := wc.mailQueue.Enqueue(sessionID, recipients, subject, body); err != nil {
			log.Errorw("failed to enqueue approval email", "error", err, "session", session.Name, "to", session.Spec.User)
			return
		}
		log.Infow("approval email enqueued for sending", "session", session.Name, "to", session.Spec.User)
	}
}

// sendSessionRejectionEmail sends a rejection notification to the requester
func (wc *BreakglassSessionController) sendSessionRejectionEmail(log *zap.SugaredLogger, session breakglassv1alpha1.BreakglassSession) {
	// Check if mail is available (either via service or legacy queue)
	mailEnabled := (wc.mailService != nil && wc.mailService.IsEnabled()) || wc.mailQueue != nil
	if !mailEnabled {
		log.Warnw("mail not available, cannot send rejection email", "session", session.Name)
		return
	}

	brandingName := "Breakglass"
	if wc.config.Frontend.BrandingName != "" {
		brandingName = wc.config.Frontend.BrandingName
	}

	// Prepare email parameters with rejection info
	params := mail.RejectedMailParams{
		SubjectFullName: session.Spec.User,
		SubjectEmail:    session.Spec.User,
		RequestedRole:   session.Spec.GrantedGroup,
		RejectorFullName: func() string {
			if session.Status.Approver != "" {
				return session.Status.Approver
			}
			return "Approver"
		}(),
		RejectorEmail:   session.Status.Approver,
		BrandingName:    brandingName,
		RejectedAt:      session.Status.RejectedAt.Format("2006-01-02 15:04:05"),
		RejectionReason: session.Status.ApprovalReason, // ApprovalReason is used for both approve and reject reasons
		SessionID:       session.Name,
		Cluster:         session.Spec.Cluster,
		Username:        session.Spec.User,
	}

	// Render the rejection email body using the template
	body, err := mail.RenderRejected(params)
	if err != nil {
		log.Errorw("failed to render rejection email template", "error", err, "session", session.Name)
		return
	}

	// Enqueue the email for sending via mail service (preferred) or legacy queue
	subject := fmt.Sprintf("Breakglass Access Rejected - %s on %s", session.Spec.GrantedGroup, session.Spec.Cluster)
	sessionID := "session-rejection-" + session.Name
	recipients := []string{session.Spec.User}

	// Prefer mail service if available
	if wc.mailService != nil && wc.mailService.IsEnabled() {
		if err := wc.mailService.Enqueue(sessionID, recipients, subject, body); err != nil {
			log.Errorw("failed to enqueue rejection email via mail service", "error", err, "session", session.Name, "to", session.Spec.User)
			return
		}
		log.Infow("rejection email enqueued for sending", "session", session.Name, "to", session.Spec.User)
		return
	}

	// Fallback to legacy queue
	if wc.mailQueue != nil {
		if err := wc.mailQueue.Enqueue(sessionID, recipients, subject, body); err != nil {
			log.Errorw("failed to enqueue rejection email", "error", err, "session", session.Name, "to", session.Spec.User)
			return
		}
		log.Infow("rejection email enqueued for sending", "session", session.Name, "to", session.Spec.User)
	}
}

// WithQueue sets the mail queue for asynchronous email sending
// Deprecated: Use WithMailService instead for hot-reload support
func (b *BreakglassSessionController) WithQueue(mailQueue *mail.Queue) *BreakglassSessionController {
	b.mailQueue = mailQueue
	return b
}

// WithMailService sets the mail service for asynchronous email sending with hot-reload support
func (b *BreakglassSessionController) WithMailService(mailService MailEnqueuer) *BreakglassSessionController {
	b.mailService = mailService
	return b
}

// WithAuditService sets the audit service for emitting audit events
func (b *BreakglassSessionController) WithAuditService(auditService AuditEmitter) *BreakglassSessionController {
	b.auditService = auditService
	return b
}

// emitSessionAuditEvent emits an audit event for session lifecycle changes
func (b *BreakglassSessionController) emitSessionAuditEvent(ctx context.Context, eventType audit.EventType, session *breakglassv1alpha1.BreakglassSession, user string, message string) {
	if b.auditService == nil || !b.auditService.IsEnabled() {
		return
	}

	event := &audit.Event{
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Actor: audit.Actor{
			User: user,
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
			"message":      message,
			"cluster":      session.Spec.Cluster,
			"grantedGroup": session.Spec.GrantedGroup,
			"state":        string(session.Status.State),
		},
	}

	b.auditService.Emit(ctx, event)
}

// emitSessionExpiredAuditEvent emits an audit event when a session expires
func (b *BreakglassSessionController) emitSessionExpiredAuditEvent(ctx context.Context, session *breakglassv1alpha1.BreakglassSession, reason string) {
	if b.auditService == nil || !b.auditService.IsEnabled() {
		return
	}

	message := "Session expired"
	switch reason {
	case "timeExpired":
		message = "Session validity period has ended"
	case "approvalTimeout":
		message = "Session approval timed out before being approved"
	case "idleTimeout":
		message = "Session expired due to idle timeout (no recent activity)"
	}

	event := &audit.Event{
		Type:      audit.EventSessionExpired,
		Severity:  audit.SeverityInfo,
		Timestamp: time.Now().UTC(),
		Actor: audit.Actor{
			User: "system", // System-initiated expiration
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
			"message":          message,
			"expirationReason": reason,
			"cluster":          session.Spec.Cluster,
			"grantedGroup":     session.Spec.GrantedGroup,
			"user":             session.Spec.User,
		},
	}

	b.auditService.Emit(ctx, event)
}

// Handlers returns the middleware(s) for this controller (required by APIController interface)
func (b *BreakglassSessionController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

// dropK8sInternalFields removes K8s internal fields from BreakglassSession for API response
func dropK8sInternalFieldsSession(s *breakglassv1alpha1.BreakglassSession) {
	if s == nil {
		return
	}
	s.ManagedFields = nil
	s.UID = ""
	s.ResourceVersion = ""
	s.Generation = 0
	if s.Annotations != nil {
		delete(s.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
}

func dropK8sInternalFieldsSessionList(list []breakglassv1alpha1.BreakglassSession) []breakglassv1alpha1.BreakglassSession {
	for i := range list {
		dropK8sInternalFieldsSession(&list[i])
	}
	return list
}

type sessionStatePredicate func(breakglassv1alpha1.BreakglassSession) bool

func parseBoolQuery(value string, defaultVal bool) bool {
	if value == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultVal
	}
	return parsed
}

func normalizeStateFilters(c *gin.Context) []string {
	rawValues := c.QueryArray("state")
	if len(rawValues) == 0 {
		if single := c.Query("state"); single != "" {
			rawValues = append(rawValues, single)
		}
	}
	normalized := make([]string, 0, len(rawValues))
	for _, value := range rawValues {
		parts := strings.Split(value, ",")
		for _, part := range parts {
			token := normalizeStateToken(part)
			if token != "" {
				normalized = append(normalized, token)
			}
		}
	}
	return normalized
}

func normalizeStateToken(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return ""
	}
	replacer := strings.NewReplacer("-", "", "_", "")
	return replacer.Replace(trimmed)
}

func buildStateFilterPredicates(tokens []string) []sessionStatePredicate {
	if len(tokens) == 0 {
		return nil
	}
	predicates := make([]sessionStatePredicate, 0, len(tokens))
	for _, token := range tokens {
		switch token {
		case "all":
			return nil
		case "pending":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return session.Status.State == breakglassv1alpha1.SessionStatePending
			})
		case "approved":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return session.Status.State == breakglassv1alpha1.SessionStateApproved
			})
		case "rejected":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return IsSessionRejected(session)
			})
		case "withdrawn":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return IsSessionWithdrawn(session)
			})
		case "expired":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return IsSessionExpired(session)
			})
		case "timeout", "approvaltimeout":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return session.Status.State == breakglassv1alpha1.SessionStateTimeout
			})
		case "active":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return IsSessionActive(session)
			})
		case "waitingforscheduledtime", "waiting", "scheduled":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return session.Status.State == breakglassv1alpha1.SessionStateWaitingForScheduledTime
			})
		case "idleexpired":
			predicates = append(predicates, func(session breakglassv1alpha1.BreakglassSession) bool {
				return session.Status.State == breakglassv1alpha1.SessionStateIdleExpired
			})
		default:
			continue
		}
	}
	return predicates
}

func userHasApprovedSession(session breakglassv1alpha1.BreakglassSession, email string) bool {
	if email == "" {
		return false
	}
	if strings.EqualFold(session.Status.Approver, email) {
		return true
	}
	for _, approver := range session.Status.Approvers {
		if strings.EqualFold(approver, email) {
			return true
		}
	}
	return false
}
