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
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
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
	reqLog.Debugw("Decoded breakglass session request", "request", request)

	// Phase 1: Resolve authenticated identity and enforce username matching
	authIdentity, ok := wc.resolveAuthenticatedIdentity(c, &request, reqLog)
	if !ok {
		return
	}

	// Phase 2: Validate session request parameters
	if err := wc.validateSessionRequest(request); err != nil {
		reqLog.With("error", err, "request", request).Warn("Invalid session request parameters")
		apiresponses.RespondUnprocessableEntity(c, "missing input request data: "+err.Error())
		return
	}
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

	// Phase 3: Load global config via cached loader
	var globalCfg *config.Config
	if wc.configLoader != nil {
		if cfg, cerr := wc.configLoader.Get(); cerr == nil {
			globalCfg = &cfg
		} else {
			reqLog.With("error", fmt.Errorf("cached config load failed: %w", cerr)).Debug("Continuing without global config")
		}
	}

	// Phase 4: Resolve user groups from token or cluster lookup
	userGroups, ok := wc.resolveUserGroups(c, ctx, cug, globalCfg, reqLog)
	if !ok {
		return
	}

	// Phase 5: Fetch matching escalations for cluster + user groups
	escalations, ok := wc.fetchMatchingEscalations(c, ctx, cug, userGroups, reqLog)
	if !ok {
		return
	}

	// Phase 6: Collect approvers and find matched escalation in a single pass
	resolution := wc.collectApproversFromEscalations(ctx, escalations, request.GroupName, reqLog)

	if !slices.Contains(resolution.possibleGroups, request.GroupName) {
		reqLog.Warnw("User not authorized for group", "user", request.Username, "group", request.GroupName)
		apiresponses.RespondForbidden(c, "user not authorized for requested group")
		return
	}
	if resolution.matchedEscalation != nil &&
		resolution.matchedEscalation.Spec.RequestReason != nil &&
		resolution.matchedEscalation.Spec.RequestReason.Mandatory {
		if strings.TrimSpace(request.Reason) == "" {
			reqLog.Warnw("Missing required request reason", "group", request.GroupName)
			apiresponses.RespondUnprocessableEntity(c, "missing required request reason")
			return
		}
	}

	// Phase 7: Resolve user identifier claim from config
	userIdentifier, clusterConfig, ok := wc.resolveUserIdentifierClaim(c, ctx, request, globalCfg, reqLog)
	if !ok {
		return
	}

	// Phase 8: Guard against concurrent creation + check for duplicates
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

	if !wc.checkDuplicateSession(c, ctx, userIdentifier, request.Clustername, request.GroupName, reqLog) {
		return
	}

	// Phase 9: Validate email identity before proceeding
	if authIdentity.email == "" {
		reqLog.Errorw("Error getting user identity email", "error", authIdentity.emailErr)
		apiresponses.RespondInternalError(c, "extract email from token", authIdentity.emailErr, reqLog)
		return
	}
	username := authIdentity.username
	reqLog.Debugw("Session creation initiated by user",
		"requestorEmail", authIdentity.email, "requestorUsername", username,
		"requestedGroup", request.GroupName, "requestedCluster", request.Clustername)

	// Phase 10: Build session spec from escalation and request
	spec, ok := wc.buildSessionSpec(c, request, userIdentifier,
		resolution.matchedEscalation, clusterConfig, resolution.selectedDenyPolicies, reqLog)
	if !ok {
		return
	}

	// Phase 11: Create and persist the session resource
	bs, ok := wc.createAndPersistSession(c, ctx, sessionCreateParams{
		spec:           spec,
		request:        request,
		userIdentifier: userIdentifier,
		matchedEsc:     resolution.matchedEscalation,
		userGroups:     userGroups,
		username:       username,
	}, reqLog)
	if !ok {
		return
	}

	// Phase 12: Send notification emails to approvers
	wc.sendSessionNotifications(*bs, resolution.matchedEscalation,
		resolution.allApprovers, resolution.approversByGroup,
		authIdentity.email, username, reqLog)

	// Emit audit event for session creation
	wc.emitSessionAuditEvent(c.Request.Context(), audit.EventSessionRequested, bs, request.Username, "Session requested")
	reqLog.Debugw("Session created",
		"user", request.Username, "cluster", request.Clustername,
		"group", request.GroupName, "generatedName", bs.Name)
	c.JSON(http.StatusCreated, *bs)
}
