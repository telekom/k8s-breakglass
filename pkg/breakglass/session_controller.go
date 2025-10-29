package breakglass

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/mail"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
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
)

var ErrSessionNotFound error = errors.New("session not found")

// BreakglassSessionRequest is defined in clusteruser.go and includes an optional Reason field.

type BreakglassSessionController struct {
	log               *zap.SugaredLogger
	config            config.Config
	sessionManager    *SessionManager
	escalationManager *EscalationManager
	middleware        gin.HandlerFunc
	identityProvider  IdentityProvider
	mail              mail.Sender
	getUserGroupsFn   GetUserGroupsFunction
	ccProvider        interface {
		GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
	}
	clusterConfigManager *ClusterConfigManager
}

// IsSessionPendingApproval returns true if the session is not rejected and not yet approved (pending approval)
func IsSessionPendingApproval(session v1alpha1.BreakglassSession) bool {
	return session.Status.ApprovedAt.IsZero() && session.Status.RejectedAt.IsZero()
}

func (BreakglassSessionController) BasePath() string {
	return "breakglassSessions"
}

func (wc *BreakglassSessionController) Register(rg *gin.RouterGroup) error {
	// RESTful endpoints for breakglass sessions (no leading slash)
	rg.GET("", wc.handleGetBreakglassSessionStatus)             // List/filter sessions
	rg.GET(":name", wc.handleGetBreakglassSessionByName)        // Get single session by name
	rg.POST("", wc.handleRequestBreakglassSession)              // Create session
	rg.POST(":name/approve", wc.handleApproveBreakglassSession) // Approve session
	rg.POST(":name/reject", wc.handleRejectBreakglassSession)   // Reject session
	rg.POST(":name/withdraw", wc.handleWithdrawMyRequest)       // Withdraw session (by requester)
	rg.POST(":name/drop", wc.handleDropMySession)               // Drop session (owner can drop active or pending)
	rg.POST(":name/cancel", wc.handleApproverCancel)            // Approver cancels a running/approved session
	return nil
}

// validateSessionRequest validates the session request input
func (wc BreakglassSessionController) validateSessionRequest(request BreakglassSessionRequest) error {
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

// toRFC1123Subdomain converts a string to a Kubernetes RFC1123 subdomain compatible value.
// It lowercases the string, replaces invalid characters with '-', collapses multiple
// separators and ensures the result starts and ends with an alphanumeric character.
// If the input cannot produce a valid name, returns "x" as a fallback.
func toRFC1123Subdomain(s string) string {
	if s == "" {
		return "x"
	}
	// Lowercase
	s = strings.ToLower(s)

	// Replace any character that is not a-z, 0-9, '-' or '.' with '-'
	// Also collapse runs of invalid chars into a single '-'
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
			prevDash = false
		} else {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	// Trim leading/trailing non-alphanumeric (dash or dot) characters
	out = strings.TrimLeft(out, "-.")
	out = strings.TrimRight(out, "-.")

	// Collapse multiple dots or dashes into single ones
	out = strings.ReplaceAll(out, "..", ".")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}

	// Ensure starts and ends with alphanumeric; if not, fallback to 'x'
	if out == "" {
		return "x"
	}
	// If first/last char is not alnum, strip until alnum or return x
	// First
	for len(out) > 0 && !isAlnum(rune(out[0])) {
		out = out[1:]
	}
	for len(out) > 0 && !isAlnum(rune(out[len(out)-1])) {
		out = out[:len(out)-1]
	}
	if out == "" {
		return "x"
	}
	return out
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func (wc BreakglassSessionController) handleRequestBreakglassSession(c *gin.Context) {
	// Get correlation ID for consistent logging
	// request-scoped logger (includes cid, method, path)
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)
	reqLog.Info("Processing breakglass session request")

	var request BreakglassSessionRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&request); err != nil {
		reqLog.With("error", err).Error("Failed to decode JSON request body")
		c.Status(http.StatusUnprocessableEntity)
		return
	}

	// Debug: log decoded request to help trace missing or malformed fields in e2e
	reqLog.Debugw("Decoded breakglass session request", "request", request)

	if err := wc.validateSessionRequest(request); err != nil {
		reqLog.With("error", err, "request", request).Warn("Invalid session request parameters")
		c.JSON(http.StatusUnprocessableEntity, "missing input request data: "+err.Error())
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
			c.JSON(http.StatusInternalServerError, "failed to extract user groups")
			return
		}
	}
	// Strip OIDC prefixes if configured (cluster retrieval might include them; token groups usually not)
	if cfg, cerr := config.Load(); cerr == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		userGroups = stripOIDCPrefixes(userGroups, cfg.Kubernetes.OIDCPrefixes)
	} else if cerr != nil {
		reqLog.With("error", errors.Wrap(cerr, "config load failed for OIDC prefix stripping")).Debug("Continuing without OIDC prefix stripping")
	}

	escalations, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(ctx, cug.Clustername, userGroups)
	if err != nil {
		reqLog.Errorw("Error getting breakglass escalations", "error", err)
		c.JSON(http.StatusInternalServerError, "failed to extract cluster breakglass escalation information")
		return
	}
	// We already filtered by cluster & user groups; treat these as possible escalations.
	possibleEscals := escalations
	// Strip K8s internal fields before logging
	for i := range possibleEscals {
		dropK8sInternalFieldsEscalation(&possibleEscals[i])
	}
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
		c.JSON(http.StatusUnauthorized, "user unauthorized for group")
		return
	} else {
		reqLog.Debugw("Possible escalations", "user", cug.Username, "cluster", cug.Clustername, "count", len(possibleEscals))
		reqLog.Debugw("Possible escalations for user", "user", cug.Username, "group", cug.GroupName, "possibleEscalations", possibleEscals)
	}

	reqLog.Debugw("Filtering possible escalations for user", "user", cug.Username, "group", cug.GroupName)
	possible := []string{}
	approvers := []string{}
	selectedDenyPolicies := []string{}
	// approverGroups := []string{}
	for _, p := range possibleEscals {
		possible = append(possible, p.Spec.EscalatedGroup)
		approvers = append(approvers, p.Spec.Approvers.Users...)
		if p.Spec.EscalatedGroup == request.GroupName {
			selectedDenyPolicies = append(selectedDenyPolicies, p.Spec.DenyPolicyRefs...)
		}
		// approverGroups = append(approverGroups, p.Spec.Approvers.Groups...)
	}

	if !slices.Contains(possible, request.GroupName) {
		reqLog.Warnw("User unauthorized for group", "user", request.Username, "group", request.GroupName)
		c.JSON(http.StatusUnauthorized, "user unauthorized for group")
		return
	}

	// Validate request reason if escalation requires it. Find escalation that matches the requested group
	var matchedEsc *v1alpha1.BreakglassEscalation
	for _, p := range possibleEscals {
		if p.Spec.EscalatedGroup == request.GroupName {
			matchedEsc = &p
			break
		}
	}
	if matchedEsc != nil && matchedEsc.Spec.RequestReason != nil && matchedEsc.Spec.RequestReason.Mandatory {
		if strings.TrimSpace(request.Reason) == "" {
			reqLog.Warnw("Missing required request reason", "group", request.GroupName)
			c.JSON(http.StatusUnprocessableEntity, "missing required request reason")
			return
		}
	}

	ses, err := wc.getActiveBreakglassSession(ctx,
		request.Username, request.Clustername, request.GroupName)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			reqLog.Errorw("Error getting breakglass sessions", "error", err)
			c.JSON(http.StatusInternalServerError, "failed to extract breakglass session information")
			return
		}
	} else {
		// A matching session exists; decide response based on its canonical state.
		reqLog.Infow("Existing session found", "session", ses.Name, "cluster", request.Clustername, "user", request.Username, "group", request.GroupName, "state", ses.Status.State)
		// Remove k8s internal fields before returning session in API response
		dropK8sInternalFieldsSession(&ses)

		// Approved session -> explicit "already approved" error
		if ses.Status.State == v1alpha1.SessionStateApproved || !ses.Status.ApprovedAt.IsZero() {
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

	useremail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.Errorw("Error getting user identity email", "error", err)
		c.JSON(http.StatusInternalServerError, "failed to extract email from token")
		return
	}
	username := wc.identityProvider.GetUsername(c)

	// Initialize session spec and populate duration fields from matched escalation when available
	spec := v1alpha1.BreakglassSessionSpec{
		Cluster:        request.Clustername,
		User:           request.Username,
		GrantedGroup:   request.GroupName,
		DenyPolicyRefs: selectedDenyPolicies,
		RequestReason:  request.Reason,
	}
	if matchedEsc != nil {
		// copy relevant duration-related fields from escalation spec to session spec
		spec.MaxValidFor = matchedEsc.Spec.MaxValidFor
		spec.RetainFor = matchedEsc.Spec.RetainFor
		spec.IdleTimeout = matchedEsc.Spec.IdleTimeout
	}

	bs := v1alpha1.BreakglassSession{Spec: spec}
	// Ensure session is created in the same namespace as the matched escalation
	if matchedEsc != nil {
		bs.Namespace = matchedEsc.Namespace
	}

	// Generate RFC1123-safe name parts for cluster and group
	safeCluster := toRFC1123Subdomain(request.Clustername)
	safeGroup := toRFC1123Subdomain(request.GroupName)
	bs.GenerateName = fmt.Sprintf("%s-%s-", safeCluster, safeGroup)
	if err := wc.sessionManager.AddBreakglassSession(ctx, bs); err != nil {
		reqLog.Errorw("error while adding breakglass session", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// If we have a matched escalation, increment its request counter in status for observability
	if matchedEsc != nil && wc.escalationManager != nil {
		// fetch latest escalation object
		if esc, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(ctx, matchedEsc.Spec.Allowed.Clusters[0], []string{}); err == nil && len(esc) > 0 {
			// Try to find by name
			for _, e := range esc {
				if e.Name == matchedEsc.Name {
					if e.Status.RequestCount == 0 {
						e.Status.RequestCount = 1
					} else {
						e.Status.RequestCount = e.Status.RequestCount + 1
					}
					_ = wc.escalationManager.UpdateBreakglassEscalationStatus(context.Background(), e)
					break
				}
			}
		}
	}

	bs, err = wc.getActiveBreakglassSession(ctx, request.Username, request.Clustername, request.GroupName)
	if err != nil && !errors.Is(err, ErrSessionNotFound) {
		reqLog.Errorw("error while getting breakglass session", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	approvalTimeout := time.Hour // TODO: make configurable per escalation/cluster

	// Compute retained-until at creation so sessions always expose when they will be cleaned up.
	var retainFor time.Duration = DefaultRetainForDuration
	if spec.RetainFor != "" {
		if d, err := time.ParseDuration(spec.RetainFor); err == nil && d > 0 {
			retainFor = d
		} else {
			reqLog.Warnw("Invalid RetainFor in session spec; falling back to default", "value", spec.RetainFor, "error", err)
		}
	}

	bs.Status = v1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(retainFor)),
		TimeoutAt:     metav1.NewTime(time.Now().Add(approvalTimeout)), // Approval timeout
		State:         v1alpha1.SessionStatePending,
		Conditions: []metav1.Condition{{
			Type:               string(v1alpha1.SessionConditionTypeIdle),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
			Message:            fmt.Sprintf("User %q requested session.", username),
		}},
	}

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(ctx, bs); err != nil {
		reqLog.Errorw("error while updating breakglass session", "error", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	if os.Getenv("BREAKGLASS_DISABLE_EMAIL") == "1" {
		reqLog.Debug("Email sending disabled via BREAKGLASS_DISABLE_EMAIL=1")
	} else {
		// Trigger a group sync before sending email (but still send based on current status)
		if wc.escalationManager != nil && wc.escalationManager.Resolver != nil {
			// Capture the request-scoped logger (which contains cid) so background logs
			// emitted during group sync include the same correlation id.
			goroutineLog := reqLog.With("cluster", bs.Spec.Cluster)
			go func(log *zap.SugaredLogger) {
				ctx := context.Background()
				// Run a sync for all approver groups in the escalation(s) for this request
				escalations, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(ctx, bs.Spec.Cluster, []string{})
				if err != nil {
					log.Warnw("Failed to list escalations for group sync", "error", err)
					return
				}
				for _, esc := range escalations {
					for _, g := range esc.Spec.Approvers.Groups {
						log.Debugw("Triggering group member sync", "escalation", esc.Name, "group", g)
						members, merr := wc.escalationManager.Resolver.Members(ctx, g)
						if merr != nil {
							log.Warnw("Group member resolution failed", "group", g, "escalation", esc.Name, "error", merr)
							continue
						}
						log.Infow("Resolved group members for sync", "group", g, "escalation", esc.Name, "count", len(members))
					}
				}
			}(goroutineLog)
		}
		if err := wc.sendOnRequestEmail(bs, useremail, username, approvers); err != nil {
			// Do not fail the request if email cannot be sent (e.g. mail server not running in e2e).
			reqLog.Warnw("Skipping email notification (send failed)", "error", err)
		}
	}

	reqLog.Debugw("Session created", "user", request.Username, "cluster", request.Clustername, "group", request.GroupName, "generatedName", bs.Name)
	c.JSON(http.StatusCreated, bs)
}

func (wc BreakglassSessionController) setSessionStatus(c *gin.Context, sesCondition v1alpha1.BreakglassSessionConditionType) {
	sessionName := c.Param("name")

	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	// Attempt to decode optional approver reason from the request body (for approve/reject)
	var approverPayload struct {
		Reason string `json:"reason,omitempty"`
	}
	// Ignore errors; payload is optional. Guard against nil Request.Body which can occur in tests/clients.
	if c.Request != nil && c.Request.Body != nil {
		_ = json.NewDecoder(c.Request.Body).Decode(&approverPayload)
	}

	var lastCondition metav1.Condition
	if l := len(bs.Status.Conditions); l > 0 {
		lastCondition = bs.Status.Conditions[l-1]
	}

	// If the session already has the same last condition, return conflict to avoid repeated transitions.
	if lastCondition.Type == string(sesCondition) {
		c.JSON(http.StatusConflict, gin.H{"error": "session already in requested state", "session": bs})
		return
	}

	// Different actions have different preconditions:
	// - Approve and Reject must only be executed when the session is pending.
	// - Other actions should be blocked only when the session is already in a true terminal state
	//   (Rejected, Withdrawn, Expired, Timeout). Approved is intentionally not part of that list
	//   because approved sessions may later transition to expired/dropped by owner or canceled by approver.
	currState := bs.Status.State
	if sesCondition == v1alpha1.SessionConditionTypeApproved || sesCondition == v1alpha1.SessionConditionTypeRejected {
		if currState != v1alpha1.SessionStatePending {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("session must be pending to perform %s; current state: %s", sesCondition, currState), "session": bs})
			return
		}
	} else {
		if currState == v1alpha1.SessionStateRejected || currState == v1alpha1.SessionStateWithdrawn || currState == v1alpha1.SessionStateExpired || currState == v1alpha1.SessionStateTimeout {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("session is in terminal state %s and cannot be modified", currState), "session": bs})
			return
		}
	}

	// Authorization: determine whether the caller is allowed to perform the action.
	// Allow the session requester to reject their own pending session. For reject actions only,
	// if the caller is the original requester and the session is still pending, bypass the approver check.
	allowOwnerReject := false
	if sesCondition == v1alpha1.SessionConditionTypeRejected {
		if requesterEmail, err := wc.identityProvider.GetEmail(c); err == nil {
			if requesterEmail == bs.Spec.User && IsSessionPendingApproval(bs) {
				allowOwnerReject = true
			}
		}
	}

	if !allowOwnerReject {
		if !wc.isSessionApprover(c, bs) {
			c.Status(http.StatusUnauthorized)
			return
		}
	}

	switch sesCondition {
	case v1alpha1.SessionConditionTypeApproved:
		// Clear any previous rejection timestamp so the approved state is canonical.
		bs.Status.RejectedAt = metav1.Time{}
		bs.Status.ApprovedAt = metav1.Now()
		// Determine expiry based on session spec MaxValidFor if provided, otherwise use default
		var validFor time.Duration = DefaultValidForDuration
		if bs.Spec.MaxValidFor != "" {
			if d, err := time.ParseDuration(bs.Spec.MaxValidFor); err == nil && d > 0 {
				validFor = d
			} else {
				wc.log.Warnw("Invalid MaxValidFor in session spec; falling back to default", "value", bs.Spec.MaxValidFor, "error", err)
			}
		}
		bs.Status.ExpiresAt = metav1.NewTime(bs.Status.ApprovedAt.Add(validFor))
		// Determine retention based on session spec RetainFor if provided, otherwise use default
		var retainFor time.Duration = DefaultRetainForDuration
		if bs.Spec.RetainFor != "" {
			if d, err := time.ParseDuration(bs.Spec.RetainFor); err == nil && d > 0 {
				retainFor = d
			} else {
				wc.log.Warnw("Invalid RetainFor in session spec; falling back to default", "value", bs.Spec.RetainFor, "error", err)
			}
		}
		bs.Status.RetainedUntil = metav1.NewTime(time.Now().Add(retainFor))
		bs.Status.TimeoutAt = metav1.Time{} // Clear approval timeout
		bs.Status.State = v1alpha1.SessionStateApproved
		// increment escalation approval count if escalation manager available and owner reference points to an escalation
		if wc.escalationManager != nil && len(bs.OwnerReferences) > 0 {
			for _, or := range bs.OwnerReferences {
				if or.Kind == "BreakglassEscalation" {
					// try to fetch escalation by name
					escs, err := wc.escalationManager.GetClusterGroupBreakglassEscalations(context.Background(), bs.Spec.Cluster, []string{})
					if err == nil {
						for _, ee := range escs {
							if ee.Name == or.Name {
								if ee.Status.ApprovalCount == 0 {
									ee.Status.ApprovalCount = 1
								} else {
									ee.Status.ApprovalCount = ee.Status.ApprovalCount + 1
								}
								_ = wc.escalationManager.UpdateBreakglassEscalationStatus(context.Background(), ee)
								break
							}
						}
					}
				}
			}
		}
		// record approver
		approverEmail, _ := wc.identityProvider.GetEmail(c)
		if approverEmail != "" {
			bs.Status.Approver = approverEmail
			// append to approvers history if not already present
			found := false
			for _, a := range bs.Status.Approvers {
				if a == approverEmail {
					found = true
					break
				}
			}
			if !found {
				bs.Status.Approvers = append(bs.Status.Approvers, approverEmail)
			}
		}
		// store approver reason if provided
		if strings.TrimSpace(approverPayload.Reason) != "" {
			bs.Status.ApprovalReason = approverPayload.Reason
		}
	case v1alpha1.SessionConditionTypeRejected:
		bs.Status.ApprovedAt = metav1.Time{}
		bs.Status.ExpiresAt = metav1.Time{}
		bs.Status.TimeoutAt = metav1.Time{}
		bs.Status.RejectedAt = metav1.Now()
		bs.Status.State = v1alpha1.SessionStateRejected
		// record approver (rejector)
		rejectorEmail, _ := wc.identityProvider.GetEmail(c)
		if rejectorEmail != "" {
			bs.Status.Approver = rejectorEmail
			found := false
			for _, a := range bs.Status.Approvers {
				if a == rejectorEmail {
					found = true
					break
				}
			}
			if !found {
				bs.Status.Approvers = append(bs.Status.Approvers, rejectorEmail)
			}
		}
		// store approver reason if provided
		if strings.TrimSpace(approverPayload.Reason) != "" {
			bs.Status.ApprovalReason = approverPayload.Reason
		}
	case v1alpha1.SessionConditionTypeIdle:
		wc.log.Error("error setting session status to idle which should be only initial state")
		c.Status(http.StatusInternalServerError)
		return
	default:
		wc.log.Error("unknown session condition type", zap.String("type", string(sesCondition)))
		c.Status(http.StatusInternalServerError)
		return
	}

	username, _ := wc.identityProvider.GetEmail(c)
	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(sesCondition),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
		Message:            fmt.Sprintf("User %q set session to %s", username, sesCondition),
	})

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, bs)
}

func (wc BreakglassSessionController) getActiveBreakglassSession(ctx context.Context,
	username,
	clustername,
	group string,
) (v1alpha1.BreakglassSession, error) {
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
		return v1alpha1.BreakglassSession{}, errors.Wrap(err, "failed to list sessions")
	}

	validSessions := make([]v1alpha1.BreakglassSession, 0, len(sessions))
	for _, ses := range sessions {
		if !IsSessionActive(ses) {
			continue
		}
		wc.log.Debugw("Found active session candidate", "session", ses.Name)
		validSessions = append(validSessions, ses)
	}

	if len(validSessions) == 0 {
		wc.log.Infow("No active breakglass session found", "user", username, "cluster", clustername, "group", group)
		return v1alpha1.BreakglassSession{}, ErrSessionNotFound
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

func (wc BreakglassSessionController) handleApproveBreakglassSession(c *gin.Context) {
	wc.setSessionStatus(c, v1alpha1.SessionConditionTypeApproved)
}

func (wc BreakglassSessionController) handleRejectBreakglassSession(c *gin.Context) {
	wc.setSessionStatus(c, v1alpha1.SessionConditionTypeRejected)
}

// handleGetBreakglassSessionStatus handles GET /status for breakglass session
func (wc *BreakglassSessionController) handleGetBreakglassSessionStatus(c *gin.Context) {
	wc.log.Debug("Handling GET /status for breakglass session")
	ctx := c.Request.Context()
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
			wc.log.Debugw("Token validation: session not found", "token", token, "error", err)
			c.JSON(http.StatusNotFound, gin.H{"valid": false})
			return
		}
		canApprove := wc.isSessionApprover(c, ses)
		alreadyActive := IsSessionActive(ses)
		valid := true
		if IsSessionExpired(ses) || ses.Status.State == v1alpha1.SessionStateWithdrawn || ses.Status.State == v1alpha1.SessionStateRejected {
			valid = false
		}
		c.JSON(http.StatusOK, gin.H{"canApprove": canApprove, "alreadyActive": alreadyActive, "valid": valid})
		return
	}

	var sessions []v1alpha1.BreakglassSession
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
		wc.log.Debugw("Using field selector for sessions query", "selector", selector.String())
		sessions, err = wc.sessionManager.GetBreakglassSessionsWithSelector(ctx, selector)
	} else {
		sessions, err = wc.sessionManager.GetAllBreakglassSessions(ctx)
	}
	if err != nil {
		wc.log.Error("Error getting breakglass sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract breakglass session information")
		return
	}

	// Filtering logic
	mine := c.Query("mine") == "true"
	state := c.Query("state")
	var userEmail string
	if mine {
		userEmail, err = wc.identityProvider.GetEmail(c)
		if err != nil {
			wc.log.Error("Error getting user identity email", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract email from token")
			return
		}
	}

	filtered := make([]v1alpha1.BreakglassSession, 0, len(sessions))
	for _, ses := range sessions {
		// Only show sessions that belong to the user (mine) or that the user can approve
		isMine := false
		if userEmail != "" && ses.Spec.User == userEmail {
			isMine = true
		}
		isApprover := wc.isSessionApprover(c, ses)
		if !isMine && !isApprover {
			continue
		}
		if mine && !isMine {
			continue
		}
		if state == "pending" && !IsSessionPendingApproval(ses) {
			continue
		}
		if state == "approved" && ses.Status.State != v1alpha1.SessionStateApproved {
			continue
		}
		if state == "rejected" && ses.Status.RejectedAt.IsZero() {
			continue
		}
		// expired: session whose ExpiresAt has passed
		if state == "expired" && !IsSessionExpired(ses) {
			continue
		}
		// timeout / approval timeout: session timed out while pending approval
		if (state == "timeout" || strings.ToLower(state) == "approvaltimeout") && ses.Status.State != v1alpha1.SessionStateTimeout {
			// also accept TimeoutAt in the past as timeout indicator
			if ses.Status.TimeoutAt.IsZero() || time.Now().Before(ses.Status.TimeoutAt.Time) {
				continue
			}
		}
		// Add explicit filter for withdrawn sessions
		if state == "withdrawn" && (ses.Status.State != v1alpha1.SessionStateWithdrawn) {
			continue
		}
		filtered = append(filtered, ses)
	}

	wc.log.Infow("Returning filtered breakglass sessions", "count", len(filtered))
	c.JSON(http.StatusOK, dropK8sInternalFieldsSessionList(filtered))
}

// handleGetBreakglassSessionByName handles GET /breakglassSessions/:name and returns a single session
func (wc *BreakglassSessionController) handleGetBreakglassSessionByName(c *gin.Context) {
	sessionName := c.Param("name")
	wc.log.Debugw("Handling GET /breakglassSessions/:name", "name", sessionName)
	ses, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		wc.log.Debugw("Get by name: session not found", "name", sessionName, "error", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, dropK8sInternalFieldsSessionList([]v1alpha1.BreakglassSession{ses}))
}

// handleWithdrawMyRequest allows the session requester to withdraw their own pending request
func (wc *BreakglassSessionController) handleWithdrawMyRequest(c *gin.Context) {
	sessionName := c.Param("name")
	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	// Only allow the original requester to withdraw
	requesterEmail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("error getting user identity email", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}
	if bs.Spec.User != requesterEmail {
		c.Status(http.StatusUnauthorized)
		return
	}

	// Only allow withdrawal if session is still pending
	if !IsSessionPendingApproval(bs) {
		c.JSON(http.StatusBadRequest, "Session is not pending and cannot be withdrawn")
		return
	}

	// Set status to Withdrawn
	bs.Status.ApprovedAt = metav1.Time{}
	bs.Status.ExpiresAt = metav1.Time{}
	bs.Status.RejectedAt = metav1.Now()
	bs.Status.State = v1alpha1.SessionStateWithdrawn
	// clear approver info for withdrawn sessions
	bs.Status.Approver = ""
	bs.Status.Approvers = nil
	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(v1alpha1.SessionConditionTypeCanceled),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
		Message:            "Session withdrawn by requester",
	})

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, bs)
}

// handleDropMySession allows the session requester (owner) to drop their own session.
// This differs from withdraw: drop permits removing either pending or approved sessions by owner.
func (wc *BreakglassSessionController) handleDropMySession(c *gin.Context) {
	sessionName := c.Param("name")
	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	// Only allow the original requester to drop
	requesterEmail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("error getting user identity email", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}
	if bs.Spec.User != requesterEmail {
		c.Status(http.StatusUnauthorized)
		return
	}

	// If approved -> mark as Expired and set RetainedUntil appropriately (owner requested termination)
	if bs.Status.State == v1alpha1.SessionStateApproved && !bs.Status.ApprovedAt.IsZero() {
		bs.Status.ExpiresAt = metav1.NewTime(time.Now())
		bs.Status.State = v1alpha1.SessionStateExpired
		bs.Status.RejectedAt = metav1.Now()
		bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
			Type:               string(v1alpha1.SessionConditionTypeExpired),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
			Message:            "Session dropped by owner",
		})
	} else {
		// Pending or other state -> behave like withdraw
		bs.Status.ApprovedAt = metav1.Time{}
		bs.Status.ExpiresAt = metav1.Time{}
		bs.Status.RejectedAt = metav1.Now()
		bs.Status.State = v1alpha1.SessionStateWithdrawn
		bs.Status.Approver = ""
		bs.Status.Approvers = nil
		bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
			Type:               string(v1alpha1.SessionConditionTypeCanceled),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
			Message:            "Session dropped by owner",
		})
	}

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, bs)
}

// handleApproverCancel allows an approver to cancel/terminate a running (approved) session.
// This endpoint is intended for approvers to immediately end an active session (set to Expired).
func (wc *BreakglassSessionController) handleApproverCancel(c *gin.Context) {
	sessionName := c.Param("name")
	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), sessionName)
	if err != nil {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	// Only approvers can cancel via this endpoint
	if !wc.isSessionApprover(c, bs) {
		c.Status(http.StatusUnauthorized)
		return
	}

	// Only allow cancellation of active/approved sessions
	if bs.Status.State != v1alpha1.SessionStateApproved || bs.Status.ApprovedAt.IsZero() {
		c.JSON(http.StatusBadRequest, "Session is not active/approved and cannot be canceled by approver")
		return
	}

	// Transition to expired immediately
	bs.Status.ExpiresAt = metav1.NewTime(time.Now())
	bs.Status.State = v1alpha1.SessionStateExpired
	bs.Status.RejectedAt = metav1.Now()
	// record approver who canceled
	approverEmail, _ := wc.identityProvider.GetEmail(c)
	if approverEmail != "" {
		bs.Status.Approver = approverEmail
		// append if not present
		found := false
		for _, a := range bs.Status.Approvers {
			if a == approverEmail {
				found = true
				break
			}
		}
		if !found {
			bs.Status.Approvers = append(bs.Status.Approvers, approverEmail)
		}
	}

	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(v1alpha1.SessionConditionTypeExpired),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
		Message:            "Session canceled by approver",
	})

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, bs)
}

func (wc BreakglassSessionController) sendOnRequestEmail(bs v1alpha1.BreakglassSession,
	requestEmail,
	requestUsername string,
	approvers []string,
) error {
	subject := fmt.Sprintf("Cluster %q user %q is requesting breakglass group assignment %q", bs.Spec.Cluster, bs.Spec.User, bs.Spec.GrantedGroup)

	wc.log.Debugw("Rendering breakglass session request email", "subject", subject, "approvers", approvers)
	body, err := mail.RenderBreakglassSessionRequest(mail.RequestBreakglassSessionMailParams{
		SubjectEmail:      requestEmail,
		SubjectFullName:   requestUsername,
		RequestedCluster:  bs.Spec.Cluster,
		RequestedUsername: bs.Spec.User,
		RequestedGroup:    bs.Spec.GrantedGroup,
		URL:               fmt.Sprintf("%s/review?name=%s", wc.config.Frontend.BaseURL, bs.Name),
	})
	if err != nil {
		wc.log.Errorf("failed to render email template: %v", err)
		return err
	}

	if err := wc.mail.Send(approvers, subject, body); err != nil {
		wc.log.Errorf("failed to send request email: %v", err)
		return err
	}

	wc.log.Infow("Breakglass session request email sent", "session", bs.Name, "approvers", approvers)
	return nil
}

// nolint:unused // might use later
func (wc BreakglassSessionController) handleListClusters(c *gin.Context) {
	sessions, err := wc.sessionManager.GetAllBreakglassSessions(c.Request.Context())
	if err != nil {
		wc.log.Error("Error getting access reviews", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "Failed to extract cluster group access information")
		return
	}

	clusters := make([]string, 0, len(sessions))
	for _, session := range sessions {
		clusters = append(clusters, session.Spec.Cluster)
	}

	c.JSON(http.StatusOK, clusters)
}

func (wc BreakglassSessionController) isSessionApprover(c *gin.Context, session v1alpha1.BreakglassSession) bool {
	email, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("Error getting user identity", zap.Error(err))
		return false
	}
	wc.log.Debug("Approver identity", "email", email)
	ctx := c.Request.Context()
	approverID := ClusterUserGroup{Username: email, Clustername: session.Spec.Cluster}

	// Base defaults for escalation evaluation. Per-escalation overrides will be applied below.
	var baseBlockSelfApproval bool
	var baseAllowedApproverDomains []string
	// Note: To simplify lookup we assume ClusterConfig for an escalation lives in the same namespace
	// as the BreakglassEscalation. Therefore we will fetch ClusterConfig per-escalation using the
	// escalation's namespace below. Keep base values empty (defaults) here.

	// Gather approver groups (prefer token groups to avoid cluster SSR dependency)
	approverGroups, gerr := wc.getUserGroupsFn(ctx, approverID)
	if raw, ok := c.Get("groups"); ok {
		if arr, ok2 := raw.([]string); ok2 && len(arr) > 0 {
			approverGroups = arr
			wc.log.Infow("Using token groups for approver authorization", "approver", email, "groups", arr, "groupCount", len(arr))
		}
	} else if gerr != nil {
		wc.log.Errorw("[E2E-DEBUG] Approver group error", "error", gerr)
		return false
	}
	wc.log.Debugw("Approver groups", "email", email, "groups", approverGroups)

	// Note: escalation-level overrides for allowed domains and blockSelfApproval
	// are applied per-escalation below while evaluating matching escalations.

	escalations, err := wc.escalationManager.GetClusterBreakglassEscalations(ctx, session.Spec.Cluster)
	if err != nil {
		wc.log.Error("Error listing cluster escalations for approval", zap.Error(err))
		return false
	}

	// Evaluate only escalation(s) that grant the session's GrantedGroup.
	wc.log.Debugw("Approver evaluation context", "session", session.Name, "sessionGrantedGroup", session.Spec.GrantedGroup, "candidateEscalationCount", len(escalations), "approverEmail", email, "approverGroups", approverGroups)
	for _, esc := range escalations {
		if esc.Spec.EscalatedGroup != session.Spec.GrantedGroup {
			continue
		}
		wc.log.Debugw("Escalation approvers", "escalation", esc.Name, "users", esc.Spec.Approvers.Users, "groups", esc.Spec.Approvers.Groups)
		// Determine effective blockSelfApproval and allowed domains for this escalation
		// Start with base defaults, then overlay ClusterConfig (if present in escalation's namespace),
		// and finally apply per-escalation overrides.
		effectiveBlockSelf := baseBlockSelfApproval
		effectiveAllowedDomains := baseAllowedApproverDomains
		if wc.clusterConfigManager != nil {
			// Try to fetch a ClusterConfig with the name matching the session.Spec.Cluster within the
			// escalation's namespace. We assume ClusterConfig objects for escalations are colocated.
			if cc, cerr := wc.clusterConfigManager.GetClusterConfigInNamespace(c.Request.Context(), esc.Namespace, session.Spec.Cluster); cerr == nil && cc != nil {
				effectiveBlockSelf = cc.Spec.BlockSelfApproval
				effectiveAllowedDomains = cc.Spec.AllowedApproverDomains
			} else if cerr != nil {
				wc.log.Debugw("No ClusterConfig found in escalation namespace, continuing with defaults", "cluster", session.Spec.Cluster, "namespace", esc.Namespace, "error", cerr)
			}
		}
		// Apply explicit escalation-level overrides
		if esc.Spec.BlockSelfApproval != nil {
			effectiveBlockSelf = *esc.Spec.BlockSelfApproval
		}
		if len(esc.Spec.AllowedApproverDomains) > 0 {
			effectiveAllowedDomains = esc.Spec.AllowedApproverDomains
		}

		// Enforce blockSelfApproval for this escalation: approver cannot be the session user
		if effectiveBlockSelf && email == session.Spec.User {
			wc.log.Debugw("Self-approval blocked by escalation/cluster setting", "escalation", esc.Name, "approver", email)
			// This escalation disallows self-approval; continue checking next escalation
			continue
		}

		// Enforce allowedApproverDomains for this escalation: if configured, require approver to match
		if len(effectiveAllowedDomains) > 0 {
			allowed := false
			for _, domain := range effectiveAllowedDomains {
				if strings.HasSuffix(strings.ToLower(email), "@"+strings.ToLower(domain)) {
					allowed = true
					break
				}
			}
			if !allowed {
				wc.log.Warnw("Approver email does not match allowed domains for escalation", "escalation", esc.Name, "approver", email, "allowedDomains", effectiveAllowedDomains)
				// Not allowed for this escalation; continue to next
				continue
			}
		}

		// Direct user approver
		if slices.Contains(esc.Spec.Approvers.Users, email) {
			wc.log.Debugw("User is session approver (direct user)", "session", session.Name, "escalation", esc.Name, "user", email)
			return true
		}
		// Group approver intersection
		for _, g := range approverGroups {
			if slices.Contains(esc.Spec.Approvers.Groups, g) {
				wc.log.Debugw("User is session approver (group)", "session", session.Name, "escalation", esc.Name, "group", g)
				return true
			}
		}
		// This escalation did not grant approver rights to the caller; continue checking other escalations
		wc.log.Debugw("Escalation found but user not in approvers (continuing)", "session", session.Name, "escalation", esc.Name, "user", email, "userGroups", approverGroups, "approverUsers", esc.Spec.Approvers.Users, "approverGroups", esc.Spec.Approvers.Groups)
		continue
	}
	// No matching escalation granting approver rights found. Log details for debugging.
	wc.log.Debugw("No escalation with matching granted group for approval", "session", session.Name, "grantedGroup", session.Spec.GrantedGroup, "approverEmail", email, "approverGroups", approverGroups)
	return false
}

func IsSessionRetained(session v1alpha1.BreakglassSession) bool {
	return time.Now().After(session.Status.RetainedUntil.Time)
}

// Session can be expired if it was previously approved
// IsSessionExpired returns true if the session's ExpiresAt has passed (for approved sessions).
// For approval timeout, use IsSessionApprovalTimedOut (TimeoutAt).
func IsSessionExpired(session v1alpha1.BreakglassSession) bool {
	return !session.Status.ExpiresAt.Time.IsZero() && time.Now().After(session.Status.ExpiresAt.Time)
}

func IsSessionValid(session v1alpha1.BreakglassSession) bool {
	return !IsSessionExpired(session)
	// session.Status.ExpiresAt.Time.IsZero() || time.Now().After(session.Status.ExpiresAt.Time)
}

// IsSessionActive returns if session can be approved or was already approved
func IsSessionActive(session v1alpha1.BreakglassSession) bool {
	return IsSessionValid(session) && session.Status.RejectedAt.IsZero()
}

func NewBreakglassSessionController(log *zap.SugaredLogger,
	cfg config.Config,
	sessionManager *SessionManager,
	escalationManager *EscalationManager,
	middleware gin.HandlerFunc,
	ccProvider interface {
		GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
	},
	clusterConfigClient client.Client,
) *BreakglassSessionController {

	ip := KeycloakIdentityProvider{}

	ctrl := &BreakglassSessionController{
		log:                  log,
		config:               cfg,
		sessionManager:       sessionManager,
		escalationManager:    escalationManager,
		middleware:           middleware,
		identityProvider:     ip,
		mail:                 mail.NewSender(cfg),
		ccProvider:           ccProvider,
		clusterConfigManager: NewClusterConfigManager(clusterConfigClient),
	}

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		if ctrl.ccProvider != nil {
			if rc, err := ctrl.ccProvider.GetRESTConfig(ctx, cug.Clustername); err == nil && rc != nil {
				remote := rest.CopyConfig(rc)
				remote.Impersonate = rest.ImpersonationConfig{UserName: cug.Username}
				client, cerr := kubernetes.NewForConfig(remote)
				if cerr != nil {
					return nil, errors.Wrap(cerr, "remote client construction failed")
				}
				res, rerr := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
				if rerr != nil {
					return nil, errors.Wrap(rerr, "remote SelfSubjectReview failed")
				}
				ui := res.Status.UserInfo
				groups := ui.Groups
				cfgLoaded, lerr := config.Load()
				if lerr == nil && len(cfgLoaded.Kubernetes.OIDCPrefixes) > 0 {
					groups = stripOIDCPrefixes(groups, cfgLoaded.Kubernetes.OIDCPrefixes)
				}
				log.Debugw("Resolved user groups via spoke cluster rest.Config", "cluster", cug.Clustername, "user", cug.Username, "groups", groups)
				return groups, nil
			}
			log.Debugw("Falling back to legacy GetUserGroups (kube context)", "cluster", cug.Clustername)
		}
		return GetUserGroups(ctx, cug)
	}

	return ctrl
}

// Handlers returns the middleware(s) for this controller (required by APIController interface)
func (b *BreakglassSessionController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

// dropK8sInternalFields removes K8s internal fields from BreakglassSession for API response
func dropK8sInternalFieldsSession(s *v1alpha1.BreakglassSession) {
	if s == nil {
		return
	}
	s.ObjectMeta.ManagedFields = nil
	if s.ObjectMeta.Annotations != nil {
		delete(s.ObjectMeta.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
}

func dropK8sInternalFieldsSessionList(list []v1alpha1.BreakglassSession) []v1alpha1.BreakglassSession {
	for i := range list {
		dropK8sInternalFieldsSession(&list[i])
	}
	return list
}
