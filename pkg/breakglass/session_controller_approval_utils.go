package breakglass

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
	escalationManager EscalationLookup,
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
						groups = StripOIDCPrefixes(groups, cfgLoaded.Kubernetes.OIDCPrefixes)
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

func ParseBoolQuery(value string, defaultVal bool) bool {
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
