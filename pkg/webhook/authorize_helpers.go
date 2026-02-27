package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/system"
)

// authorizeState holds mutable state accumulated across the phases of handleAuthorize.
// Each helper reads/writes fields on this struct instead of passing many parameters.
type authorizeState struct {
	// Immutable inputs
	startTime   time.Time
	clusterName string
	ctx         context.Context //nolint:containedctx // scoped to a single request; passed to helpers
	reqLog      *zap.SugaredLogger
	phases      *SARPhaseTracker

	// Parsed request
	sar authorizationv1.SubjectAccessReview

	// Cluster context
	clusterCfg *breakglassv1alpha1.ClusterConfig
	issuer     string

	// Session context
	groups        []string
	sessions      []breakglassv1alpha1.BreakglassSession
	idpMismatches []breakglassv1alpha1.BreakglassSession
	tenant        string

	// Decision state (filled progressively)
	allowed           bool
	allowSource       string // "rbac" | "session" | "debug-session"
	allowDetail       string
	reason            string
	escals            []breakglassv1alpha1.BreakglassEscalation
	sessionSARSkipErr error
}

// parseSARRequest reads the request body, unmarshals the SubjectAccessReview, and
// initialises the authorizeState. Returns (state, ok); writes HTTP status on failure.
func (wc *WebhookController) parseSARRequest(c *gin.Context) (*authorizeState, bool) {
	s := &authorizeState{
		startTime:   time.Now(),
		clusterName: c.Param("cluster_name"),
		ctx:         c.Request.Context(),
	}
	metrics.WebhookSARRequests.WithLabelValues(s.clusterName).Inc()
	wc.log.With("cluster", s.clusterName).Debug("Processing authorization request for cluster")

	s.phases = NewSARPhaseTracker(s.clusterName, wc.log)
	s.phases.StartPhase() // Start parse phase

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSARBodySize)
	bodyBytes, rerr := io.ReadAll(c.Request.Body)
	if rerr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(rerr, &maxErr) {
			wc.log.With("error", rerr.Error()).Warn("SubjectAccessReview body too large")
			c.Status(http.StatusRequestEntityTooLarge)
			return nil, false
		}
		wc.log.With("error", rerr.Error()).Error("Failed to read request body for SubjectAccessReview")
		c.Status(http.StatusUnprocessableEntity)
		return nil, false
	}
	// restore body for potential downstream reads (not strictly needed here)
	c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Log raw request body at debug (truncate to 8KB to avoid huge logs)
	s.reqLog = system.GetReqLogger(c, wc.log)
	s.reqLog = system.EnrichReqLoggerWithAuth(c, s.reqLog)
	s.reqLog.Debugw("SubjectAccessReview request received", "bodySize", len(bodyBytes))

	// Now that we have an enriched request logger, record handler entry with cluster
	s.reqLog.Debugw("handleAuthorize entered", "cluster", s.clusterName)

	if err := json.Unmarshal(bodyBytes, &s.sar); err != nil {
		s.reqLog.With("error", err.Error()).Errorw("Failed to decode SubjectAccessReview body", "bodySize", len(bodyBytes))
		c.Status(http.StatusUnprocessableEntity)
		return nil, false
	}
	s.phases.EndPhase(PhaseParse) // End parse phase

	s.reqLog.Debug("Received SubjectAccessReview")
	s.reqLog.Infow("Processing authorization",
		"username", s.sar.Spec.User,
		"groupsRequested", s.sar.Spec.Groups)
	return s, true
}

// resolveClusterConfig loads the ClusterConfig for the target cluster.
// Returns ok=false if the cluster is not registered or on internal error.
func (wc *WebhookController) resolveClusterConfig(c *gin.Context, s *authorizeState) bool {
	s.phases.StartPhase() // Start cluster_config phase
	if wc.ccProvider != nil {
		cfg, cfgErr := wc.getClusterConfigAcrossNamespaces(s.ctx, s.clusterName)
		if cfgErr != nil {
			if errors.Is(cfgErr, cluster.ErrClusterConfigNotFound) {
				actionSummary := summarizeAction(&s.sar)
				reason := fmt.Sprintf(
					"Cluster %q is not registered with Breakglass, so %s cannot be authorized yet. "+
						"Ask your platform administrators to onboard the cluster or choose one of the onboarded clusters.",
					s.clusterName, actionSummary)
				reason = wc.finalizeReason(reason, false, s.clusterName)
				metrics.WebhookSARDenied.WithLabelValues(s.clusterName).Inc()
				metrics.WebhookSARDuration.WithLabelValues(s.clusterName, "denied").
					Observe(time.Since(s.startTime).Seconds())
				if s.sar.Spec.ResourceAttributes != nil {
					ra := s.sar.Spec.ResourceAttributes
					metrics.WebhookSARDecisionsByAction.WithLabelValues(
						s.clusterName, ra.Verb, ra.Group, ra.Resource,
						ra.Namespace, ra.Subresource, "denied", "cluster-missing").Inc()
				}
				s.reqLog.Warnw("Cluster not registered for Breakglass", "cluster", s.clusterName)
				c.JSON(http.StatusOK, &SubjectAccessReviewResponse{
					ApiVersion: s.sar.APIVersion,
					Kind:       s.sar.Kind,
					Status: SubjectAccessReviewResponseStatus{
						Allowed: false,
						Reason:  reason,
					},
				})
				return false
			}
			s.reqLog.With("error", cfgErr.Error()).Error("Failed to load ClusterConfig for SAR validation")
			c.Status(http.StatusInternalServerError)
			return false
		}
		s.clusterCfg = cfg
	}
	s.phases.EndPhase(PhaseClusterConfig) // End cluster_config phase
	return true
}

// logSARAction emits structured logging and metrics for the requested API action
// and extracts the OIDC issuer for multi-IDP session filtering.
func (wc *WebhookController) logSARAction(s *authorizeState) {
	// Emit the actual requested API action (from SAR) at Info level for observability.
	// This includes resource attributes (verb, group, resource, namespace, name, subresource)
	// or non-resource attributes (path, verb) when present.
	if s.sar.Spec.ResourceAttributes != nil {
		ra := s.sar.Spec.ResourceAttributes
		// Increment action-based request metric (omit name to reduce cardinality)
		metrics.WebhookSARRequestsByAction.WithLabelValues(
			s.clusterName, ra.Verb, ra.Group, ra.Resource, ra.Namespace, ra.Subresource).Inc()
		// Build a small structured action for log ingestion systems
		action := map[string]string{
			"verb":        ra.Verb,
			"apiGroup":    ra.Group,
			"resource":    ra.Resource,
			"namespace":   ra.Namespace,
			"name":        ra.Name,
			"subresource": ra.Subresource,
		}
		s.reqLog.Infow("SubjectAccessReview requested action",
			"verb", ra.Verb,
			"apiGroup", ra.Group,
			"resource", ra.Resource,
			"namespace", ra.Namespace,
			"name", ra.Name,
			"subresource", ra.Subresource,
			"action", action,
		)
	} else if s.sar.Spec.NonResourceAttributes != nil {
		nra := s.sar.Spec.NonResourceAttributes
		metrics.WebhookSARRequestsByAction.WithLabelValues(
			s.clusterName, nra.Verb, "", "nonresource", "", "").Inc()
		action := map[string]string{
			"path": nra.Path,
			"verb": nra.Verb,
		}
		s.reqLog.Infow("SubjectAccessReview requested non-resource action",
			"path", nra.Path,
			"verb", nra.Verb,
			"action", action,
		)
	} else {
		s.reqLog.Infow("SubjectAccessReview contains no resource or non-resource attributes")
		metrics.WebhookSARRequestsByAction.WithLabelValues(s.clusterName, "", "", "unknown", "", "").Inc()
	}

	// Extract issuer from SAR for multi-IDP session filtering
	if s.sar.Spec.Extra != nil {
		issuerValues := s.sar.Spec.Extra["identity.t-caas.telekom.com/issuer"]
		if len(issuerValues) > 0 {
			s.issuer = issuerValues[0]
			s.reqLog.Debugw("Extracted issuer from SAR for session matching", "issuer", s.issuer)
		}
	}
}

// loadSessionsAndGroups retrieves user groups, active sessions, IDP mismatches,
// and tenant for the target cluster. Returns ok=false on internal error.
func (wc *WebhookController) loadSessionsAndGroups(c *gin.Context, s *authorizeState) bool {
	s.phases.StartPhase() // Start sessions phase
	var err error
	s.groups, s.sessions, s.idpMismatches, s.tenant, err = wc.getUserGroupsAndSessionsWithIDPInfo(
		s.ctx, s.sar.Spec.User, s.clusterName, s.issuer, s.clusterCfg)
	if err != nil {
		s.reqLog.With("error", err.Error()).Error("Failed to retrieve user groups for cluster")
		c.Status(http.StatusInternalServerError)
		return false
	}
	s.phases.EndPhase(PhaseSessions) // End sessions phase
	s.reqLog.With("groups", s.groups, "sessions", len(s.sessions),
		"tenant", s.tenant, "idpMismatches", len(s.idpMismatches)).
		Debug("Retrieved user groups for cluster")
	return true
}

// checkEarlyDebugSession checks if a pod operation is allowed by a debug session
// before deny-policy evaluation. Returns handled=true if an allow response was written.
// This must be checked BEFORE deny policy evaluation to ensure debug sessions work correctly.
// Supports exec, attach, portforward, and log subresources based on AllowedPodOperations config.
func (wc *WebhookController) checkEarlyDebugSession(c *gin.Context, s *authorizeState) bool {
	s.phases.StartPhase() // Start debug_session phase (may be brief if no check needed)
	if s.sar.Spec.ResourceAttributes != nil {
		ra := s.sar.Spec.ResourceAttributes
		if ra.Resource == "pods" && isDebugSessionSubresource(ra.Subresource) && ra.Name != "" {
			if debugAllowed, debugSession, debugReason := wc.checkDebugSessionAccess(
				s.ctx, s.sar.Spec.User, s.clusterName, ra, s.reqLog); debugAllowed {
				s.phases.EndPhase(PhaseDebugSession) // End debug_session phase
				s.phases.LogSummary()                // Log timing summary
				s.reqLog.Infow("Debug session authorizing pod operation (bypassing deny policies)",
					"session", debugSession, "pod", ra.Name,
					"namespace", ra.Namespace, "operation", ra.Subresource)
				metrics.WebhookSARAllowed.WithLabelValues(s.clusterName).Inc()
				metrics.WebhookSARDecisionsByAction.WithLabelValues(
					s.clusterName, ra.Verb, ra.Group, ra.Resource,
					ra.Namespace, ra.Subresource, "allowed", "debug-session").Inc()
				metrics.WebhookSARDuration.WithLabelValues(s.clusterName, "allowed").
					Observe(time.Since(s.startTime).Seconds())
				reason := wc.finalizeReason(debugReason, true, s.clusterName)
				c.JSON(http.StatusOK, &SubjectAccessReviewResponse{
					ApiVersion: s.sar.APIVersion,
					Kind:       s.sar.Kind,
					Status:     SubjectAccessReviewResponseStatus{Allowed: true, Reason: reason},
				})
				return true
			}
		}
	}
	s.phases.EndPhase(PhaseDebugSession) // End debug_session phase (even if no early return)
	return false
}

// evaluateDenyPolicies runs global and per-session deny-policy evaluation.
// Returns handled=true if a deny response was written.
func (wc *WebhookController) evaluateDenyPolicies(c *gin.Context, s *authorizeState) bool {
	s.phases.StartPhase() // Start deny_policy phase
	if s.sar.Spec.ResourceAttributes == nil {
		s.phases.EndPhase(PhaseDenyPolicy)
		return false
	}

	ra := s.sar.Spec.ResourceAttributes

	// Get PodSecurityOverrides from user's active session escalation (if any)
	podSecurityOverrides := wc.getPodSecurityOverridesFromSessions(s.ctx, s.sessions, s.reqLog)

	act := policy.Action{
		Verb:                 ra.Verb,
		APIGroup:             ra.Group,
		Resource:             ra.Resource,
		Namespace:            ra.Namespace,
		Name:                 ra.Name,
		Subresource:          ra.Subresource,
		ClusterID:            s.clusterName,
		Tenant:               s.tenant,
		PodSecurityOverrides: podSecurityOverrides,
	}

	// Fetch namespace labels for DenyPolicy SelectorTerms evaluation
	if act.Namespace != "" {
		nsLabels, err := wc.fetchNamespaceLabels(s.ctx, s.clusterName, act.Namespace)
		if err != nil {
			s.reqLog.Debugw("Failed to fetch namespace labels for DenyPolicy evaluation",
				"error", err.Error(), "namespace", act.Namespace)
			// NamespaceLabels will be nil; SelectorTerms cannot be evaluated
		} else {
			act.NamespaceLabels = nsLabels
		}
	}

	// Fetch pod spec for exec/attach/portforward requests to enable security evaluation
	if act.Resource == "pods" && isExecSubresource(act.Subresource) && act.Name != "" {
		pod, err := wc.fetchPodFromCluster(s.ctx, s.clusterName, act.Namespace, act.Name)
		if err != nil {
			s.reqLog.Warnw("Failed to fetch pod for security evaluation",
				"error", err.Error(), "pod", act.Name, "namespace", act.Namespace)
			// Pod will be nil; policy failMode determines behavior
		} else {
			act.Pod = pod
			s.reqLog.Debugw("Fetched pod for security evaluation",
				"pod", pod.Name, "namespace", pod.Namespace)
		}
	}

	// Global deny-policy evaluation
	if denied, pol, podSecResult, derr := wc.denyEval.MatchWithDetails(s.ctx, act); derr != nil {
		s.reqLog.With("error", derr.Error(), "action", act).Error("deny evaluation error")
	} else {
		// Emit pod security audit event if we have a result
		if podSecResult != nil {
			wc.emitPodSecurityAudit(s.ctx, s.sar.Spec.User, s.groups, s.clusterName, &s.sar, pol, podSecResult)
		}
		if denied {
			// Log detailed rejection info at INFO level for observability
			s.reqLog.Infow("Request denied by global/cluster DenyPolicy",
				"policy", pol,
				"verb", act.Verb,
				"apiGroup", act.APIGroup,
				"resource", act.Resource,
				"namespace", act.Namespace,
				"resourceName", act.Name,
				"subresource", act.Subresource,
				"cluster", s.clusterName,
				"tenant", s.tenant,
				"username", s.sar.Spec.User,
				"activeSessions", len(s.sessions),
			)
			// Emit denied metric for global policy short-circuit
			metrics.WebhookSARDenied.WithLabelValues(s.clusterName).Inc()
			metrics.WebhookSARDecisionsByAction.WithLabelValues(
				s.clusterName, act.Verb, act.APIGroup, act.Resource,
				act.Namespace, act.Subresource, "denied", "global").Inc()
			metrics.WebhookSARDuration.WithLabelValues(s.clusterName, "denied").
				Observe(time.Since(s.startTime).Seconds())
			s.reqLog.Debugw("Global denyEval matched", "policy", pol, "action", act)

			// Emit audit event for policy denial
			wc.emitPolicyDenialAudit(s.ctx, s.sar.Spec.User, s.groups, s.clusterName, &s.sar, pol, "global")

			reason := wc.buildDenyPolicyReason(s, pol)
			s.phases.EndPhase(PhaseDenyPolicy)
			s.phases.LogSummary()
			c.JSON(http.StatusOK, &SubjectAccessReviewResponse{
				ApiVersion: s.sar.APIVersion,
				Kind:       s.sar.Kind,
				Status:     SubjectAccessReviewResponseStatus{Allowed: false, Reason: reason},
			})
			return true
		}
	}

	// Session-scoped deny-policy evaluation
	for _, sess := range s.sessions {
		act.Session = sess.Name
		if denied, pol, podSecResult, derr := wc.denyEval.MatchWithDetails(s.ctx, act); derr != nil {
			s.reqLog.With("error", derr.Error(), "session", sess.Name, "action", act).
				Error("deny evaluation error for session")
		} else {
			// Emit pod security audit event if we have a result
			if podSecResult != nil {
				wc.emitPodSecurityAudit(s.ctx, s.sar.Spec.User, s.groups, s.clusterName, &s.sar, pol, podSecResult)
			}
			if denied {
				// Log detailed rejection info at INFO level for observability
				s.reqLog.Infow("Request denied by session-scoped DenyPolicy",
					"policy", pol,
					"session", sess.Name,
					"sessionGroup", sess.Spec.GrantedGroup,
					"verb", act.Verb,
					"apiGroup", act.APIGroup,
					"resource", act.Resource,
					"namespace", act.Namespace,
					"resourceName", act.Name,
					"subresource", act.Subresource,
					"cluster", s.clusterName,
					"username", s.sar.Spec.User,
				)
				// Emit denied metric for session-scoped policy short-circuit
				metrics.WebhookSARDenied.WithLabelValues(s.clusterName).Inc()
				metrics.WebhookSARDecisionsByAction.WithLabelValues(
					s.clusterName, act.Verb, act.APIGroup, act.Resource,
					act.Namespace, act.Subresource, "denied", "session").Inc()
				metrics.WebhookSARDuration.WithLabelValues(s.clusterName, "denied").
					Observe(time.Since(s.startTime).Seconds())
				s.reqLog.Debugw("Session denyEval matched", "policy", pol, "session", sess.Name, "action", act)

				// Emit audit event for session-scoped policy denial
				wc.emitPolicyDenialAudit(s.ctx, s.sar.Spec.User, s.groups, s.clusterName, &s.sar, pol, "session:"+sess.Name)

				reason := wc.buildDenyPolicyReason(s, pol)
				s.phases.EndPhase(PhaseDenyPolicy) // End deny_policy phase (early exit)
				s.phases.LogSummary()              // Log timing summary
				c.JSON(http.StatusOK, &SubjectAccessReviewResponse{
					ApiVersion: s.sar.APIVersion,
					Kind:       s.sar.Kind,
					Status:     SubjectAccessReviewResponseStatus{Allowed: false, Reason: reason},
				})
				return true
			}
		}
	}

	s.phases.EndPhase(PhaseDenyPolicy) // End deny_policy phase
	return false
}

// buildDenyPolicyReason constructs the deny reason including escalation availability and IDP hint.
func (wc *WebhookController) buildDenyPolicyReason(s *authorizeState, pol string) string {
	// Determine if any escalation paths exist for this user (use groups from sessions plus system:authenticated)
	uniqueGroups := append([]string{}, s.groups...)
	uniqueGroups = append(uniqueGroups, "system:authenticated")
	ug := dedupeStrings(uniqueGroups)
	escals, eerr := wc.escalManager.GetClusterGroupBreakglassEscalations(s.ctx, s.clusterName, ug)
	count := 0
	if eerr != nil {
		s.reqLog.With("error", eerr.Error()).Error("Failed to count escalations for deny response")
	} else {
		count = len(escals)
	}

	var reason string
	if count > 0 {
		reason = fmt.Sprintf("Denied by policy %s; %d breakglass escalation(s) available", pol, count)
	} else {
		reason = fmt.Sprintf("Denied by policy %s; No breakglass flow available for your user", pol)
	}
	// Add IDP hint if available
	if hint := wc.getIDPHintFromIssuer(s.ctx, &s.sar, s.reqLog); hint != "" {
		reason = fmt.Sprintf("%s %s", reason, hint)
	}
	return wc.finalizeReason(reason, false, s.clusterName)
}

// performRBACCheck runs the standard RBAC check against the target cluster.
// Returns ok=false on fatal internal error.
func (wc *WebhookController) performRBACCheck(c *gin.Context, s *authorizeState) bool {
	// Perform standard RBAC check against target cluster (not hub) using its kubeconfig
	s.phases.StartPhase() // Start rbac_check phase
	var can bool
	var rbacErr error
	// Log input to RBAC check for easier debugging
	s.reqLog.Debugw("Invoking RBAC canDoFn",
		"groups", s.groups, "resourceAttributes", s.sar.Spec.ResourceAttributes,
		"cluster", s.clusterName)

	if wc.ccProvider != nil {
		if rc, rerr := wc.ccProvider.GetRESTConfig(s.ctx, s.clusterName); rerr == nil {
			can, rbacErr = wc.canDoFn(s.ctx, rc, s.groups, s.sar, s.clusterName)
		} else {
			// downgrade to info; this will commonly happen if RBAC does not yet allow clusterconfig get
			s.reqLog.With("error", rerr).Info(
				"Failed to get REST config for standard RBAC check; using legacy fallback")
			// Record that session SAR checks will be skipped because we couldn't load REST config
			s.sessionSARSkipErr = rerr
			// Still invoke injected canDoFn with nil to allow tests to control behavior
			can, rbacErr = wc.canDoFn(s.ctx, nil, s.groups, s.sar, s.clusterName)
		}
	} else {
		can, rbacErr = wc.canDoFn(s.ctx, nil, s.groups, s.sar, s.clusterName)
	}
	s.phases.EndPhase(PhaseRBAC) // End rbac_check phase

	if rbacErr != nil {
		msg := rbacErr.Error()
		// Treat missing rest config or legacy context absence as denial (not internal error).
		// Also treat authorization/impersonation errors as denial - this happens when using
		// OIDC-authenticated ClusterConfigs where the service account may lack impersonation
		// permissions on the target cluster. In these cases, we should fall through to
		// session-based authorization rather than returning an internal server error.
		if msg == "rest config is nil" ||
			strings.Contains(msg, "does not exist") ||
			strings.Contains(msg, "no such file") ||
			strings.Contains(msg, "is forbidden") ||
			strings.Contains(msg, "cannot impersonate") ||
			strings.Contains(msg, "Forbidden") {
			s.reqLog.With("error", rbacErr).Warn(
				"RBAC check failed (infrastructure unavailable or forbidden); treating as denied and falling through to session-based authorization")
			can = false
		} else {
			s.reqLog.With("error", rbacErr).Error("RBAC canDoFn error")
			c.Status(http.StatusInternalServerError)
			return false
		}
	}
	s.reqLog.Debugw("RBAC check result", "allowed", can, "groupCount", len(s.groups))

	if can {
		s.reqLog.Info("User authorized through regular RBAC permissions")
		s.allowed = true
		s.allowSource = "rbac"
		s.allowDetail = fmt.Sprintf("groups=%v", s.groups)
		// Emit allowed decision metric for action
		if s.sar.Spec.ResourceAttributes != nil {
			ra := s.sar.Spec.ResourceAttributes
			metrics.WebhookSARDecisionsByAction.WithLabelValues(
				s.clusterName, ra.Verb, ra.Group, ra.Resource,
				ra.Namespace, ra.Subresource, "allowed", "rbac").Inc()
		}
	}
	return true
}

// resolveSessionAuthorization performs session-based authorization, debug-session fallback,
// and escalation discovery when RBAC denied the request. Returns ok=false on fatal error.
func (wc *WebhookController) resolveSessionAuthorization(c *gin.Context, s *authorizeState) bool {
	username := s.sar.Spec.User
	s.reqLog.Debug("User not authorized through regular RBAC, checking for breakglass escalations")

	// Session SAR checks: attempt authorization impersonating each granted group via admin kubeconfig.
	// This handles both resource and non-resource attributes.
	s.phases.StartPhase() // Start session_sars phase
	if wc.ccProvider != nil && (s.sar.Spec.ResourceAttributes != nil || s.sar.Spec.NonResourceAttributes != nil) {
		if rc, err := wc.ccProvider.GetRESTConfig(s.ctx, s.clusterName); err != nil {
			s.reqLog.With("error", err.Error()).Warn(
				"Unable to load target cluster rest.Config for SAR; skipping session SAR checks")
			// mark that we skipped session SAR checks for diagnostics
			s.sessionSARSkipErr = err
		} else if allowedSession, grp, sesName, impersonated := wc.authorizeViaSessions(
			s.ctx, rc, s.sessions, s.sar, s.clusterName, s.reqLog); allowedSession {
			s.reqLog.With("grantedGroup", grp, "session", sesName, "impersonatedGroup", impersonated).
				Debug("Authorized via breakglass session group on target cluster")
			s.allowed = true
			s.allowSource = "session"
			s.allowDetail = fmt.Sprintf("group=%s session=%s impersonated=%s", grp, sesName, impersonated)
			// Emit a single correlated info log showing the final accepted impersonated group for observability
			s.reqLog.Infow("Final accepted impersonated group",
				"username", username, "cluster", s.clusterName,
				"grantedGroup", grp, "session", sesName, "impersonatedGroup", impersonated)

			// Record session activity for idle timeout detection and usage analytics (#314)
			wc.recordSessionActivity(s.sessions, sesName, s.clusterName, grp)
		}
	}
	s.phases.EndPhase(PhaseSessionSARs) // End session_sars phase

	// Debug session pod exec check: allow exec into debug pods if user is a session participant
	if !s.allowed && s.sar.Spec.ResourceAttributes != nil {
		ra := s.sar.Spec.ResourceAttributes
		if debugAllowed, debugSession, debugReason := wc.checkDebugSessionAccess(
			s.ctx, username, s.clusterName, ra, s.reqLog); debugAllowed {
			s.allowed = true
			s.allowSource = "debug-session"
			s.allowDetail = fmt.Sprintf("session=%s", debugSession)
			s.reason = debugReason
			// Emit metric for debug session authorization
			metrics.WebhookSARDecisionsByAction.WithLabelValues(
				s.clusterName, ra.Verb, ra.Group, ra.Resource,
				ra.Namespace, ra.Subresource, "allowed", "debug-session").Inc()
		}
	}

	// Get user groups from active sessions
	// Pass empty issuer string since we're just counting available escalations, not filtering by IDP
	s.phases.StartPhase() // Start escalations phase
	activeUserGroups, _, _, err := wc.getUserGroupsAndSessions(s.ctx, username, s.clusterName, "", s.clusterCfg)
	if err != nil {
		s.reqLog.With("error", err.Error()).Error("Failed to retrieve user groups for cluster")
		c.Status(http.StatusInternalServerError)
		return false
	}
	s.reqLog.With("activeUserGroups", activeUserGroups).Debug("Retrieved user groups from active sessions")

	// Add basic user groups that all authenticated users should have
	allUserGroups := append(activeUserGroups, "system:authenticated")
	uniqueGroups := dedupeStrings(allUserGroups)
	s.reqLog.With("allUserGroups", uniqueGroups).Debug("Final user groups including basic authenticated groups")

	// Check for group-based escalations
	var escalErr error
	s.escals, escalErr = wc.escalManager.GetClusterGroupBreakglassEscalations(s.ctx, s.clusterName, uniqueGroups)
	if escalErr != nil {
		s.reqLog.With("error", escalErr.Error()).Error("Failed to retrieve group escalations")
		c.Status(http.StatusInternalServerError)
		return false
	}
	s.reqLog.With("escalationsCount", len(s.escals)).Debug("Retrieved group-specific escalations")

	// Check for target group escalations if we have a specific group request
	var groupescals []breakglassv1alpha1.BreakglassEscalation
	// SECURITY FIX: Check if ResourceAttributes is not nil before accessing its fields
	if s.sar.Spec.ResourceAttributes != nil && s.sar.Spec.ResourceAttributes.Group != "" {
		var groupErr error
		groupescals, groupErr = wc.escalManager.GetClusterGroupTargetBreakglassEscalation(s.ctx,
			s.clusterName,
			uniqueGroups,
			s.sar.Spec.ResourceAttributes.Group,
		)
		if groupErr != nil {
			s.reqLog.With("error", groupErr.Error()).Error("Failed to retrieve target group escalations")
			c.Status(http.StatusInternalServerError)
			return false
		}
	}
	s.reqLog.With("groupEscalationsCount", len(groupescals)).Debug("Retrieved target group escalations")

	s.escals = append(s.escals, groupescals...)
	s.reqLog.With("totalEscalations", len(s.escals)).Debug("Total available escalation paths")

	// Filter escalations based on requestor's IDP (multi-IDP awareness)
	// If an escalation has AllowedIdentityProvidersForRequests, the requestor's IDP must be in that list
	var idpFilteredEscals []breakglassv1alpha1.BreakglassEscalation
	for _, esc := range s.escals {
		if wc.isRequestFromAllowedIDP(s.ctx, s.issuer, &esc, s.reqLog) {
			idpFilteredEscals = append(idpFilteredEscals, esc)
		}
	}

	if len(idpFilteredEscals) < len(s.escals) {
		s.reqLog.Debugw("Escalations filtered by requestor IDP",
			"beforeFilter", len(s.escals), "afterFilter", len(idpFilteredEscals), "issuer", s.issuer)
	}
	s.escals = idpFilteredEscals
	s.phases.EndPhase(PhaseEscalations) // End escalations phase

	if len(s.escals) > 0 {
		s.reqLog.Debugw("Escalation paths available", "count", len(s.escals))
		// Only set the deny reason when the request was not already allowed
		// (session or debug-session checks may have allowed it earlier).
		if !s.allowed {
			s.reason = fmt.Sprintf(denyReasonMessage,
				wc.config.Frontend.BaseURL, url.QueryEscape(s.clusterName))
		}
	} else {
		s.reqLog.Debugw("No escalation paths for user", "username", username)
	}
	s.reqLog.With("escalations", s.escals).Debug("Available escalation paths for user")
	return true
}

// buildFinalReason populates the positive reason for allowed decisions and appends
// diagnostic notes for denials (session SAR skip, IDP mismatch, IDP hint).
func (wc *WebhookController) buildFinalReason(s *authorizeState) {
	if s.allowed && s.reason == "" { // populate positive reason
		switch s.allowSource {
		case "rbac":
			s.reason = fmt.Sprintf("Allowed by RBAC (%s)", s.allowDetail)
		case "session":
			s.reason = fmt.Sprintf("Allowed by breakglass session (%s)", s.allowDetail)
		}
	}

	// If we denied the request but the user has active sessions and we were unable to
	// perform session SAR checks (for example because the cluster kubeconfig is
	// missing), append a helpful note so callers and users know why a valid session
	// didn't result in an allow decision.
	if !s.allowed && len(s.sessions) > 0 {
		// If we recorded a skip for session SAR checks, add a diagnostic note to the reason
		if s.sessionSARSkipErr != nil {
			metrics.WebhookSessionSARSSkipped.WithLabelValues(s.clusterName).Inc()
			// Collect session names and granted groups for the diagnostic message
			sessInfo := make([]string, 0, len(s.sessions))
			for _, sess := range s.sessions {
				sessInfo = append(sessInfo, sess.Name+"("+sess.Spec.GrantedGroup+")")
			}
			diag := fmt.Sprintf(
				"Note: %d active breakglass session(s) found: %v. "+
					"Session-level authorization checks were skipped due to cluster validation error: %s. "+
					"If you believe you have valid access, ensure the platform has the cluster kubeconfig configured.",
				len(s.sessions), sessInfo, s.sessionSARSkipErr.Error())
			if s.reason == "" {
				s.reason = diag
			} else {
				s.reason = s.reason + " " + diag
			}
			// Also log this at info so admins see the mismatch between session state and SAR capabilities
			s.reqLog.With("sessions", sessInfo, "error", s.sessionSARSkipErr.Error()).
				Info("Active sessions present but unable to validate them against target cluster")
		}
	}

	// If we denied the request and there are sessions with IDP issuer mismatches,
	// provide a helpful error message indicating the user has sessions but from a different IDP
	if !s.allowed && len(s.idpMismatches) > 0 && s.issuer != "" {
		// Collect the IDPs from the mismatched sessions (show which IDP should have been used)
		idpSet := make(map[string]bool)
		for _, sess := range s.idpMismatches {
			if sess.Spec.IdentityProviderName != "" {
				idpSet[sess.Spec.IdentityProviderName] = true
			}
		}
		var idpNames []string
		for idp := range idpSet {
			idpNames = append(idpNames, idp)
		}

		if len(idpNames) > 0 {
			idpList := strings.Join(idpNames, ", ")
			diag := fmt.Sprintf(
				"Note: %d breakglass session(s) found but from different identity provider(s): %s. "+
					"Your current token is from a different identity provider. "+
					"For access with your current identity provider, open a new breakglass request.",
				len(s.idpMismatches), idpList)
			if s.reason == "" {
				s.reason = diag
			} else {
				s.reason = s.reason + " " + diag
			}
			// Log this at info level so admins can see IDP mismatches
			s.reqLog.With("currentIssuer", s.issuer,
				"sessionsWithMismatch", len(s.idpMismatches),
				"sessionIDPs", idpNames).
				Info("User has valid sessions but from different identity provider")
		}
	}

	// Add IDP hint to denial reasons (helps users understand which provider authenticated them)
	if !s.allowed {
		if hint := wc.getIDPHintFromIssuer(s.ctx, &s.sar, s.reqLog); hint != "" {
			if s.reason == "" {
				s.reason = hint
			} else {
				s.reason = fmt.Sprintf("%s %s", s.reason, hint)
			}
		}
	}

	// Ensure the reason always includes a helpful link to the breakglass UI
	s.reason = wc.finalizeReason(s.reason, s.allowed, s.clusterName)
}

// sendAuthorizationResponse emits final metrics, builds the SAR response, logs
// denial diagnostics, and writes the JSON response.
func (wc *WebhookController) sendAuthorizationResponse(c *gin.Context, s *authorizeState) {
	username := s.sar.Spec.User

	if s.allowed {
		metrics.WebhookSARAllowed.WithLabelValues(s.clusterName).Inc()
		// Increment action-based decision metric only for session-authorized decisions.
		// RBAC and debug-session paths are already recorded at decision time to avoid duplicate/misleading labels.
		if s.sar.Spec.ResourceAttributes != nil && s.allowSource == "session" {
			ra := s.sar.Spec.ResourceAttributes
			metrics.WebhookSARDecisionsByAction.WithLabelValues(
				s.clusterName, ra.Verb, ra.Group, ra.Resource,
				ra.Namespace, ra.Subresource, "allowed", "session").Inc()
		}
	} else {
		metrics.WebhookSARDenied.WithLabelValues(s.clusterName).Inc()
		if s.sar.Spec.ResourceAttributes != nil {
			ra := s.sar.Spec.ResourceAttributes
			metrics.WebhookSARDecisionsByAction.WithLabelValues(
				s.clusterName, ra.Verb, ra.Group, ra.Resource,
				ra.Namespace, ra.Subresource, "denied", "final").Inc()
		}
	}

	response := SubjectAccessReviewResponse{
		ApiVersion: s.sar.APIVersion,
		Kind:       s.sar.Kind,
		Status: SubjectAccessReviewResponseStatus{
			Allowed: s.allowed,
			Reason:  s.reason,
		},
	}
	s.reqLog.Debugw("Authorization decision",
		"allowed", s.allowed, "reason", s.reason,
		"sessionCount", len(s.sessions), "source", s.allowSource)

	// Log detailed denial summary at INFO level for easier debugging
	if !s.allowed {
		denialDetails := map[string]interface{}{
			"username":             username,
			"cluster":              s.clusterName,
			"activeSessions":       len(s.sessions),
			"idpMismatches":        len(s.idpMismatches),
			"escalationsAvailable": len(s.escals),
		}
		if s.sar.Spec.ResourceAttributes != nil {
			ra := s.sar.Spec.ResourceAttributes
			denialDetails["verb"] = ra.Verb
			denialDetails["apiGroup"] = ra.Group
			denialDetails["resource"] = ra.Resource
			denialDetails["namespace"] = ra.Namespace
			denialDetails["resourceName"] = ra.Name
			denialDetails["subresource"] = ra.Subresource
		}
		if s.sar.Spec.NonResourceAttributes != nil {
			nra := s.sar.Spec.NonResourceAttributes
			denialDetails["nonResourcePath"] = nra.Path
			denialDetails["nonResourceVerb"] = nra.Verb
		}
		if s.sessionSARSkipErr != nil {
			denialDetails["sessionSARSkipped"] = true
			denialDetails["sessionSARSkipReason"] = s.sessionSARSkipErr.Error()
		}
		// Collect session info for debugging
		if len(s.sessions) > 0 {
			sessNames := make([]string, len(s.sessions))
			for i, sess := range s.sessions {
				sessNames[i] = sess.Name + "(" + sess.Spec.GrantedGroup + ")"
			}
			denialDetails["sessionDetails"] = sessNames
		}
		s.reqLog.Infow("SAR request DENIED - summary", "details", denialDetails, "finalReason", s.reason)
	}

	// Marshal response to log exact bytes sent to caller for debugging malformation issues
	respBytes, merr := json.Marshal(response)
	respLog := ""
	if merr != nil {
		s.reqLog.With("error", merr.Error()).Error("Failed to marshal SubjectAccessReview response for debug logging")
	} else {
		respLog = string(respBytes)
		if len(respLog) > 8192 {
			respLog = respLog[:8192] + "...(truncated)"
		}
		s.reqLog.Debugw("Returning SubjectAccessReview response (raw)", "body", respLog)
	}

	// c.JSON sets Content-Type automatically; just log for correlation
	s.reqLog.Debug("Sending JSON response via c.JSON")

	// Also emit an Info-level summary with the key decision and a truncated raw response
	respLogForInfo := ""
	if respLog != "" {
		respLogForInfo = respLog
		if len(respLogForInfo) > 512 {
			respLogForInfo = respLogForInfo[:512] + "...(truncated)"
		}
	}
	s.reqLog.Infow("SubjectAccessReview processed",
		"username", username, "cluster", s.clusterName,
		"allowed", s.allowed, "reason", s.reason, "response", respLogForInfo)

	// Emit audit event for authorization decisions
	wc.emitAccessDecisionAudit(s.ctx, username, s.sar.Spec.Groups, s.clusterName,
		&s.sar, s.allowed, s.allowSource, s.reason)

	// Record total SAR processing duration
	decision := "allowed"
	if !s.allowed {
		decision = "denied"
	}
	metrics.WebhookSARDuration.WithLabelValues(s.clusterName, decision).
		Observe(time.Since(s.startTime).Seconds())

	// Ensure correlation ID header is present for apiserver correlation
	if cidv, ok := c.Get("cid"); ok {
		if cidstr, ok2 := cidv.(string); ok2 && cidstr != "" {
			c.Writer.Header().Set("X-Request-ID", cidstr)
		}
	}

	c.JSON(http.StatusOK, &response)
	s.reqLog.Debug("Authorization handler completed successfully")
}
