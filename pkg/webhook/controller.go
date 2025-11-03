package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/telekom/das-schiff-breakglass/api/v1alpha1"
	"github.com/telekom/das-schiff-breakglass/pkg/breakglass"
	"github.com/telekom/das-schiff-breakglass/pkg/cluster"
	"github.com/telekom/das-schiff-breakglass/pkg/config"
	"github.com/telekom/das-schiff-breakglass/pkg/metrics"
	"github.com/telekom/das-schiff-breakglass/pkg/policy"
	"github.com/telekom/das-schiff-breakglass/pkg/system"
)

// denyReasonMessage is a user-facing instruction included in SubjectAccessReview deny responses.
// It points users to the Breakglass UI (frontend root) and explains what to do there. The first
// %s is the configured frontend base URL, the second %s is the cluster name (URL-escaped) which
// will be provided as the `search` query parameter to pre-populate the cluster filter in the UI.
const denyReasonMessage = "Access denied. To request temporary access via Breakglass, visit %s?search=%s and open a new request. Include the reason for access, the target cluster, and the requested group(s). If you need help, contact your platform admins."

// buildReason appends a helpful link to the breakglass frontend for a given cluster.
func (wc *WebhookController) buildBreakglassLink(cluster string) string {
	base := strings.TrimRight(wc.config.Frontend.BaseURL, "/")
	if base == "" {
		return ""
	}
	// Prepopulate the frontend search filter with the cluster name so the request UI shows matching breakglass groups.
	// URL-encode the cluster value to be safe.
	return fmt.Sprintf("%s?search=%s", base, urlQueryEscape(cluster))
}

// urlQueryEscape escapes a string for inclusion in a URL query parameter.
func urlQueryEscape(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, " ", "+"), "#", "%23")
}

// finalizeReason ensures the SAR reason always contains a helpful link to the breakglass UI.
func (wc *WebhookController) finalizeReason(reason string, allowed bool, cluster string) string {
	link := wc.buildBreakglassLink(cluster)
	if link == "" {
		// nothing to append
		return reason
	}
	// If reason already contains the link, don't append it again
	if strings.Contains(reason, link) {
		return reason
	}
	if reason == "" {
		if allowed {
			return fmt.Sprintf("Allowed; view details or sessions at %s", link)
		}
		return fmt.Sprintf(denyReasonMessage, wc.config.Frontend.BaseURL, cluster)
	}
	// If reason already contains something, append a short pointer to the link
	return fmt.Sprintf("%s; see %s", reason, link)
}

type SubjectAccessReviewResponseStatus struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

type SubjectAccessReviewResponse struct {
	ApiVersion string                            `json:"apiVersion"`
	Kind       string                            `json:"kind"`
	Status     SubjectAccessReviewResponseStatus `json:"status"`
}

type WebhookController struct {
	log          *zap.SugaredLogger
	config       config.Config
	sesManager   *breakglass.SessionManager
	escalManager *breakglass.EscalationManager
	canDoFn      breakglass.CanGroupsDoFunction
	ccProvider   *cluster.ClientProvider
	denyEval     *policy.Evaluator
}

// getClusterConfigAcrossNamespaces performs a ClusterConfig lookup across all namespaces
// by delegating to the ClientProvider legacy behavior (empty namespace). The Webhook
// controller does not have an escalation namespace context, so callers should use this
// helper when they need the provider to search across namespaces.
func (wc *WebhookController) getClusterConfigAcrossNamespaces(ctx context.Context, name string) (*v1alpha1.ClusterConfig, error) {
	if wc.ccProvider == nil {
		return nil, fmt.Errorf("cluster client provider not configured")
	}
	return wc.ccProvider.GetAcrossAllNamespaces(ctx, name)
}

func (WebhookController) BasePath() string {
	return "breakglass/webhook"
}

func (wc *WebhookController) Register(rg *gin.RouterGroup) error {
	wc.log.With("path", "breakglass/webhook").Info("Registering webhook controller routes")
	rg.POST("/authorize/:cluster_name", wc.handleAuthorize)
	wc.log.Debug("Webhook controller routes registered successfully")
	return nil
}

func (b WebhookController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{}
}

func (wc *WebhookController) handleAuthorize(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	// record incoming SAR request (label by cluster)
	metrics.WebhookSARRequests.WithLabelValues(clusterName).Inc()
	ctx := c.Request.Context()
	wc.log.With("cluster", clusterName).Debug("Processing authorization request for cluster")

	sar := authorizationv1.SubjectAccessReview{}

	// Read raw body for better debug logging and then decode
	bodyBytes, rerr := io.ReadAll(c.Request.Body)
	if rerr != nil {
		wc.log.With("error", rerr.Error()).Error("Failed to read request body for SubjectAccessReview")
		c.Status(http.StatusUnprocessableEntity)
		return
	}
	// restore body for potential downstream reads (not strictly needed here)
	c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Log raw request body at debug (truncate to 8KB to avoid huge logs)
	reqLog := system.GetReqLogger(c, wc.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)

	rawLog := string(bodyBytes)
	if len(rawLog) > 8192 {
		rawLog = rawLog[:8192] + "...(truncated)"
	}
	reqLog.Debugw("Raw SubjectAccessReview request body", "body", rawLog)

	// Now that we have an enriched request logger, record handler entry with cluster
	reqLog.Debugw("handleAuthorize entered", "cluster", clusterName)

	if err := json.Unmarshal(bodyBytes, &sar); err != nil {
		reqLog.With("error", err.Error()).Errorw("Failed to decode SubjectAccessReview body (raw payload logged)", "raw", rawLog)
		c.Status(http.StatusUnprocessableEntity)
		return
	}

	reqLog.Debug("Received SubjectAccessReview")

	username := sar.Spec.User
	reqLog.Infow("Processing authorization", "username", username, "groupsRequested", sar.Spec.Groups)

	groups, sessions, tenant, err := wc.getUserGroupsAndSessions(ctx, username, clusterName)
	if err != nil {
		reqLog.With("error", err.Error()).Error("Failed to retrieve user groups for cluster")
		c.Status(http.StatusInternalServerError)
		return
	}
	reqLog.With("groups", groups, "sessions", len(sessions), "tenant", tenant).Debug("Retrieved user groups for cluster")

	// DENY POLICY EVALUATION (phase 1 - cluster/tenant global)
	if sar.Spec.ResourceAttributes != nil {
		act := policy.Action{
			Verb:        sar.Spec.ResourceAttributes.Verb,
			APIGroup:    sar.Spec.ResourceAttributes.Group,
			Resource:    sar.Spec.ResourceAttributes.Resource,
			Namespace:   sar.Spec.ResourceAttributes.Namespace,
			Name:        sar.Spec.ResourceAttributes.Name,
			Subresource: sar.Spec.ResourceAttributes.Subresource,
			ClusterID:   clusterName,
			Tenant:      tenant,
		}
		if denied, pol, derr := wc.denyEval.Match(ctx, act); derr != nil {
			reqLog.With("error", derr.Error(), "action", act).Error("deny evaluation error")
		} else if denied {
			reqLog.With("policy", pol).Info("Request denied by global/cluster policy")
			reqLog.Debugw("Global denyEval matched", "policy", pol, "action", act)
			// Determine if any escalation paths exist for this user (use groups from sessions plus system:authenticated)
			uniqueGroups := append([]string{}, groups...)
			uniqueGroups = append(uniqueGroups, "system:authenticated")
			ug := dedupeStrings(uniqueGroups)
			escals, eerr := wc.escalManager.GetClusterGroupBreakglassEscalations(ctx, clusterName, ug)
			count := 0
			if eerr != nil {
				reqLog.With("error", eerr.Error()).Error("Failed to count escalations for deny response")
			} else {
				count = len(escals)
			}
			var reason string
			if count > 0 {
				reason = fmt.Sprintf("Denied by policy %s; %d breakglass escalation(s) available", pol, count)
			} else {
				reason = fmt.Sprintf("Denied by policy %s; No breakglass flow available for your user", pol)
			}
			reason = wc.finalizeReason(reason, false, clusterName)
			c.JSON(http.StatusOK, &SubjectAccessReviewResponse{ApiVersion: sar.APIVersion, Kind: sar.Kind, Status: SubjectAccessReviewResponseStatus{Allowed: false, Reason: reason}})
			return
		}
		// session-scoped policies
		for _, s := range sessions {
			act.Session = s.Name
			if denied, pol, derr := wc.denyEval.Match(ctx, act); derr != nil {
				reqLog.With("error", derr.Error(), "session", s.Name, "action", act).Error("deny evaluation error for session")
			} else if denied {
				reqLog.With("policy", pol, "session", s.Name).Info("Request denied by session policy")
				reqLog.Debugw("Session denyEval matched", "policy", pol, "session", s.Name, "action", act)
				// Determine escalation availability for this session/user combination
				uniqueGroups := append([]string{}, groups...)
				uniqueGroups = append(uniqueGroups, "system:authenticated")
				ug := dedupeStrings(uniqueGroups)
				escals, eerr := wc.escalManager.GetClusterGroupBreakglassEscalations(ctx, clusterName, ug)
				count := 0
				if eerr != nil {
					reqLog.With("error", eerr.Error()).Error("Failed to count escalations for session deny response")
				} else {
					count = len(escals)
				}
				var reason string
				if count > 0 {
					reason = fmt.Sprintf("Denied by policy %s; %d breakglass escalation(s) available", pol, count)
				} else {
					reason = fmt.Sprintf("Denied by policy %s; No breakglass flow available for your user", pol)
				}
				reason = wc.finalizeReason(reason, false, clusterName)
				c.JSON(http.StatusOK, &SubjectAccessReviewResponse{ApiVersion: sar.APIVersion, Kind: sar.Kind, Status: SubjectAccessReviewResponseStatus{Allowed: false, Reason: reason}})
				return
			}
		}
	}

	// NOTE: If we want to know specific group that allowed user to perform the operation we would
	// need to iterate over groups (sessions) and note the first that is ok. Then we could update its
	// last used parameters and idle value.
	// Perform standard RBAC check against target cluster (not hub) using its kubeconfig
	var can bool
	var rbacErr error
	// Log input to RBAC check for easier debugging
	reqLog.Debugw("Invoking RBAC canDoFn", "groups", groups, "resourceAttributes", sar.Spec.ResourceAttributes, "cluster", clusterName)

	var sessionSARSkippedErr error
	if wc.ccProvider != nil {
		if rc, rerr := wc.ccProvider.GetRESTConfig(ctx, clusterName); rerr == nil {
			can, rbacErr = wc.canDoFn(ctx, rc, groups, sar, clusterName)
		} else {
			// downgrade to info; this will commonly happen if RBAC does not yet allow clusterconfig get
			reqLog.With("error", rerr).Info("Failed to get REST config for standard RBAC check; using legacy fallback")
			// Record that session SAR checks will be skipped because we couldn't load REST config
			sessionSARSkippedErr = rerr
			// Still invoke injected canDoFn with nil to allow tests to control behavior
			can, rbacErr = wc.canDoFn(ctx, nil, groups, sar, clusterName)
		}
	} else {
		can, rbacErr = wc.canDoFn(ctx, nil, groups, sar, clusterName)
	}
	if rbacErr != nil {
		msg := rbacErr.Error()
		// Treat missing rest config or legacy context absence as denial (not internal error)
		if msg == "rest config is nil" || strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file") {
			reqLog.With("error", rbacErr).Warn("RBAC infrastructure unavailable; treating as denied and continuing")
			can = false
		} else {
			reqLog.With("error", rbacErr).Error("RBAC canDoFn error")
			c.Status(http.StatusInternalServerError)
			return
		}
	}
	reqLog.Debugw("RBAC check result", "allowed", can, "groupCount", len(groups))

	allowed := false
	reason := ""
	allowSource := "" // rbac|session
	allowDetail := ""

	if can {
		reqLog.Info("User authorized through regular RBAC permissions")
		allowed = true
		allowSource = "rbac"
		allowDetail = fmt.Sprintf("groups=%v", groups)
	} else {
		reqLog.Debug("User not authorized through regular RBAC, checking for breakglass escalations")

		// Session SAR checks: attempt authorization impersonating each granted group via admin kubeconfig.
		if wc.ccProvider != nil && sar.Spec.ResourceAttributes != nil {
			if rc, err := wc.ccProvider.GetRESTConfig(ctx, clusterName); err != nil {
				reqLog.With("error", err.Error()).Warn("Unable to load target cluster rest.Config for SAR; skipping session SAR checks")
				// mark that we skipped session SAR checks for diagnostics
				sessionSARSkippedErr = err
			} else if allowedSession, grp, sesName, impersonated := wc.authorizeViaSessions(ctx, rc, sessions, sar, clusterName, reqLog); allowedSession {
				reqLog.With("grantedGroup", grp, "session", sesName, "impersonatedGroup", impersonated).Debug("Authorized via breakglass session group on target cluster")
				allowed = true
				allowSource = "session"
				allowDetail = fmt.Sprintf("group=%s session=%s impersonated=%s", grp, sesName, impersonated)
				// Emit a single correlated info log showing the final accepted impersonated group for observability
				reqLog.Infow("Final accepted impersonated group", "username", username, "cluster", clusterName, "grantedGroup", grp, "session", sesName, "impersonatedGroup", impersonated)
			}
		}

		// Get user groups from active sessions
		activeUserGroups, _, _, err := wc.getUserGroupsAndSessions(ctx, username, clusterName)
		if err != nil {
			reqLog.With("error", err.Error()).Error("Failed to retrieve user groups for cluster")
			c.Status(http.StatusInternalServerError)
			return
		}
		reqLog.With("activeUserGroups", activeUserGroups).Debug("Retrieved user groups from active sessions")

		// Add basic user groups that all authenticated users should have
		allUserGroups := append(activeUserGroups, "system:authenticated")
		uniqueGroups := dedupeStrings(allUserGroups)
		reqLog.With("allUserGroups", uniqueGroups).Debug("Final user groups including basic authenticated groups")

		// Check for group-based escalations
		escals, err := wc.escalManager.GetClusterGroupBreakglassEscalations(ctx, clusterName, uniqueGroups)
		if err != nil {
			reqLog.With("error", err.Error()).Error("Failed to retrieve group escalations")
			c.Status(http.StatusInternalServerError)
			return
		}
		reqLog.With("escalationsCount", len(escals)).Debug("Retrieved group-specific escalations")

		// Check for target group escalations if we have a specific group request
		var groupescals []v1alpha1.BreakglassEscalation
		if sar.Spec.ResourceAttributes.Group != "" {
			groupescals, err = wc.escalManager.GetClusterGroupTargetBreakglassEscalation(ctx,
				clusterName,
				uniqueGroups,
				sar.Spec.ResourceAttributes.Group,
			)
			if err != nil {
				reqLog.With("error", err.Error()).Error("Failed to retrieve target group escalations")
				c.Status(http.StatusInternalServerError)
				return
			}
		}
		reqLog.With("groupEscalationsCount", len(groupescals)).Debug("Retrieved target group escalations")

		escals = append(escals, groupescals...)
		reqLog.With("totalEscalations", len(escals)).Debug("Total available escalation paths")

		if len(escals) > 0 {
			reqLog.Debugw("Escalation paths available", "count", len(escals))
			reason = fmt.Sprintf(denyReasonMessage,
				wc.config.Frontend.BaseURL, clusterName)
		} else {
			reqLog.Debugw("No escalation paths for user", "username", username)
		}
		reqLog.With("escalations", escals).Debug("Available escalation paths for user")
	}

	if allowed && reason == "" { // populate positive reason
		switch allowSource {
		case "rbac":
			reason = fmt.Sprintf("Allowed by RBAC (%s)", allowDetail)
		case "session":
			reason = fmt.Sprintf("Allowed by breakglass session (%s)", allowDetail)
		}
	}

	// If we denied the request but the user has active sessions and we were unable to
	// perform session SAR checks (for example because the cluster kubeconfig is
	// missing), append a helpful note so callers and users know why a valid session
	// didn't result in an allow decision.
	if !allowed && len(sessions) > 0 {
		// If we recorded a skip for session SAR checks, add a diagnostic note to the reason
		if sessionSARSkippedErr != nil {
			metrics.WebhookSessionSARSSkipped.WithLabelValues(clusterName).Inc()
			// Collect session names and granted groups for the diagnostic message
			sessInfo := make([]string, 0, len(sessions))
			for _, s := range sessions {
				sessInfo = append(sessInfo, s.Name+"("+s.Spec.GrantedGroup+")")
			}
			diag := fmt.Sprintf(" Note: %d active breakglass session(s) found: %v. Session-level authorization checks were skipped due to cluster validation error: %s. If you believe you have valid access, ensure the platform has the cluster kubeconfig configured.", len(sessions), sessInfo, sessionSARSkippedErr.Error())
			if reason == "" {
				reason = diag
			} else {
				reason = reason + "" + diag
			}
			// Also log this at info so admins see the mismatch between session state and SAR capabilities
			reqLog.With("sessions", sessInfo, "error", sessionSARSkippedErr.Error()).Info("Active sessions present but unable to validate them against target cluster")
		}
	}

	// Ensure the reason always includes a helpful link to the breakglass UI
	reason = wc.finalizeReason(reason, allowed, clusterName)
	if allowed {
		metrics.WebhookSARAllowed.WithLabelValues(clusterName).Inc()
	} else {
		metrics.WebhookSARDenied.WithLabelValues(clusterName).Inc()
	}
	response := SubjectAccessReviewResponse{
		ApiVersion: sar.APIVersion,
		Kind:       sar.Kind,
		Status: SubjectAccessReviewResponseStatus{
			Allowed: allowed,
			Reason:  reason,
		},
	}
	reqLog.Debugw("Authorization decision", "allowed", allowed, "reason", reason, "sessionCount", len(sessions), "source", allowSource)
	// Marshal response to log exact bytes sent to caller for debugging malformation issues
	respBytes, merr := json.Marshal(response)
	respLog := ""
	if merr != nil {
		reqLog.With("error", merr.Error()).Error("Failed to marshal SubjectAccessReview response for debug logging")
	} else {
		respLog = string(respBytes)
		if len(respLog) > 8192 {
			respLog = respLog[:8192] + "...(truncated)"
		}
		reqLog.Debugw("Returning SubjectAccessReview response (raw)", "body", respLog)
	}

	// Ensure content type is explicit and log it for correlation with apiserver
	c.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	reqLog.Debugw("Sending response", "content-type", c.Writer.Header().Get("Content-Type"))

	// Also emit an Info-level summary with the key decision and a truncated raw response
	respLogForInfo := ""
	if respLog != "" {
		respLogForInfo = respLog
		if len(respLogForInfo) > 512 {
			respLogForInfo = respLogForInfo[:512] + "...(truncated)"
		}
	}
	reqLog.Infow("SubjectAccessReview processed", "username", username, "cluster", clusterName, "allowed", allowed, "reason", reason, "response", respLogForInfo)

	// Ensure correlation ID header is present for apiserver correlation
	if cidv, ok := c.Get("cid"); ok {
		if cidstr, ok2 := cidv.(string); ok2 && cidstr != "" {
			c.Writer.Header().Set("X-Request-ID", cidstr)
		}
	}

	c.JSON(http.StatusOK, &response)
	reqLog.Debug("Authorization handler completed successfully")
}

// getUserGroupsForCluster removed (unused)

func NewWebhookController(log *zap.SugaredLogger,
	cfg config.Config,
	sesManager *breakglass.SessionManager,
	escalManager *breakglass.EscalationManager,
	ccProvider *cluster.ClientProvider,
	denyEval *policy.Evaluator,
) *WebhookController {

	return &WebhookController{
		log:          log,
		config:       cfg,
		sesManager:   sesManager,
		escalManager: escalManager,
		canDoFn:      breakglass.CanGroupsDo,
		ccProvider:   ccProvider,
		denyEval:     denyEval,
	}
}

// getUserGroupsAndSessions returns groups from active sessions, list of sessions, and a tenant (best-effort from cluster config).
func (wc *WebhookController) getUserGroupsAndSessions(ctx context.Context, username, clustername string) ([]string, []v1alpha1.BreakglassSession, string, error) {
	sessions, err := wc.getSessions(ctx, username, clustername)
	if err != nil {
		return nil, nil, "", err
	}
	groups := make([]string, 0, len(sessions))
	for _, s := range sessions {
		groups = append(groups, s.Spec.GrantedGroup)
	}
	// best-effort tenant lookup
	tenant := ""
	if wc.ccProvider != nil {
		if cfg, err := wc.getClusterConfigAcrossNamespaces(ctx, clustername); err == nil && cfg != nil {
			tenant = cfg.Spec.Tenant
		}
	}
	return groups, sessions, tenant, nil
}

// getSessions filtered (reuse existing approval logic)
func (wc *WebhookController) getSessions(ctx context.Context, username, clustername string) ([]v1alpha1.BreakglassSession, error) {
	selector := fields.SelectorFromSet(fields.Set{"spec.cluster": clustername, "spec.user": username})
	all, err := wc.sesManager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		return nil, err
	}
	out := make([]v1alpha1.BreakglassSession, 0, len(all))
	now := time.Now()
	for _, s := range all {
		if breakglass.IsSessionRetained(s) {
			continue
		}
		if s.Status.RejectedAt.IsZero() && !s.Status.ExpiresAt.IsZero() && s.Status.ExpiresAt.After(now) {
			out = append(out, s)
		}
	}
	return out, nil
}

// dedupeStrings removes duplicates from a slice of strings while preserving order.
func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool)
	for _, v := range in {
		if !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

// authorizeViaSessions performs per-session SubjectAccessReviews using the session's granted group.
func (wc *WebhookController) authorizeViaSessions(ctx context.Context, rc *rest.Config, sessions []v1alpha1.BreakglassSession, incoming authorizationv1.SubjectAccessReview, clusterName string, reqLog ...*zap.SugaredLogger) (bool, string, string, string) {
	var logger *zap.SugaredLogger
	if len(reqLog) > 0 {
		logger = reqLog[0]
	}
	if len(sessions) == 0 || incoming.Spec.ResourceAttributes == nil {
		return false, "", "", ""
	}
	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		if logger != nil {
			logger.With("error", err).Error("failed creating clientset for session SAR")
		} else if wc.log != nil {
			wc.log.With("error", err).Error("failed creating clientset for session SAR")
		}
		return false, "", "", ""
	}
	sarClient := clientset.AuthorizationV1().SubjectAccessReviews()
	for _, s := range sessions {
		var allowedGroupsToCheck []string
		// Resolve escalation via OwnerReferences first
		if len(s.OwnerReferences) > 0 && wc.escalManager != nil {
			for _, or := range s.OwnerReferences {
				escs, eerr := wc.escalManager.GetBreakglassEscalationsWithFilter(ctx, func(be v1alpha1.BreakglassEscalation) bool {
					return be.Name == or.Name
				})
				if eerr != nil {
					if logger != nil {
						logger.With("error", eerr, "ownerRef", or).Debug("failed to lookup escalation for session ownerRef")
					} else if wc.log != nil {
						wc.log.With("error", eerr, "ownerRef", or).Debug("failed to lookup escalation for session ownerRef")
					}
					continue
				}
				if len(escs) > 0 {
					allowedGroupsToCheck = escs[0].Spec.Allowed.Groups
					break
				}
			}
		}

		if len(allowedGroupsToCheck) == 0 {
			// Fallback: when no escalation allowed groups are available, try
			// the plain granted group so sessions without explicit escalation
			// ownerRefs still enable standard session-based SAR checks.
			allowedGroupsToCheck = []string{s.Spec.GrantedGroup}
			if logger != nil {
				logger.Debugw("No escalation allowed groups found; falling back to session granted group for prefix detection", "session", s.Name, "grantedGroup", s.Spec.GrantedGroup)
			} else if wc.log != nil {
				wc.log.Debugw("No escalation allowed groups found; falling back to session granted group for prefix detection", "session", s.Name, "grantedGroup", s.Spec.GrantedGroup)
			}
		}

		prefixes := wc.config.Kubernetes.OIDCPrefixes
		// Find a primary prefix by matching incoming groups to allowed groups
		var primaryPrefix string
		if incoming.Spec.Groups != nil && len(prefixes) > 0 {
			for _, ig := range incoming.Spec.Groups {
				for _, allowed := range allowedGroupsToCheck {
					for _, p := range prefixes {
						if strings.HasPrefix(ig, p) && strings.HasSuffix(ig, allowed) {
							primaryPrefix = p
							break
						}
					}
					if primaryPrefix != "" {
						break
					}
				}
				if primaryPrefix != "" {
					break
				}
			}
		}

		// Build ordered list of impersonation groups to try. We include the plain
		// granted group as a baseline. If a primary prefix is detected, try it
		// first, then the plain group, then remaining prefixes. Otherwise try
		// plain group first followed by configured prefixes.
		groupsToTry := make([]string, 0, len(prefixes)+1)
		if primaryPrefix != "" {
			groupsToTry = append(groupsToTry, primaryPrefix+s.Spec.GrantedGroup)
			groupsToTry = append(groupsToTry, s.Spec.GrantedGroup)
			for _, p := range prefixes {
				if p != primaryPrefix {
					groupsToTry = append(groupsToTry, p+s.Spec.GrantedGroup)
				}
			}
		} else {
			groupsToTry = append(groupsToTry, s.Spec.GrantedGroup)
			for _, p := range prefixes {
				groupsToTry = append(groupsToTry, p+s.Spec.GrantedGroup)
			}
		}

		if logger != nil {
			logger.Debugw("Impersonation groups to try", "groupsToTry", groupsToTry, "session", s.Name)
		} else if wc.log != nil {
			wc.log.Debugw("Impersonation groups to try", "groupsToTry", groupsToTry, "session", s.Name)
		}

		for _, g := range groupsToTry {
			sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   "system:breakglass-session",
				Groups: []string{g},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   incoming.Spec.ResourceAttributes.Namespace,
					Verb:        incoming.Spec.ResourceAttributes.Verb,
					Group:       incoming.Spec.ResourceAttributes.Group,
					Resource:    incoming.Spec.ResourceAttributes.Resource,
					Subresource: incoming.Spec.ResourceAttributes.Subresource,
					Name:        incoming.Spec.ResourceAttributes.Name,
				},
			}}
			if logger != nil {
				logger.Debugw("Creating SubjectAccessReview for session impersonation", "group", g, "session", s.Name)
			} else if wc.log != nil {
				wc.log.Debugw("Creating SubjectAccessReview for session impersonation", "group", g, "session", s.Name)
			}
			resp, err := sarClient.Create(ctx, sar, metav1.CreateOptions{})
			if err != nil {
				if logger != nil {
					logger.With("error", err, "group", g).Warn("session SAR error")
					logger.Debugw("Failed SAR create error details", "error", err, "sarSpec", sar.Spec)
				} else if wc.log != nil {
					wc.log.With("error", err, "group", g).Warn("session SAR error")
					wc.log.Debugw("Failed SAR create error details", "error", err, "sarSpec", sar.Spec)
				}
				metrics.WebhookSessionSARErrors.WithLabelValues(clusterName, s.Name, g).Inc()
				continue
			}
			if resp != nil {
				if logger != nil {
					logger.Debugw("Session SAR response", "group", g, "session", s.Name, "allowed", resp.Status.Allowed, "reason", resp.Status.Reason)
				} else if wc.log != nil {
					wc.log.Debugw("Session SAR response", "group", g, "session", s.Name, "allowed", resp.Status.Allowed, "reason", resp.Status.Reason)
				}
			}
			if resp != nil && resp.Status.Allowed {
				metrics.WebhookSessionSARsAllowed.WithLabelValues(clusterName, s.Name, g).Inc()
				return true, s.Spec.GrantedGroup, s.Name, g
			}
			metrics.WebhookSessionSARsDenied.WithLabelValues(clusterName, s.Name, g).Inc()
		}
	}
	return false, "", "", ""
}
