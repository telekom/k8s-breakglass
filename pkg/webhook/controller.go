package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/system"
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

func summarizeAction(sar *authorizationv1.SubjectAccessReview) string {
	if sar == nil {
		return "the requested action"
	}
	if ra := sar.Spec.ResourceAttributes; ra != nil {
		resource := ra.Resource
		if ra.Subresource != "" {
			resource = fmt.Sprintf("%s/%s", resource, ra.Subresource)
		}
		target := resource
		if ra.Name != "" {
			target = fmt.Sprintf("%s %s", resource, ra.Name)
		}
		ns := ra.Namespace
		if ns == "" {
			ns = "(cluster-wide)"
		}
		return fmt.Sprintf("%s %s in namespace %s", ra.Verb, target, ns)
	}
	if nra := sar.Spec.NonResourceAttributes; nra != nil {
		return fmt.Sprintf("%s %s", nra.Verb, nra.Path)
	}
	return "the requested action"
}

// getIDPHintFromIssuer retrieves issuer information from the SAR and returns a helpful
// hint message about which identity provider authenticated the user, if available.
// This helps users understand which IDP issued their token when authentication fails.
func (wc *WebhookController) getIDPHintFromIssuer(ctx context.Context, sar *authorizationv1.SubjectAccessReview, reqLog *zap.SugaredLogger) string {
	if sar == nil {
		return ""
	}

	// Extract issuer from SAR.Spec.Extra field
	// The "identity.t-caas.telekom.com/issuer" extra field contains the OIDC issuer URL
	// that authenticated this user (extracted from their JWT token's 'iss' claim)
	// Note: Extra fields in Kubernetes SubjectAccessReview are slice of strings, not single values
	var issuer string
	if sar.Spec.Extra != nil {
		issuerValues := sar.Spec.Extra["identity.t-caas.telekom.com/issuer"]
		if len(issuerValues) > 0 {
			issuer = issuerValues[0]
		}
	}

	// Fallback: also check annotations (for backward compatibility)
	if issuer == "" && sar.ObjectMeta.Annotations != nil {
		issuer = sar.ObjectMeta.Annotations["identity.t-caas.telekom.com/issuer"]
	}

	if issuer == "" {
		// Issuer not provided, skip hint generation
		return ""
	}

	reqLog.Debugw("Extracting IDP hint from issuer", "issuer", issuer)

	// Try to find matching IdentityProvider by issuer
	// This helps users know which provider authenticated them
	idpList := &v1alpha1.IdentityProviderList{}
	if err := wc.escalManager.List(ctx, idpList); err != nil {
		reqLog.With("error", err.Error()).Warn("Failed to list IdentityProviders for IDP hint")
		// Fallback: just mention the issuer
		return fmt.Sprintf("(Your token was issued by %s)", issuer)
	}

	// Find IdentityProvider with matching issuer
	for _, idp := range idpList.Items {
		if idp.Spec.Issuer == issuer {
			displayName := idp.Spec.DisplayName
			if displayName == "" {
				displayName = idp.Name
			}
			return fmt.Sprintf("(Your token was authenticated by '%s')", displayName)
		}
	}

	// Issuer didn't match any configured IDP - provide helpful guidance
	// List all available providers to help user identify the right one
	var displayNames []string
	for _, idp := range idpList.Items {
		if idp.Spec.Disabled {
			continue // skip disabled providers
		}
		displayName := idp.Spec.DisplayName
		if displayName == "" {
			displayName = idp.Name
		}
		displayNames = append(displayNames, displayName)
	}

	if len(displayNames) > 0 {
		return fmt.Sprintf("(Your token issuer '%s' is not configured. Available providers: %s)", issuer, strings.Join(displayNames, ", "))
	}

	// Fallback: just mention the issuer
	return fmt.Sprintf("(Your token was issued by %s)", issuer)
}

// isRequestFromAllowedIDP checks if a requestor from a specific issuer (IDP) is allowed to use a specific escalation.
// If the escalation has AllowedIdentityProvidersForRequests, the issuer must match one of those.
// If AllowedIdentityProvidersForRequests is empty, the request is allowed from any IDP (backward compatible).
// This function maps IDP issuer URLs to IDP names for matching.
func (wc *WebhookController) isRequestFromAllowedIDP(ctx context.Context, issuer string, esc *v1alpha1.BreakglassEscalation, reqLog *zap.SugaredLogger) bool {
	// If no IDP restrictions, request is allowed from any IDP
	if len(esc.Spec.AllowedIdentityProvidersForRequests) == 0 {
		return true
	}

	// If multi-IDP mode is enabled but no issuer provided, deny by default
	if issuer == "" {
		reqLog.Debugw("Request missing issuer information required for multi-IDP validation", "escalation", esc.Name)
		return false
	}

	// Find matching IdentityProvider by issuer
	idpList := &v1alpha1.IdentityProviderList{}
	if err := wc.escalManager.List(ctx, idpList); err != nil {
		reqLog.With("error", err.Error()).Warn("Failed to list IdentityProviders for request validation")
		// Fail open: if we can't load IDPs, don't block the request
		return true
	}

	// Map issuer to IDP name
	var matchedIDPName string
	for _, idp := range idpList.Items {
		if idp.Spec.Issuer == issuer && !idp.Spec.Disabled {
			matchedIDPName = idp.Name
			break
		}
	}

	// If issuer doesn't match any enabled IDP, deny
	if matchedIDPName == "" {
		reqLog.Debugw("Request from unknown or disabled IDP issuer", "issuer", issuer, "escalation", esc.Name)
		return false
	}

	// Check if the matched IDP is in the escalation's allowed list
	for _, allowedIDPName := range esc.Spec.AllowedIdentityProvidersForRequests {
		if allowedIDPName == matchedIDPName {
			reqLog.Debugw("Request allowed: IDP in AllowedIdentityProvidersForRequests", "idp", matchedIDPName, "escalation", esc.Name)
			return true
		}
	}

	reqLog.Debugw("Request denied: IDP not in AllowedIdentityProvidersForRequests", "idp", matchedIDPName, "allowedIDPs", esc.Spec.AllowedIdentityProvidersForRequests, "escalation", esc.Name)
	return false
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

// PodFetchFunction is the signature for functions that fetch pods from a cluster.
type PodFetchFunction func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error)

type WebhookController struct {
	log          *zap.SugaredLogger
	config       config.Config
	sesManager   *breakglass.SessionManager
	escalManager *breakglass.EscalationManager
	canDoFn      breakglass.CanGroupsDoFunction
	ccProvider   *cluster.ClientProvider
	denyEval     *policy.Evaluator
	podFetchFn   PodFetchFunction // optional override for testing
}

// checkDebugSessionAccess checks if a pod exec request is allowed by an active debug session.
// Returns (allowed, sessionName, reason) where allowed is true if the user can exec into the pod
// via a debug session they are participating in.
func (wc *WebhookController) checkDebugSessionAccess(ctx context.Context, username, clusterName string, ra *authorizationv1.ResourceAttributes, reqLog *zap.SugaredLogger) (bool, string, string) {
	// Only check for pods/exec requests
	if ra == nil || ra.Resource != "pods" || ra.Subresource != "exec" {
		return false, "", ""
	}

	if ra.Name == "" || ra.Namespace == "" {
		return false, "", ""
	}

	if wc.escalManager == nil || wc.escalManager.Client == nil {
		reqLog.Debug("Debug session check skipped: no client available")
		return false, "", ""
	}

	// List active debug sessions for this cluster
	debugSessionList := &v1alpha1.DebugSessionList{}
	if err := wc.escalManager.List(ctx, debugSessionList); err != nil {
		reqLog.Warnw("Failed to list debug sessions for pod exec check", "error", err)
		return false, "", ""
	}

	// Check each active debug session
	for _, ds := range debugSessionList.Items {
		// Only check active sessions for this cluster
		if ds.Status.State != v1alpha1.DebugSessionStateActive || ds.Spec.Cluster != clusterName {
			continue
		}

		// Check if the pod is in the allowed pods list
		podAllowed := false
		for _, ap := range ds.Status.AllowedPods {
			if ap.Namespace == ra.Namespace && ap.Name == ra.Name {
				podAllowed = true
				break
			}
		}
		if !podAllowed {
			continue
		}

		// Check if the user is a participant of this session
		for _, p := range ds.Status.Participants {
			if p.User == username {
				reason := fmt.Sprintf("Allowed by debug session %s (role: %s)", ds.Name, p.Role)
				reqLog.Infow("Debug session pod exec allowed",
					"session", ds.Name,
					"pod", fmt.Sprintf("%s/%s", ra.Namespace, ra.Name),
					"user", username,
					"role", p.Role)
				return true, ds.Name, reason
			}
		}
	}

	return false, "", ""
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
	actionSummary := summarizeAction(&sar)

	username := sar.Spec.User
	reqLog.Infow("Processing authorization", "username", username, "groupsRequested", sar.Spec.Groups)

	var clusterCfg *v1alpha1.ClusterConfig
	if wc.ccProvider != nil {
		cfg, cfgErr := wc.getClusterConfigAcrossNamespaces(ctx, clusterName)
		if cfgErr != nil {
			if errors.Is(cfgErr, cluster.ErrClusterConfigNotFound) {
				reason := fmt.Sprintf("Cluster %q is not registered with Breakglass, so %s cannot be authorized yet. Ask your platform administrators to onboard the cluster or choose one of the onboarded clusters.", clusterName, actionSummary)
				reason = wc.finalizeReason(reason, false, clusterName)
				metrics.WebhookSARDenied.WithLabelValues(clusterName).Inc()
				if sar.Spec.ResourceAttributes != nil {
					ra := sar.Spec.ResourceAttributes
					metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, ra.Verb, ra.Group, ra.Resource, ra.Namespace, ra.Subresource, "denied", "cluster-missing").Inc()
				}
				reqLog.Warnw("Cluster not registered for Breakglass", "cluster", clusterName)
				c.JSON(http.StatusOK, &SubjectAccessReviewResponse{
					ApiVersion: sar.APIVersion,
					Kind:       sar.Kind,
					Status: SubjectAccessReviewResponseStatus{
						Allowed: false,
						Reason:  reason,
					},
				})
				return
			}
			reqLog.With("error", cfgErr.Error()).Error("Failed to load ClusterConfig for SAR validation")
			c.Status(http.StatusInternalServerError)
			return
		}
		clusterCfg = cfg
	}

	// Emit the actual requested API action (from SAR) at Info level for observability.
	// This includes resource attributes (verb, group, resource, namespace, name, subresource)
	// or non-resource attributes (path, verb) when present.
	if sar.Spec.ResourceAttributes != nil {
		ra := sar.Spec.ResourceAttributes
		// Increment action-based request metric (omit name to reduce cardinality)
		metrics.WebhookSARRequestsByAction.WithLabelValues(clusterName, ra.Verb, ra.Group, ra.Resource, ra.Namespace, ra.Subresource).Inc()
		// Build a small structured action for log ingestion systems
		action := map[string]string{
			"verb":        ra.Verb,
			"apiGroup":    ra.Group,
			"resource":    ra.Resource,
			"namespace":   ra.Namespace,
			"name":        ra.Name,
			"subresource": ra.Subresource,
		}
		reqLog.Infow("SubjectAccessReview requested action",
			"verb", ra.Verb,
			"apiGroup", ra.Group,
			"resource", ra.Resource,
			"namespace", ra.Namespace,
			"name", ra.Name,
			"subresource", ra.Subresource,
			"action", action,
		)
	} else if sar.Spec.NonResourceAttributes != nil {
		nra := sar.Spec.NonResourceAttributes
		metrics.WebhookSARRequestsByAction.WithLabelValues(clusterName, nra.Verb, "", "nonresource", "", "").Inc()
		action := map[string]string{
			"path": nra.Path,
			"verb": nra.Verb,
		}
		reqLog.Infow("SubjectAccessReview requested non-resource action",
			"path", nra.Path,
			"verb", nra.Verb,
			"action", action,
		)
	} else {
		reqLog.Infow("SubjectAccessReview contains no resource or non-resource attributes")
		metrics.WebhookSARRequestsByAction.WithLabelValues(clusterName, "", "", "unknown", "", "").Inc()
	}

	// Extract issuer from SAR for multi-IDP session filtering
	var issuer string
	if sar.Spec.Extra != nil {
		issuerValues := sar.Spec.Extra["identity.t-caas.telekom.com/issuer"]
		if len(issuerValues) > 0 {
			issuer = issuerValues[0]
			reqLog.Debugw("Extracted issuer from SAR for session matching", "issuer", issuer)
		}
	}

	groups, sessions, idpMismatches, tenant, err := wc.getUserGroupsAndSessionsWithIDPInfo(ctx, username, clusterName, issuer, clusterCfg)
	if err != nil {
		reqLog.With("error", err.Error()).Error("Failed to retrieve user groups for cluster")
		c.Status(http.StatusInternalServerError)
		return
	}
	reqLog.With("groups", groups, "sessions", len(sessions), "tenant", tenant, "idpMismatches", len(idpMismatches)).Debug("Retrieved user groups for cluster")

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

		// Fetch pod spec for exec/attach/portforward requests to enable security evaluation
		if act.Resource == "pods" && isExecSubresource(act.Subresource) && act.Name != "" {
			pod, err := wc.fetchPodFromCluster(ctx, clusterName, act.Namespace, act.Name)
			if err != nil {
				reqLog.Warnw("Failed to fetch pod for security evaluation",
					"error", err.Error(), "pod", act.Name, "namespace", act.Namespace)
				// Pod will be nil; policy failMode determines behavior
			} else {
				act.Pod = pod
				reqLog.Debugw("Fetched pod for security evaluation",
					"pod", pod.Name, "namespace", pod.Namespace)
			}
		}

		if denied, pol, derr := wc.denyEval.Match(ctx, act); derr != nil {
			reqLog.With("error", derr.Error(), "action", act).Error("deny evaluation error")
		} else if denied {
			reqLog.With("policy", pol).Info("Request denied by global/cluster policy")
			// Emit denied metric for global policy short-circuit
			metrics.WebhookSARDenied.WithLabelValues(clusterName).Inc()
			metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, act.Verb, act.APIGroup, act.Resource, act.Namespace, act.Subresource, "denied", "global").Inc()
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
			// Add IDP hint if available
			if hint := wc.getIDPHintFromIssuer(ctx, &sar, reqLog); hint != "" {
				reason = fmt.Sprintf("%s %s", reason, hint)
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
				// Emit denied metric for session-scoped policy short-circuit
				metrics.WebhookSARDenied.WithLabelValues(clusterName).Inc()
				metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, act.Verb, act.APIGroup, act.Resource, act.Namespace, act.Subresource, "denied", "session").Inc()
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
				// Add IDP hint if available
				if hint := wc.getIDPHintFromIssuer(ctx, &sar, reqLog); hint != "" {
					reason = fmt.Sprintf("%s %s", reason, hint)
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
		// Emit allowed decision metric for action
		if sar.Spec.ResourceAttributes != nil {
			ra := sar.Spec.ResourceAttributes
			metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, ra.Verb, ra.Group, ra.Resource, ra.Namespace, ra.Subresource, "allowed", "rbac").Inc()
		}
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

		// Debug session pod exec check: allow exec into debug pods if user is a session participant
		if !allowed && sar.Spec.ResourceAttributes != nil {
			if debugAllowed, debugSession, debugReason := wc.checkDebugSessionAccess(ctx, username, clusterName, sar.Spec.ResourceAttributes, reqLog); debugAllowed {
				allowed = true
				allowSource = "debug-session"
				allowDetail = fmt.Sprintf("session=%s", debugSession)
				reason = debugReason
				// Emit metric for debug session authorization
				metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, sar.Spec.ResourceAttributes.Verb, sar.Spec.ResourceAttributes.Group, sar.Spec.ResourceAttributes.Resource, sar.Spec.ResourceAttributes.Namespace, sar.Spec.ResourceAttributes.Subresource, "allowed", "debug-session").Inc()
			}
		}

		// Get user groups from active sessions
		// Pass empty issuer string since we're just counting available escalations, not filtering by IDP
		activeUserGroups, _, _, err := wc.getUserGroupsAndSessions(ctx, username, clusterName, "", clusterCfg)
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
		// SECURITY FIX: Check if ResourceAttributes is not nil before accessing its fields
		if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Group != "" {
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

		// Filter escalations based on requestor's IDP (multi-IDP awareness)
		// If an escalation has AllowedIdentityProvidersForRequests, the requestor's IDP must be in that list
		var idpFilteredEscals []v1alpha1.BreakglassEscalation
		for _, esc := range escals {
			if wc.isRequestFromAllowedIDP(ctx, issuer, &esc, reqLog) {
				idpFilteredEscals = append(idpFilteredEscals, esc)
			}
		}

		if len(idpFilteredEscals) < len(escals) {
			reqLog.Debugw("Escalations filtered by requestor IDP", "beforeFilter", len(escals), "afterFilter", len(idpFilteredEscals), "issuer", issuer)
		}
		escals = idpFilteredEscals

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
				reason = reason + " " + diag
			}
			// Also log this at info so admins see the mismatch between session state and SAR capabilities
			reqLog.With("sessions", sessInfo, "error", sessionSARSkippedErr.Error()).Info("Active sessions present but unable to validate them against target cluster")
		}
	}

	// If we denied the request and there are sessions with IDP issuer mismatches,
	// provide a helpful error message indicating the user has sessions but from a different IDP
	if !allowed && len(idpMismatches) > 0 && issuer != "" {
		// Collect the IDPs from the mismatched sessions (show which IDP should have been used)
		idpSet := make(map[string]bool)
		for _, s := range idpMismatches {
			if s.Spec.IdentityProviderName != "" {
				idpSet[s.Spec.IdentityProviderName] = true
			}
		}
		var idpNames []string
		for idp := range idpSet {
			idpNames = append(idpNames, idp)
		}

		if len(idpNames) > 0 {
			idpList := strings.Join(idpNames, ", ")
			diag := fmt.Sprintf(" Note: %d breakglass session(s) found but from different identity provider(s): %s. Your current token is from a different identity provider. For access with your current identity provider, open a new breakglass request.", len(idpMismatches), idpList)
			if reason == "" {
				reason = diag
			} else {
				reason = reason + " " + diag
			}
			// Log this at info level so admins can see IDP mismatches
			reqLog.With("currentIssuer", issuer, "sessionsWithMismatch", len(idpMismatches), "sessionIDPs", idpNames).Info("User has valid sessions but from different identity provider")
		}
	}

	// Add IDP hint to denial reasons (helps users understand which provider authenticated them)
	if !allowed {
		if hint := wc.getIDPHintFromIssuer(ctx, &sar, reqLog); hint != "" {
			if reason == "" {
				reason = hint
			} else {
				reason = fmt.Sprintf("%s %s", reason, hint)
			}
		}
	}

	// Ensure the reason always includes a helpful link to the breakglass UI
	reason = wc.finalizeReason(reason, allowed, clusterName)
	if allowed {
		metrics.WebhookSARAllowed.WithLabelValues(clusterName).Inc()
		// also increment action-based decision metric if we have resource attributes
		if sar.Spec.ResourceAttributes != nil {
			ra := sar.Spec.ResourceAttributes
			metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, ra.Verb, ra.Group, ra.Resource, ra.Namespace, ra.Subresource, "allowed", "session").Inc()
		}
	} else {
		metrics.WebhookSARDenied.WithLabelValues(clusterName).Inc()
		if sar.Spec.ResourceAttributes != nil {
			ra := sar.Spec.ResourceAttributes
			metrics.WebhookSARDecisionsByAction.WithLabelValues(clusterName, ra.Verb, ra.Group, ra.Resource, ra.Namespace, ra.Subresource, "denied", "final").Inc()
		}
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
// It filters sessions by IDP issuer if present, ensuring multi-IDP scenarios only use sessions created with matching identity providers.
func (wc *WebhookController) getUserGroupsAndSessions(ctx context.Context, username, clustername, issuer string, clusterCfg *v1alpha1.ClusterConfig) ([]string, []v1alpha1.BreakglassSession, string, error) {
	groups, sessions, _, tenant, err := wc.getUserGroupsAndSessionsWithIDPInfo(ctx, username, clustername, issuer, clusterCfg)
	return groups, sessions, tenant, err
}

// getUserGroupsAndSessionsWithIDPInfo returns groups from active sessions, list of sessions, IDP mismatch info, and a tenant.
// It filters sessions by IDP issuer if present, ensuring multi-IDP scenarios only use sessions created with matching identity providers.
// Returns: (groups, sessions, idpMismatchedSessions, tenant, error)
func (wc *WebhookController) getUserGroupsAndSessionsWithIDPInfo(ctx context.Context, username, clustername, issuer string, clusterCfg *v1alpha1.ClusterConfig) ([]string, []v1alpha1.BreakglassSession, []v1alpha1.BreakglassSession, string, error) {
	sessions, idpMismatches, err := wc.getSessionsWithIDPMismatchInfo(ctx, username, clustername, issuer)
	if err != nil {
		return nil, nil, nil, "", err
	}
	groups := make([]string, 0, len(sessions))
	for _, s := range sessions {
		groups = append(groups, s.Spec.GrantedGroup)
	}
	// best-effort tenant lookup
	tenant := ""
	if clusterCfg != nil {
		tenant = clusterCfg.Spec.Tenant
	} else if wc.ccProvider != nil {
		if cfg, err := wc.getClusterConfigAcrossNamespaces(ctx, clustername); err == nil && cfg != nil {
			tenant = cfg.Spec.Tenant
		}
	}
	return groups, sessions, idpMismatches, tenant, nil
}

// getSessionsWithIDPMismatchInfo filtered (reuse existing approval logic)
// If issuer is provided, only returns sessions that match the issuer (multi-IDP mode)
// If issuer is empty, returns all sessions (single-IDP or backward compatibility mode)
// Also returns a list of sessions that were filtered out due to IDP issuer mismatch
func (wc *WebhookController) getSessionsWithIDPMismatchInfo(ctx context.Context, username, clustername, issuer string) ([]v1alpha1.BreakglassSession, []v1alpha1.BreakglassSession, error) {
	selector := fields.SelectorFromSet(fields.Set{"spec.cluster": clustername, "spec.user": username})
	all, err := wc.sesManager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		return nil, nil, err
	}
	out := make([]v1alpha1.BreakglassSession, 0, len(all))
	idpMismatches := make([]v1alpha1.BreakglassSession, 0)
	now := time.Now()
	for _, s := range all {
		if breakglass.IsSessionRetained(s) {
			continue
		}
		if s.Status.RejectedAt.IsZero() && !s.Status.ExpiresAt.IsZero() && s.Status.ExpiresAt.After(now) {
			// If issuer is provided and session does NOT allow IDP mismatch,
			// only include sessions that match the issuer (multi-IDP mode)
			if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
				// Track sessions filtered out due to IDP mismatch
				idpMismatches = append(idpMismatches, s)
				continue
			}
			out = append(out, s)
		}
	}
	return out, idpMismatches, nil
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
				esc, eerr := wc.escalManager.GetBreakglassEscalation(ctx, s.Namespace, or.Name)
				if eerr != nil {
					if logger != nil {
						logger.With("error", eerr, "ownerRef", or, "session", s.Name).Debug("failed to lookup escalation for session ownerRef")
					} else if wc.log != nil {
						wc.log.With("error", eerr, "ownerRef", or, "session", s.Name).Debug("failed to lookup escalation for session ownerRef")
					}
					continue
				}
				allowedGroupsToCheck = esc.Spec.Allowed.Groups
				break
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
				// Track IDP-based authorization if session has IDP specified
				if s.Spec.IdentityProviderName != "" {
					metrics.EscalationIDPAuthorizationChecks.WithLabelValues(s.Spec.GrantedGroup, s.Spec.IdentityProviderName, "allowed").Inc()
				}
				return true, s.Spec.GrantedGroup, s.Name, g
			}
			metrics.WebhookSessionSARsDenied.WithLabelValues(clusterName, s.Name, g).Inc()
		}
	}
	return false, "", "", ""
}

func (wc *WebhookController) SetCanDoFn(f func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error)) {
	wc.canDoFn = f
}

// SetPodFetchFn sets a custom function for fetching pods from clusters.
// This is primarily used for testing to inject mock pods.
func (wc *WebhookController) SetPodFetchFn(f PodFetchFunction) {
	wc.podFetchFn = f
}

// isExecSubresource returns true if the subresource is exec, attach, or portforward.
// These subresources allow interactive access to pods and require security evaluation.
func isExecSubresource(subresource string) bool {
	return subresource == "exec" || subresource == "attach" || subresource == "portforward"
}

// fetchPodFromCluster retrieves a pod spec from the target cluster for security evaluation.
func (wc *WebhookController) fetchPodFromCluster(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
	// Use injected function if available (for testing)
	if wc.podFetchFn != nil {
		return wc.podFetchFn(ctx, clusterName, namespace, name)
	}

	if wc.ccProvider == nil {
		return nil, fmt.Errorf("cluster client provider not configured")
	}
	rc, err := wc.ccProvider.GetRESTConfig(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get REST config for cluster %s: %w", clusterName, err)
	}
	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset for cluster %s: %w", clusterName, err)
	}
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s from cluster %s: %w", namespace, name, clusterName, err)
	}
	return pod, nil
}
