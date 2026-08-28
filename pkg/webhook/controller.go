package webhook

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/ratelimit"
	"github.com/telekom/k8s-breakglass/pkg/system"
)

// denyReasonMessage is a user-facing instruction included in SubjectAccessReview deny responses.
// It points users to the Breakglass UI (frontend root) and explains what to do there. The first
// %s is the configured frontend base URL, the second %s is the cluster name (URL-escaped) which
// will be provided as the `search` query parameter to pre-populate the cluster filter in the UI.
const denyReasonMessage = "Access denied. To request temporary access via Breakglass, visit %s?search=%s and open a new request. Include the reason for access, the target cluster, and the requested group(s). If you need help, contact your platform admins."

const maxSARBodySize = 1 << 20 // 1 MiB

const auditNamespaceLabelLookupTimeout = 500 * time.Millisecond

// buildReason appends a helpful link to the breakglass frontend for a given cluster.
func (wc *WebhookController) buildBreakglassLink(cluster string) string {
	base := strings.TrimRight(wc.config.Frontend.BaseURL, "/")
	if base == "" {
		return ""
	}
	// Prepopulate the frontend search filter with the cluster name so the request UI shows matching breakglass groups.
	// URL-encode the cluster value to be safe.
	return fmt.Sprintf("%s?search=%s", base, url.QueryEscape(cluster))
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
		return fmt.Sprintf(denyReasonMessage, wc.config.Frontend.BaseURL, url.QueryEscape(cluster))
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
	idpList := &breakglassv1alpha1.IdentityProviderList{}
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
	// Unless hardened mode is enabled, list available providers to help user identify the right one
	if wc.config.HardenedIDPHintsEnabled() {
		// Hardened mode: don't expose available provider names to prevent reconnaissance
		return "(Your token issuer is not configured for this cluster)"
	}

	// Default mode: list available providers to help users
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
func (wc *WebhookController) isRequestFromAllowedIDP(ctx context.Context, issuer string, esc *breakglassv1alpha1.BreakglassEscalation, reqLog *zap.SugaredLogger) bool {
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
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := wc.escalManager.List(ctx, idpList, client.MatchingFields{"spec.issuer": issuer}); err != nil {
		reqLog.With("error", err.Error()).Error("Failed to list IdentityProviders for request validation - denying request (fail-closed)")
		// Fail closed: if we can't load IDPs, deny the request for security
		// This prevents potential authorization bypass during transient API errors
		return false
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

// NamespaceLabelsFetchFunction is the signature for functions that fetch namespace labels from a cluster.
type NamespaceLabelsFetchFunction func(ctx context.Context, clusterName, namespace string) (map[string]string, error)

type WebhookController struct {
	log                    *zap.SugaredLogger
	config                 config.Config
	sesManager             *breakglass.SessionManager
	escalManager           *escalation.EscalationManager
	canDoFn                breakglass.CanGroupsDoFunction
	ccProvider             *cluster.ClientProvider
	denyEval               *policy.Evaluator
	podFetchFn             PodFetchFunction             // optional override for testing
	namespaceLabelsFetchFn NamespaceLabelsFetchFunction // optional override for testing
	auditService           *audit.Service               // optional audit service for access decision events
	rateLimiter            *ratelimit.IPRateLimiter     // per-IP rate limiter for SAR requests
	activityTracker        *ActivityTracker             // optional buffered session activity tracker (#314)
}

// checkDebugSessionAccess checks if a pod operation is allowed by an active debug session.
// Returns (allowed, sessionName, reason) where allowed is true if the user can perform
// the requested operation on the pod via a debug session they are participating in.
// Supports exec, attach, portforward, and log subresources based on AllowedPodOperations config.
func (wc *WebhookController) checkDebugSessionAccess(ctx context.Context, username, clusterName string, ra *authorizationv1.ResourceAttributes, reqLog *zap.SugaredLogger) (bool, string, string) {
	ds, reason := wc.findDebugSessionAccess(ctx, username, clusterName, ra, reqLog)
	if ds == nil {
		return false, "", ""
	}
	return true, ds.Name, reason
}

// findDebugSessionAccess returns the exact live DebugSession that authorized
// the request. Cached discovery is only a hint: the returned object is
// reread through the API reader and must still be Active with a non-zero,
// strictly-future expiry at the decision boundary.
func (wc *WebhookController) findDebugSessionAccess(ctx context.Context, username, clusterName string, ra *authorizationv1.ResourceAttributes, reqLog *zap.SugaredLogger) (*breakglassv1alpha1.DebugSession, string) {
	// Only check for pods with supported subresources
	if ra == nil || ra.Resource != "pods" || !isDebugSessionSubresource(ra.Subresource) {
		return nil, ""
	}

	if ra.Name == "" || ra.Namespace == "" {
		return nil, ""
	}

	if wc.escalManager == nil || wc.escalManager.Client == nil {
		reqLog.Debug("Debug session check skipped: no client available")
		return nil, ""
	}

	// List active debug sessions for this cluster using indexed fields
	debugSessionList := &breakglassv1alpha1.DebugSessionList{}
	fieldSelector := client.MatchingFields{
		"spec.cluster":             clusterName,
		"status.state":             string(breakglassv1alpha1.DebugSessionStateActive),
		"status.participants.user": username,
	}
	if err := wc.escalManager.List(ctx, debugSessionList, fieldSelector); err != nil {
		reqLog.Warnw("Failed to list debug sessions for pod operation check", "error", err)
		return nil, ""
	}

	// Check each active debug session
	reader := client.Reader(wc.escalManager.Client)
	if wc.sesManager != nil {
		reader = wc.sesManager.Reader()
	}
	for _, discovered := range debugSessionList.Items {
		ds := discovered.DeepCopy()
		if reader != nil {
			var live breakglassv1alpha1.DebugSession
			if err := reader.Get(ctx, client.ObjectKey{Namespace: discovered.Namespace, Name: discovered.Name}, &live); err != nil {
				reqLog.Debugw("Debug session discovery candidate disappeared before live fence", "session", discovered.Name, "error", err)
				continue
			}
			ds = &live
		}
		// Only check active sessions for this cluster
		if ds.Status.State != breakglassv1alpha1.DebugSessionStateActive || ds.Spec.Cluster != clusterName {
			continue
		}
		// Debug sessions must always carry a live lease. Missing, equal, and
		// past expiry are all denied; only a strictly-future timestamp grants.
		if ds.Status.ExpiresAt == nil || !time.Now().Before(ds.Status.ExpiresAt.Time) {
			var expiresAt interface{}
			if ds.Status.ExpiresAt != nil {
				expiresAt = ds.Status.ExpiresAt.Time
			}
			reqLog.Debugw("Debug session skipped because it is expired or missing expiry",
				"session", ds.Name, "expiresAt", expiresAt)
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

		// Check if the specific operation is allowed by this session's AllowedPodOperations
		if !ds.Status.AllowedPodOperations.IsOperationAllowed(ra.Subresource) {
			reqLog.Debugw("Debug session found but operation not allowed",
				"session", ds.Name,
				"pod", fmt.Sprintf("%s/%s", ra.Namespace, ra.Name),
				"operation", ra.Subresource)
			continue
		}

		// Check if the user is a participant of this session
		for _, p := range ds.Status.Participants {
			if p.User != username {
				continue
			}
			if p.LeftAt != nil {
				continue
			}
			if !canDebugSessionParticipantAccessPodOperations(p.Role) {
				reqLog.Debugw("Debug session participant role cannot perform pod operation",
					"session", ds.Name,
					"user", username,
					"role", p.Role,
					"operation", ra.Subresource)
				continue
			}
			reason := fmt.Sprintf("Allowed by debug session %s (role: %s, operation: %s)", ds.Name, p.Role, ra.Subresource)
			reqLog.Infow("Debug session pod operation allowed",
				"session", ds.Name,
				"pod", fmt.Sprintf("%s/%s", ra.Namespace, ra.Name),
				"user", username,
				"role", p.Role,
				"operation", ra.Subresource)
			return ds, reason
		}
	}

	return nil, ""
}

// liveDebugSessionAccess is the final authorization fence for a debug-session
// allow. It reads the exact candidate through the uncached reader and repeats
// every identity/state/pod/participant/lease check at one decision instant.
func (wc *WebhookController) liveDebugSessionAccess(ctx context.Context, username, clusterName string, ra *authorizationv1.ResourceAttributes, namespace, name, uid string) (bool, string) {
	if wc.sesManager == nil || ra == nil || namespace == "" || name == "" {
		return false, ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var ds breakglassv1alpha1.DebugSession
	if err := wc.sesManager.Reader().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &ds); err != nil {
		return false, ""
	}
	if uid != "" && string(ds.UID) != uid {
		return false, ""
	}
	if ds.Status.State != breakglassv1alpha1.DebugSessionStateActive || ds.Spec.Cluster != clusterName {
		return false, ""
	}
	now := time.Now()
	if ds.Status.ExpiresAt == nil || !now.Before(ds.Status.ExpiresAt.Time) {
		return false, ""
	}
	podAllowed := false
	for _, pod := range ds.Status.AllowedPods {
		if pod.Namespace == ra.Namespace && pod.Name == ra.Name {
			podAllowed = true
			break
		}
	}
	if !podAllowed || !ds.Status.AllowedPodOperations.IsOperationAllowed(ra.Subresource) {
		return false, ""
	}
	for _, participant := range ds.Status.Participants {
		if participant.User == username && participant.LeftAt == nil && canDebugSessionParticipantAccessPodOperations(participant.Role) {
			return true, fmt.Sprintf("Allowed by debug session %s (role: %s, operation: %s)", ds.Name, participant.Role, ra.Subresource)
		}
	}
	return false, ""
}

// getPodSecurityOverridesFromSessions retrieves the PodSecurityOverrides from the escalation
// associated with the user's active sessions. If multiple sessions exist with different escalations,
// the first non-nil PodSecurityOverrides is returned (escalations are processed in session order).
func (wc *WebhookController) getPodSecurityOverridesFromSessions(ctx context.Context, sessions []breakglassv1alpha1.BreakglassSession, reqLog *zap.SugaredLogger) *breakglassv1alpha1.PodSecurityOverrides {
	if wc.escalManager == nil {
		return nil
	}

	for _, s := range sessions {
		if s.Status.State != breakglassv1alpha1.SessionStateApproved {
			continue
		}

		// Look up escalation via owner references
		for _, or := range s.OwnerReferences {
			if or.Kind != "BreakglassEscalation" {
				continue
			}

			esc, err := wc.escalManager.GetBreakglassEscalation(ctx, s.Namespace, or.Name)
			if err != nil {
				if reqLog != nil {
					reqLog.Debugw("Failed to lookup escalation for PodSecurityOverrides",
						"error", err.Error(), "escalation", or.Name, "session", s.Name)
				}
				continue
			}

			if esc.Spec.PodSecurityOverrides != nil && esc.Spec.PodSecurityOverrides.Enabled {
				if reqLog != nil {
					reqLog.Debugw("Found PodSecurityOverrides from escalation",
						"escalation", esc.Name, "session", s.Name,
						"maxAllowedScore", esc.Spec.PodSecurityOverrides.MaxAllowedScore,
						"exemptFactors", esc.Spec.PodSecurityOverrides.ExemptFactors)
				}
				return esc.Spec.PodSecurityOverrides
			}
		}
	}

	return nil
}

// getClusterConfigAcrossNamespaces performs a ClusterConfig lookup across all namespaces
// by delegating to the ClientProvider legacy behavior (empty namespace). The Webhook
// controller does not have an escalation namespace context, so callers should use this
// helper when they need the provider to search across namespaces.
func (wc *WebhookController) getClusterConfigAcrossNamespaces(ctx context.Context, name string) (*breakglassv1alpha1.ClusterConfig, error) {
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
	// Return per-IP rate limiting middleware for SAR endpoints
	if b.rateLimiter != nil {
		return []gin.HandlerFunc{b.rateLimiter.Middleware()}
	}
	return []gin.HandlerFunc{}
}

func (wc *WebhookController) handleAuthorize(c *gin.Context) {
	// Phase 1: Parse & validate SAR request
	s, ok := wc.parseSARRequest(c)
	if !ok {
		return
	}

	// Phase 2: Resolve cluster configuration
	if !wc.resolveClusterConfig(c, s) {
		return
	}

	// Phase 3: Log the requested action & extract issuer
	wc.logSARAction(s)

	// Phase 4: Load sessions, groups, tenant
	if !wc.loadSessionsAndGroups(c, s) {
		return
	}

	// Phase 5: Early debug-session allow (before deny policies)
	if wc.checkEarlyDebugSession(c, s) {
		// The early phase only records the debug-session candidate. Route it
		// through the common final live fence before producing an allow response.
		s.phases.LogSummary()
		wc.buildFinalReason(s)
		wc.sendAuthorizationResponse(c, s)
		return
	}

	// Phase 6: Impersonation evaluation (KEP-5284 constrained impersonation).
	// Runs BEFORE the generic deny-policy and RBAC phases so that impersonation
	// verbs this build does not recognise are denied explicitly rather than
	// falling through to a path that has no notion of them.
	s.phases.StartPhase()
	if wc.evaluateImpersonation(c, s) {
		return
	}
	s.phases.EndPhase(PhaseImpersonation)

	// Phase 7: Deny-policy evaluation (global + per-session)
	if wc.evaluateDenyPolicies(c, s) {
		return
	}

	// Phase 8: Standard RBAC check
	if !wc.performRBACCheck(c, s) {
		return
	}

	// Phase 9: Session-based authorization + escalation discovery
	if !s.allowed {
		if !wc.resolveSessionAuthorization(c, s) {
			return
		}
	}

	// Phase 10: Build final reason with diagnostics
	s.phases.LogSummary()
	wc.buildFinalReason(s)

	// Phase 11: Emit metrics & send response. The response helper performs the
	// final live session/cluster fence before any allow-side effects.
	wc.sendAuthorizationResponse(c, s)
}

// liveSessionAuthorizationCandidates performs the final authorization fence
// against exact live session reads. Session discovery and the target-cluster SAR
// can take long enough for a session to expire or be dropped after the cached
// discovery read. A failed read removes that candidate rather than trusting the
// stale snapshot. When candidates were attributed to the allow, any one live
// candidate is sufficient; when no attribution was possible, all discovered
// sessions are treated as contributors and must remain live.
func (wc *WebhookController) liveSessionAuthorizationCandidates(ctx context.Context, sessions []breakglassv1alpha1.BreakglassSession, candidates []sessionAuthorizationCandidate) []sessionAuthorizationCandidate {
	if wc.sesManager == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refs := candidates
	allCandidates := len(refs) == 0
	if allCandidates {
		if len(sessions) == 0 {
			return nil
		}
		refs = make([]sessionAuthorizationCandidate, 0, len(sessions))
		for i := range sessions {
			session := &sessions[i]
			refs = append(refs, sessionAuthorizationCandidate{
				namespace: session.Namespace, name: session.Name, uid: string(session.UID), user: session.Spec.User,
				cluster: session.Spec.Cluster, grantedGroup: session.Spec.GrantedGroup,
				identityProviderName: session.Spec.IdentityProviderName,
			})
		}
	}
	currentSessions := make([]struct {
		candidate sessionAuthorizationCandidate
		session   breakglassv1alpha1.BreakglassSession
	}, 0, len(refs))
	for _, ref := range refs {
		if ref.name == "" {
			if allCandidates {
				return nil
			}
			continue
		}
		var current breakglassv1alpha1.BreakglassSession
		if err := wc.sesManager.Reader().Get(ctx, client.ObjectKey{Namespace: ref.namespace, Name: ref.name}, &current); err != nil {
			if wc.log != nil {
				wc.log.Debugw("final session access fence could not read session", "session", ref.name, "error", err)
			}
			continue
		}
		if string(current.UID) != ref.uid || current.Spec.User != ref.user || current.Spec.Cluster != ref.cluster || current.Spec.GrantedGroup != ref.grantedGroup || current.Spec.IdentityProviderName != ref.identityProviderName || !current.Status.RejectedAt.IsZero() {
			continue
		}
		currentSessions = append(currentSessions, struct {
			candidate sessionAuthorizationCandidate
			session   breakglassv1alpha1.BreakglassSession
		}{candidate: ref, session: current})
	}
	now := time.Now()
	live := make([]sessionAuthorizationCandidate, 0, len(currentSessions))
	for _, current := range currentSessions {
		if breakglass.IsSessionAccessActiveAt(current.session, now) {
			live = append(live, current.candidate)
		}
	}
	if allCandidates && len(live) != len(refs) {
		return nil
	}
	return live
}

// isSessionAccessStillActive retains the narrow helper used by existing tests
// and callers while applying the same any-live-candidate semantics used by the
// request path when an attributed candidate is provided.
func (wc *WebhookController) isSessionAccessStillActive(ctx context.Context, sessions []breakglassv1alpha1.BreakglassSession, candidate *sessionAuthorizationCandidate) bool {
	var candidates []sessionAuthorizationCandidate
	if candidate != nil {
		candidates = []sessionAuthorizationCandidate{*candidate}
	}
	return len(wc.liveSessionAuthorizationCandidates(ctx, sessions, candidates)) > 0
}

func (wc *WebhookController) isClusterConfigStillActive(ctx context.Context, configured *breakglassv1alpha1.ClusterConfig) bool {
	if wc.ccProvider == nil || configured == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	live, err := wc.ccProvider.GetInNamespaceLive(ctx, configured.Namespace, configured.Name)
	if err != nil {
		if wc.log != nil {
			wc.log.Debugw("final cluster configuration fence denied session access", "cluster", configured.Name, "error", err)
		}
		return false
	}
	return live.Namespace == configured.Namespace && live.Name == configured.Name && live.UID == configured.UID && live.DeletionTimestamp.IsZero()
}

// emitAccessDecisionAudit emits an audit event for SAR authorization decisions.
// This captures both allowed and denied access attempts for audit trail purposes.
func (wc *WebhookController) emitAccessDecisionAudit(ctx context.Context, username string, groups []string, cluster string, sar *authorizationv1.SubjectAccessReview, allowed bool, source, reason string) {
	if wc.auditService == nil {
		return
	}

	eventType := audit.EventAccessGranted
	severity := audit.SeverityInfo
	if !allowed {
		eventType = audit.EventAccessDenied
		severity = audit.SeverityWarning
	}

	target, verb, subresource, apiGroup := wc.auditTargetFromSAR(ctx, cluster, sar)

	// Build details map
	details := map[string]interface{}{
		"allowed":     allowed,
		"verb":        verb,
		"source":      source,
		"apiGroup":    apiGroup,
		"subresource": subresource,
	}
	if reason != "" {
		details["reason"] = reason
	}

	event := &audit.Event{
		Type:     eventType,
		Severity: severity,
		Actor: audit.Actor{
			User:   username,
			Groups: groups,
		},
		Target:  target,
		Details: details,
	}

	wc.auditService.Emit(ctx, event)
}

// emitPolicyDenialAudit emits an audit event when a DenyPolicy blocks access.
func (wc *WebhookController) emitPolicyDenialAudit(ctx context.Context, username string, groups []string, cluster string, sar *authorizationv1.SubjectAccessReview, policyName, scope string) {
	if wc.auditService == nil {
		return
	}

	target, verb, subresource, apiGroup := wc.auditTargetFromSAR(ctx, cluster, sar)

	event := &audit.Event{
		Type:     audit.EventAccessDeniedPolicy,
		Severity: audit.SeverityWarning,
		Actor: audit.Actor{
			User:   username,
			Groups: groups,
		},
		Target: target,
		Details: map[string]interface{}{
			"policyName":  policyName,
			"policyScope": scope,
			"verb":        verb,
			"apiGroup":    apiGroup,
			"subresource": subresource,
		},
	}

	wc.auditService.Emit(ctx, event)
}

// emitPodSecurityAudit emits an audit event for pod security evaluation results.
func (wc *WebhookController) emitPodSecurityAudit(ctx context.Context, username string, groups []string, cluster string, sar *authorizationv1.SubjectAccessReview, policyName string, result *policy.PodSecurityResult) {
	if wc.auditService == nil || result == nil {
		return
	}

	// Determine event type based on result
	var eventType audit.EventType
	var severity audit.Severity
	switch {
	case result.Denied:
		eventType = audit.EventPodSecurityDenied
		severity = audit.SeverityCritical
	case result.Action == "warn":
		eventType = audit.EventPodSecurityWarning
		severity = audit.SeverityWarning
	case result.OverrideApplied:
		eventType = audit.EventPodSecurityOverride
		severity = audit.SeverityWarning
	default:
		// For allowed results without override, emit evaluated event at info level
		eventType = audit.EventPodSecurityEvaluated
		severity = audit.SeverityInfo
	}

	target, verb, subresource, apiGroup := wc.auditTargetFromSAR(ctx, cluster, sar)

	event := &audit.Event{
		Type:     eventType,
		Severity: severity,
		Actor: audit.Actor{
			User:   username,
			Groups: groups,
		},
		Target: target,
		Details: map[string]interface{}{
			"policyName":      policyName,
			"action":          result.Action,
			"riskScore":       result.Score,
			"riskFactors":     result.Factors,
			"reason":          result.Reason,
			"verb":            verb,
			"apiGroup":        apiGroup,
			"subresource":     subresource,
			"overrideApplied": result.OverrideApplied,
		},
	}

	wc.auditService.Emit(ctx, event)
}

func (wc *WebhookController) auditTargetFromSAR(ctx context.Context, cluster string, sar *authorizationv1.SubjectAccessReview) (audit.Target, string, string, string) {
	target := audit.Target{Cluster: cluster}
	var verb, subresource, apiGroup string
	if sar == nil {
		return target, verb, subresource, apiGroup
	}
	if sar.Spec.ResourceAttributes != nil {
		ra := sar.Spec.ResourceAttributes
		target.Kind = ra.Resource
		target.Name = ra.Name
		target.Namespace = ra.Namespace
		target.NamespaceLabels = wc.auditNamespaceLabels(ctx, cluster, ra.Namespace)
		verb = ra.Verb
		subresource = ra.Subresource
		apiGroup = ra.Group
	} else if sar.Spec.NonResourceAttributes != nil {
		nra := sar.Spec.NonResourceAttributes
		target.Kind = "nonresource"
		target.Name = nra.Path
		verb = nra.Verb
	}
	return target, verb, subresource, apiGroup
}

func (wc *WebhookController) auditNamespaceLabels(ctx context.Context, cluster, namespace string) map[string]string {
	if namespace == "" || (wc.namespaceLabelsFetchFn == nil && wc.ccProvider == nil) {
		return nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, auditNamespaceLabelLookupTimeout)
	defer cancel()
	labels, err := wc.fetchNamespaceLabels(lookupCtx, cluster, namespace)
	if err != nil {
		if wc.log != nil {
			wc.log.Debugw("failed to fetch namespace labels for audit event filtering",
				"error", err.Error(), "cluster", cluster, "namespace", namespace)
		}
		return nil
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

// getUserGroupsForCluster removed (unused)

// Option is a functional option for configuring WebhookController.
// Use option constructors (WithPodFetchFunc, WithNamespaceLabelsFetchFunc, etc.)
// to customize behavior, especially for testing.
type Option func(*WebhookController)

// WithPodFetchFunc overrides the default pod-fetching behavior.
// Useful in tests to avoid hitting a real cluster API server.
func WithPodFetchFunc(fn PodFetchFunction) Option {
	return func(wc *WebhookController) {
		wc.podFetchFn = fn
	}
}

// WithNamespaceLabelsFetchFunc overrides the default namespace-label lookup.
func WithNamespaceLabelsFetchFunc(fn NamespaceLabelsFetchFunction) Option {
	return func(wc *WebhookController) {
		wc.namespaceLabelsFetchFn = fn
	}
}

// WithCanDoFunc overrides the authorization check for group permissions.
// Panics if fn is nil to fail fast during initialization rather than at runtime.
func WithCanDoFunc(fn breakglass.CanGroupsDoFunction) Option {
	if fn == nil {
		panic("WithCanDoFunc: fn must not be nil")
	}
	return func(wc *WebhookController) {
		wc.canDoFn = fn
	}
}

func NewWebhookController(log *zap.SugaredLogger,
	cfg config.Config,
	sesManager *breakglass.SessionManager,
	escalManager *escalation.EscalationManager,
	ccProvider *cluster.ClientProvider,
	denyEval *policy.Evaluator,
	opts ...Option,
) *WebhookController {
	wc := &WebhookController{
		log:          log,
		config:       cfg,
		sesManager:   sesManager,
		escalManager: escalManager,
		canDoFn:      breakglass.CanGroupsDo,
		ccProvider:   ccProvider,
		denyEval:     denyEval,
		// Per-IP rate limiter for SAR requests: 1000 req/s per IP, burst of 5000
		// SARs are called very frequently by the Kubernetes API server
		rateLimiter: ratelimit.New(ratelimit.DefaultSARConfig()),
	}
	for _, opt := range opts {
		opt(wc)
	}
	return wc
}

// WithAuditService sets the audit service for access decision audit events.
func (wc *WebhookController) WithAuditService(svc *audit.Service) *WebhookController {
	wc.auditService = svc
	return wc
}

// WithActivityTracker sets the activity tracker for buffered session activity updates.
// When set, the webhook records activity for each session-authorized request.
func (wc *WebhookController) WithActivityTracker(at *ActivityTracker) *WebhookController {
	wc.activityTracker = at
	return wc
}

// ActivityTrackerCleaner returns the activity tracker, or nil if activity
// tracking is not enabled. The returned *ActivityTracker satisfies the
// breakglass.ActivityCleaner interface for use in the cleanup routine.
func (wc *WebhookController) ActivityTrackerCleaner() *ActivityTracker {
	return wc.activityTracker
}

// StopActivityTracker stops the background activity tracker goroutine and flushes remaining entries.
// Safe to call even if no tracker is set.
func (wc *WebhookController) StopActivityTracker(ctx context.Context) {
	if wc.activityTracker != nil {
		wc.activityTracker.Stop(ctx)
	}
}

// getUserGroupsAndSessions returns groups from active sessions, list of sessions, and a tenant (best-effort from cluster config).
// It filters sessions by IDP issuer if present, ensuring multi-IDP scenarios only use sessions created with matching identity providers.
func (wc *WebhookController) getUserGroupsAndSessions(ctx context.Context, username, clustername, issuer string, clusterCfg *breakglassv1alpha1.ClusterConfig) ([]string, []breakglassv1alpha1.BreakglassSession, string, error) {
	groups, sessions, _, tenant, err := wc.getUserGroupsAndSessionsWithIDPInfo(ctx, username, clustername, issuer, clusterCfg)
	return groups, sessions, tenant, err
}

// getUserGroupsAndSessionsWithIDPInfo returns groups from active sessions, list of sessions, IDP mismatch info, and a tenant.
// It filters sessions by IDP issuer if present, ensuring multi-IDP scenarios only use sessions created with matching identity providers.
// Returns: (groups, sessions, idpMismatchedSessions, tenant, error)
func (wc *WebhookController) getUserGroupsAndSessionsWithIDPInfo(ctx context.Context, username, clustername, issuer string, clusterCfg *breakglassv1alpha1.ClusterConfig) ([]string, []breakglassv1alpha1.BreakglassSession, []breakglassv1alpha1.BreakglassSession, string, error) {
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
func (wc *WebhookController) getSessionsWithIDPMismatchInfo(ctx context.Context, username, clustername, issuer string) ([]breakglassv1alpha1.BreakglassSession, []breakglassv1alpha1.BreakglassSession, error) {
	all, err := wc.sesManager.GetClusterUserBreakglassSessions(ctx, clustername, username)
	if err != nil {
		return nil, nil, err
	}
	out := make([]breakglassv1alpha1.BreakglassSession, 0, len(all))
	idpMismatches := make([]breakglassv1alpha1.BreakglassSession, 0)
	for _, s := range all {
		if breakglass.IsSessionRetained(s) {
			continue
		}
		// Only include sessions that currently grant access. This shared helper
		// fails closed for an Approved session with a missing expiry and treats
		// the expiry boundary as expired, keeping webhook authorization aligned
		// with the controller, API, and cleanup paths.
		if !breakglass.IsSessionAccessActive(s) {
			continue
		}
		// Preserve the existing defense against contradictory approval metadata.
		if !s.Status.RejectedAt.IsZero() {
			continue
		}
		// If issuer is provided and session does NOT allow IDP mismatch,
		// only include sessions that match the issuer (multi-IDP mode)
		if issuer != "" && !s.Spec.AllowIDPMismatch && s.Spec.IdentityProviderIssuer != issuer {
			// Track sessions filtered out due to IDP mismatch
			idpMismatches = append(idpMismatches, s)
			continue
		}
		out = append(out, s)
	}
	return out, idpMismatches, nil
}

// dedupeStrings removes duplicates from a slice of strings while preserving order.
func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		if _, exists := seen[v]; !exists {
			out = append(out, v)
			seen[v] = struct{}{}
		}
	}
	return out
}

// authorizeViaSessions performs per-session SubjectAccessReviews using the
// session's granted group. It retains the historical first-winner return shape;
// the request path uses authorizeViaSessionsWithCandidates so every independent
// winner can be revalidated by the final live fence.
func (wc *WebhookController) authorizeViaSessions(ctx context.Context, rc *rest.Config, sessions []breakglassv1alpha1.BreakglassSession, incoming authorizationv1.SubjectAccessReview, clusterName string, reqLog ...*zap.SugaredLogger) (bool, string, string, string) {
	allowed, group, name, impersonated, _ := wc.authorizeViaSessionsWithCandidates(ctx, rc, sessions, incoming, clusterName, reqLog...)
	return allowed, group, name, impersonated
}

func (wc *WebhookController) authorizeViaSessionsWithCandidates(ctx context.Context, rc *rest.Config, sessions []breakglassv1alpha1.BreakglassSession, incoming authorizationv1.SubjectAccessReview, clusterName string, reqLog ...*zap.SugaredLogger) (bool, string, string, string, []sessionAuthorizationCandidate) {
	// Resolve logger once to avoid repeated if/else chains.
	log := wc.log
	if len(reqLog) > 0 && reqLog[0] != nil {
		log = reqLog[0]
	}
	if len(sessions) == 0 || (incoming.Spec.ResourceAttributes == nil && incoming.Spec.NonResourceAttributes == nil) {
		return false, "", "", "", nil
	}
	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		if log != nil {
			log.With("error", err).Error("failed creating clientset for session SAR")
		}
		return false, "", "", "", nil
	}
	sarClient := clientset.AuthorizationV1().SubjectAccessReviews()
	var firstGroup, firstName, firstImpersonated string
	var candidates []sessionAuthorizationCandidate
	for _, s := range sessions {
		// Never trust a caller-supplied session snapshot for authorization. The
		// final response also performs a live read because this loop can cross
		// the expiry boundary while target-cluster SARs are in flight.
		if !breakglass.IsSessionAccessActive(s) {
			continue
		}
		var allowedGroupsToCheck []string
		// Resolve escalation via OwnerReferences first
		if len(s.OwnerReferences) > 0 && wc.escalManager != nil {
			for _, or := range s.OwnerReferences {
				esc, eerr := wc.escalManager.GetBreakglassEscalation(ctx, s.Namespace, or.Name)
				if eerr != nil {
					if log != nil {
						log.With("error", eerr, "ownerRef", or, "session", s.Name).Debug("failed to lookup escalation for session ownerRef")
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
			if log != nil {
				log.Debugw("No escalation allowed groups found; falling back to session granted group for prefix detection", "session", s.Name, "sessionGroup", system.RedactGroupName(s.Spec.GrantedGroup))
			}
		}

		prefixes := wc.config.Kubernetes.OIDCPrefixes
		// Find a primary prefix by matching incoming groups to allowed groups.
		// Pre-build a map of valid prefix+group combinations for O(n) lookup
		// per session. The map itself is O(m*k) to build (m prefixes × k allowed
		// groups), then each of the n incoming groups is a single map lookup.
		// NOTE: This uses exact match (prefix+group == incoming group), which is
		// stricter than the previous HasPrefix+HasSuffix approach. This is
		// intentional and consistent with StripOIDCPrefixes elsewhere.
		// The map key is the full concatenated string (prefix+group), which is
		// exactly the form incoming groups appear in. If two different
		// (prefix, group) pairs produce the same concatenation, either prefix
		// is a valid match for that incoming group string.
		var primaryPrefix string
		if len(incoming.Spec.Groups) > 0 && len(prefixes) > 0 {
			validCombinations := make(map[string]string, len(prefixes)*len(allowedGroupsToCheck))
			for _, p := range prefixes {
				for _, allowed := range allowedGroupsToCheck {
					validCombinations[p+allowed] = p
				}
			}
			for _, ig := range incoming.Spec.Groups {
				if p, ok := validCombinations[ig]; ok {
					primaryPrefix = p
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

		if log != nil {
			log.Debugw("Impersonation groups to try", "groupCount", len(groupsToTry), "session", s.Name)
		}

		for _, g := range groupsToTry {
			sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   "system:breakglass-session",
				Groups: []string{g},
			}}
			// Populate either ResourceAttributes or NonResourceAttributes from the incoming SAR
			if incoming.Spec.ResourceAttributes != nil {
				sar.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
					Namespace:   incoming.Spec.ResourceAttributes.Namespace,
					Verb:        incoming.Spec.ResourceAttributes.Verb,
					Group:       incoming.Spec.ResourceAttributes.Group,
					Version:     incoming.Spec.ResourceAttributes.Version,
					Resource:    incoming.Spec.ResourceAttributes.Resource,
					Subresource: incoming.Spec.ResourceAttributes.Subresource,
					Name:        incoming.Spec.ResourceAttributes.Name,
				}
			} else if incoming.Spec.NonResourceAttributes != nil {
				sar.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{
					Path: incoming.Spec.NonResourceAttributes.Path,
					Verb: incoming.Spec.NonResourceAttributes.Verb,
				}
			}
			if log != nil {
				log.Debugw("Creating SubjectAccessReview for session impersonation", "group", system.RedactGroupName(g), "session", s.Name)
			}
			resp, err := sarClient.Create(ctx, sar, metav1.CreateOptions{})
			if err != nil {
				if log != nil {
					log.With("error", err, "group", system.RedactGroupName(g)).Warn("session SAR error")
					log.Debugw("Failed SAR create error details", "error", err, "group", system.RedactGroupName(g), "hasResourceAttributes", sar.Spec.ResourceAttributes != nil, "hasNonResourceAttributes", sar.Spec.NonResourceAttributes != nil)
				}
				metrics.WebhookSessionSARErrors.WithLabelValues(clusterName).Inc()
				continue
			}
			if resp != nil {
				if log != nil {
					log.Debugw("Session SAR response", "group", system.RedactGroupName(g), "session", s.Name, "allowed", resp.Status.Allowed, "reason", resp.Status.Reason)
				}
			}
			if resp != nil && resp.Status.Allowed {
				if firstName == "" {
					firstGroup, firstName, firstImpersonated = s.Spec.GrantedGroup, s.Name, g
				}
				candidates = append(candidates, sessionAuthorizationCandidate{
					namespace: s.Namespace, name: s.Name, uid: string(s.UID),
					user: s.Spec.User, cluster: s.Spec.Cluster, grantedGroup: s.Spec.GrantedGroup,
					identityProviderName: s.Spec.IdentityProviderName,
				})
				// One successful impersonation group is enough for this session;
				// continue with the other sessions to preserve independent winners.
				break
			}
			metrics.WebhookSessionSARsDenied.WithLabelValues(clusterName).Inc()
		}
	}
	if firstName == "" {
		return false, "", "", "", nil
	}
	return true, firstGroup, firstName, firstImpersonated, candidates
}

func (wc *WebhookController) SetCanDoFn(f func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error)) {
	wc.canDoFn = f
}

// SetPodFetchFn sets a custom function for fetching pods from clusters.
// This is primarily used for testing to inject mock pods.
func (wc *WebhookController) SetPodFetchFn(f PodFetchFunction) {
	wc.podFetchFn = f
}

// SetNamespaceLabelsFetchFn sets a custom function for fetching namespace labels from clusters.
// This is primarily used for testing to inject mock namespace labels.
func (wc *WebhookController) SetNamespaceLabelsFetchFn(f NamespaceLabelsFetchFunction) {
	wc.namespaceLabelsFetchFn = f
}

// isDebugSessionSubresource returns true if the subresource can be controlled by debug sessions.
// This includes exec, attach, portforward, and log (which are configured via AllowedPodOperations).
func isDebugSessionSubresource(subresource string) bool {
	return subresource == "exec" || subresource == "attach" || subresource == "portforward" || subresource == "log"
}

func canDebugSessionParticipantAccessPodOperations(role breakglassv1alpha1.ParticipantRole) bool {
	return role == breakglassv1alpha1.ParticipantRoleOwner || role == breakglassv1alpha1.ParticipantRoleParticipant
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
	clientset, err := wc.ccProvider.GetClientset(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get clientset for cluster %s: %w", clusterName, err)
	}
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s from cluster %s: %w", namespace, name, clusterName, err)
	}
	return pod, nil
}

// fetchNamespaceLabels retrieves namespace labels from the target cluster for DenyPolicy evaluation.
// Returns nil if namespace cannot be fetched (DenyPolicy SelectorTerms will be skipped).
func (wc *WebhookController) fetchNamespaceLabels(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
	// Use injected function if available (for testing)
	if wc.namespaceLabelsFetchFn != nil {
		return wc.namespaceLabelsFetchFn(ctx, clusterName, namespace)
	}

	if wc.ccProvider == nil {
		return nil, fmt.Errorf("cluster client provider not configured")
	}
	clientset, err := wc.ccProvider.GetClientset(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get clientset for cluster %s: %w", clusterName, err)
	}
	ns, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace %s from cluster %s: %w", namespace, clusterName, err)
	}
	return ns.Labels, nil
}

// recordSessionActivity records activity for the named session using the buffered activity tracker.
// It looks up the session's namespace from the provided sessions list and records the current time.
// This is a non-blocking operation: activity is buffered and flushed periodically.
func (wc *WebhookController) recordSessionActivity(sessions []breakglassv1alpha1.BreakglassSession, sessionName, clusterName, grantedGroup string) {
	metrics.SessionActivityRequests.WithLabelValues(clusterName, grantedGroup).Inc()

	if wc.activityTracker == nil {
		return
	}

	// Find the session namespace. This is a linear O(n) scan, but the sessions
	// slice is per-user-per-cluster so typically contains 1-3 items, making a
	// map lookup unnecessary overhead for the common case.
	for i := range sessions {
		if sessions[i].Name == sessionName {
			wc.activityTracker.RecordActivity(sessions[i].Namespace, sessions[i].Name, sessions[i].UID, time.Now())
			return
		}
	}
}
