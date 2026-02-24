package breakglass

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type BreakglassEscalationController struct {
	manager          *EscalationManager
	log              *zap.SugaredLogger
	middleware       gin.HandlerFunc
	identityProvider IdentityProvider
	getUserGroupsFn  GetUserGroupsFunction
	configPath       string // Path to breakglass config file for OIDC prefix stripping
}

// dropK8sInternalFieldsEscalation removes K8s internal fields from BreakglassEscalation for API response
func dropK8sInternalFieldsEscalation(e *breakglassv1alpha1.BreakglassEscalation) {
	if e == nil {
		return
	}
	e.ManagedFields = nil
	e.UID = ""
	e.ResourceVersion = ""
	e.Generation = 0
	if e.Annotations != nil {
		delete(e.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
	e.Status.ApproverGroupMembers = nil
	e.Status.IDPGroupMemberships = nil
}

func dropK8sInternalFieldsEscalationList(list []breakglassv1alpha1.BreakglassEscalation) []breakglassv1alpha1.BreakglassEscalation {
	for i := range list {
		dropK8sInternalFieldsEscalation(&list[i])
	}
	return list
}
func (ec *BreakglassEscalationController) Register(rg *gin.RouterGroup) error {
	basePath := ec.BasePath()
	ec.log.With("basePath", basePath).Info("Registering escalation controller endpoints (RESTful)")
	rg.GET("", instrumentedHandler("handleGetEscalations", ec.handleGetEscalations))
	ec.log.With("endpoint", basePath).Debug("Escalation endpoint registered successfully (RESTful)")
	return nil
}

func (ec BreakglassEscalationController) handleGetEscalations(c *gin.Context) {
	// Get correlation ID for consistent logging
	reqLog := system.GetReqLogger(c, ec.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)
	reqLog.Info("Processing escalations request")
	metrics.APIEndpointRequests.WithLabelValues("handleGetEscalations").Inc()

	// Parse query parameters for filtering
	clusterFilter := c.Query("cluster")
	activeOnly := parseBoolQuery(c.Query("activeOnly"), false)

	email, err := ec.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.With("error", err).Error("Failed to extract user email from authentication token")
		metrics.APIEndpointErrors.WithLabelValues("handleGetEscalations", "500").Inc()
		apiresponses.RespondInternalErrorSimple(c, "failed to extract user identity")
		return
	}
	reqLog.With("email", email).Debug("Successfully extracted user email from token")

	// Attempt to resolve groups from token first (preferred) then fallback to cluster-based resolution
	var userGroups []string
	// Raw token groups (pre-normalization) for trace diagnostics
	if raw, exists := c.Get("groups"); exists {
		if arr, ok := raw.([]string); ok {
			reqLog.With("rawTokenGroups", arr, "rawTokenGroupCount", len(arr)).Debug("Extracted raw token groups from JWT claims")
		}
	}
	if tg, exists := c.Get("groups"); exists {
		if arr, ok := tg.([]string); ok {
			userGroups = append(userGroups, arr...)
		}
	}
	if len(userGroups) == 0 { // fallback
		userContext := ClusterUserGroup{Username: email}
		var gerr error
		userGroups, gerr = ec.getUserGroupsFn(c.Request.Context(), userContext)
		if gerr != nil {
			reqLog.With("error", gerr.Error(), "user", email).Error("Failed to retrieve user groups for escalation determination")
			metrics.APIEndpointErrors.WithLabelValues("handleGetEscalations", "500").Inc()
			apiresponses.RespondInternalErrorSimple(c, "failed to extract user groups")
			return
		}
	}

	// Apply OIDC prefix stripping if configured (token groups will not have the prefix; cluster groups might)
	if cfg, cerr := config.Load(ec.configPath); cerr == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		userGroups = stripOIDCPrefixes(userGroups, cfg.Kubernetes.OIDCPrefixes)
	} else if cerr != nil {
		// Avoid logging wrapped errors (which may include stack traces). Log a concise message only.
		reqLog.With("error", cerr.Error()).Debug("Continuing without OIDC prefix stripping")
	}
	reqLog.With("userGroups", userGroups, "groupCount", len(userGroups)).Debug("Resolved user groups (token first)")

	escalations, err := ec.manager.GetGroupBreakglassEscalations(c.Request.Context(), userGroups)
	if err != nil {
		reqLog.With("error", err.Error()).Error("Failed to retrieve escalations from manager")
		metrics.APIEndpointErrors.WithLabelValues("handleGetEscalations", "500").Inc()
		apiresponses.RespondInternalErrorSimple(c, "failed to extract user escalations")
		return
	}
	reqLog.With("escalationCount", len(escalations)).Debug("Successfully fetched escalations from manager")

	// Policy: hide "read-only" escalation if user already possesses the read-only group (no privilege gain)
	filtered := make([]breakglassv1alpha1.BreakglassEscalation, 0, len(escalations))
	userGroupSet := map[string]struct{}{}
	for _, g := range userGroups {
		userGroupSet[g] = struct{}{}
	}

	// Apply cluster and activeOnly filters
	for _, esc := range escalations {
		// Filter by cluster if specified
		if clusterFilter != "" {
			if !escalationMatchesCluster(esc, clusterFilter) {
				continue
			}
		}

		// Filter by active status if requested
		if activeOnly {
			if !isEscalationReady(&esc) {
				continue
			}
		}

		filtered = append(filtered, esc)
	}

	// Return full objects including (future) status with approverGroupMembers for UI
	response := make([]breakglassv1alpha1.BreakglassEscalation, 0, len(filtered))
	response = append(response, filtered...)

	// Filter out hidden groups from the response - they should not be visible to users in the UI
	for i := range response {
		if len(response[i].Spec.Approvers.HiddenFromUI) > 0 {
			// Build set of hidden items for quick lookup
			hiddenSet := make(map[string]bool)
			for _, item := range response[i].Spec.Approvers.HiddenFromUI {
				hiddenSet[item] = true
			}

			// Filter out hidden groups and users from the visible approvers
			filteredGroups := []string{}
			for _, group := range response[i].Spec.Approvers.Groups {
				if !hiddenSet[group] {
					filteredGroups = append(filteredGroups, group)
				}
			}

			filteredUsers := []string{}
			for _, user := range response[i].Spec.Approvers.Users {
				if !hiddenSet[user] {
					filteredUsers = append(filteredUsers, user)
				}
			}

			// Update the response with filtered approvers
			response[i].Spec.Approvers.Groups = filteredGroups
			response[i].Spec.Approvers.Users = filteredUsers

			// Remove HiddenFromUI field from response (client doesn't need to see it)
			response[i].Spec.Approvers.HiddenFromUI = nil
		}
	}

	reqLog.With("responseCount", len(response)).Debug("Returning escalations response (filtered, hidden groups removed)")
	c.JSON(http.StatusOK, dropK8sInternalFieldsEscalationList(response))
}

func (BreakglassEscalationController) BasePath() string {
	return "breakglassEscalations"
}

func (b BreakglassEscalationController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

func NewBreakglassEscalationController(log *zap.SugaredLogger,
	manager *EscalationManager,
	middleware gin.HandlerFunc,
	configPath string,
) *BreakglassEscalationController {
	log.Debug("Initializing BreakglassEscalationController with Keycloak identity provider")

	identityProvider := KeycloakIdentityProvider{log: log}
	log.Debug("KeycloakIdentityProvider configured for user identity extraction")

	controller := &BreakglassEscalationController{
		log:              log,
		manager:          manager,
		middleware:       middleware,
		identityProvider: identityProvider,
		getUserGroupsFn: func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return GetUserGroupsWithConfig(ctx, cug, configPath)
		},
		configPath: configPath,
	}

	log.Debug("BreakglassEscalationController initialization completed successfully")
	return controller
}

// isEscalationReady checks if an escalation has Ready=True condition.
func isEscalationReady(esc *breakglassv1alpha1.BreakglassEscalation) bool {
	for _, cond := range esc.Status.Conditions {
		if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
