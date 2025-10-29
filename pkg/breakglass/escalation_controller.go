package breakglass

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
	"go.uber.org/zap"
)

type BreakglassEscalationController struct {
	manager          *EscalationManager
	log              *zap.SugaredLogger
	middleware       gin.HandlerFunc
	identityProvider IdentityProvider
	getUserGroupsFn  GetUserGroupsFunction
}

// dropK8sInternalFieldsEscalation removes K8s internal fields from BreakglassEscalation for API response
func dropK8sInternalFieldsEscalation(e *v1alpha1.BreakglassEscalation) {
	if e == nil {
		return
	}
	e.ObjectMeta.ManagedFields = nil
	if e.ObjectMeta.Annotations != nil {
		delete(e.ObjectMeta.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
}

func dropK8sInternalFieldsEscalationList(list []v1alpha1.BreakglassEscalation) []v1alpha1.BreakglassEscalation {
	for i := range list {
		dropK8sInternalFieldsEscalation(&list[i])
	}
	return list
}
func (ec *BreakglassEscalationController) Register(rg *gin.RouterGroup) error {
	basePath := ec.BasePath()
	ec.log.With("basePath", basePath).Info("Registering escalation controller endpoints (RESTful)")
	rg.GET("", ec.handleGetEscalations)
	ec.log.With("endpoint", basePath).Debug("Escalation endpoint registered successfully (RESTful)")
	return nil
}

func (ec BreakglassEscalationController) handleGetEscalations(c *gin.Context) {
	// Get correlation ID for consistent logging
	reqLog := system.GetReqLogger(c, ec.log)
	reqLog = system.EnrichReqLoggerWithAuth(c, reqLog)
	reqLog.Info("Processing escalations request")

	email, err := ec.identityProvider.GetEmail(c)
	if err != nil {
		reqLog.With("error", err).Error("Failed to extract user email from authentication token")
		c.JSON(http.StatusInternalServerError, "failed to extract user identity")
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
			c.JSON(http.StatusInternalServerError, "failed to extract user groups")
			return
		}
	}

	// Apply OIDC prefix stripping if configured (token groups will not have the prefix; cluster groups might)
	if cfg, cerr := config.Load(); cerr == nil && len(cfg.Kubernetes.OIDCPrefixes) > 0 {
		userGroups = stripOIDCPrefixes(userGroups, cfg.Kubernetes.OIDCPrefixes)
	} else if cerr != nil {
		// Avoid logging wrapped errors (which may include stack traces). Log a concise message only.
		reqLog.With("error", cerr.Error()).Debug("Continuing without OIDC prefix stripping")
	}
	reqLog.With("userGroups", userGroups, "groupCount", len(userGroups)).Debug("Resolved user groups (token first)")

	escalations, err := ec.manager.GetGroupBreakglassEscalations(c.Request.Context(), userGroups)
	if err != nil {
		reqLog.With("error", err.Error()).Error("Failed to retrieve escalations from manager")
		c.JSON(http.StatusInternalServerError, "failed to extract user escalations")
		return
	}
	reqLog.With("escalationCount", len(escalations)).Debug("Successfully fetched escalations from manager")

	// Policy: hide "read-only" escalation if user already possesses the read-only group (no privilege gain)
	filtered := make([]v1alpha1.BreakglassEscalation, 0, len(escalations))
	userGroupSet := map[string]struct{}{}
	for _, g := range userGroups {
		userGroupSet[g] = struct{}{}
	}
	filtered = append(filtered, escalations...)

	// Return full objects including (future) status with approverGroupMembers for UI
	response := make([]v1alpha1.BreakglassEscalation, 0, len(filtered))
	response = append(response, filtered...)
	reqLog.With("responseCount", len(response)).Debug("Returning escalations response (filtered)")
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
) *BreakglassEscalationController {

	log.Debug("Initializing BreakglassEscalationController with Keycloak identity provider")

	identityProvider := KeycloakIdentityProvider{}
	log.Debug("KeycloakIdentityProvider configured for user identity extraction")

	controller := &BreakglassEscalationController{
		log:              log,
		manager:          manager,
		middleware:       middleware,
		identityProvider: identityProvider,
		getUserGroupsFn:  GetUserGroups,
	}

	log.Debug("BreakglassEscalationController initialization completed successfully")
	return controller
}
