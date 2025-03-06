package breakglass

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap"
)

type BreakglassEscalationController struct {
	manager          *EscalationManager
	log              *zap.SugaredLogger
	middleware       gin.HandlerFunc
	identityProvider IdentityProvider
}

func (ec *BreakglassEscalationController) Register(rg *gin.RouterGroup) error {
	rg.GET("/escalations", ec.handleGetEscalations)
	return nil
}

func (ec BreakglassEscalationController) handleGetEscalations(c *gin.Context) {
	email, err := ec.identityProvider.GetEmail(c)
	if err != nil {
		ec.log.Error("failed to get email identity", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract user identity")
		return
	}

	escalations, err := ec.manager.GetUserBreakglassEscalations(c.Request.Context(), email)
	if err != nil {
		ec.log.Error("Error getting user identity email", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract user escalations")
		return
	}

	escalationSpec := make([]v1alpha1.BreakglassEscalationSpec, 0, len(escalations))
	for _, esc := range escalations {
		escalationSpec = append(escalationSpec, esc.Spec)
	}

	c.JSON(http.StatusOK, escalationSpec)
}

func (BreakglassEscalationController) BasePath() string {
	return "breakglassEscalation/"
}

func (b BreakglassEscalationController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

func NewBreakglassEscalationController(log *zap.SugaredLogger,
	manager *EscalationManager,
	middleware gin.HandlerFunc,
) *BreakglassEscalationController {
	ip := KeycloakIdentityProvider{}
	return &BreakglassEscalationController{
		log:              log,
		manager:          manager,
		middleware:       middleware,
		identityProvider: ip,
	}
}
