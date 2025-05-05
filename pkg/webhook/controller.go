package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/fields"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
)

const denyReasonMessage = "please request proper group assignment at %s/request?cluster=%s"

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
}

func (WebhookController) BasePath() string {
	return "breakglass/webhook"
}

func (wc *WebhookController) Register(rg *gin.RouterGroup) error {
	rg.POST("/authorize/:cluster_name", wc.handleAuthorize)
	return nil
}

func (b WebhookController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{}
}

func (wc *WebhookController) handleAuthorize(c *gin.Context) {
	cluster := c.Param("cluster_name")
	ctx := c.Request.Context()

	sar := authorizationv1.SubjectAccessReview{}

	err := json.NewDecoder(c.Request.Body).Decode(&sar)
	if err != nil {
		log.Println("error while decoding body:", err)
		c.Status(http.StatusUnprocessableEntity)
		return
	}

	username := sar.Spec.User
	groups, err := wc.getUserGroupsForCluster(ctx, username, cluster)
	if err != nil {
		log.Println("error while getting user groups", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// NOTE: If we want to know specific group that allowed user to perform the operation we would
	// need to iterate over groups (sessions) and note the first that is ok. Then we could update its
	// last used parameters and idle value.
	can, err := wc.canDoFn(ctx, groups, sar, cluster)
	if err != nil {
		log.Println("error while checking RBAC permissions", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	allowed := false
	reason := ""

	if can {
		allowed = true
	} else {
		escals, err := wc.escalManager.GetClusterUserBreakglassEscalations(ctx,
			breakglass.ClusterUserGroup{
				Clustername: cluster,
				Username:    username,
			})
		if err != nil {
			log.Println("error while getting user escalations", err)
			c.Status(http.StatusInternalServerError)
			return
		}

		if len(escals) > 0 {
			reason = fmt.Sprintf(denyReasonMessage,
				wc.config.Frontend.BaseURL, cluster)
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

	c.JSON(http.StatusOK, &response)
}

func (wc *WebhookController) getUserGroupsForCluster(ctx context.Context,
	username string,
	clustername string,
) ([]string, error) {
	selector := fields.SelectorFromSet(
		fields.Set{
			"spec.cluster": clustername,
			"spec.user":    username,
		},
	)
	sessions, err := wc.sesManager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get ClusterGroupAccess")
	}

	groups := make([]string, 0, len(sessions))
	for _, session := range sessions {
		if breakglass.IsSessionValid(session) {
			groups = append(groups, session.Spec.GrantedGroup)
		}
	}

	return groups, nil
}

func NewWebhookController(log *zap.SugaredLogger,
	cfg config.Config,
	sesManager *breakglass.SessionManager,
	escalManager *breakglass.EscalationManager,
) *WebhookController {
	controller := &WebhookController{
		log:          log,
		config:       cfg,
		sesManager:   sesManager,
		escalManager: escalManager,
		canDoFn:      breakglass.CanGroupsDo,
	}

	return controller
}
