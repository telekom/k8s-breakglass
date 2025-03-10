package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/kubernetes/pkg/apis/authorization"
)

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
	log        *zap.SugaredLogger
	config     config.Config
	sesManager *breakglass.SessionManager
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

	sar := authorization.SubjectAccessReview{}
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
	can, err := breakglass.CanGroupsDo(ctx, groups, sar, cluster)
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
		reason = fmt.Sprintf("please request proper group assignment at %s/breakglassSession/request?cluster=%s",
			wc.config.Frontend.BaseURL, cluster)
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
			"spec.cluster":              clustername,
			"spec.username":             username,
			"status.expired":            "false",
			"status.approved":           "true",
			"status.idleTimeoutReached": "false",
		},
	)
	sessions, err := wc.sesManager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get ClusterGroupAccess")
	}

	groups := make([]string, 0, len(sessions))
	for _, session := range sessions {
		groups = append(groups, session.Spec.Group)
	}

	return groups, nil
}

func NewWebhookController(log *zap.SugaredLogger, cfg config.Config, manager *breakglass.SessionManager) *WebhookController {
	controller := &WebhookController{
		log:        log,
		config:     cfg,
		sesManager: manager,
	}

	return controller
}
