package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	accessreview "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review/api/v1alpha1"
	"go.uber.org/zap"
	"k8s.io/kubernetes/pkg/apis/authorization"
)

const defaultReviewRequestTimeout = 5 * time.Minute

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
	log     *zap.SugaredLogger
	config  config.Config
	manager *accessreview.CRDManager
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

	groups, err := wc.getUserGroupsForCluster(ctx, sar.Spec.User, cluster)
	if err != nil {
		log.Println("error while getting user groups", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	can, err := accessreview.CanUserDo(sar, groups)
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
		reason = fmt.Sprintf("Please request proper group assignment at https://%s/request?cluster=%s", wc.config.ClusterAccess.FrontendPage, cluster)
	}

	// TODO: If not allowed deny and add group request link as a reason.

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
	groups := []string{"breakglass-service-create"}

	return groups, nil
}

func (wc WebhookController) GetSubjectReviews(
	ctx context.Context,
	cluster string,
	s authorization.SubjectAccessReviewSpec,
) ([]v1alpha1.ClusterAccessReview, error) {
	// TODO: user can be anonymous then we probably want to return empty
	reviews, err := wc.manager.GetClusterUserReviews(ctx, cluster, s.User)
	if err != nil {
		return nil, errors.Wrapf(err, "failed get cluster %q subject reviews for user %q", cluster, s.User)
	}

	outReviews := []v1alpha1.ClusterAccessReview{}
	for _, review := range reviews {
		if IsValid(review) && AreSubjectEqual(review.Spec.Subject, s) {
			outReviews = append(outReviews, review)
		}
	}
	return outReviews, nil
}

func (wc WebhookController) cleanupOldReviewRequests() {
	cleanupRefreshTime := 1 * time.Minute
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := wc.manager.DeleteReviewsOlderThan(ctx, time.Now()); err != nil {
			wc.log.Errorf("Failed to delete old requests %v", err)
		}
	}

	for {
		wc.log.Info("Running cleanup task")
		cleanup()
		wc.log.Info("Finished cleanup task")
		time.Sleep(cleanupRefreshTime)
	}
}

func NewWebhookController(log *zap.SugaredLogger, cfg config.Config, manager *accessreview.CRDManager) *WebhookController {
	controller := &WebhookController{
		log:     log,
		config:  cfg,
		manager: manager,
	}

	go controller.cleanupOldReviewRequests()

	return controller
}

func IsValid(car v1alpha1.ClusterAccessReview) bool {
	timeNow := time.Now()
	return timeNow.Before(car.Spec.Until.Time)
}

func AreSubjectEqual(carSubj v1alpha1.ClusterAccessReviewSubject, authSubj authorization.SubjectAccessReviewSpec) bool {
	return carSubj.Username == authSubj.User &&
		carSubj.Namespace == authSubj.ResourceAttributes.Namespace &&
		carSubj.Resource == authSubj.ResourceAttributes.Resource &&
		carSubj.Verb == authSubj.ResourceAttributes.Verb
}
