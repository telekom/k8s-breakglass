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

	// TODO: Implement getting local groups assigned to user
	// groups := wc.GetUserClusterGroups(sar.Spec.User, cluster)
	// Sample group that allows service creation
	groups := []string{"breakglass-service-create"}

	can, err := accessreview.CanUserDo(sar, groups)
	fmt.Println("CAN-I:=", can, err)
	if can {
		response := SubjectAccessReviewResponse{
			ApiVersion: sar.APIVersion,
			Kind:       sar.Kind,
			Status: SubjectAccessReviewResponseStatus{
				Allowed: true,
			},
		}

		c.JSON(http.StatusOK, &response)
		return
	}
	// TODO: If not allowed deny and add group request link as a reason.

	car := v1alpha1.NewClusterAccessReview(cluster, v1alpha1.ClusterAccessReviewSubject{
		Username:  sar.Spec.User,
		Namespace: sar.Spec.ResourceAttributes.Namespace,
		Resource:  sar.Spec.ResourceAttributes.Resource,
		Verb:      sar.Spec.ResourceAttributes.Verb,
	}, defaultReviewRequestTimeout)

	allowed := false
	reason := ""
	reviews, err := wc.GetSubjectReviews(ctx, cluster, sar.Spec)
	if err != nil {
		log.Printf("Error getting access review from database: %v", err)
		c.JSON(http.StatusInternalServerError, "Failed to extract review information")
		return
	}

	if len(reviews) == 0 {
		// todo: reason should be only a link to create request
		reason = "Access added to be reviewed by administrator."
		if err := wc.manager.AddAccessReview(ctx, car); err != nil {
			log.Printf("Error adding access review to database: %v", err)
			c.JSON(http.StatusInternalServerError, "Failed to process review request")
			return
		}
	} else {
		for _, review := range reviews {
			switch review.Spec.Status {
			case v1alpha1.StatusAccepted:
				allowed = true
				// TODO: Do actually we want to delete such review?
				// This will give access for only very short amount of time (by default it is 5minutes)
				// https://kubernetes.io/docs/reference/config-api/apiserver-config.v1beta1/
				// Probably we want to simply extend time on update.
				if err := wc.manager.DeleteReviewByName(ctx, review.GetName()); err != nil {
					log.Printf("Error deleting access review from db: %v", err)
					c.JSON(http.StatusInternalServerError, "Failed to process review request")
				}
			case v1alpha1.StatusPending:
				allowed = false
				reason = "Access pending to be reviewed by administrator."
			case v1alpha1.StatusRejected:
				allowed = false
				reason = "Access already once rejected. New request will be created."
				// TODO: Do we want some logic to only allow that after some timeout
				// especially if rejected more than once
				if err := wc.manager.UpdateReviewStatusByName(ctx, review.GetName(), v1alpha1.StatusPending); err != nil {
					log.Printf("Error updating access review status: %v", err)
					c.JSON(http.StatusInternalServerError, "Failed to process review request")
				}
			}
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
