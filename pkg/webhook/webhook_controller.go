package webhook

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	accessreview "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review"
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
	log    *zap.SugaredLogger
	config config.Config
	db     *accessreview.AccessReviewDB
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

	sar := authorization.SubjectAccessReview{}
	err := json.NewDecoder(c.Request.Body).Decode(&sar)
	fmt.Println(cluster)
	if err != nil {
		log.Println("error while decoding body:", err)
		c.Status(http.StatusUnprocessableEntity)
		return
	}

	// Probably this type of message will be send via email.
	fmt.Println("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	fmt.Printf(`User %q (uid=%q) would like to access cluster %q groups are %q
    Requested operation %q %q version %q for namespace %q and group %q. Extra info: %#v
    NonResource: %#v
    `,
		sar.Spec.User,
		sar.Spec.UID,
		cluster,
		sar.Spec.Groups,
		sar.Spec.ResourceAttributes.Verb,
		sar.Spec.ResourceAttributes.Resource,
		sar.Spec.ResourceAttributes.Version,
		sar.Spec.ResourceAttributes.Namespace,
		sar.Spec.ResourceAttributes.Group,
		sar.Spec.Extra,
		sar.Spec.NonResourceAttributes,
	)
	fmt.Println("\n--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n")

	ar := accessreview.NewAccessReview(cluster, sar.Spec, defaultReviewRequestTimeout)
	allowed := false
	reason := ""
	reviews, err := wc.GetSubjectReviews(cluster, sar.Spec)
	if err != nil {
		log.Printf("Error getting access review from database: %v", err)
		c.JSON(http.StatusInternalServerError, "Failed to extract review information")
		return
	}

	fmt.Println("Subject reviews:=", reviews)
	fmt.Println("Subject reviews:=", len(reviews))

	if len(reviews) == 0 {
		reason = "Access added to be reviewed by administrator."
		if err := wc.db.AddAccessReview(ar); err != nil {
			log.Printf("Error adding access review to database: %v", err)
			c.JSON(http.StatusInternalServerError, "Failed to process review request")
			return
		}
	} else {
		for _, review := range reviews {
			switch review.Status {
			case accessreview.StatusAccepted:
				allowed = true
				if err := wc.db.DeleteReviewByID(ar.ID); err != nil {
					log.Printf("Error deleting access review from db: %v", err)
					c.JSON(http.StatusInternalServerError, "Failed to process review request")
				}
			case accessreview.StatusPending:
				allowed = false
				reason = "Access pending to be reviewed by administrator."
			case accessreview.StatusRejected:
				allowed = false
				reason = "Access already once rejected. New request will be created."
				// TODO: Do we want some logic to only allow that after some timeout
				// especially if rejected more than once
				if err := wc.db.UpdateReviewStatus(review.ID, accessreview.StatusPending); err != nil {
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
	cluster string, s authorization.SubjectAccessReviewSpec,
) ([]accessreview.AccessReview, error) {
	reviews, err := wc.db.GetClusterUserReviews(cluster, s.User)
	if err != nil {
		return nil, errors.Wrapf(err, "failed get cluster %q subject reviews for user %q", cluster, s.User)
	}

	outReviews := []accessreview.AccessReview{}
	for _, review := range reviews {
		if review.IsValid() && reflect.DeepEqual(review.Subject, s) {
			outReviews = append(outReviews, review)
		}
	}
	return outReviews, nil
}

func (wc WebhookController) cleanupOldReviewRequests() {
	for {
		wc.log.Info("Running cleanup task")
		if err := wc.db.DeleteReviewsOlderThan(time.Now()); err != nil {
			wc.log.Errorf("Failed to delete old requests %v", err)
		}
		wc.log.Info("Finished cleanup task")
		time.Sleep(defaultReviewRequestTimeout)
	}
}

func NewWebhookController(log *zap.SugaredLogger, cfg config.Config, manager *accessreview.AccessReviewDB) *WebhookController {
	controller := &WebhookController{
		log:    log,
		config: cfg,
		db:     manager,
	}

	go controller.cleanupOldReviewRequests()

	return controller
}
