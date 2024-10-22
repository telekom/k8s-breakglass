package accessreview

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
)

type ClusterAccessReviewController struct {
	log     *zap.SugaredLogger
	config  config.Config
	manager *AccessReviewDB
}

func (ClusterAccessReviewController) BasePath() string {
	return "breakglass/cluster_access/"
}

func (wc *ClusterAccessReviewController) Register(rg *gin.RouterGroup) error {
	rg.GET("/reviews", wc.handleGetReviews)
	// TODO: approval mechanism
	rg.POST("/approve", wc.handleGetReviews)
	return nil
}

func (b ClusterAccessReviewController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{}
}

func (wc ClusterAccessReviewController) handleGetReviews(c *gin.Context) {
	// Will return list of actual reviews or since some time passed by user and other parameters like status etc
	reviews, _ := wc.manager.GetAccessReviews()
	c.JSON(http.StatusOK, reviews)
}

func NewClusterAccessReviewController(log *zap.SugaredLogger,
	cfg config.Config, manager *AccessReviewDB,
) *ClusterAccessReviewController {
	controller := &ClusterAccessReviewController{
		log:     log,
		config:  cfg,
		manager: manager,
	}

	return controller
}
