package accessreview

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"go.uber.org/zap"
)

type ClusterAccessReviewController struct {
	log        *zap.SugaredLogger
	config     config.Config
	manager    *AccessReviewDB
	middleware gin.HandlerFunc
}

func (ClusterAccessReviewController) BasePath() string {
	return "breakglass/cluster_access/"
}

func (wc *ClusterAccessReviewController) Register(rg *gin.RouterGroup) error {
	rg.GET("/reviews", wc.handleGetReviews)
	rg.POST("/accept/:id", wc.handleAccept)
	rg.POST("/reject/:id", wc.handleReject)
	return nil
}

func (b ClusterAccessReviewController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

func (wc ClusterAccessReviewController) handleGetReviews(c *gin.Context) {
	reviews, err := wc.manager.GetAccessReviews()
	if err != nil {
		log.Printf("Error getting access reviews %v", err)
		c.JSON(http.StatusInternalServerError, "Failed to extract review information")
		return
	}

	c.JSON(http.StatusOK, reviews)
}

func (wc ClusterAccessReviewController) handleAccept(c *gin.Context) {
	wc.handleStatusChange(c, StatusAccepted)
}

func (wc ClusterAccessReviewController) handleReject(c *gin.Context) {
	wc.handleStatusChange(c, StatusRejected)
}

func (wc ClusterAccessReviewController) handleStatusChange(c *gin.Context, newStatus AccessReviewApplicationStatus) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		log.Printf("Error getting id from request %v", err)
		c.JSON(http.StatusBadRequest, "Failed to parse input id")
		return
	}
	err = wc.manager.UpdateReviewStatus(uint(id), newStatus)
	if err != nil {
		log.Printf("Error getting access review with id %q %v", id, err)
		c.JSON(http.StatusInternalServerError, "Failed to extract review information")
		return
	}

	c.Status(http.StatusOK)
}

func NewClusterAccessReviewController(log *zap.SugaredLogger,
	cfg config.Config,
	manager *AccessReviewDB,
	middleware gin.HandlerFunc,
) *ClusterAccessReviewController {
	controller := &ClusterAccessReviewController{
		log:        log,
		config:     cfg,
		manager:    manager,
		middleware: middleware,
	}

	return controller
}
