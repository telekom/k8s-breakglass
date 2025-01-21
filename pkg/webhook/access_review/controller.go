package accessreview

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook/access_review/api/v1alpha1"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MonthDuration = time.Hour * 24 * 30

type BreakglassSessionController struct {
	log              *zap.SugaredLogger
	config           config.Config
	manager          *CRDManager
	middleware       gin.HandlerFunc
	identityProvider IdentityProvider
}

func (BreakglassSessionController) BasePath() string {
	return "breakglassSession/"
}

func (wc *BreakglassSessionController) Register(rg *gin.RouterGroup) error {
	rg.GET("/status", wc.handleGetBreakglassSessionStatus)
	rg.POST("/request", wc.handleRequestBreakglassSession)

	return nil
}

func (b BreakglassSessionController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

func (wc BreakglassSessionController) handleGetBreakglassSessionStatus(c *gin.Context) {
	user := c.Param("username")
	cluster := c.Param("clustername")
	group := c.Param("groupname")
	uname := c.Param("uname")

	if cluster == "" && user == "" && group == "" && uname == "" {
		c.Status(http.StatusBadRequest)
		return
	}

	if !wc.isPerformedByBreakglassAdmin(c) {
		c.Status(http.StatusUnauthorized)
		return
	}

	sessions, err := wc.manager.GetBreakglassSessionsWithSelector(c.Request.Context(),
		SessionSelector(uname, user, cluster, group))
	if err != nil {
		log.Printf("Error getting breakglass sessions %v", err)
		c.JSON(http.StatusInternalServerError, "failed to extract cluster group access information")
		return
	}

	c.JSON(http.StatusOK, sessions)
}

func (wc BreakglassSessionController) handleRequestBreakglassSession(c *gin.Context) {
	type BreakglassSessionRequest struct {
		Clustername  string `json:"clustername,omitempty"`
		Username     string `json:"username,omitempty"`
		Clustergroup string `json:"clustergroup,omitempty"`
	}

	request := BreakglassSessionRequest{}
	err := json.NewDecoder(c.Request.Body).Decode(&request)
	if err != nil {
		log.Println("error while decoding body:", err)
		c.Status(http.StatusUnprocessableEntity)
		return
	}
	if request.Clustername == "" || request.Username == "" || request.Clustergroup == "" {
		c.JSON(http.StatusUnprocessableEntity, "missing input request data")
		return
	}

	sessions, err := wc.manager.GetBreakglassSessionsWithSelector(c.Request.Context(),
		SessionSelector("", request.Username, request.Clustername, request.Clustergroup))
	if err != nil {
		log.Printf("Error getting breakglass sessions %v", err)
		c.JSON(http.StatusInternalServerError, "failed to extract cluster group access information")
		return
	}
	if len(sessions) > 0 {
		c.JSON(http.StatusOK, "already requested")
		return
	}

	identity, err := wc.identityProvider.GetIdentityEmail(c)
	if err != nil {
		log.Printf("Error getting user identity: %v", err)
		return
	}

	bs := v1alpha1.NewBreakglassSession(
		request.Clustername,
		request.Username,
		request.Clustergroup,
		wc.getApprovers())

	bs.Name = fmt.Sprintf("%s-%s-%s", request.Clustername, request.Username, request.Clustergroup)
	if err := wc.manager.AddBreakglassSession(c.Request.Context(), bs); err != nil {
		log.Println("error while adding breakglass session", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	bs, err = wc.manager.GetBreakglassSessionByName(c.Request.Context(), bs.Name)
	if err != nil {
		log.Println("error while getting bs session", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	bs.Status = v1alpha1.BreakglassSessionStatus{
		Expired:            false,
		Approved:           false,
		IdleTimeoutReached: false,
		CreatedAt:          metav1.Now(),
		StoreUntil:         metav1.NewTime(time.Now().Add(MonthDuration)),
	}

	// If user is approver he can automatically create approved request for himself or some user
	if slices.Contains(bs.Spec.Approvers, identity) {
		bs.Status.Approved = true
		bs.Status.ApprovedAt = metav1.Now()
	}

	if err := wc.manager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		log.Println("error while updating breakglass session", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusCreated, request)
}

func (wc BreakglassSessionController) handleListClusters(c *gin.Context) {
	sessions, err := wc.manager.GetAllBreakglassSessions(c.Request.Context())
	if err != nil {
		log.Printf("Error getting access reviews %v", err)
		c.JSON(http.StatusInternalServerError, "Failed to extract cluster group access information")
		return
	}

	clusters := make([]string, 0, len(sessions))
	for _, session := range sessions {
		clusters = append(clusters, session.Spec.Cluster)
	}

	c.JSON(http.StatusOK, clusters)
}

// handleGetGroups
func (wc BreakglassSessionController) handleGetGroups(c *gin.Context) {
	// TODO: Should be stored in CRD or in config yaml
	groupList := []string{}
	c.JSON(http.StatusOK, groupList)
}

func (wc BreakglassSessionController) getApprovers() []string {
	return wc.config.ClusterAccess.Approvers
}

func (wc BreakglassSessionController) isPerformedByBreakglassAdmin(c *gin.Context) bool {
	identity, err := wc.identityProvider.GetIdentityEmail(c)
	if err != nil {
		log.Printf("Error getting user identity: %v", err)
		return false
	}

	return slices.Contains(wc.getApprovers(), identity)
}

func NewBreakglassSessionController(log *zap.SugaredLogger,
	cfg config.Config,
	manager *CRDManager,
	middleware gin.HandlerFunc,
) *BreakglassSessionController {
	// TODO: Probably a switch based on config
	ip := KeycloakIdentityProvider{}

	controller := &BreakglassSessionController{
		log:              log,
		config:           cfg,
		manager:          manager,
		middleware:       middleware,
		identityProvider: ip,
	}

	return controller
}
