package breakglass

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/mail"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	MonthDuration = time.Hour * 24 * 30
	WeekDuration  = time.Hour * 24 * 7
)

var ErrSessionNotFound error = errors.New("session not found")

type BreakglassSessionController struct {
	log              *zap.SugaredLogger
	config           config.Config
	manager          *CRDManager
	middleware       gin.HandlerFunc
	identityProvider IdentityProvider
	mail             mail.Sender
}

func (BreakglassSessionController) BasePath() string {
	return "breakglassSession/"
}

func (wc *BreakglassSessionController) Register(rg *gin.RouterGroup) error {
	rg.GET("/status", wc.handleGetBreakglassSessionStatus)
	rg.POST("/request", wc.handleRequestBreakglassSession)
	rg.POST("/approve/:uname", wc.handleApproveBreakglassSession)
	rg.POST("/reject/:uname", wc.handleRejectBreakglassSession)

	return nil
}

func (b BreakglassSessionController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{b.middleware}
}

func (wc BreakglassSessionController) handleGetBreakglassSessionStatus(c *gin.Context) {
	user := c.Query("username")
	cluster := c.Query("clustername")
	group := c.Query("groupname")
	uname := c.Query("uname")

	if !wc.isPerformedByBreakglassAdmin(c) {
		c.Status(http.StatusUnauthorized)
		return
	}

	sessions, err := wc.manager.GetBreakglassSessionsWithSelectorString(c.Request.Context(),
		SessionSelector(uname, user, cluster, group))
	if err != nil {
		wc.log.Error("Error getting breakglass sessions", zap.Error(err))
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
		wc.log.Error("Error while decoding body", zap.Error(err))
		c.Status(http.StatusUnprocessableEntity)
		return
	}
	if request.Clustername == "" || request.Username == "" || request.Clustergroup == "" {
		c.JSON(http.StatusUnprocessableEntity, "missing input request data")
		return
	}

	ses, err := wc.getBreakglassSession(c.Request.Context(),
		request.Username, request.Clustername, request.Clustergroup)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			wc.log.Error("Error getting breakglass sessions", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract cluster group access information")
			return
		}
	} else if !ses.Status.Expired {
		c.JSON(http.StatusOK, "already requested")
		return
	}

	useremail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("Error getting user identity email", zap.Error(err))
		return
	}
	username := wc.identityProvider.GetUsername(c)

	approvers := wc.getApprovers()

	bs := v1alpha1.NewBreakglassSession(
		request.Clustername,
		request.Username,
		request.Clustergroup,
		approvers)

	bs.GenerateName = fmt.Sprintf("%s-%s-%s-", request.Clustername, request.Username, request.Clustergroup)
	if err := wc.manager.AddBreakglassSession(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while adding breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	bs, err = wc.getBreakglassSession(c.Request.Context(), request.Username, request.Clustername, request.Clustergroup)
	if err != nil && !errors.Is(err, ErrSessionNotFound) {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
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
	if slices.Contains(bs.Spec.Approvers, useremail) {
		bs.Status.Approved = true
		bs.Status.ApprovedAt = metav1.Now()
	}

	if err := wc.manager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	if err := wc.sendOnRequestEmail(bs, useremail, username); err != nil {
		wc.log.Error("Error while sending breakglass session request notification email", zap.Error(err))
		c.Status(http.StatusInternalServerError)
	}

	c.JSON(http.StatusCreated, request)
}

func (wc BreakglassSessionController) updateStatus(c *gin.Context, statusFn func(*telekomv1alpha1.BreakglassSession)) {
	if !wc.isPerformedByBreakglassAdmin(c) {
		c.Status(http.StatusUnauthorized)
		return
	}
	uname := c.Param("uname")

	bs, err := wc.manager.GetBreakglassSessionByName(c.Request.Context(), uname)
	if err != nil {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	statusFn(&bs)

	if err := wc.manager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, bs)
}

func (wc BreakglassSessionController) getBreakglassSession(ctx context.Context,
	username,
	clustername,
	group string,
) (telekomv1alpha1.BreakglassSession, error) {
	selector := fields.SelectorFromSet(
		fields.Set{
			"spec.cluster":  clustername,
			"spec.username": username,
			"spec.group":    group,
		},
	)
	sessions, err := wc.manager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		return telekomv1alpha1.BreakglassSession{}, errors.Wrap(err, "failed to list sessions")
	}
	if len(sessions) == 0 {
		return telekomv1alpha1.BreakglassSession{}, ErrSessionNotFound
	}
	return sessions[0], nil
}

func (wc BreakglassSessionController) handleApproveBreakglassSession(c *gin.Context) {
	wc.updateStatus(c,
		func(bs *telekomv1alpha1.BreakglassSession) {
			bs.Status.Approved = true
			bs.Status.ApprovedAt = metav1.Now()
			bs.Status.ValidUntil = metav1.NewTime(bs.Status.ApprovedAt.Add(WeekDuration))
		})
}

func (wc BreakglassSessionController) handleRejectBreakglassSession(c *gin.Context) {
	wc.updateStatus(c,
		func(bs *telekomv1alpha1.BreakglassSession) {
			bs.Status.Approved = false
			bs.Status.ApprovedAt = metav1.Time{}
			bs.Status.ValidUntil = metav1.Time{}
		})
}

func (wc BreakglassSessionController) sendOnRequestEmail(bs v1alpha1.BreakglassSession, requestEmail, requestUsername string) error {
	subject := fmt.Sprintf("Cluster %q user %q is requesting breakglass group assignment %q", bs.Spec.Cluster, bs.Spec.Username, bs.Spec.Group)
	approvers := bs.Spec.Approvers

	if bs.Status.Approved {
		// TODO: In case user is an admin and get instantly approved request we coudl send notification only
		wc.log.Info("sending notification...")
	} else {
		body, err := mail.RenderBreakglassSessionRequest(mail.RequestBreakglassSessionMailParams{
			SubjectEmail:      requestEmail,
			SubjectFullName:   requestUsername,
			RequestedCluster:  bs.Spec.Cluster,
			RequestedUsername: bs.Spec.Username,
			RequestedGroup:    bs.Spec.Group,
			URL:               fmt.Sprintf("%s/breakglassSession/review?name=%s", wc.config.ClusterAccess.FrontendPage, bs.Name),
		})
		if err != nil {
			wc.log.Errorf("failed to render email template: %v", err)
			return err
		}

		if err := wc.mail.Send(approvers, subject, body); err != nil {
			wc.log.Errorf("failed to send request email: %v", err)
			return err
		}
	}

	return nil
}

func (wc BreakglassSessionController) handleListClusters(c *gin.Context) {
	sessions, err := wc.manager.GetAllBreakglassSessions(c.Request.Context())
	if err != nil {
		wc.log.Error("Error getting access reviews", zap.Error(err))
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

// Marks sessions that are expired and removes those that should no longer be stored.
func (wc BreakglassSessionController) markClenaupExpiredSession(ctx context.Context) {
	sessions, err := wc.manager.GetAllBreakglassSessions(ctx)
	if err != nil {
		wc.log.Error("error listing breakglass sessions for cleanup", zap.Error(err))
		return
	}

	now := time.Now()
	deletionLabel := map[string]string{"deletion": "true"}
	for _, ses := range sessions {
		if now.Before(ses.Status.StoreUntil.Time) {
			ses.SetLabels(deletionLabel)
			if err := wc.manager.UpdateBreakglassSession(ctx, ses); err != nil {
				wc.log.Error("error failed to set label", zap.Error(err))
			}
		} else if now.Before(ses.Status.ValidUntil.Time) {
			ses.Status.Expired = true
			if err := wc.manager.UpdateBreakglassSessionStatus(ctx, ses); err != nil {
				wc.log.Error("error while updating breakglass session", zap.Error(err))
				continue
			}
		}
	}

	if err := wc.manager.DeleteAllOf(ctx,
		&telekomv1alpha1.BreakglassSession{},
		&client.DeleteAllOfOptions{
			ListOptions: client.ListOptions{
				LabelSelector: labels.SelectorFromSet(deletionLabel),
			},
		}); err != nil {
		wc.log.Error("error while deleting expired breakglass sessions", zap.Error(err))
	}

	time.Sleep(WeekDuration)
}

func (wc BreakglassSessionController) getApprovers() []string {
	return wc.config.ClusterAccess.Approvers
}

func (wc BreakglassSessionController) isPerformedByBreakglassAdmin(c *gin.Context) bool {
	identity, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("Error getting user identity", zap.Error(err))
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
		mail:             mail.NewSender(cfg),
	}

	go controller.markClenaupExpiredSession(context.Background())

	return controller
}
