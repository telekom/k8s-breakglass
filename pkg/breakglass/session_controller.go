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
)

const (
	MonthDuration = time.Hour * 24 * 30
	WeekDuration  = time.Hour * 24 * 7
)

var ErrSessionNotFound error = errors.New("session not found")

type BreakglassSessionRequest ClusterUserGroup

type BreakglassSessionController struct {
	log               *zap.SugaredLogger
	config            config.Config
	sessionManager    *SessionManager
	escalationManager *EscalationManager
	middleware        gin.HandlerFunc
	identityProvider  IdentityProvider
	mail              mail.Sender
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
	ctx := c.Request.Context()

	// TODO: To decide if we want to treat email or username as main identity
	userName, _ := wc.identityProvider.GetEmail(c)

	sessions, err := wc.sessionManager.GetBreakglassSessionsWithSelectorString(ctx,
		SessionSelector(uname, user, cluster, group))
	if err != nil {
		wc.log.Error("Error getting breakglass sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract breakglass session information")
		return
	}

	sessionsPerCluster := make(map[string][]telekomv1alpha1.BreakglassSession)
	for _, ses := range sessions {
		if _, has := sessionsPerCluster[ses.Spec.Cluster]; !has {
			sessionsPerCluster[ses.Spec.Cluster] = []telekomv1alpha1.BreakglassSession{}
		}
		sessionsPerCluster[ses.Spec.Cluster] = append(sessionsPerCluster[ses.Spec.Cluster], ses)
	}

	displayable := []v1alpha1.BreakglassSession{}

	for clusterName, sessions := range sessionsPerCluster {
		escalations, err := wc.escalationManager.GetClusterBreakglassEscalations(ctx, clusterName)
		if err != nil {
			wc.log.Error("Error getting breakglass escalations", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract breakglass escalation information")
			return
		}

		sessions, err := EscalationFiltering{
			FilterUserData:   ClusterUserGroup{Clustername: clusterName, Username: userName},
			UserGroupExtract: GetUserGroups,
		}.FilterSessionsForUserApprovable(ctx, sessions, escalations)
		if err != nil {
			wc.log.Error("Error fitlering for user approvable", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract user breakglass information")
			return
		}

		displayable = append(displayable, sessions...)
	}

	c.JSON(http.StatusOK, displayable)
}

func (wc BreakglassSessionController) handleRequestBreakglassSession(c *gin.Context) {
	request := BreakglassSessionRequest{}
	err := json.NewDecoder(c.Request.Body).Decode(&request)
	if err != nil {
		wc.log.Error("Error while decoding body", zap.Error(err))
		c.Status(http.StatusUnprocessableEntity)
		return
	}
	if request.Clustername == "" || request.Username == "" || request.Groupname == "" {
		c.JSON(http.StatusUnprocessableEntity, "missing input request data")
		return
	}

	ctx := c.Request.Context()
	cug := ClusterUserGroup(request)

	escalations, err := wc.escalationManager.GetClusterUserBreakglassEscalations(ctx, cug)
	if err != nil {
		wc.log.Error("Error getting breakglass escalations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract cluster breakglass escalation information")

	}

	possibleEscals, err := EscalationFiltering{
		FilterUserData:   cug,
		UserGroupExtract: GetUserGroups,
	}.FilterForUserPossibleEscalations(ctx, escalations)
	if err != nil {
		wc.log.Error("Error getting breakglass escalation groups", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract cluster group escalation information")
		return
	}

	possible := []string{}
	approvers := []string{}
	// approverGroups := []string{}
	for _, p := range possibleEscals {
		possible = append(possible, p.Spec.EscalatedGroup)
		approvers = append(approvers, p.Spec.Approvers.Users...)
		// approverGroups = append(approverGroups, p.Spec.Approvers.Groups...)
	}

	if !slices.Contains(possible, request.Groupname) {
		c.JSON(http.StatusUnauthorized, "user unauthorized for group")
		return
	}

	ses, err := wc.getBreakglassSession(ctx,
		request.Username, request.Clustername, request.Groupname)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			wc.log.Error("Error getting breakglass sessions", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract breakglass session information")
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

	bs := v1alpha1.NewBreakglassSession(
		request.Clustername,
		request.Username,
		request.Groupname)

	bs.GenerateName = fmt.Sprintf("%s-%s-%s-", request.Clustername, request.Username, request.Groupname)
	if err := wc.sessionManager.AddBreakglassSession(ctx, bs); err != nil {
		wc.log.Error("error while adding breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	bs, err = wc.getBreakglassSession(ctx, request.Username, request.Clustername, request.Groupname)
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

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(ctx, bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	if err := wc.sendOnRequestEmail(bs, useremail, username, approvers); err != nil {
		wc.log.Error("Error while sending breakglass session request notification email", zap.Error(err))
		c.Status(http.StatusInternalServerError)
	}

	c.JSON(http.StatusCreated, request)
}

func (wc BreakglassSessionController) updateStatus(c *gin.Context, statusFn func(*telekomv1alpha1.BreakglassSession)) {
	uname := c.Param("uname")

	bs, err := wc.sessionManager.GetBreakglassSessionByName(c.Request.Context(), uname)
	if err != nil {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	if !wc.isSessionApprover(c, bs) {
		c.Status(http.StatusUnauthorized)
		return
	}

	statusFn(&bs)

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
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
	sessions, err := wc.sessionManager.GetBreakglassSessionsWithSelector(ctx, selector)
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

func (wc BreakglassSessionController) sendOnRequestEmail(bs v1alpha1.BreakglassSession,
	requestEmail,
	requestUsername string,
	approvers []string,
) error {
	subject := fmt.Sprintf("Cluster %q user %q is requesting breakglass group assignment %q", bs.Spec.Cluster, bs.Spec.Username, bs.Spec.Group)

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

// nolint:unused // might use later
func (wc BreakglassSessionController) handleListClusters(c *gin.Context) {
	sessions, err := wc.sessionManager.GetAllBreakglassSessions(c.Request.Context())
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

func (wc BreakglassSessionController) isSessionApprover(c *gin.Context, session telekomv1alpha1.BreakglassSession) bool {
	email, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("Error getting user identity", zap.Error(err))
		return false
	}
	approverID := ClusterUserGroup{
		Username:    email,
		Clustername: session.Spec.Cluster,
	}
	ctx := c.Request.Context()

	escalations, err := wc.escalationManager.GetClusterUserGroupBreakglassEscalation(
		ctx,
		ClusterUserGroup{
			Username:    session.Spec.Username,
			Clustername: session.Spec.Cluster,
			Groupname:   session.Spec.Group,
		})
	if err != nil {
		wc.log.Error("Error getting user escalations", zap.Error(err))
		return false
	}

	sessions, err := EscalationFiltering{
		FilterUserData:   approverID,
		UserGroupExtract: GetUserGroups,
	}.FilterSessionsForUserApprovable(
		ctx,
		[]telekomv1alpha1.BreakglassSession{session},
		escalations)
	if err != nil {
		wc.log.Error("Error filtering for approver sessions", zap.Error(err))
		return false
	}

	return len(sessions) == 1
}

func NewBreakglassSessionController(log *zap.SugaredLogger,
	cfg config.Config,
	sessionManager *SessionManager,
	escalationManager *EscalationManager,
	middleware gin.HandlerFunc,
) *BreakglassSessionController {
	// TODO: Probably a switch based on config
	ip := KeycloakIdentityProvider{}

	controller := &BreakglassSessionController{
		log:               log,
		config:            cfg,
		sessionManager:    sessionManager,
		escalationManager: escalationManager,
		middleware:        middleware,
		identityProvider:  ip,
		mail:              mail.NewSender(cfg),
	}

	return controller
}
