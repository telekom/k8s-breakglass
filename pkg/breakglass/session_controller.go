package breakglass

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/mail"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

const (
	MonthDuration            = time.Hour * 24 * 30
	WeekDuration             = time.Hour * 24 * 7
	DefaultValidForDuration  = time.Hour
	DefaultRetainForDuration = MonthDuration
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
	getUserGroupsFn   GetUserGroupsFunction
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
	active := c.Query("activeOnly")
	var activeOnly bool
	var err error
	if active != "" {
		activeOnly, err = strconv.ParseBool(c.Query("activeOnly"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, "failed to parse activeOnly query parameter")
			return
		}
	}

	ctx := c.Request.Context()

	// TODO: To decide if we want to treat email or username as main identity
	userName, _ := wc.identityProvider.GetEmail(c)

	selector := SessionSelector(uname, user, cluster, group)
	var sessions []v1alpha1.BreakglassSession
	if selector != "" {
		sessions, err = wc.sessionManager.GetBreakglassSessionsWithSelectorString(ctx,
			selector)
	} else {
		sessions, err = wc.sessionManager.GetAllBreakglassSessions(ctx)
	}

	if err != nil {
		wc.log.Error("Error getting breakglass sessions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract breakglass session information")
		return
	}

	sessionsPerCluster := make(map[string][]v1alpha1.BreakglassSession)
	for _, ses := range sessions {
		if _, has := sessionsPerCluster[ses.Spec.Cluster]; !has {
			sessionsPerCluster[ses.Spec.Cluster] = []v1alpha1.BreakglassSession{}
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
			UserGroupExtract: wc.getUserGroupsFn,
		}.FilterSessionsForUserApprovable(ctx, sessions, escalations)
		if err != nil {
			wc.log.Error("Error fitlering for user approvable", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract user breakglass information")
			return
		}

		if activeOnly {
			for _, ses := range sessions {
				if IsSessionActive(ses) {
					displayable = append(displayable, ses)
				}
			}
		} else {
			displayable = append(displayable, sessions...)
		}
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
		UserGroupExtract: wc.getUserGroupsFn,
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

	ses, err := wc.getActiveBreakglassSession(ctx,
		request.Username, request.Clustername, request.Groupname)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			wc.log.Error("Error getting breakglass sessions", zap.Error(err))
			c.JSON(http.StatusInternalServerError, "failed to extract breakglass session information")
			return
		}
	} else if IsSessionActive(ses) {
		c.JSON(http.StatusOK, "already requested")
		return
	}

	useremail, err := wc.identityProvider.GetEmail(c)
	if err != nil {
		wc.log.Error("Error getting user identity email", zap.Error(err))
		c.JSON(http.StatusInternalServerError, "failed to extract email from token")
		return
	}
	username := wc.identityProvider.GetUsername(c)

	bs := v1alpha1.BreakglassSession{
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      request.Clustername,
			User:         request.Username,
			GrantedGroup: request.Groupname,
		},
	}

	bs.GenerateName = fmt.Sprintf("%s-%s-", request.Clustername, request.Groupname)
	if err := wc.sessionManager.AddBreakglassSession(ctx, bs); err != nil {
		wc.log.Error("error while adding breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	bs, err = wc.getActiveBreakglassSession(ctx, request.Username, request.Clustername, request.Groupname)
	if err != nil && !errors.Is(err, ErrSessionNotFound) {
		wc.log.Error("error while getting breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	bs.Status = v1alpha1.BreakglassSessionStatus{
		RetainedUntil: metav1.NewTime(time.Now().Add(MonthDuration)),
		Conditions: []metav1.Condition{{
			Type:               string(v1alpha1.SessionConditionTypeIdle),
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
			Message:            fmt.Sprintf("User %q requested session.", username),
		}},
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

func (wc BreakglassSessionController) setSessionStatus(c *gin.Context, sesCondition v1alpha1.BreakglassSessionConditionType) {
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

	var lastCondition metav1.Condition
	if l := len(bs.Status.Conditions); l > 0 {
		lastCondition = bs.Status.Conditions[l-1]
	}

	if lastCondition.Type == string(sesCondition) {
		c.JSON(http.StatusOK, bs)
	}

	switch sesCondition {
	case v1alpha1.SessionConditionTypeApproved:
		bs.Status.ApprovedAt = metav1.Now()
		bs.Status.ExpiresAt = metav1.NewTime(bs.Status.ApprovedAt.Add(time.Hour))
	case v1alpha1.SessionConditionTypeRejected:
		bs.Status.ApprovedAt = metav1.Time{}
		bs.Status.ExpiresAt = metav1.Time{}
		bs.Status.RejectedAt = metav1.Now()
	case v1alpha1.SessionConditionTypeIdle:
		wc.log.Error("error setting session status to idle which should be only initial state")
		c.Status(http.StatusInternalServerError)
		return
	default:
		wc.log.Error("unknown session condition type", zap.String("type", string(sesCondition)))
		c.Status(http.StatusInternalServerError)
		return
	}

	username, _ := wc.identityProvider.GetEmail(c)
	bs.Status.Conditions = append(bs.Status.Conditions, metav1.Condition{
		Type:               string(sesCondition),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(v1alpha1.SessionConditionReasonEditedByApprover),
		Message:            fmt.Sprintf("User %q set session to %s", username, sesCondition),
	})

	if err := wc.sessionManager.UpdateBreakglassSessionStatus(c.Request.Context(), bs); err != nil {
		wc.log.Error("error while updating breakglass session", zap.Error(err))
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, bs)
}

func (wc BreakglassSessionController) getActiveBreakglassSession(ctx context.Context,
	username,
	clustername,
	group string,
) (v1alpha1.BreakglassSession, error) {
	selector := fields.SelectorFromSet(
		fields.Set{
			"spec.cluster":      clustername,
			"spec.user":         username,
			"spec.grantedGroup": group,
		},
	)
	sessions, err := wc.sessionManager.GetBreakglassSessionsWithSelector(ctx, selector)
	if err != nil {
		return v1alpha1.BreakglassSession{}, errors.Wrap(err, "failed to list sessions")
	}

	validSessions := make([]v1alpha1.BreakglassSession, 0, len(sessions))
	for _, ses := range sessions {
		if !IsSessionActive(ses) {
			continue
		}

		validSessions = append(validSessions, ses)
	}

	if len(validSessions) == 0 {
		return v1alpha1.BreakglassSession{}, ErrSessionNotFound
	} else if len(validSessions) > 1 {
		wc.log.Error("there is more than single active breakglass session it should not happen",
			zap.Int("num_sessions", len(validSessions)),
			zap.String("user_data", fmt.Sprintf("%#v", ClusterUserGroup{
				Clustername: clustername,
				Username:    username,
				Groupname:   group,
			})))
	}
	return validSessions[0], nil
}

func (wc BreakglassSessionController) handleApproveBreakglassSession(c *gin.Context) {
	wc.setSessionStatus(c, v1alpha1.SessionConditionTypeApproved)
}

func (wc BreakglassSessionController) handleRejectBreakglassSession(c *gin.Context) {
	wc.setSessionStatus(c, v1alpha1.SessionConditionTypeRejected)
}

func (wc BreakglassSessionController) sendOnRequestEmail(bs v1alpha1.BreakglassSession,
	requestEmail,
	requestUsername string,
	approvers []string,
) error {
	subject := fmt.Sprintf("Cluster %q user %q is requesting breakglass group assignment %q", bs.Spec.Cluster, bs.Spec.User, bs.Spec.GrantedGroup)

	body, err := mail.RenderBreakglassSessionRequest(mail.RequestBreakglassSessionMailParams{
		SubjectEmail:      requestEmail,
		SubjectFullName:   requestUsername,
		RequestedCluster:  bs.Spec.Cluster,
		RequestedUsername: bs.Spec.User,
		RequestedGroup:    bs.Spec.GrantedGroup,
		URL:               fmt.Sprintf("%s/review?name=%s", wc.config.Frontend.BaseURL, bs.Name),
	})
	if err != nil {
		wc.log.Errorf("failed to render email template: %v", err)
		return err
	}

	if err := wc.mail.Send(approvers, subject, body); err != nil {
		wc.log.Errorf("failed to send request email: %v", err)
		return err
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

func (wc BreakglassSessionController) isSessionApprover(c *gin.Context, session v1alpha1.BreakglassSession) bool {
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
			Username:    session.Spec.User,
			Clustername: session.Spec.Cluster,
			Groupname:   session.Spec.GrantedGroup,
		})
	if err != nil {
		wc.log.Error("Error getting user escalations", zap.Error(err))
		return false
	}

	sessions, err := EscalationFiltering{
		FilterUserData:   approverID,
		UserGroupExtract: wc.getUserGroupsFn,
	}.FilterSessionsForUserApprovable(
		ctx,
		[]v1alpha1.BreakglassSession{session},
		escalations)
	if err != nil {
		wc.log.Error("Error filtering for approver sessions", zap.Error(err))
		return false
	}

	return len(sessions) == 1
}

func IsSessionRetained(session v1alpha1.BreakglassSession) bool {
	return time.Now().After(session.Status.RetainedUntil.Time)
}

// Session can be expired if it was previously approved
func IsSessionExpired(session v1alpha1.BreakglassSession) bool {
	return !session.Status.ExpiresAt.Time.IsZero() && time.Now().After(session.Status.ExpiresAt.Time)
}

func IsSessionValid(session v1alpha1.BreakglassSession) bool {
	return !IsSessionExpired(session)
	// session.Status.ExpiresAt.Time.IsZero() || time.Now().After(session.Status.ExpiresAt.Time)
}

// IsSessionActive returns if session can be approved or was already approved
func IsSessionActive(session v1alpha1.BreakglassSession) bool {
	return IsSessionValid(session) && session.Status.RejectedAt.IsZero()
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
		getUserGroupsFn:   GetUserGroups,
	}

	return controller
}
