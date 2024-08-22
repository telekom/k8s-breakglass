package breakglass

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/mail"
	"golang.org/x/exp/maps"
)

func internalServerError(c *gin.Context, err error) {
	sendError(c, http.StatusInternalServerError, err)
}

func sendError(c *gin.Context, code int, err error) {
	c.JSON(code, gin.H{
		"error": err.Error(),
	})
}

func (b *BreakglassController) Register(rg *gin.RouterGroup) error {

	rg.GET("/", b.getActiveBreakglass)
	rg.GET("/available", b.getAvailableBreakglasses)
	rg.POST("/request", b.requestBreakglass)
	rg.GET("/request", b.validateBreaglassRequest)
	rg.POST("/approve", b.approveBreakglassRequest)
	rg.DELETE("/drop", b.dropBreakglass)
	rg.POST("/test", b.givePermission)

	return nil
}

func (b *BreakglassController) getActiveBreakglass(c *gin.Context) {
	// Get active Breakglass
	states, err := b.keycloak.GetActiveBreakglass(c, c.GetString("user_id"))
	if err != nil {
		internalServerError(c, err)
		return
	}
	c.JSON(http.StatusOK, states)
}

func (b *BreakglassController) getAvailableBreakglasses(c *gin.Context) {
	// Get possible transitions of a user (is in from group of a transition)
	userTransitions, err := b.getUserTransitions(c, c.GetString("user_id"))
	if err != nil {
		internalServerError(c, err)
		return
	}
	c.JSON(http.StatusOK, userTransitions)
}

func getApprovers(ctx context.Context, keycloak *KeycloakConnector, approvalGroups []string) ([]string, error) {
	approvers := map[string]struct{}{} // set of receiver emails
	for _, gn := range approvalGroups {
		g, err := keycloak.getGroupByName(ctx, gn)
		if err != nil {
			return []string{}, fmt.Errorf("failed to fetch group: %v", err)
		}
		users, err := keycloak.GetGroupMembers(ctx, *g)
		if err != nil {
			return []string{}, fmt.Errorf("failed to fetch group members: %v", err)
		}
		for _, u := range users {
			if u.Email != nil {
				approvers[*u.Email] = struct{}{}
			}
		}
	}
	return maps.Keys(approvers), nil

}

func fullNameFromUser(user gocloak.User) string {
	name := ""
	if user.FirstName != nil {
		name = *user.FirstName
	}
	if user.LastName != nil {
		if name != "" {
			name += " "
		}
		name += *user.LastName
	}
	return name
}

func (b *BreakglassController) requestBreakglass(c *gin.Context) {
	var request BreakglassRequestRequest
	err := c.BindJSON(&request)
	if err != nil {
		return
	}

	isAllowed := false
	// Get possible transitions of user
	userTransitions, err := b.getUserTransitions(c, c.GetString("user_id"))
	if err != nil {
		internalServerError(c, err)
		return
	}

	// Requested transition must be part of possible transitions
	for _, transition := range userTransitions {
		if transition.Equal(request.Transition) {
			isAllowed = true
			break
		}
	}
	// If transition is not allowed, return error
	if !isAllowed {
		sendError(c, http.StatusUnauthorized, fmt.Errorf("not allowed to request this breakglass access"))
		return
	}

	user, err := b.keycloak.GetUser(c, c.GetString("user_id"))
	if err != nil {
		internalServerError(c, err)
	}

	now := time.Now()
	requestor := Requestor{
		Name: fullNameFromUser(*user),
	}
	if user.Email != nil {
		requestor.Email = *user.Email
	}

	// Create a signed JWT and return with request in claims and a lifetime specified in config
	claims := BreakglassJWTClaims{
		Transition: request.Transition,
		Requestor:  requestor,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: now.Add(time.Duration(b.config.BreakglassJWT.Expiry) * time.Second).Unix(),
			IssuedAt:  now.Unix(),
			NotBefore: now.Unix(),
			Issuer:    b.config.BreakglassJWT.Issuer,
			Subject:   c.GetString("user_id"),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(b.jwtPrivateKey)
	if err != nil {
		internalServerError(c, fmt.Errorf("unable to generate token: %v", err))
		return
	}

	approverList, err := getApprovers(c, b.keycloak, claims.Transition.ApprovalGroups)
	if err != nil {
		b.log.Error(err)
	}

	if len(approverList) == 0 {
		sendError(c, http.StatusBadRequest, errors.New("no approver found"))
	}

	u, err := url.Parse(b.config.Server.BaseURL)
	if err != nil {
		internalServerError(c, err)
		return
	}
	u.Path += "/approve"
	u.RawQuery = url.Values{"token": []string{token}}.Encode()

	body, err := mail.RenderRequest(mail.RequestMailParams{
		SubjectFullName: requestor.Name,
		SubjectEmail:    requestor.Email,
		RequestedRole:   request.Transition.To,
		URL:             u.String(),
	})
	if err != nil {
		b.log.Errorf("failed to render email template: %v", err)
		internalServerError(c, fmt.Errorf("failed to request breakglass."))
	}

	subject := fmt.Sprintf("%s is requesting %s", requestor.Name, request.Transition.To)
	err = b.mail.Send(approverList, subject, body)
	if err != nil {
		b.log.Errorf("failed to send email: %v", err)
		internalServerError(c, fmt.Errorf("failed to request breakglass."))
	}
	// Log request message to smops
	b.log.Infof("Breakglass request sent: %s is requesting %s", *user.Username, request.Transition.To)
	// Return signed JWT
	c.JSON(http.StatusOK, BreakglassApprovalRequest{
		Token: token,
	})
}

func (b *BreakglassController) approveBreakglassRequest(c *gin.Context) {
	approvingUserID := c.GetString("user_id")

	// POST Body is JSON approval request (token => signed JWT)
	var approvalRequest BreakglassApprovalRequest
	err := c.BindJSON(&approvalRequest)
	if err != nil {
		return
	}

	// Parse and validate JWT signature
	claim, err := parseRequestToken(approvalRequest.Token, b.jwtPublicKey)
	if err != nil {
		internalServerError(c, err)
		return
	}

	approver, err := b.keycloak.GetUser(c, approvingUserID)
	if err != nil {
		internalServerError(c, err)
		return
	}

	approvingUserGroups, err := b.keycloak.GetUserGroups(c, approvingUserID)
	if err != nil {
		internalServerError(c, err)
		return
	}

	// If not allowed approver, return error
	if !isAllowedToApprove(approvingUserID, approvingUserGroups, claim) {
		sendError(c, http.StatusForbidden, fmt.Errorf("not allowed to approve this request"))
		return
	}

	if !b.isBreakglassTargetGroup(claim.Transition.To) {
		sendError(c, http.StatusBadRequest, fmt.Errorf("transition target is not a valid breakglass group"))
		return
	}

	// Persist Breaglass to Keycloak
	err = b.keycloak.PersistBreakglass(c, claim.Subject, claim.Transition.To, claim.Transition.Duration)
	if err != nil {
		internalServerError(c, err)
		return
	}

	receivers, err := getApprovers(c, b.keycloak, claim.Transition.ApprovalGroups)
	if err != nil {
		b.log.Error(err)
	}
	receivers = append(receivers, *&claim.Requestor.Email)

	body, err := mail.RenderApproved(mail.ApprovedMailParams{
		SubjectFullName:  claim.Requestor.Name,
		SubjectEmail:     claim.Requestor.Email,
		RequestedRole:    claim.Transition.To,
		ApproverFullName: fullNameFromUser(*approver),
		ApproverEmail:    *approver.Email,
	})
	if err != nil {
		b.log.Errorf("error rendering email template: %v", err)
	}
	if len(body) > 0 {
		if err := b.mail.Send(receivers, "Breakglass Request approved", body); err != nil {
			b.log.Errorf("failed to send email: %v", err)
		}
	}
	// Log success message to smops
	requester, err := b.keycloak.GetUser(c, claim.Subject)
	if err != nil {
		internalServerError(c, err)
		return
	}
	b.log.Infof("Breakglass request approved: Adding user %s to group %s", *requester.Username, claim.Transition.To)

	// Return success message
	c.JSON(http.StatusOK, gin.H{
		"success": fmt.Sprintf("Adding user %s to group %s", claim.Subject, claim.Transition.To),
	})
}

type validateBreakglassResponse struct {
	CanApprove    bool `json:"canApprove"`
	AlreadyActive bool `json:"alreadyActive"`
}

func (b *BreakglassController) validateBreaglassRequest(c *gin.Context) {
	apprUserID := c.GetString("user_id")
	token := c.Query("token")

	result := validateBreakglassResponse{}

	// Parse and validate JWT signature
	claim, err := parseRequestToken(token, b.jwtPublicKey)
	if err != nil {
		internalServerError(c, err)
		return
	}

	reqUserGroups, err := b.keycloak.GetUserGroups(c, claim.Subject)
	if err != nil {
		b.log.Error("failed to fetch requestiong user's groups", err)
		internalServerError(c, fmt.Errorf("failed to validate breakglass request"))
	}

	// if the group is already active there is no need to approve.
	if findGroup(reqUserGroups, claim.Transition.To) != nil {
		result.AlreadyActive = true
		c.JSON(http.StatusOK, result)
		return
	}

	apprUserGroups, err := b.keycloak.GetUserGroups(c, apprUserID)
	if err != nil {
		internalServerError(c, err)
		return
	}

	// If not allowed approver, return error
	result.CanApprove = isAllowedToApprove(apprUserID, apprUserGroups, claim)

	// Return success message
	c.JSON(http.StatusOK, result)
}

func (b *BreakglassController) dropBreakglass(c *gin.Context) {
	groupName := c.Query("group")
	userId := c.GetString("user_id")

	err := b.keycloak.DropBreakglass(c, userId, groupName)
	if err != nil {
		internalServerError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": fmt.Sprintf("Successfully dropped group %s", groupName),
	})
}

func (b *BreakglassController) givePermission(c *gin.Context) {
	var req PermissionRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Println("Error binding JSON:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userName := req.UserName
	clusterName := req.ClusterName
	fmt.Printf("Received user_name: %s, cluster_name: %s\n", userName, clusterName)

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s registered with cluster %s", req.UserName, req.ClusterName)})

	// TODO add user and a cluster name to a data structure
}
