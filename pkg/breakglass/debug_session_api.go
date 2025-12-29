/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package breakglass

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// DebugSessionAPIController provides REST API endpoints for debug sessions
type DebugSessionAPIController struct {
	log        *zap.SugaredLogger
	client     ctrlclient.Client
	ccProvider *cluster.ClientProvider
	middleware gin.HandlerFunc
}

// NewDebugSessionAPIController creates a new debug session API controller
func NewDebugSessionAPIController(log *zap.SugaredLogger, client ctrlclient.Client, ccProvider *cluster.ClientProvider, middleware gin.HandlerFunc) *DebugSessionAPIController {
	return &DebugSessionAPIController{
		log:        log,
		client:     client,
		ccProvider: ccProvider,
		middleware: middleware,
	}
}

// BasePath returns the base path for debug session routes
func (c *DebugSessionAPIController) BasePath() string {
	return "debugSessions"
}

// Handlers returns middleware to apply to all routes
func (c *DebugSessionAPIController) Handlers() []gin.HandlerFunc {
	if c.middleware != nil {
		return []gin.HandlerFunc{c.middleware}
	}
	return nil
}

// Register registers the debug session routes
func (c *DebugSessionAPIController) Register(rg *gin.RouterGroup) error {
	// Session endpoints
	rg.GET("", instrumentedHandler("handleListDebugSessions", c.handleListDebugSessions))
	rg.GET(":name", instrumentedHandler("handleGetDebugSession", c.handleGetDebugSession))
	rg.POST("", instrumentedHandler("handleCreateDebugSession", c.handleCreateDebugSession))
	rg.POST(":name/join", instrumentedHandler("handleJoinDebugSession", c.handleJoinDebugSession))
	rg.POST(":name/leave", instrumentedHandler("handleLeaveDebugSession", c.handleLeaveDebugSession))
	rg.POST(":name/renew", instrumentedHandler("handleRenewDebugSession", c.handleRenewDebugSession))
	rg.POST(":name/terminate", instrumentedHandler("handleTerminateDebugSession", c.handleTerminateDebugSession))
	rg.POST(":name/approve", instrumentedHandler("handleApproveDebugSession", c.handleApproveDebugSession))
	rg.POST(":name/reject", instrumentedHandler("handleRejectDebugSession", c.handleRejectDebugSession))

	// Template endpoints
	rg.GET("templates", instrumentedHandler("handleListTemplates", c.handleListTemplates))
	rg.GET("templates/:name", instrumentedHandler("handleGetTemplate", c.handleGetTemplate))
	rg.GET("podTemplates", instrumentedHandler("handleListPodTemplates", c.handleListPodTemplates))
	rg.GET("podTemplates/:name", instrumentedHandler("handleGetPodTemplate", c.handleGetPodTemplate))
	return nil
}

// CreateDebugSessionRequest represents the request body for creating a debug session
type CreateDebugSessionRequest struct {
	TemplateRef       string            `json:"templateRef" binding:"required"`
	Cluster           string            `json:"cluster" binding:"required"`
	RequestedDuration string            `json:"requestedDuration,omitempty"`
	NodeSelector      map[string]string `json:"nodeSelector,omitempty"`
	Namespace         string            `json:"namespace,omitempty"`
	Reason            string            `json:"reason,omitempty"`
}

// JoinDebugSessionRequest represents the request to join an existing debug session
type JoinDebugSessionRequest struct {
	Role string `json:"role,omitempty"` // "viewer" or "participant"
}

// RenewDebugSessionRequest represents the request to extend session duration
type RenewDebugSessionRequest struct {
	ExtendBy string `json:"extendBy" binding:"required"` // Duration like "1h", "30m"
}

// ApprovalRequest represents the request body for approve/reject actions
type ApprovalRequest struct {
	Reason string `json:"reason,omitempty"`
}

// DebugSessionListResponse represents the response for listing debug sessions
type DebugSessionListResponse struct {
	Sessions []DebugSessionSummary `json:"sessions"`
	Total    int                   `json:"total"`
}

// DebugSessionSummary represents a summarized debug session for list responses
type DebugSessionSummary struct {
	Name         string                     `json:"name"`
	TemplateRef  string                     `json:"templateRef"`
	Cluster      string                     `json:"cluster"`
	RequestedBy  string                     `json:"requestedBy"`
	State        v1alpha1.DebugSessionState `json:"state"`
	StartsAt     *metav1.Time               `json:"startsAt,omitempty"`
	ExpiresAt    *metav1.Time               `json:"expiresAt,omitempty"`
	Participants int                        `json:"participants"`
	AllowedPods  int                        `json:"allowedPods"`
}

// DebugSessionDetailResponse represents the detailed debug session response
type DebugSessionDetailResponse struct {
	v1alpha1.DebugSession
}

// handleListDebugSessions returns a list of debug sessions
func (c *DebugSessionAPIController) handleListDebugSessions(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	// Get query parameters for filtering
	cluster := ctx.Query("cluster")
	state := ctx.Query("state")
	user := ctx.Query("user")
	mine := ctx.Query("mine") == "true"

	// Get current user from context
	currentUser, _ := ctx.Get("username")
	if currentUser == nil {
		currentUser = ""
	}

	sessionList := &v1alpha1.DebugSessionList{}
	listOpts := []ctrlclient.ListOption{}

	// Note: cluster/state/user filters are applied client-side after fetching
	// Field selectors would require additional indexer setup

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.List(apiCtx, sessionList, listOpts...); err != nil {
		reqLog.Errorw("Failed to list debug sessions", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list debug sessions"})
		return
	}

	// Apply filters
	var filtered []v1alpha1.DebugSession
	for _, s := range sessionList.Items {
		// Cluster filter
		if cluster != "" && s.Spec.Cluster != cluster {
			continue
		}
		// State filter
		if state != "" && string(s.Status.State) != state {
			continue
		}
		// User filter
		if user != "" && s.Spec.RequestedBy != user {
			continue
		}
		// Mine filter
		if mine && s.Spec.RequestedBy != currentUser.(string) {
			continue
		}
		filtered = append(filtered, s)
	}

	// Build response summaries
	summaries := make([]DebugSessionSummary, 0, len(filtered))
	for _, s := range filtered {
		summaries = append(summaries, DebugSessionSummary{
			Name:         s.Name,
			TemplateRef:  s.Spec.TemplateRef,
			Cluster:      s.Spec.Cluster,
			RequestedBy:  s.Spec.RequestedBy,
			State:        s.Status.State,
			StartsAt:     s.Status.StartsAt,
			ExpiresAt:    s.Status.ExpiresAt,
			Participants: len(s.Status.Participants),
			AllowedPods:  len(s.Status.AllowedPods),
		})
	}

	ctx.JSON(http.StatusOK, DebugSessionListResponse{
		Sessions: summaries,
		Total:    len(summaries),
	})
}

// handleGetDebugSession returns details for a specific debug session
func (c *DebugSessionAPIController) handleGetDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "session name is required"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	ctx.JSON(http.StatusOK, DebugSessionDetailResponse{DebugSession: *session})
}

// handleCreateDebugSession creates a new debug session
func (c *DebugSessionAPIController) handleCreateDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	var req CreateDebugSessionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate template exists
	template := &v1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: req.TemplateRef}, template); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("template '%s' not found", req.TemplateRef)})
			return
		}
		reqLog.Errorw("Failed to get template", "template", req.TemplateRef, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to validate template"})
		return
	}

	// Validate cluster is allowed by template
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0 {
		allowed := false
		for _, pattern := range template.Spec.Allowed.Clusters {
			if matchPattern(pattern, req.Cluster) {
				allowed = true
				break
			}
		}
		if !allowed {
			ctx.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("cluster '%s' is not allowed by template", req.Cluster)})
			return
		}
	}

	// Get current user from context
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Generate session name
	sessionName := fmt.Sprintf("debug-%s-%s-%d", toRFC1123Subdomain(currentUser.(string)), toRFC1123Subdomain(req.Cluster), time.Now().Unix())

	// Create the debug session
	session := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: sessionName,
			Labels: map[string]string{
				DebugSessionLabelKey:  sessionName,
				DebugTemplateLabelKey: req.TemplateRef,
				DebugClusterLabelKey:  req.Cluster,
			},
		},
		Spec: v1alpha1.DebugSessionSpec{
			TemplateRef:       req.TemplateRef,
			Cluster:           req.Cluster,
			RequestedBy:       currentUser.(string),
			RequestedDuration: req.RequestedDuration,
			NodeSelector:      req.NodeSelector,
			Reason:            req.Reason,
		},
	}

	if err := c.client.Create(apiCtx, session); err != nil {
		if apierrors.IsAlreadyExists(err) {
			ctx.JSON(http.StatusConflict, gin.H{"error": "session already exists"})
			return
		}
		reqLog.Errorw("Failed to create debug session", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create debug session"})
		return
	}

	reqLog.Infow("Debug session created",
		"name", sessionName,
		"cluster", req.Cluster,
		"template", req.TemplateRef,
		"user", currentUser)

	metrics.DebugSessionsCreated.WithLabelValues(req.Cluster, req.TemplateRef).Inc()

	ctx.JSON(http.StatusCreated, DebugSessionDetailResponse{DebugSession: *session})
}

// handleJoinDebugSession allows a user to join an existing debug session
func (c *DebugSessionAPIController) handleJoinDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	var req JoinDebugSessionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		// Default to viewer role if not specified
		req.Role = string(v1alpha1.ParticipantRoleViewer)
	}
	if req.Role == "" {
		req.Role = string(v1alpha1.ParticipantRoleViewer)
	}

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	// Check session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("cannot join session in state '%s'", session.Status.State)})
		return
	}

	// Check if user already joined
	username := currentUser.(string)
	for _, p := range session.Status.Participants {
		if p.User == username {
			ctx.JSON(http.StatusConflict, gin.H{"error": "user already joined this session"})
			return
		}
	}

	// Check max participants if configured
	if session.Status.ResolvedTemplate != nil &&
		session.Status.ResolvedTemplate.TerminalSharing != nil &&
		session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants > 0 {
		if int32(len(session.Status.Participants)) >= session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "maximum participants reached"})
			return
		}
	}

	// Determine role
	role := v1alpha1.ParticipantRoleViewer
	if req.Role == string(v1alpha1.ParticipantRoleParticipant) {
		role = v1alpha1.ParticipantRoleParticipant
	}

	// Add participant
	now := metav1.Now()
	session.Status.Participants = append(session.Status.Participants, v1alpha1.DebugSessionParticipant{
		User:     username,
		Role:     role,
		JoinedAt: now,
	})

	if err := c.client.Status().Update(apiCtx, session); err != nil {
		reqLog.Errorw("Failed to add participant", "session", name, "user", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to join session"})
		return
	}

	reqLog.Infow("User joined debug session", "session", name, "user", username, "role", role)
	metrics.DebugSessionParticipants.WithLabelValues(session.Spec.Cluster, name).Set(float64(len(session.Status.Participants)))

	ctx.JSON(http.StatusOK, gin.H{"message": "successfully joined session", "role": role})
}

// handleRenewDebugSession extends the session duration
func (c *DebugSessionAPIController) handleRenewDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	var req RenewDebugSessionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Parse extension duration
	extendBy, err := time.ParseDuration(req.ExtendBy)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid duration format"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	// Check session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("cannot renew session in state '%s'", session.Status.State)})
		return
	}

	// Check renewal constraints
	if session.Status.ResolvedTemplate != nil && session.Status.ResolvedTemplate.Constraints != nil {
		constraints := session.Status.ResolvedTemplate.Constraints

		// Check if renewals are allowed
		if !constraints.AllowRenewal {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "session renewals are not allowed by template"})
			return
		}

		// Check max renewals
		if constraints.MaxRenewals > 0 && session.Status.RenewalCount >= constraints.MaxRenewals {
			ctx.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("maximum renewals (%d) reached", constraints.MaxRenewals)})
			return
		}

		// Check total duration would not exceed max
		if constraints.MaxDuration != "" {
			maxDur, err := time.ParseDuration(constraints.MaxDuration)
			if err == nil && session.Status.StartsAt != nil {
				currentDuration := time.Since(session.Status.StartsAt.Time)
				if currentDuration+extendBy > maxDur {
					ctx.JSON(http.StatusForbidden, gin.H{
						"error": fmt.Sprintf("extension would exceed maximum duration of %s", constraints.MaxDuration),
					})
					return
				}
			}
		}
	}

	// Extend the expiration
	if session.Status.ExpiresAt == nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "session has no expiration time"})
		return
	}

	newExpiry := metav1.NewTime(session.Status.ExpiresAt.Add(extendBy))
	session.Status.ExpiresAt = &newExpiry
	session.Status.RenewalCount++

	if err := c.client.Status().Update(apiCtx, session); err != nil {
		reqLog.Errorw("Failed to renew session", "session", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to renew session"})
		return
	}

	reqLog.Infow("Debug session renewed",
		"session", name,
		"extendBy", extendBy,
		"newExpiry", newExpiry.Time,
		"renewalCount", session.Status.RenewalCount)

	ctx.JSON(http.StatusOK, gin.H{
		"message":      "session renewed successfully",
		"newExpiresAt": newExpiry.Time,
		"renewalCount": session.Status.RenewalCount,
	})
}

// handleTerminateDebugSession terminates a debug session early
func (c *DebugSessionAPIController) handleTerminateDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	// Check if user is allowed to terminate (owner or admin)
	// For now, only the owner can terminate
	if session.Spec.RequestedBy != currentUser.(string) {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "only the session owner can terminate"})
		return
	}

	// Check session can be terminated
	if session.Status.State == v1alpha1.DebugSessionStateTerminated ||
		session.Status.State == v1alpha1.DebugSessionStateExpired ||
		session.Status.State == v1alpha1.DebugSessionStateFailed {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("session is already in terminal state '%s'", session.Status.State)})
		return
	}

	// Mark as terminated
	session.Status.State = v1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Terminated by %s", currentUser)

	if err := c.client.Status().Update(apiCtx, session); err != nil {
		reqLog.Errorw("Failed to terminate session", "session", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to terminate session"})
		return
	}

	reqLog.Infow("Debug session terminated", "session", name, "user", currentUser)
	metrics.DebugSessionsTerminated.WithLabelValues(session.Spec.Cluster, "user_terminated").Inc()

	ctx.JSON(http.StatusOK, gin.H{"message": "session terminated successfully"})
}

// handleApproveDebugSession approves a pending debug session
func (c *DebugSessionAPIController) handleApproveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	var req ApprovalRequest
	_ = ctx.ShouldBindJSON(&req) // Optional body

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	// Check session is pending approval
	if session.Status.State != v1alpha1.DebugSessionStatePendingApproval {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("session is not pending approval (state: %s)", session.Status.State)})
		return
	}

	// Check if user is authorized to approve (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	if !c.isUserAuthorizedToApprove(apiCtx, session, currentUser.(string), userGroups) {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "user is not authorized to approve this session"})
		return
	}

	// Mark as approved
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &v1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.ApprovedBy = currentUser.(string)
	session.Status.Approval.ApprovedAt = &now
	session.Status.Approval.Reason = req.Reason

	if err := c.client.Status().Update(apiCtx, session); err != nil {
		reqLog.Errorw("Failed to approve session", "session", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve session"})
		return
	}

	reqLog.Infow("Debug session approved", "session", name, "approver", currentUser)
	metrics.DebugSessionApproved.WithLabelValues(session.Spec.Cluster, "user").Inc()

	ctx.JSON(http.StatusOK, gin.H{"message": "session approved successfully"})
}

// handleRejectDebugSession rejects a pending debug session
func (c *DebugSessionAPIController) handleRejectDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	var req ApprovalRequest
	_ = ctx.ShouldBindJSON(&req) // Optional body with reason

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	// Check session is pending approval
	if session.Status.State != v1alpha1.DebugSessionStatePendingApproval {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("session is not pending approval (state: %s)", session.Status.State)})
		return
	}

	// Check if user is authorized to reject (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	if !c.isUserAuthorizedToApprove(apiCtx, session, currentUser.(string), userGroups) {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "user is not authorized to reject this session"})
		return
	}

	// Mark as rejected
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &v1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.RejectedBy = currentUser.(string)
	session.Status.Approval.RejectedAt = &now
	session.Status.Approval.Reason = req.Reason

	// Move to terminated state
	session.Status.State = v1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Rejected by %s: %s", currentUser, req.Reason)

	if err := c.client.Status().Update(apiCtx, session); err != nil {
		reqLog.Errorw("Failed to reject session", "session", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reject session"})
		return
	}

	reqLog.Infow("Debug session rejected", "session", name, "rejector", currentUser, "reason", req.Reason)
	metrics.DebugSessionRejected.WithLabelValues(session.Spec.Cluster, "user_rejected").Inc()

	ctx.JSON(http.StatusOK, gin.H{"message": "session rejected successfully"})
}

// handleLeaveDebugSession allows a participant to leave a session
func (c *DebugSessionAPIController) handleLeaveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	session := &v1alpha1.DebugSession{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, session); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get debug session"})
		return
	}

	// Find the participant
	username := currentUser.(string)
	found := false
	now := metav1.Now()
	for i := range session.Status.Participants {
		if session.Status.Participants[i].User == username {
			// Check if owner - owners cannot leave
			if session.Status.Participants[i].Role == v1alpha1.ParticipantRoleOwner {
				ctx.JSON(http.StatusForbidden, gin.H{"error": "session owner cannot leave; use terminate instead"})
				return
			}
			// Mark as left
			session.Status.Participants[i].LeftAt = &now
			found = true
			break
		}
	}

	if !found {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "user is not a participant in this session"})
		return
	}

	if err := c.client.Status().Update(apiCtx, session); err != nil {
		reqLog.Errorw("Failed to leave session", "session", name, "user", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to leave session"})
		return
	}

	reqLog.Infow("User left debug session", "session", name, "user", username)
	// Update active participant count (exclude those who left)
	activeCount := 0
	for _, p := range session.Status.Participants {
		if p.LeftAt == nil {
			activeCount++
		}
	}
	metrics.DebugSessionParticipants.WithLabelValues(session.Spec.Cluster, name).Set(float64(activeCount))

	ctx.JSON(http.StatusOK, gin.H{"message": "successfully left session"})
}

// DebugSessionTemplateResponse represents a template in API responses
type DebugSessionTemplateResponse struct {
	Name             string                            `json:"name"`
	DisplayName      string                            `json:"displayName"`
	Description      string                            `json:"description,omitempty"`
	Mode             v1alpha1.DebugSessionTemplateMode `json:"mode"`
	WorkloadType     v1alpha1.DebugWorkloadType        `json:"workloadType,omitempty"`
	PodTemplateRef   string                            `json:"podTemplateRef,omitempty"`
	TargetNamespace  string                            `json:"targetNamespace,omitempty"`
	Constraints      *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	AllowedClusters  []string                          `json:"allowedClusters,omitempty"`
	AllowedGroups    []string                          `json:"allowedGroups,omitempty"`
	RequiresApproval bool                              `json:"requiresApproval"`
}

// DebugPodTemplateResponse represents a pod template in API responses
type DebugPodTemplateResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Containers  int    `json:"containers"`
}

// handleListTemplates returns available debug session templates
func (c *DebugSessionAPIController) handleListTemplates(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	templateList := &v1alpha1.DebugSessionTemplateList{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.List(apiCtx, templateList); err != nil {
		reqLog.Errorw("Failed to list debug session templates", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list templates"})
		return
	}

	// Get user's groups for filtering
	userGroups, _ := ctx.Get("groups")
	groups := []string{}
	if userGroups != nil {
		if g, ok := userGroups.([]string); ok {
			groups = g
		}
	}

	// Filter and transform
	var templates []DebugSessionTemplateResponse
	for _, t := range templateList.Items {
		// Check if user has access to this template
		if t.Spec.Allowed != nil && len(t.Spec.Allowed.Groups) > 0 {
			hasAccess := false
			for _, allowedGroup := range t.Spec.Allowed.Groups {
				if allowedGroup == "*" {
					hasAccess = true
					break
				}
				for _, userGroup := range groups {
					if matchPattern(allowedGroup, userGroup) {
						hasAccess = true
						break
					}
				}
				if hasAccess {
					break
				}
			}
			if !hasAccess {
				continue
			}
		}

		resp := DebugSessionTemplateResponse{
			Name:             t.Name,
			DisplayName:      t.Spec.DisplayName,
			Description:      t.Spec.Description,
			Mode:             t.Spec.Mode,
			WorkloadType:     t.Spec.WorkloadType,
			TargetNamespace:  t.Spec.TargetNamespace,
			Constraints:      t.Spec.Constraints,
			RequiresApproval: t.Spec.Approvers != nil && len(t.Spec.Approvers.Groups) > 0,
		}

		if t.Spec.PodTemplateRef != nil {
			resp.PodTemplateRef = t.Spec.PodTemplateRef.Name
		}
		if t.Spec.Allowed != nil {
			resp.AllowedClusters = t.Spec.Allowed.Clusters
			resp.AllowedGroups = t.Spec.Allowed.Groups
		}

		templates = append(templates, resp)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

// handleGetTemplate returns details for a specific template
func (c *DebugSessionAPIController) handleGetTemplate(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "template name is required"})
		return
	}

	template := &v1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		reqLog.Errorw("Failed to get template", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get template"})
		return
	}

	ctx.JSON(http.StatusOK, template)
}

// handleListPodTemplates returns available debug pod templates
func (c *DebugSessionAPIController) handleListPodTemplates(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	templateList := &v1alpha1.DebugPodTemplateList{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.List(apiCtx, templateList); err != nil {
		reqLog.Errorw("Failed to list debug pod templates", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list pod templates"})
		return
	}

	var templates []DebugPodTemplateResponse
	for _, t := range templateList.Items {
		templates = append(templates, DebugPodTemplateResponse{
			Name:        t.Name,
			DisplayName: t.Spec.DisplayName,
			Description: t.Spec.Description,
			Containers:  len(t.Spec.Template.Spec.Containers),
		})
	}

	ctx.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

// handleGetPodTemplate returns details for a specific pod template
func (c *DebugSessionAPIController) handleGetPodTemplate(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "template name is required"})
		return
	}

	template := &v1alpha1.DebugPodTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "pod template not found"})
			return
		}
		reqLog.Errorw("Failed to get pod template", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get pod template"})
		return
	}

	ctx.JSON(http.StatusOK, template)
}

// isUserAuthorizedToApprove checks if the user is authorized to approve/reject a debug session
// The user must be in one of the approver groups/users defined in the session's template
func (c *DebugSessionAPIController) isUserAuthorizedToApprove(ctx context.Context, session *v1alpha1.DebugSession, username string, userGroupsInterface interface{}) bool {
	// If template has no resolved approvers info in status, fall back to fetching template
	if session.Status.ResolvedTemplate == nil || session.Status.ResolvedTemplate.Approvers == nil {
		// Fetch the template to check approvers
		template := &v1alpha1.DebugSessionTemplate{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.TemplateRef}, template); err != nil {
			// If we can't fetch template, allow approval (fail open for usability)
			c.log.Warnw("Could not fetch template to check approvers, allowing approval",
				"session", session.Name, "template", session.Spec.TemplateRef, "error", err)
			return true
		}

		// If template has no approvers configured, allow any authenticated user
		if template.Spec.Approvers == nil {
			return true
		}

		return c.checkApproverAuthorization(template.Spec.Approvers, username, userGroupsInterface)
	}

	// Use resolved template from status
	return c.checkApproverAuthorization(session.Status.ResolvedTemplate.Approvers, username, userGroupsInterface)
}

// checkApproverAuthorization checks if user is in the approved users/groups
func (c *DebugSessionAPIController) checkApproverAuthorization(approvers *v1alpha1.DebugSessionApprovers, username string, userGroupsInterface interface{}) bool {
	// Check if user is in allowed users list
	for _, allowedUser := range approvers.Users {
		if matchPattern(allowedUser, username) {
			return true
		}
	}

	// Check if user is in any of the allowed groups
	if userGroupsInterface != nil {
		var userGroups []string
		switch g := userGroupsInterface.(type) {
		case []string:
			userGroups = g
		case []interface{}:
			for _, v := range g {
				if s, ok := v.(string); ok {
					userGroups = append(userGroups, s)
				}
			}
		}

		for _, userGroup := range userGroups {
			for _, allowedGroup := range approvers.Groups {
				if matchPattern(allowedGroup, userGroup) {
					return true
				}
			}
		}
	}

	// If no approvers defined at all, allow any authenticated user
	if len(approvers.Users) == 0 && len(approvers.Groups) == 0 {
		return true
	}

	return false
}

// matchPattern checks if a string matches a glob pattern (simplified)
func matchPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix)
	}
	return pattern == value
}
