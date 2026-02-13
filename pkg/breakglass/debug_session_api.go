/*
Copyright 2026.

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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/naming"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// DebugSessionAPIController provides REST API endpoints for debug sessions
type DebugSessionAPIController struct {
	log          *zap.SugaredLogger
	client       ctrlclient.Client
	apiReader    ctrlclient.Reader // Uncached reader for consistent reads
	ccProvider   *cluster.ClientProvider
	middleware   gin.HandlerFunc
	mailService  MailEnqueuer
	auditService AuditEmitter
	disableEmail bool
	brandingName string
	baseURL      string
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

// WithMailService sets the mail service for sending email notifications
func (c *DebugSessionAPIController) WithMailService(mailService MailEnqueuer, brandingName, baseURL string) *DebugSessionAPIController {
	c.mailService = mailService
	c.brandingName = brandingName
	c.baseURL = baseURL
	return c
}

// WithAuditService sets the audit service for emitting audit events
func (c *DebugSessionAPIController) WithAuditService(auditService AuditEmitter) *DebugSessionAPIController {
	c.auditService = auditService
	return c
}

// WithDisableEmail disables email notifications
func (c *DebugSessionAPIController) WithDisableEmail(disable bool) *DebugSessionAPIController {
	c.disableEmail = disable
	return c
}

// WithAPIReader sets an uncached reader for consistent reads after writes.
// If not set, the controller falls back to the cached client for reads.
func (c *DebugSessionAPIController) WithAPIReader(reader ctrlclient.Reader) *DebugSessionAPIController {
	c.apiReader = reader
	return c
}

// reader returns the appropriate reader - apiReader if set, otherwise the cached client.
func (c *DebugSessionAPIController) reader() ctrlclient.Reader {
	if c.apiReader != nil {
		return c.apiReader
	}
	return c.client
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

	// Kubectl-debug mode endpoints
	rg.POST(":name/injectEphemeralContainer", instrumentedHandler("handleInjectEphemeralContainer", c.handleInjectEphemeralContainer))
	rg.POST(":name/createPodCopy", instrumentedHandler("handleCreatePodCopy", c.handleCreatePodCopy))
	rg.POST(":name/createNodeDebugPod", instrumentedHandler("handleCreateNodeDebugPod", c.handleCreateNodeDebugPod))

	// Template endpoints
	rg.GET("templates", instrumentedHandler("handleListTemplates", c.handleListTemplates))
	rg.GET("templates/:name", instrumentedHandler("handleGetTemplate", c.handleGetTemplate))
	rg.GET("templates/:name/clusters", instrumentedHandler("handleGetTemplateClusters", c.handleGetTemplateClusters))
	rg.GET("podTemplates", instrumentedHandler("handleListPodTemplates", c.handleListPodTemplates))
	rg.GET("podTemplates/:name", instrumentedHandler("handleGetPodTemplate", c.handleGetPodTemplate))
	return nil
}

// getDebugSessionByName finds a debug session by name across all namespaces
// or optionally in a specific namespace if provided via query param.
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) getDebugSessionByName(ctx context.Context, name, namespaceHint string) (*v1alpha1.DebugSession, error) {
	reader := c.reader()
	// If namespace hint provided, try that first
	if namespaceHint != "" {
		session := &v1alpha1.DebugSession{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: name, Namespace: namespaceHint}, session); err == nil {
			return session, nil
		}
	}

	// Search across all namespaces using label selector
	sessionList := &v1alpha1.DebugSessionList{}
	if err := reader.List(ctx, sessionList, ctrlclient.MatchingLabels{DebugSessionLabelKey: name}); err != nil {
		return nil, err
	}

	if len(sessionList.Items) == 0 {
		// Fallback: try default namespace
		session := &v1alpha1.DebugSession{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: name, Namespace: "default"}, session); err != nil {
			return nil, apierrors.NewNotFound(schema.GroupResource{Group: "breakglass.t-caas.telekom.com", Resource: "debugsessions"}, name)
		}
		return session, nil
	}

	return &sessionList.Items[0], nil
}

// CreateDebugSessionRequest represents the request body for creating a debug session
type CreateDebugSessionRequest struct {
	TemplateRef              string                          `json:"templateRef" binding:"required"`
	Cluster                  string                          `json:"cluster" binding:"required"`
	BindingRef               string                          `json:"bindingRef,omitempty"` // Optional: explicit binding selection as "namespace/name" (when multiple match)
	RequestedDuration        string                          `json:"requestedDuration,omitempty"`
	NodeSelector             map[string]string               `json:"nodeSelector,omitempty"`
	Namespace                string                          `json:"namespace,omitempty"`
	Reason                   string                          `json:"reason,omitempty"`
	InvitedParticipants      []string                        `json:"invitedParticipants,omitempty"`
	TargetNamespace          string                          `json:"targetNamespace,omitempty"`          // User-selected namespace (if allowed by template)
	SelectedSchedulingOption string                          `json:"selectedSchedulingOption,omitempty"` // User-selected scheduling option
	ExtraDeployValues        map[string]apiextensionsv1.JSON `json:"extraDeployValues,omitempty"`        // User-provided values for template variables
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

// InjectEphemeralContainerRequest represents the request to inject an ephemeral container
type InjectEphemeralContainerRequest struct {
	Namespace       string                  `json:"namespace" binding:"required"`
	PodName         string                  `json:"podName" binding:"required"`
	ContainerName   string                  `json:"containerName" binding:"required"`
	Image           string                  `json:"image" binding:"required"`
	Command         []string                `json:"command,omitempty"`
	SecurityContext *corev1.SecurityContext `json:"securityContext,omitempty"`
}

// CreatePodCopyRequest represents the request to create a debug copy of a pod
type CreatePodCopyRequest struct {
	Namespace  string `json:"namespace" binding:"required"`
	PodName    string `json:"podName" binding:"required"`
	DebugImage string `json:"debugImage,omitempty"` // Optional debug container image
}

// CreateNodeDebugPodRequest represents the request to create a node debug pod
type CreateNodeDebugPodRequest struct {
	NodeName string `json:"nodeName" binding:"required"`
}

// DebugSessionListResponse represents the response for listing debug sessions
type DebugSessionListResponse struct {
	Sessions []DebugSessionSummary `json:"sessions"`
	Total    int                   `json:"total"`
}

// DebugSessionSummary represents a summarized debug session for list responses
type DebugSessionSummary struct {
	Name                   string                         `json:"name"`
	TemplateRef            string                         `json:"templateRef"`
	Cluster                string                         `json:"cluster"`
	RequestedBy            string                         `json:"requestedBy"`
	RequestedByDisplayName string                         `json:"requestedByDisplayName,omitempty"`
	State                  v1alpha1.DebugSessionState     `json:"state"`
	StatusMessage          string                         `json:"statusMessage,omitempty"`
	StartsAt               *metav1.Time                   `json:"startsAt,omitempty"`
	ExpiresAt              *metav1.Time                   `json:"expiresAt,omitempty"`
	Participants           int                            `json:"participants"`
	IsParticipant          bool                           `json:"isParticipant"`
	AllowedPods            int                            `json:"allowedPods"`
	AllowedPodOperations   *v1alpha1.AllowedPodOperations `json:"allowedPodOperations,omitempty"`
}

// DebugSessionDetailResponse represents the detailed debug session response
type DebugSessionDetailResponse struct {
	v1alpha1.DebugSession
	// Warnings contains non-critical issues or notes about defaults that were applied
	Warnings []string `json:"warnings,omitempty"`
}

// handleListDebugSessions returns a list of debug sessions
func (c *DebugSessionAPIController) handleListDebugSessions(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	// Get query parameters for filtering
	cluster := ctx.Query("cluster")
	state := ctx.Query("state")
	user := ctx.Query("user")
	mine := ctx.Query("mine") == "true"

	// Get current user from context with safe type assertion
	currentUserStr := ""
	if currentUser, exists := ctx.Get("username"); exists && currentUser != nil {
		if userStr, ok := currentUser.(string); ok {
			currentUserStr = userStr
		}
	}

	sessionList := &v1alpha1.DebugSessionList{}
	listOpts := []ctrlclient.ListOption{}

	// Note: cluster/state/user filters are applied client-side after fetching
	// Field selectors would require additional indexer setup

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.reader().List(apiCtx, sessionList, listOpts...); err != nil {
		reqLog.Errorw("Failed to list debug sessions", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list debug sessions")
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
		if mine && s.Spec.RequestedBy != currentUserStr {
			continue
		}
		filtered = append(filtered, s)
	}

	// Build response summaries
	summaries := make([]DebugSessionSummary, 0, len(filtered))
	for _, s := range filtered {
		// Check if the current user is already a participant (to hide Join button)
		isParticipant := false
		for _, p := range s.Status.Participants {
			if p.LeftAt == nil && (p.User == currentUserStr || p.Email == currentUserStr) {
				isParticipant = true
				break
			}
		}
		summaries = append(summaries, DebugSessionSummary{
			Name:                   s.Name,
			TemplateRef:            s.Spec.TemplateRef,
			Cluster:                s.Spec.Cluster,
			RequestedBy:            s.Spec.RequestedBy,
			RequestedByDisplayName: s.Spec.RequestedByDisplayName,
			State:                  s.Status.State,
			StatusMessage:          s.Status.Message,
			StartsAt:               s.Status.StartsAt,
			ExpiresAt:              s.Status.ExpiresAt,
			Participants:           len(s.Status.Participants),
			IsParticipant:          isParticipant,
			AllowedPods:            len(s.Status.AllowedPods),
			AllowedPodOperations:   s.Status.AllowedPodOperations,
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
	namespaceHint := ctx.Query("namespace")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "session name is required")
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	ctx.JSON(http.StatusOK, DebugSessionDetailResponse{DebugSession: *session})
}

// handleCreateDebugSession creates a new debug session
func (c *DebugSessionAPIController) handleCreateDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	var req CreateDebugSessionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		reqLog.Warnw("Failed to parse CreateDebugSession request", "error", err)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	reqLog.Debugw("Received CreateDebugSession request",
		"templateRef", req.TemplateRef,
		"cluster", req.Cluster,
		"bindingRef", req.BindingRef,
		"targetNamespace", req.TargetNamespace,
		"selectedSchedulingOption", req.SelectedSchedulingOption,
		"requestedDuration", req.RequestedDuration,
	)

	// Sanitize reason to prevent injection attacks
	if req.Reason != "" {
		sanitized, err := SanitizeReasonText(req.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize reason, using empty string", "error", err)
			req.Reason = "" // Use empty string as safe fallback
		} else {
			req.Reason = sanitized
		}
	}

	// Validate template exists
	template := &v1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: req.TemplateRef}, template); err != nil {
		if apierrors.IsNotFound(err) {
			reqLog.Warnw("Template not found", "templateRef", req.TemplateRef)
			apiresponses.RespondBadRequest(ctx, fmt.Sprintf("template '%s' not found", req.TemplateRef))
			return
		}
		reqLog.Errorw("Failed to get template", "template", req.TemplateRef, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to validate template")
		return
	}

	// Fetch bindings and cluster configs to check if cluster is allowed via template or binding
	var bindingList v1alpha1.DebugSessionClusterBindingList
	var clusterConfigList v1alpha1.ClusterConfigList
	if err := c.client.List(apiCtx, &bindingList); err != nil {
		reqLog.Errorw("Failed to list bindings for cluster validation", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to validate cluster access")
		return
	}
	if err := c.client.List(apiCtx, &clusterConfigList); err != nil {
		reqLog.Errorw("Failed to list cluster configs for cluster validation", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to validate cluster access")
		return
	}

	// Build cluster name -> ClusterConfig map for binding resolution
	clusterMap := make(map[string]*v1alpha1.ClusterConfig, len(clusterConfigList.Items))
	for i := range clusterConfigList.Items {
		cc := &clusterConfigList.Items[i]
		clusterMap[cc.Name] = cc
	}

	// Check if cluster is allowed by template or any binding
	allowedResult := c.isClusterAllowedByTemplateOrBinding(template, req.Cluster, bindingList.Items, clusterMap)
	if !allowedResult.Allowed {
		var errDetails string
		if template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0 {
			errDetails = fmt.Sprintf("cluster '%s' is not allowed by template '%s'. Template cluster patterns: %v. No bindings grant access to this cluster.",
				req.Cluster, req.TemplateRef, template.Spec.Allowed.Clusters)
		} else {
			errDetails = fmt.Sprintf("cluster '%s' is not allowed. Template '%s' has no allowed cluster patterns and no bindings grant access to this cluster.",
				req.Cluster, req.TemplateRef)
		}
		reqLog.Warnw("Cluster not allowed by template or binding",
			"templateRef", req.TemplateRef,
			"requestedCluster", req.Cluster,
			"templateAllowedClusters", func() []string {
				if template.Spec.Allowed != nil {
					return template.Spec.Allowed.Clusters
				}
				return nil
			}(),
			"bindingsChecked", len(bindingList.Items),
		)
		apiresponses.RespondForbidden(ctx, errDetails)
		return
	}
	reqLog.Debugw("Cluster access validated",
		"requestedCluster", req.Cluster,
		"allowedBySource", allowedResult.AllowedBySource,
	)

	// Track warnings for defaults that were applied
	var warnings []string

	// Validate and resolve target namespace (pass binding for constraint override)
	targetNamespace, err := c.resolveTargetNamespace(template, req.TargetNamespace, allowedResult.MatchingBinding)
	if err != nil {
		// Provide more context about namespace constraints when validation fails
		var effectiveAllowUserNs bool
		var effectiveDefault string
		if allowedResult.MatchingBinding != nil && allowedResult.MatchingBinding.Spec.NamespaceConstraints != nil {
			effectiveAllowUserNs = allowedResult.MatchingBinding.Spec.NamespaceConstraints.AllowUserNamespace
			effectiveDefault = allowedResult.MatchingBinding.Spec.NamespaceConstraints.DefaultNamespace
		} else if template.Spec.NamespaceConstraints != nil {
			effectiveAllowUserNs = template.Spec.NamespaceConstraints.AllowUserNamespace
			effectiveDefault = template.Spec.NamespaceConstraints.DefaultNamespace
		}
		reqLog.Warnw("Target namespace validation failed",
			"templateRef", req.TemplateRef,
			"requestedNamespace", req.TargetNamespace,
			"allowUserNamespace", effectiveAllowUserNs,
			"defaultNamespace", effectiveDefault,
			"bindingUsed", allowedResult.MatchingBinding != nil,
			"error", err,
		)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}
	// Track warning if namespace was defaulted
	if req.TargetNamespace == "" && targetNamespace != "" {
		warnings = append(warnings, fmt.Sprintf("Target namespace defaulted to '%s'", targetNamespace))
		reqLog.Debugw("Namespace defaulted", "defaultedTo", targetNamespace)
	}

	// Validate and resolve scheduling option
	resolvedScheduling, selectedOption, err := c.resolveSchedulingConstraints(template, req.SelectedSchedulingOption, allowedResult.MatchingBinding)
	if err != nil {
		reqLog.Warnw("Scheduling option validation failed",
			"templateRef", req.TemplateRef,
			"selectedSchedulingOption", req.SelectedSchedulingOption,
			"error", err,
		)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}
	// Track warning if scheduling option was defaulted
	if req.SelectedSchedulingOption == "" && selectedOption != "" {
		warnings = append(warnings, fmt.Sprintf("Scheduling option defaulted to '%s'", selectedOption))
		reqLog.Debugw("Scheduling option defaulted", "defaultedTo", selectedOption)
	}
	// Track warning if scheduling option was ignored (no options in template or binding but client sent one)
	if req.SelectedSchedulingOption != "" && selectedOption == "" {
		// Determine if any scheduling options exist (template or binding)
		hasOptions := (template.Spec.SchedulingOptions != nil && len(template.Spec.SchedulingOptions.Options) > 0) ||
			(allowedResult.MatchingBinding != nil && allowedResult.MatchingBinding.Spec.SchedulingOptions != nil && len(allowedResult.MatchingBinding.Spec.SchedulingOptions.Options) > 0)
		if !hasOptions {
			warnings = append(warnings, fmt.Sprintf("Scheduling option '%s' was ignored (template has no scheduling options)", req.SelectedSchedulingOption))
			reqLog.Debugw("Scheduling option ignored", "ignoredOption", req.SelectedSchedulingOption)
		}
	}

	// Get current user from context
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	// Get email from context (set by auth middleware from "email" claim)
	userEmail := ""
	if email, exists := ctx.Get("email"); exists && email != nil {
		if emailStr, ok := email.(string); ok {
			userEmail = emailStr
		}
	}

	// Get display name from context (set by auth middleware from "name" claim)
	displayName := ""
	if dn, exists := ctx.Get("displayName"); exists && dn != nil {
		if dnStr, ok := dn.(string); ok {
			displayName = dnStr
		}
	}

	// Get user groups from context for authorization and auto-approval logic
	var userGroups []string
	if groups, exists := ctx.Get("groups"); exists && groups != nil {
		if g, ok := groups.([]string); ok {
			userGroups = g
		}
	}

	// Coerce extraDeployValues types based on template variable definitions.
	// HTML form inputs and YAML defaults can produce string-encoded numbers/booleans
	// (e.g., "5" instead of 5). Normalize them before validation and storage so
	// templates render correct YAML (e.g., `storage: 5Gi` not `storage: "5"Gi`).
	if len(req.ExtraDeployValues) > 0 {
		req.ExtraDeployValues = v1alpha1.CoerceExtraDeployValues(req.ExtraDeployValues, template.Spec.ExtraDeployVariables)
	}

	// Validate extraDeployValues against template's extraDeployVariables
	// This includes checking allowedGroups on variables and options
	if len(req.ExtraDeployValues) > 0 || len(template.Spec.ExtraDeployVariables) > 0 {
		valErrs := v1alpha1.ValidateExtraDeployValuesWithGroups(
			req.ExtraDeployValues,
			template.Spec.ExtraDeployVariables,
			userGroups,
			field.NewPath("extraDeployValues"),
		)
		if len(valErrs) > 0 {
			// Format validation errors for API response
			errMessages := make([]string, 0, len(valErrs))
			for _, e := range valErrs {
				errMessages = append(errMessages, e.Error())
			}
			reqLog.Warnw("ExtraDeployValues validation failed",
				"templateRef", req.TemplateRef,
				"userGroups", userGroups,
				"errors", errMessages,
			)
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":  "extraDeployValues validation failed",
				"errors": errMessages,
			})
			return
		}
	}

	// Generate session name - use safe type assertion
	currentUserStr, ok := currentUser.(string)
	if !ok {
		apiresponses.RespondInternalErrorSimple(ctx, "invalid user context type")
		return
	}
	sessionName := fmt.Sprintf("debug-%s-%s-%d", naming.ToRFC1123Subdomain(currentUserStr), naming.ToRFC1123Subdomain(req.Cluster), time.Now().Unix())

	// Determine namespace from ClusterConfig for the requested cluster
	// DebugSessions should be in the same namespace as the ClusterConfig
	namespace := req.Namespace
	if namespace == "" {
		// Find ClusterConfig by cluster name to get its namespace
		clusterConfigs := &v1alpha1.ClusterConfigList{}
		if err := c.client.List(apiCtx, clusterConfigs); err == nil {
			for _, cc := range clusterConfigs.Items {
				if cc.Name == req.Cluster || cc.Spec.Tenant == req.Cluster {
					namespace = cc.Namespace
					break
				}
			}
		}
	}
	if namespace == "" {
		namespace = "default"
	}

	// Create the debug session
	session := &v1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sessionName,
			Namespace: namespace,
			Labels: map[string]string{
				DebugSessionLabelKey:  sessionName,
				DebugTemplateLabelKey: req.TemplateRef,
				DebugClusterLabelKey:  req.Cluster,
			},
		},
		Spec: v1alpha1.DebugSessionSpec{
			TemplateRef:                   req.TemplateRef,
			Cluster:                       req.Cluster,
			RequestedBy:                   currentUserStr,
			RequestedByEmail:              userEmail,
			RequestedByDisplayName:        displayName,
			UserGroups:                    userGroups,
			RequestedDuration:             req.RequestedDuration,
			NodeSelector:                  req.NodeSelector,
			Reason:                        req.Reason,
			InvitedParticipants:           req.InvitedParticipants,
			TargetNamespace:               targetNamespace,
			SelectedSchedulingOption:      selectedOption,
			ResolvedSchedulingConstraints: resolvedScheduling,
			ExtraDeployValues:             req.ExtraDeployValues,
		},
	}

	// Copy reason configurations as snapshots so session is self-contained
	// This avoids needing to look up the template later
	if template.Spec.RequestReason != nil {
		session.Spec.RequestReasonConfig = template.Spec.RequestReason.DeepCopy()
	}
	if template.Spec.ApprovalReason != nil {
		session.Spec.ApprovalReasonConfig = template.Spec.ApprovalReason.DeepCopy()
	}

	// Set explicit binding reference if provided (format: "namespace/name")
	var resolvedBinding *v1alpha1.DebugSessionClusterBinding
	if req.BindingRef != "" {
		parts := strings.SplitN(req.BindingRef, "/", 2)
		if len(parts) == 2 {
			session.Spec.BindingRef = &v1alpha1.BindingReference{
				Name:      parts[1],
				Namespace: parts[0],
			}
			// Fetch the binding for limit checking
			resolvedBinding = &v1alpha1.DebugSessionClusterBinding{}
			if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: parts[1], Namespace: parts[0]}, resolvedBinding); err != nil {
				if apierrors.IsNotFound(err) {
					reqLog.Warnw("Binding not found", "bindingRef", req.BindingRef)
					apiresponses.RespondBadRequest(ctx, fmt.Sprintf("binding '%s' not found", req.BindingRef))
					return
				}
				reqLog.Errorw("Failed to get binding", "binding", req.BindingRef, "error", err)
				apiresponses.RespondInternalErrorSimple(ctx, "failed to validate binding")
				return
			}

			// Check if binding is active
			if !IsBindingActive(resolvedBinding) {
				reqLog.Warnw("Binding is not active",
					"bindingRef", req.BindingRef,
					"disabled", resolvedBinding.Spec.Disabled,
					"effectiveFrom", resolvedBinding.Spec.EffectiveFrom,
					"expiresAt", resolvedBinding.Spec.ExpiresAt,
				)
				apiresponses.RespondForbidden(ctx, "binding is not active (disabled, expired, or not yet effective)")
				return
			}
		} else {
			reqLog.Warnw("Invalid bindingRef format, expected namespace/name", "bindingRef", req.BindingRef)
		}
	}

	// Check binding session limits if a binding is resolved
	if resolvedBinding != nil {
		if err := c.checkBindingSessionLimits(apiCtx, resolvedBinding, userEmail); err != nil {
			reqLog.Warnw("Binding session limits exceeded",
				"bindingRef", req.BindingRef,
				"userEmail", userEmail,
				"error", err,
			)
			apiresponses.RespondForbidden(ctx, err.Error())
			return
		}

		// Apply binding labels to the session
		if len(resolvedBinding.Spec.Labels) > 0 {
			for k, v := range resolvedBinding.Spec.Labels {
				session.Labels[k] = v
			}
		}

		// Apply binding annotations to the session
		if len(resolvedBinding.Spec.Annotations) > 0 {
			if session.Annotations == nil {
				session.Annotations = make(map[string]string)
			}
			for k, v := range resolvedBinding.Spec.Annotations {
				session.Annotations[k] = v
			}
		}
	}

	// NOTE: Using Create() instead of SSA for DebugSession creation.
	// Reason: We need AlreadyExists detection to return HTTP 409 Conflict to the user.
	// SSA would silently update an existing session, which is not the desired UX.
	// The session name is deterministic (debug-{user}-{cluster}-{timestamp}), so SSA
	// would technically work, but we want explicit conflict detection for the API.
	//
	// TODO(SSA): Consider using SSA with a pre-check Get() if we want SSA semantics
	// while preserving conflict detection for duplicate session names.
	if err := c.client.Create(apiCtx, session); err != nil {
		if apierrors.IsAlreadyExists(err) {
			apiresponses.RespondConflict(ctx, "session already exists")
			return
		}
		reqLog.Errorw("Failed to create debug session", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to create debug session")
		return
	}

	// Send request email to approvers
	c.sendDebugSessionRequestEmail(apiCtx, session, template, resolvedBinding)

	// Send confirmation email to requester
	c.sendDebugSessionCreatedEmail(apiCtx, session, template, resolvedBinding)

	// Emit audit event for session creation
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionCreated, session, currentUser.(string), "Debug session created")

	reqLog.Infow("Debug session created",
		"name", sessionName,
		"cluster", req.Cluster,
		"template", req.TemplateRef,
		"user", currentUser)

	metrics.DebugSessionsCreated.WithLabelValues(req.Cluster, req.TemplateRef).Inc()

	response := DebugSessionDetailResponse{DebugSession: *session}
	if len(warnings) > 0 {
		response.Warnings = warnings
		reqLog.Infow("Session created with warnings", "warnings", warnings)
	}
	ctx.JSON(http.StatusCreated, response)
}

// handleJoinDebugSession allows a user to join an existing debug session
func (c *DebugSessionAPIController) handleJoinDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

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
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("cannot join session in state '%s'", session.Status.State))
		return
	}

	// Check if user already joined
	username := currentUser.(string)
	for _, p := range session.Status.Participants {
		if p.User == username {
			apiresponses.RespondConflict(ctx, "user already joined this session")
			return
		}
	}

	// Check max participants if configured
	if session.Status.ResolvedTemplate != nil &&
		session.Status.ResolvedTemplate.TerminalSharing != nil &&
		session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants > 0 {
		if int32(len(session.Status.Participants)) >= session.Status.ResolvedTemplate.TerminalSharing.MaxParticipants {
			apiresponses.RespondForbidden(ctx, "maximum participants reached")
			return
		}
	}

	// Determine role
	role := v1alpha1.ParticipantRoleViewer
	if req.Role == string(v1alpha1.ParticipantRoleParticipant) {
		role = v1alpha1.ParticipantRoleParticipant
	}

	// Get display name from context (set by auth middleware from "name" claim)
	displayName := ""
	if dn, exists := ctx.Get("displayName"); exists && dn != nil {
		if dnStr, ok := dn.(string); ok {
			displayName = dnStr
		}
	}

	// Get email from context (set by auth middleware from "email" claim)
	userEmail := ""
	if email, exists := ctx.Get("email"); exists && email != nil {
		if emailStr, ok := email.(string); ok {
			userEmail = emailStr
		}
	}

	// Add participant
	now := metav1.Now()
	session.Status.Participants = append(session.Status.Participants, v1alpha1.DebugSessionParticipant{
		User:        username,
		Email:       userEmail,
		DisplayName: displayName,
		Role:        role,
		JoinedAt:    now,
	})

	if err := applyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to add participant", "session", name, "user", username, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to join session")
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
	namespaceHint := ctx.Query("namespace")

	// Get current user for authorization check
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	username := currentUser.(string)

	var req RenewDebugSessionRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Parse extension duration (supports day units like "1d")
	extendBy, err := v1alpha1.ParseDuration(req.ExtendBy)
	if err != nil {
		apiresponses.RespondBadRequest(ctx, "invalid duration format")
		return
	}

	// Validate duration is positive
	if extendBy <= 0 {
		apiresponses.RespondBadRequest(ctx, "extension duration must be positive")
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check if user is owner or participant
	isOwnerOrParticipant := session.Spec.RequestedBy == username
	if !isOwnerOrParticipant {
		for _, p := range session.Status.Participants {
			if p.User == username {
				isOwnerOrParticipant = true
				break
			}
		}
	}
	if !isOwnerOrParticipant {
		apiresponses.RespondForbidden(ctx, "only session owner or participants can renew")
		return
	}

	// Check session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("cannot renew session in state '%s'", session.Status.State))
		return
	}

	// Check renewal constraints
	if session.Status.ResolvedTemplate != nil && session.Status.ResolvedTemplate.Constraints != nil {
		constraints := session.Status.ResolvedTemplate.Constraints

		// Check if renewals are allowed (defaults to true if not set)
		if constraints.AllowRenewal != nil && !*constraints.AllowRenewal {
			apiresponses.RespondForbidden(ctx, "session renewals are not allowed by template")
			return
		}

		// Check max renewals (nil means use default of 3, 0 means no renewals allowed)
		if constraints.MaxRenewals != nil {
			maxRenewals := *constraints.MaxRenewals
			if maxRenewals == 0 || session.Status.RenewalCount >= maxRenewals {
				apiresponses.RespondForbidden(ctx, fmt.Sprintf("maximum renewals (%d) reached", maxRenewals))
				return
			}
		} else {
			// Default max renewals is 3
			if session.Status.RenewalCount >= 3 {
				apiresponses.RespondForbidden(ctx, "maximum renewals (3) reached")
				return
			}
		}

		// Check total duration would not exceed max
		if constraints.MaxDuration != "" {
			maxDur, err := v1alpha1.ParseDuration(constraints.MaxDuration)
			if err == nil && session.Status.StartsAt != nil {
				currentDuration := time.Since(session.Status.StartsAt.Time)
				if currentDuration+extendBy > maxDur {
					apiresponses.RespondForbidden(ctx, fmt.Sprintf("extension would exceed maximum duration of %s", constraints.MaxDuration))
					return
				}
			}
		}
	}

	// Extend the expiration
	if session.Status.ExpiresAt == nil {
		apiresponses.RespondBadRequest(ctx, "session has no expiration time")
		return
	}

	newExpiry := metav1.NewTime(session.Status.ExpiresAt.Add(extendBy))
	session.Status.ExpiresAt = &newExpiry
	session.Status.RenewalCount++

	if err := applyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to renew session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to renew session")
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
	namespaceHint := ctx.Query("namespace")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check if user is allowed to terminate (owner or admin)
	// For now, only the owner can terminate
	if session.Spec.RequestedBy != currentUser.(string) {
		apiresponses.RespondForbidden(ctx, "only the session owner can terminate")
		return
	}

	// Check session can be terminated
	if session.Status.State == v1alpha1.DebugSessionStateTerminated ||
		session.Status.State == v1alpha1.DebugSessionStateExpired ||
		session.Status.State == v1alpha1.DebugSessionStateFailed {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is already in terminal state '%s'", session.Status.State))
		return
	}

	// Mark as terminated
	session.Status.State = v1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Terminated by %s", currentUser)

	if err := applyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to terminate session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to terminate session")
		return
	}

	// Emit audit event for session termination
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionTerminated, session, currentUser.(string), "Debug session terminated by user")

	reqLog.Infow("Debug session terminated", "session", name, "user", currentUser)
	metrics.DebugSessionsTerminated.WithLabelValues(session.Spec.Cluster, "user_terminated").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleApproveDebugSession approves a pending debug session
func (c *DebugSessionAPIController) handleApproveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	var req ApprovalRequest
	_ = ctx.ShouldBindJSON(&req) // Optional body

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check session is pending approval
	if session.Status.State != v1alpha1.DebugSessionStatePendingApproval {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not pending approval (state: %s)", session.Status.State))
		return
	}

	// Check if user is authorized to approve (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	if !c.isUserAuthorizedToApprove(apiCtx, session, currentUser.(string), userGroups) {
		apiresponses.RespondForbidden(ctx, "user is not authorized to approve this session")
		return
	}

	// Mark as approved
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &v1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.ApprovedBy = currentUser.(string)
	session.Status.Approval.ApprovedAt = &now
	// Sanitize approval reason to prevent injection attacks
	if req.Reason != "" {
		sanitized, err := SanitizeReasonText(req.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize approval reason, using empty string", "error", err)
			session.Status.Approval.Reason = "" // Use empty string as safe fallback
		} else {
			session.Status.Approval.Reason = sanitized
		}
	} else {
		session.Status.Approval.Reason = req.Reason
	}

	if err := applyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to approve session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to approve session")
		return
	}

	// Send approval email to requester
	c.sendDebugSessionApprovalEmail(apiCtx, session)

	// Emit audit event for session approval
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionStarted, session, currentUser.(string), "Debug session approved")

	reqLog.Infow("Debug session approved", "session", name, "approver", currentUser)
	metrics.DebugSessionApproved.WithLabelValues(session.Spec.Cluster, "user").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleRejectDebugSession rejects a pending debug session
func (c *DebugSessionAPIController) handleRejectDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	var req ApprovalRequest
	_ = ctx.ShouldBindJSON(&req) // Optional body with reason

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Check session is pending approval
	if session.Status.State != v1alpha1.DebugSessionStatePendingApproval {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not pending approval (state: %s)", session.Status.State))
		return
	}

	// Check if user is authorized to reject (in allowed approver groups)
	userGroups, _ := ctx.Get("groups")
	if !c.isUserAuthorizedToApprove(apiCtx, session, currentUser.(string), userGroups) {
		apiresponses.RespondForbidden(ctx, "user is not authorized to reject this session")
		return
	}

	// Mark as rejected
	now := metav1.Now()
	if session.Status.Approval == nil {
		session.Status.Approval = &v1alpha1.DebugSessionApproval{}
	}
	session.Status.Approval.RejectedBy = currentUser.(string)
	session.Status.Approval.RejectedAt = &now
	// Sanitize rejection reason to prevent injection attacks
	sanitizedReason := req.Reason
	if req.Reason != "" {
		var err error
		sanitizedReason, err = SanitizeReasonText(req.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize rejection reason, using empty string", "error", err)
			sanitizedReason = "" // Use empty string as safe fallback
		}
	}
	session.Status.Approval.Reason = sanitizedReason

	// Move to terminated state
	session.Status.State = v1alpha1.DebugSessionStateTerminated
	session.Status.Message = fmt.Sprintf("Rejected by %s: %s", currentUser, sanitizedReason)

	if err := applyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to reject session", "session", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to reject session")
		return
	}

	// Send rejection email to requester
	c.sendDebugSessionRejectionEmail(apiCtx, session)

	// Emit audit event for session rejection
	c.emitDebugSessionAuditEvent(apiCtx, audit.EventDebugSessionTerminated, session, currentUser.(string), fmt.Sprintf("Debug session rejected: %s", req.Reason))

	reqLog.Infow("Debug session rejected", "session", name, "rejector", currentUser, "reason", req.Reason)
	metrics.DebugSessionRejected.WithLabelValues(session.Spec.Cluster, "user_rejected").Inc()

	// Return updated session - client expects the session object, not just a message
	ctx.JSON(http.StatusOK, session)
}

// handleLeaveDebugSession allows a participant to leave a session
func (c *DebugSessionAPIController) handleLeaveDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	session, err := c.getDebugSessionByName(apiCtx, name, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
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
				apiresponses.RespondForbidden(ctx, "session owner cannot leave; use terminate instead")
				return
			}
			// Mark as left
			session.Status.Participants[i].LeftAt = &now
			found = true
			break
		}
	}

	if !found {
		apiresponses.RespondNotFoundSimple(ctx, "user is not a participant in this session")
		return
	}

	if err := applyDebugSessionStatus(apiCtx, c.client, session); err != nil {
		reqLog.Errorw("Failed to leave session", "session", name, "user", username, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to leave session")
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
	Name                  string                            `json:"name"`
	DisplayName           string                            `json:"displayName"`
	Description           string                            `json:"description,omitempty"`
	Mode                  v1alpha1.DebugSessionTemplateMode `json:"mode"`
	WorkloadType          v1alpha1.DebugWorkloadType        `json:"workloadType,omitempty"`
	PodTemplateRef        string                            `json:"podTemplateRef,omitempty"`
	TargetNamespace       string                            `json:"targetNamespace,omitempty"`
	Constraints           *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	AllowedClusters       []string                          `json:"allowedClusters,omitempty"`
	AllowedGroups         []string                          `json:"allowedGroups,omitempty"`
	RequiresApproval      bool                              `json:"requiresApproval"`
	SchedulingOptions     *SchedulingOptionsResponse        `json:"schedulingOptions,omitempty"`
	NamespaceConstraints  *NamespaceConstraintsResponse     `json:"namespaceConstraints,omitempty"`
	ExtraDeployVariables  []v1alpha1.ExtraDeployVariable    `json:"extraDeployVariables,omitempty"`
	Priority              int32                             `json:"priority,omitempty"`
	Hidden                bool                              `json:"hidden,omitempty"`
	Deprecated            bool                              `json:"deprecated,omitempty"`
	DeprecationMessage    string                            `json:"deprecationMessage,omitempty"`
	HasAvailableClusters  bool                              `json:"hasAvailableClusters"`            // True if at least one cluster is available for this template
	AvailableClusterCount int                               `json:"availableClusterCount,omitempty"` // Number of clusters user can deploy to
}

// SchedulingOptionsResponse represents scheduling options in API responses
type SchedulingOptionsResponse struct {
	Required bool                       `json:"required"`
	Options  []SchedulingOptionResponse `json:"options"`
}

// SchedulingOptionResponse represents a single scheduling option in API responses
type SchedulingOptionResponse struct {
	Name                  string                        `json:"name"`
	DisplayName           string                        `json:"displayName"`
	Description           string                        `json:"description,omitempty"`
	Default               bool                          `json:"default,omitempty"`
	SchedulingConstraints *SchedulingConstraintsSummary `json:"schedulingConstraints,omitempty"`
}

// NamespaceConstraintsResponse represents namespace constraints in API responses
type NamespaceConstraintsResponse struct {
	AllowedPatterns       []string                        `json:"allowedPatterns,omitempty"`
	AllowedLabelSelectors []NamespaceSelectorTermResponse `json:"allowedLabelSelectors,omitempty"`
	DeniedPatterns        []string                        `json:"deniedPatterns,omitempty"`
	DeniedLabelSelectors  []NamespaceSelectorTermResponse `json:"deniedLabelSelectors,omitempty"`
	DefaultNamespace      string                          `json:"defaultNamespace,omitempty"`
	AllowUserNamespace    bool                            `json:"allowUserNamespace"`
}

// NamespaceSelectorTermResponse represents a label selector term in API responses
type NamespaceSelectorTermResponse struct {
	MatchLabels      map[string]string                      `json:"matchLabels,omitempty"`
	MatchExpressions []NamespaceSelectorRequirementResponse `json:"matchExpressions,omitempty"`
}

// NamespaceSelectorRequirementResponse represents a label selector requirement in API responses
type NamespaceSelectorRequirementResponse struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// DebugPodTemplateResponse represents a pod template in API responses
type DebugPodTemplateResponse struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Containers  int    `json:"containers"`
}

// TemplateClustersResponse represents the response for GET /templates/{name}/clusters
type TemplateClustersResponse struct {
	TemplateName        string                   `json:"templateName"`
	TemplateDisplayName string                   `json:"templateDisplayName"`
	Clusters            []AvailableClusterDetail `json:"clusters"`
}

// AvailableClusterDetail represents a cluster with resolved constraints for a template.
// When multiple bindings match a cluster, BindingOptions contains all available options.
// The first binding option (or BindingRef for backward compatibility) is the default.
type AvailableClusterDetail struct {
	Name                          string                            `json:"name"`
	DisplayName                   string                            `json:"displayName,omitempty"`
	Environment                   string                            `json:"environment,omitempty"`
	Location                      string                            `json:"location,omitempty"`
	Site                          string                            `json:"site,omitempty"`
	Tenant                        string                            `json:"tenant,omitempty"`
	BindingRef                    *BindingReference                 `json:"bindingRef,omitempty"`     // Default/primary binding (backward compat)
	BindingOptions                []BindingOption                   `json:"bindingOptions,omitempty"` // All available binding options
	Constraints                   *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`    // Default constraints (from first binding)
	SchedulingConstraints         *SchedulingConstraintsSummary     `json:"schedulingConstraints,omitempty"`
	SchedulingOptions             *SchedulingOptionsResponse        `json:"schedulingOptions,omitempty"`
	NamespaceConstraints          *NamespaceConstraintsResponse     `json:"namespaceConstraints,omitempty"`
	Impersonation                 *ImpersonationSummary             `json:"impersonation,omitempty"`
	RequiredAuxResourceCategories []string                          `json:"requiredAuxiliaryResourceCategories,omitempty"`
	Approval                      *ApprovalInfo                     `json:"approval,omitempty"`
	RequestReason                 *ReasonConfigInfo                 `json:"requestReason,omitempty"`
	ApprovalReason                *ReasonConfigInfo                 `json:"approvalReason,omitempty"`
	Notification                  *NotificationConfigInfo           `json:"notification,omitempty"`
	Status                        *ClusterStatusInfo                `json:"status,omitempty"`
}

// BindingOption represents a single binding option for a cluster with its resolved configuration.
// When users select a cluster with multiple binding options, they can choose which binding to use.
type BindingOption struct {
	BindingRef                    BindingReference                  `json:"bindingRef"`
	DisplayName                   string                            `json:"displayName,omitempty"` // Effective display name for this binding
	Constraints                   *v1alpha1.DebugSessionConstraints `json:"constraints,omitempty"`
	SchedulingConstraints         *SchedulingConstraintsSummary     `json:"schedulingConstraints,omitempty"`
	SchedulingOptions             *SchedulingOptionsResponse        `json:"schedulingOptions,omitempty"`
	NamespaceConstraints          *NamespaceConstraintsResponse     `json:"namespaceConstraints,omitempty"`
	Impersonation                 *ImpersonationSummary             `json:"impersonation,omitempty"`
	RequiredAuxResourceCategories []string                          `json:"requiredAuxiliaryResourceCategories,omitempty"`
	Approval                      *ApprovalInfo                     `json:"approval,omitempty"`
	RequestReason                 *ReasonConfigInfo                 `json:"requestReason,omitempty"`
	ApprovalReason                *ReasonConfigInfo                 `json:"approvalReason,omitempty"`
	Notification                  *NotificationConfigInfo           `json:"notification,omitempty"`
}

// BindingReference identifies the binding that enabled access
type BindingReference struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	DisplayNamePrefix string `json:"displayNamePrefix,omitempty"`
}

// SchedulingConstraintsSummary summarizes scheduling constraints for API responses
type SchedulingConstraintsSummary struct {
	Summary          string              `json:"summary,omitempty"`
	NodeSelector     map[string]string   `json:"nodeSelector,omitempty"`
	DeniedNodeLabels map[string]string   `json:"deniedNodeLabels,omitempty"`
	Tolerations      []TolerationSummary `json:"tolerations,omitempty"`
}

// TolerationSummary summarizes a toleration for API responses
type TolerationSummary struct {
	Key      string `json:"key"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// ImpersonationSummary summarizes impersonation configuration for API responses
type ImpersonationSummary struct {
	Enabled        bool   `json:"enabled"`
	ServiceAccount string `json:"serviceAccount,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// ApprovalInfo contains approval requirements for a cluster
type ApprovalInfo struct {
	Required       bool     `json:"required"`
	ApproverGroups []string `json:"approverGroups,omitempty"`
	ApproverUsers  []string `json:"approverUsers,omitempty"`
	CanAutoApprove bool     `json:"canAutoApprove,omitempty"`
}

// ClusterStatusInfo contains cluster health status
type ClusterStatusInfo struct {
	Healthy     bool   `json:"healthy"`
	LastChecked string `json:"lastChecked,omitempty"`
}

// ReasonConfigInfo contains reason configuration for API responses
type ReasonConfigInfo struct {
	Mandatory        bool     `json:"mandatory"`
	Description      string   `json:"description,omitempty"`
	MinLength        int32    `json:"minLength,omitempty"`
	MaxLength        int32    `json:"maxLength,omitempty"`
	SuggestedReasons []string `json:"suggestedReasons,omitempty"`
}

// NotificationConfigInfo contains notification configuration for API responses
type NotificationConfigInfo struct {
	Enabled bool `json:"enabled"`
}

// handleListTemplates returns available debug session templates
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) handleListTemplates(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	templateList := &v1alpha1.DebugSessionTemplateList{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.reader().List(apiCtx, templateList); err != nil {
		reqLog.Errorw("Failed to list debug session templates", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list templates")
		return
	}

	// Fetch all ClusterConfigs for pattern resolution
	clusterConfigList := &v1alpha1.ClusterConfigList{}
	if err := c.reader().List(apiCtx, clusterConfigList); err != nil {
		reqLog.Warnw("Failed to list cluster configs for pattern resolution", "error", err)
		// Continue without pattern resolution - clusters will be empty
	}
	allClusterNames := make([]string, 0, len(clusterConfigList.Items))
	clusterMap := make(map[string]*v1alpha1.ClusterConfig, len(clusterConfigList.Items))
	for i := range clusterConfigList.Items {
		cc := &clusterConfigList.Items[i]
		allClusterNames = append(allClusterNames, cc.Name)
		clusterMap[cc.Name] = cc
	}

	// Fetch all bindings to determine which templates have available clusters
	bindingList := &v1alpha1.DebugSessionClusterBindingList{}
	if err := c.reader().List(apiCtx, bindingList); err != nil {
		reqLog.Warnw("Failed to list bindings for template cluster resolution", "error", err)
		// Continue without binding resolution
	}

	// Get user's groups for filtering
	userGroups, _ := ctx.Get("groups")
	groups := []string{}
	if userGroups != nil {
		if g, ok := userGroups.([]string); ok {
			groups = g
		}
	}

	includeHidden := ctx.Query("includeHidden") == "true"
	includeUnavailable := ctx.Query("includeUnavailable") == "true"

	// Filter and transform
	var templates []DebugSessionTemplateResponse
	for _, t := range templateList.Items {
		if t.Spec.Hidden && !includeHidden {
			continue
		}
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

		// Calculate available cluster count for this template
		availableClusterCount := c.countAvailableClustersForTemplate(&t, bindingList.Items, clusterMap, allClusterNames)
		hasAvailableClusters := availableClusterCount > 0

		// Skip templates without available clusters unless explicitly requested
		if !hasAvailableClusters && !includeUnavailable {
			reqLog.Debugw("Skipping template without available clusters",
				"template", t.Name,
				"includeUnavailable", includeUnavailable,
			)
			continue
		}

		resp := DebugSessionTemplateResponse{
			Name:                  t.Name,
			DisplayName:           t.Spec.DisplayName,
			Description:           t.Spec.Description,
			Mode:                  t.Spec.Mode,
			WorkloadType:          t.Spec.WorkloadType,
			TargetNamespace:       t.Spec.TargetNamespace,
			Constraints:           t.Spec.Constraints,
			RequiresApproval:      t.Spec.Approvers != nil && (len(t.Spec.Approvers.Groups) > 0 || len(t.Spec.Approvers.Users) > 0),
			ExtraDeployVariables:  t.Spec.ExtraDeployVariables,
			Priority:              t.Spec.Priority,
			Hidden:                t.Spec.Hidden,
			Deprecated:            t.Spec.Deprecated,
			DeprecationMessage:    t.Spec.DeprecationMessage,
			HasAvailableClusters:  hasAvailableClusters,
			AvailableClusterCount: availableClusterCount,
		}

		if t.Spec.PodTemplateRef != nil {
			resp.PodTemplateRef = t.Spec.PodTemplateRef.Name
		}
		if t.Spec.Allowed != nil {
			// Resolve cluster patterns to actual cluster names
			resp.AllowedClusters = resolveClusterPatterns(t.Spec.Allowed.Clusters, allClusterNames)
			resp.AllowedGroups = t.Spec.Allowed.Groups
		}

		// Include scheduling options if present
		if t.Spec.SchedulingOptions != nil {
			resp.SchedulingOptions = &SchedulingOptionsResponse{
				Required: t.Spec.SchedulingOptions.Required,
				Options:  make([]SchedulingOptionResponse, 0, len(t.Spec.SchedulingOptions.Options)),
			}
			for _, opt := range t.Spec.SchedulingOptions.Options {
				resp.SchedulingOptions.Options = append(resp.SchedulingOptions.Options, SchedulingOptionResponse{
					Name:                  opt.Name,
					DisplayName:           opt.DisplayName,
					Description:           opt.Description,
					Default:               opt.Default,
					SchedulingConstraints: buildConstraintsSummary(opt.SchedulingConstraints),
				})
			}
		}

		// Include namespace constraints if present
		if t.Spec.NamespaceConstraints != nil {
			resp.NamespaceConstraints = &NamespaceConstraintsResponse{
				DefaultNamespace:   t.Spec.NamespaceConstraints.DefaultNamespace,
				AllowUserNamespace: t.Spec.NamespaceConstraints.AllowUserNamespace,
			}
			if t.Spec.NamespaceConstraints.AllowedNamespaces != nil {
				resp.NamespaceConstraints.AllowedPatterns = t.Spec.NamespaceConstraints.AllowedNamespaces.Patterns
				resp.NamespaceConstraints.AllowedLabelSelectors = convertSelectorTerms(t.Spec.NamespaceConstraints.AllowedNamespaces.SelectorTerms)
			}
			if t.Spec.NamespaceConstraints.DeniedNamespaces != nil {
				resp.NamespaceConstraints.DeniedPatterns = t.Spec.NamespaceConstraints.DeniedNamespaces.Patterns
				resp.NamespaceConstraints.DeniedLabelSelectors = convertSelectorTerms(t.Spec.NamespaceConstraints.DeniedNamespaces.SelectorTerms)
			}
		}

		templates = append(templates, resp)
	}

	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Priority != templates[j].Priority {
			return templates[i].Priority > templates[j].Priority
		}
		return templates[i].Name < templates[j].Name
	})

	ctx.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

// handleGetTemplate returns details for a specific template
// Uses the uncached apiReader if configured, for consistent reads after writes.
// Returns the same flat response format as the list endpoint.
func (c *DebugSessionAPIController) handleGetTemplate(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "template name is required")
		return
	}

	template := &v1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.reader().Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "template not found")
			return
		}
		reqLog.Errorw("Failed to get template", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get template")
		return
	}

	// Build response using same format as list endpoint
	resp := DebugSessionTemplateResponse{
		Name:                 template.Name,
		DisplayName:          template.Spec.DisplayName,
		Description:          template.Spec.Description,
		Mode:                 template.Spec.Mode,
		WorkloadType:         template.Spec.WorkloadType,
		TargetNamespace:      template.Spec.TargetNamespace,
		Constraints:          template.Spec.Constraints,
		RequiresApproval:     template.Spec.Approvers != nil && (len(template.Spec.Approvers.Groups) > 0 || len(template.Spec.Approvers.Users) > 0),
		ExtraDeployVariables: template.Spec.ExtraDeployVariables,
		Priority:             template.Spec.Priority,
		Hidden:               template.Spec.Hidden,
		Deprecated:           template.Spec.Deprecated,
		DeprecationMessage:   template.Spec.DeprecationMessage,
	}

	if template.Spec.PodTemplateRef != nil {
		resp.PodTemplateRef = template.Spec.PodTemplateRef.Name
	}
	if template.Spec.Allowed != nil {
		resp.AllowedClusters = template.Spec.Allowed.Clusters
		resp.AllowedGroups = template.Spec.Allowed.Groups
	}

	// Include scheduling options if present
	if template.Spec.SchedulingOptions != nil {
		resp.SchedulingOptions = &SchedulingOptionsResponse{
			Required: template.Spec.SchedulingOptions.Required,
			Options:  make([]SchedulingOptionResponse, 0, len(template.Spec.SchedulingOptions.Options)),
		}
		for _, opt := range template.Spec.SchedulingOptions.Options {
			resp.SchedulingOptions.Options = append(resp.SchedulingOptions.Options, SchedulingOptionResponse{
				Name:                  opt.Name,
				DisplayName:           opt.DisplayName,
				Description:           opt.Description,
				Default:               opt.Default,
				SchedulingConstraints: buildConstraintsSummary(opt.SchedulingConstraints),
			})
		}
	}

	// Include namespace constraints if present
	if template.Spec.NamespaceConstraints != nil {
		resp.NamespaceConstraints = &NamespaceConstraintsResponse{
			DefaultNamespace:   template.Spec.NamespaceConstraints.DefaultNamespace,
			AllowUserNamespace: template.Spec.NamespaceConstraints.AllowUserNamespace,
		}
		if template.Spec.NamespaceConstraints.AllowedNamespaces != nil {
			resp.NamespaceConstraints.AllowedPatterns = template.Spec.NamespaceConstraints.AllowedNamespaces.Patterns
			resp.NamespaceConstraints.AllowedLabelSelectors = convertSelectorTerms(template.Spec.NamespaceConstraints.AllowedNamespaces.SelectorTerms)
		}
		if template.Spec.NamespaceConstraints.DeniedNamespaces != nil {
			resp.NamespaceConstraints.DeniedPatterns = template.Spec.NamespaceConstraints.DeniedNamespaces.Patterns
			resp.NamespaceConstraints.DeniedLabelSelectors = convertSelectorTerms(template.Spec.NamespaceConstraints.DeniedNamespaces.SelectorTerms)
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

// handleGetTemplateClusters returns cluster-specific details for a template
func (c *DebugSessionAPIController) handleGetTemplateClusters(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "template name is required")
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	// Fetch the template
	template := &v1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "template not found")
			return
		}
		reqLog.Errorw("Failed to get template", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get template")
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

	// Check if user has access to this template
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Groups) > 0 {
		hasAccess := false
		for _, allowedGroup := range template.Spec.Allowed.Groups {
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
			apiresponses.RespondForbidden(ctx, "access denied to this template")
			return
		}
	}

	// Fetch ClusterConfigs and ClusterBindings in parallel for performance
	var clusterConfigList v1alpha1.ClusterConfigList
	var bindingList v1alpha1.DebugSessionClusterBindingList
	var ccErr, bindErr error

	// Use goroutines with sync.WaitGroup for parallel fetching
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ccErr = c.client.List(apiCtx, &clusterConfigList)
	}()

	go func() {
		defer wg.Done()
		bindErr = c.client.List(apiCtx, &bindingList)
	}()

	wg.Wait()

	if ccErr != nil {
		reqLog.Errorw("Failed to list cluster configs", "error", ccErr)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list clusters")
		return
	}

	if bindErr != nil {
		reqLog.Errorw("Failed to list cluster bindings", "error", bindErr)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list bindings")
		return
	}

	// Build cluster name -> ClusterConfig map
	clusterMap := make(map[string]*v1alpha1.ClusterConfig, len(clusterConfigList.Items))
	for i := range clusterConfigList.Items {
		cc := &clusterConfigList.Items[i]
		clusterMap[cc.Name] = cc
	}

	// Find all bindings that apply to this template
	applicableBindings := c.findBindingsForTemplate(template, bindingList.Items)

	// Build the response - resolve clusters from bindings and template's allowed.clusters
	clusterDetails := c.resolveTemplateClusters(template, applicableBindings, clusterMap, groups)

	// Apply optional query filters
	environment := ctx.Query("environment")
	location := ctx.Query("location")
	bindingName := ctx.Query("bindingName")

	filteredClusters := make([]AvailableClusterDetail, 0, len(clusterDetails))
	for _, cd := range clusterDetails {
		if environment != "" && cd.Environment != environment {
			continue
		}
		if location != "" && cd.Location != location {
			continue
		}
		if bindingName != "" && (cd.BindingRef == nil || cd.BindingRef.Name != bindingName) {
			continue
		}
		filteredClusters = append(filteredClusters, cd)
	}

	response := TemplateClustersResponse{
		TemplateName:        template.Name,
		TemplateDisplayName: template.Spec.DisplayName,
		Clusters:            filteredClusters,
	}

	ctx.JSON(http.StatusOK, response)
}

// countAvailableClustersForTemplate counts how many clusters are available for a template.
// It considers both bindings and direct template.Spec.Allowed.Clusters patterns.
func (c *DebugSessionAPIController) countAvailableClustersForTemplate(
	template *v1alpha1.DebugSessionTemplate,
	allBindings []v1alpha1.DebugSessionClusterBinding,
	clusterMap map[string]*v1alpha1.ClusterConfig,
	allClusterNames []string,
) int {
	seenClusters := make(map[string]bool)

	// Find bindings that match this template
	applicableBindings := c.findBindingsForTemplate(template, allBindings)

	// Collect clusters from bindings
	for i := range applicableBindings {
		binding := &applicableBindings[i]
		bindingClusters := c.resolveClustersFromBinding(binding, clusterMap)
		for _, clusterName := range bindingClusters {
			if clusterMap[clusterName] != nil {
				seenClusters[clusterName] = true
			}
		}
	}

	// Also check template's direct allowed.clusters patterns
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0 {
		resolvedClusters := resolveClusterPatterns(template.Spec.Allowed.Clusters, allClusterNames)
		for _, clusterName := range resolvedClusters {
			if clusterMap[clusterName] != nil {
				seenClusters[clusterName] = true
			}
		}
	}

	return len(seenClusters)
}

// findBindingsForTemplate returns all bindings that reference the given template
func (c *DebugSessionAPIController) findBindingsForTemplate(template *v1alpha1.DebugSessionTemplate, bindings []v1alpha1.DebugSessionClusterBinding) []v1alpha1.DebugSessionClusterBinding {
	var result []v1alpha1.DebugSessionClusterBinding
	for i := range bindings {
		binding := &bindings[i]
		bindingID := fmt.Sprintf("%s/%s", binding.Namespace, binding.Name)
		if !IsBindingActive(binding) {
			c.log.Debugw("findBindingsForTemplate: skipping inactive binding",
				"template", template.Name,
				"binding", bindingID,
			)
			continue
		}
		// Check templateRef
		if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name == template.Name {
			c.log.Debugw("findBindingsForTemplate: matched by templateRef",
				"template", template.Name,
				"binding", bindingID,
			)
			result = append(result, *binding)
			continue
		}
		// Check templateSelector
		if binding.Spec.TemplateSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
			if err != nil {
				c.log.Warnw("findBindingsForTemplate: failed to parse templateSelector",
					"binding", bindingID,
					"error", err,
				)
			} else {
				labelSet := labelSetFromMap(template.Labels)
				matches := selector.Matches(labelSet)
				c.log.Debugw("findBindingsForTemplate: checking templateSelector",
					"template", template.Name,
					"templateLabels", template.Labels,
					"binding", bindingID,
					"selectorString", selector.String(),
					"matches", matches,
				)
				if matches {
					result = append(result, *binding)
				}
			}
		}
	}
	return result
}

// resolveTemplateClusters resolves all available clusters for a template.
// When multiple bindings match the same cluster, all binding options are returned
// so users can select which binding configuration to use.
func (c *DebugSessionAPIController) resolveTemplateClusters(template *v1alpha1.DebugSessionTemplate, bindings []v1alpha1.DebugSessionClusterBinding, clusterMap map[string]*v1alpha1.ClusterConfig, userGroups []string) []AvailableClusterDetail {
	// Build a map of cluster -> all matching bindings
	clusterBindings := make(map[string][]*v1alpha1.DebugSessionClusterBinding)

	// Collect all bindings for each cluster
	for i := range bindings {
		binding := &bindings[i]
		bindingClusters := c.resolveClustersFromBinding(binding, clusterMap)
		for _, clusterName := range bindingClusters {
			clusterBindings[clusterName] = append(clusterBindings[clusterName], binding)
		}
	}

	var result []AvailableClusterDetail
	seenClusters := make(map[string]bool)

	// Build cluster details with all binding options
	for clusterName, matchingBindings := range clusterBindings {
		if seenClusters[clusterName] {
			continue
		}
		seenClusters[clusterName] = true

		cc := clusterMap[clusterName]
		if cc == nil {
			continue
		}

		// Build detail with all binding options
		detail := c.buildClusterDetailWithBindings(template, matchingBindings, cc, userGroups)
		result = append(result, detail)
	}

	// Then, resolve clusters from template's allowed.clusters (fallback, no binding)
	if template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0 {
		allClusterNames := make([]string, 0, len(clusterMap))
		for name := range clusterMap {
			allClusterNames = append(allClusterNames, name)
		}
		allowedClusters := resolveClusterPatterns(template.Spec.Allowed.Clusters, allClusterNames)
		for _, clusterName := range allowedClusters {
			if seenClusters[clusterName] {
				continue
			}
			seenClusters[clusterName] = true

			cc := clusterMap[clusterName]
			if cc == nil {
				continue
			}

			// No binding - use template defaults
			detail := c.buildClusterDetailWithBindings(template, nil, cc, userGroups)
			result = append(result, detail)
		}
	}

	return result
}

// buildClusterDetailWithBindings creates a cluster detail with all matching binding options.
// The first binding becomes the default (for backward compatibility with BindingRef).
func (c *DebugSessionAPIController) buildClusterDetailWithBindings(template *v1alpha1.DebugSessionTemplate, matchingBindings []*v1alpha1.DebugSessionClusterBinding, cc *v1alpha1.ClusterConfig, userGroups []string) AvailableClusterDetail {
	detail := AvailableClusterDetail{
		Name:        cc.Name,
		DisplayName: cc.Name,
		Environment: cc.Labels["environment"],
		Location:    cc.Labels["location"],
		Site:        cc.Labels["site"],
		Tenant:      cc.Labels["tenant"],
		Status:      c.resolveClusterStatus(cc),
	}

	if len(matchingBindings) == 0 {
		// No bindings - use template defaults
		detail.Constraints = template.Spec.Constraints
		detail.SchedulingConstraints = c.getSchedulingConstraintsSummary(template, nil)
		detail.SchedulingOptions = c.resolveSchedulingOptions(template, nil)
		detail.NamespaceConstraints = c.resolveNamespaceConstraints(template, nil)
		detail.Impersonation = c.resolveImpersonation(template, nil)
		detail.Approval = c.resolveApproval(template, nil, cc, userGroups)
		detail.RequiredAuxResourceCategories = c.resolveRequiredAuxResourceCategories(template, nil)
		return detail
	}

	// Build all binding options
	detail.BindingOptions = make([]BindingOption, 0, len(matchingBindings))
	for _, binding := range matchingBindings {
		effectiveDisplayName := v1alpha1.GetEffectiveDisplayName(binding, template.Spec.DisplayName, template.Name)
		option := BindingOption{
			BindingRef: BindingReference{
				Name:              binding.Name,
				Namespace:         binding.Namespace,
				DisplayNamePrefix: binding.Spec.DisplayNamePrefix,
			},
			DisplayName:                   effectiveDisplayName,
			Constraints:                   c.mergeConstraints(template.Spec.Constraints, binding),
			SchedulingConstraints:         c.getSchedulingConstraintsSummary(template, binding),
			SchedulingOptions:             c.resolveSchedulingOptions(template, binding),
			NamespaceConstraints:          c.resolveNamespaceConstraints(template, binding),
			Impersonation:                 c.resolveImpersonation(template, binding),
			RequiredAuxResourceCategories: c.resolveRequiredAuxResourceCategories(template, binding),
			Approval:                      c.resolveApproval(template, binding, cc, userGroups),
			RequestReason:                 c.resolveRequestReason(template, binding),
			ApprovalReason:                c.resolveApprovalReason(template, binding),
			Notification:                  c.resolveNotification(template, binding),
		}
		detail.BindingOptions = append(detail.BindingOptions, option)
	}

	// Set primary binding (first one) for backward compatibility
	if len(matchingBindings) > 0 {
		primaryBinding := matchingBindings[0]
		detail.BindingRef = &BindingReference{
			Name:              primaryBinding.Name,
			Namespace:         primaryBinding.Namespace,
			DisplayNamePrefix: primaryBinding.Spec.DisplayNamePrefix,
		}
		// Set default constraints from primary binding for backward compatibility
		detail.Constraints = c.mergeConstraints(template.Spec.Constraints, primaryBinding)
		detail.SchedulingConstraints = c.getSchedulingConstraintsSummary(template, primaryBinding)
		detail.SchedulingOptions = c.resolveSchedulingOptions(template, primaryBinding)
		detail.NamespaceConstraints = c.resolveNamespaceConstraints(template, primaryBinding)
		detail.Impersonation = c.resolveImpersonation(template, primaryBinding)
		detail.Approval = c.resolveApproval(template, primaryBinding, cc, userGroups)
		detail.RequiredAuxResourceCategories = c.resolveRequiredAuxResourceCategories(template, primaryBinding)
		detail.RequestReason = c.resolveRequestReason(template, primaryBinding)
		detail.ApprovalReason = c.resolveApprovalReason(template, primaryBinding)
		detail.Notification = c.resolveNotification(template, primaryBinding)
	}

	return detail
}

// resolveClustersFromBinding resolves cluster names from a binding's spec
func (c *DebugSessionAPIController) resolveClustersFromBinding(binding *v1alpha1.DebugSessionClusterBinding, clusterMap map[string]*v1alpha1.ClusterConfig) []string {
	var result []string
	bindingID := fmt.Sprintf("%s/%s", binding.Namespace, binding.Name)

	// Add explicit clusters
	for _, clusterName := range binding.Spec.Clusters {
		if _, exists := clusterMap[clusterName]; exists {
			result = append(result, clusterName)
		}
	}

	c.log.Debugw("resolveClustersFromBinding: explicit clusters",
		"binding", bindingID,
		"explicitClusters", binding.Spec.Clusters,
		"matchedExplicitClusters", result,
	)

	// Add clusters matching selector
	if binding.Spec.ClusterSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err != nil {
			c.log.Warnw("resolveClustersFromBinding: failed to parse clusterSelector",
				"binding", bindingID,
				"error", err,
			)
		} else {
			selectorString := selector.String()
			c.log.Debugw("resolveClustersFromBinding: checking clusterSelector",
				"binding", bindingID,
				"selectorString", selectorString,
				"clusterMapSize", len(clusterMap),
			)
			for name, cc := range clusterMap {
				labelSet := labelSetFromMap(cc.Labels)
				matches := selector.Matches(labelSet)
				if matches {
					result = append(result, name)
					c.log.Debugw("resolveClustersFromBinding: cluster matched selector",
						"binding", bindingID,
						"cluster", name,
						"clusterLabels", cc.Labels,
					)
				}
			}
		}
	}

	c.log.Debugw("resolveClustersFromBinding: final result",
		"binding", bindingID,
		"resolvedClusters", result,
	)

	return result
}

// mergeConstraints merges template and binding constraints
func (c *DebugSessionAPIController) mergeConstraints(templateConstraints *v1alpha1.DebugSessionConstraints, binding *v1alpha1.DebugSessionClusterBinding) *v1alpha1.DebugSessionConstraints {
	if binding == nil || binding.Spec.Constraints == nil {
		return templateConstraints
	}
	if templateConstraints == nil {
		return binding.Spec.Constraints
	}

	// Binding constraints override template constraints
	merged := templateConstraints.DeepCopy()
	bc := binding.Spec.Constraints

	if bc.MaxDuration != "" {
		merged.MaxDuration = bc.MaxDuration
	}
	if bc.DefaultDuration != "" {
		merged.DefaultDuration = bc.DefaultDuration
	}
	if bc.MaxConcurrentSessions > 0 {
		merged.MaxConcurrentSessions = bc.MaxConcurrentSessions
	}
	if bc.MaxRenewals != nil {
		merged.MaxRenewals = bc.MaxRenewals
	}

	return merged
}

// getSchedulingConstraintsSummary builds a summary of scheduling constraints
func (c *DebugSessionAPIController) getSchedulingConstraintsSummary(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *SchedulingConstraintsSummary {
	var sc *v1alpha1.SchedulingConstraints

	// Binding constraints take precedence
	if binding != nil && binding.Spec.SchedulingConstraints != nil {
		sc = binding.Spec.SchedulingConstraints
	} else if template.Spec.SchedulingConstraints != nil {
		sc = template.Spec.SchedulingConstraints
	}

	if sc == nil {
		return nil
	}

	return buildConstraintsSummary(sc)
}

// buildConstraintsSummary builds a SchedulingConstraintsSummary from SchedulingConstraints.
// Shared between cluster-level and per-option constraint summaries.
func buildConstraintsSummary(sc *v1alpha1.SchedulingConstraints) *SchedulingConstraintsSummary {
	if sc == nil {
		return nil
	}

	summary := &SchedulingConstraintsSummary{
		NodeSelector:     sc.NodeSelector,
		DeniedNodeLabels: sc.DeniedNodeLabels,
	}

	// Convert tolerations to summaries
	if len(sc.Tolerations) > 0 {
		summary.Tolerations = make([]TolerationSummary, 0, len(sc.Tolerations))
		for _, t := range sc.Tolerations {
			summary.Tolerations = append(summary.Tolerations, TolerationSummary{
				Key:      t.Key,
				Operator: string(t.Operator),
				Value:    t.Value,
				Effect:   string(t.Effect),
			})
		}
	}

	// Build summary string
	var parts []string
	if len(sc.DeniedNodeLabels) > 0 {
		parts = append(parts, "Some node labels are restricted")
	}
	if len(sc.NodeSelector) > 0 {
		parts = append(parts, "Specific node labels required")
	}
	if len(sc.DeniedNodes) > 0 {
		parts = append(parts, "Some nodes are denied")
	}
	if len(sc.Tolerations) > 0 {
		parts = append(parts, "Custom tolerations applied")
	}
	if len(parts) > 0 {
		summary.Summary = strings.Join(parts, "; ")
	}

	return summary
}

// resolveSchedulingOptions resolves scheduling options from binding or template
func (c *DebugSessionAPIController) resolveSchedulingOptions(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *SchedulingOptionsResponse {
	var so *v1alpha1.SchedulingOptions

	// Binding options take precedence
	if binding != nil && binding.Spec.SchedulingOptions != nil {
		so = binding.Spec.SchedulingOptions
	} else if template.Spec.SchedulingOptions != nil {
		so = template.Spec.SchedulingOptions
	}

	if so == nil {
		return nil
	}

	response := &SchedulingOptionsResponse{
		Required: so.Required,
		Options:  make([]SchedulingOptionResponse, 0, len(so.Options)),
	}

	for _, opt := range so.Options {
		response.Options = append(response.Options, SchedulingOptionResponse{
			Name:                  opt.Name,
			DisplayName:           opt.DisplayName,
			Description:           opt.Description,
			Default:               opt.Default,
			SchedulingConstraints: buildConstraintsSummary(opt.SchedulingConstraints),
		})
	}

	return response
}

// resolveNamespaceConstraints resolves namespace constraints from binding or template
func (c *DebugSessionAPIController) resolveNamespaceConstraints(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *NamespaceConstraintsResponse {
	var nc *v1alpha1.NamespaceConstraints

	// Binding constraints take precedence
	if binding != nil && binding.Spec.NamespaceConstraints != nil {
		nc = binding.Spec.NamespaceConstraints
	} else if template.Spec.NamespaceConstraints != nil {
		nc = template.Spec.NamespaceConstraints
	}

	if nc == nil {
		return nil
	}

	response := &NamespaceConstraintsResponse{
		DefaultNamespace:   nc.DefaultNamespace,
		AllowUserNamespace: nc.AllowUserNamespace,
	}

	if nc.AllowedNamespaces != nil {
		response.AllowedPatterns = nc.AllowedNamespaces.Patterns
		response.AllowedLabelSelectors = convertSelectorTerms(nc.AllowedNamespaces.SelectorTerms)
	}
	if nc.DeniedNamespaces != nil {
		response.DeniedPatterns = nc.DeniedNamespaces.Patterns
		response.DeniedLabelSelectors = convertSelectorTerms(nc.DeniedNamespaces.SelectorTerms)
	}

	return response
}

// resolveImpersonation resolves impersonation settings from binding or template
func (c *DebugSessionAPIController) resolveImpersonation(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *ImpersonationSummary {
	var imp *v1alpha1.ImpersonationConfig

	// Binding impersonation takes precedence
	if binding != nil && binding.Spec.Impersonation != nil {
		imp = binding.Spec.Impersonation
	} else if template.Spec.Impersonation != nil {
		imp = template.Spec.Impersonation
	}

	if imp == nil {
		return nil
	}

	summary := &ImpersonationSummary{
		Enabled: true,
	}

	if imp.ServiceAccountRef != nil {
		summary.ServiceAccount = imp.ServiceAccountRef.Name
		summary.Namespace = imp.ServiceAccountRef.Namespace
	}

	return summary
}

// resolveApproval resolves approval requirements from binding, template, or ClusterConfig.
// It also evaluates AutoApproveFor conditions to determine if the current user
// would be auto-approved, matching the logic in the reconciler's requiresApproval().
func (c *DebugSessionAPIController) resolveApproval(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding, cc *v1alpha1.ClusterConfig, userGroups []string) *ApprovalInfo {
	info := &ApprovalInfo{}

	var autoApproveFor *v1alpha1.AutoApproveConfig

	// Check binding approvers first
	if binding != nil && binding.Spec.Approvers != nil {
		info.Required = len(binding.Spec.Approvers.Groups) > 0 || len(binding.Spec.Approvers.Users) > 0
		info.ApproverGroups = binding.Spec.Approvers.Groups
		info.ApproverUsers = binding.Spec.Approvers.Users
		autoApproveFor = binding.Spec.Approvers.AutoApproveFor
	} else if template.Spec.Approvers != nil {
		// Check template approvers
		info.Required = len(template.Spec.Approvers.Groups) > 0 || len(template.Spec.Approvers.Users) > 0
		info.ApproverGroups = template.Spec.Approvers.Groups
		info.ApproverUsers = template.Spec.Approvers.Users
		autoApproveFor = template.Spec.Approvers.AutoApproveFor
	}

	// Evaluate auto-approve conditions if approval is required
	if info.Required && autoApproveFor != nil {
		info.CanAutoApprove = c.evaluateAutoApprove(autoApproveFor, cc.Name, userGroups)
	}

	return info
}

// evaluateAutoApprove checks if auto-approve conditions are met for the given cluster and user groups.
// This mirrors the reconciler's checkAutoApprove() logic for API preview purposes.
func (c *DebugSessionAPIController) evaluateAutoApprove(autoApprove *v1alpha1.AutoApproveConfig, clusterName string, userGroups []string) bool {
	// Check cluster patterns
	for _, pattern := range autoApprove.Clusters {
		if matched, _ := filepath.Match(pattern, clusterName); matched {
			return true
		}
	}

	// Check group matches
	for _, autoApproveGroup := range autoApprove.Groups {
		for _, userGroup := range userGroups {
			if userGroup == autoApproveGroup {
				return true
			}
		}
	}

	return false
}

// resolveClusterStatus returns cluster health status
func (c *DebugSessionAPIController) resolveClusterStatus(cc *v1alpha1.ClusterConfig) *ClusterStatusInfo {
	status := &ClusterStatusInfo{}

	// Check for Ready condition
	for _, cond := range cc.Status.Conditions {
		if cond.Type == string(v1alpha1.ClusterConfigConditionReady) {
			status.Healthy = cond.Status == metav1.ConditionTrue
			status.LastChecked = cond.LastTransitionTime.Format("2006-01-02T15:04:05Z")
			break
		}
	}

	return status
}

// resolveRequiredAuxResourceCategories returns required auxiliary resource categories
// from binding or template configuration.
func (c *DebugSessionAPIController) resolveRequiredAuxResourceCategories(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) []string {
	// Collect categories from both template and binding
	categories := make(map[string]bool)

	// Template required categories take precedence
	if template.Spec.RequiredAuxiliaryResourceCategories != nil {
		for _, cat := range template.Spec.RequiredAuxiliaryResourceCategories {
			categories[cat] = true
		}
	}

	// Binding required categories are added
	if binding != nil && len(binding.Spec.RequiredAuxiliaryResourceCategories) > 0 {
		for _, cat := range binding.Spec.RequiredAuxiliaryResourceCategories {
			categories[cat] = true
		}
	}

	if len(categories) == 0 {
		return nil
	}

	result := make([]string, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}
	return result
}

// resolveRequestReason resolves request reason configuration from binding or template
func (c *DebugSessionAPIController) resolveRequestReason(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *ReasonConfigInfo {
	// Binding overrides template
	if binding != nil && binding.Spec.RequestReason != nil {
		return &ReasonConfigInfo{
			Mandatory:        binding.Spec.RequestReason.Mandatory,
			Description:      binding.Spec.RequestReason.Description,
			MinLength:        binding.Spec.RequestReason.MinLength,
			MaxLength:        binding.Spec.RequestReason.MaxLength,
			SuggestedReasons: binding.Spec.RequestReason.SuggestedReasons,
		}
	}

	// Fall back to template
	if template.Spec.RequestReason != nil {
		return &ReasonConfigInfo{
			Mandatory:        template.Spec.RequestReason.Mandatory,
			Description:      template.Spec.RequestReason.Description,
			MinLength:        template.Spec.RequestReason.MinLength,
			MaxLength:        template.Spec.RequestReason.MaxLength,
			SuggestedReasons: template.Spec.RequestReason.SuggestedReasons,
		}
	}

	return nil
}

// resolveApprovalReason resolves approval reason configuration from binding or template
func (c *DebugSessionAPIController) resolveApprovalReason(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *ReasonConfigInfo {
	// Binding overrides template
	if binding != nil && binding.Spec.ApprovalReason != nil {
		return &ReasonConfigInfo{
			Mandatory:   binding.Spec.ApprovalReason.Mandatory,
			Description: binding.Spec.ApprovalReason.Description,
		}
	}

	// Fall back to template
	if template.Spec.ApprovalReason != nil {
		return &ReasonConfigInfo{
			Mandatory:   template.Spec.ApprovalReason.Mandatory,
			Description: template.Spec.ApprovalReason.Description,
		}
	}

	return nil
}

// resolveNotification resolves notification configuration from binding or template
func (c *DebugSessionAPIController) resolveNotification(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *NotificationConfigInfo {
	// Binding overrides template
	if binding != nil && binding.Spec.Notification != nil {
		return &NotificationConfigInfo{
			Enabled: binding.Spec.Notification.Enabled,
		}
	}

	// Fall back to template
	if template.Spec.Notification != nil {
		return &NotificationConfigInfo{
			Enabled: template.Spec.Notification.Enabled,
		}
	}

	return nil
}

type notificationEvent string

const (
	notificationEventRequest  notificationEvent = "request"
	notificationEventApproval notificationEvent = "approval"
	notificationEventExpiry   notificationEvent = "expiry"
)

func resolveNotificationConfig(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) *v1alpha1.DebugSessionNotificationConfig {
	if binding != nil && binding.Spec.Notification != nil {
		return binding.Spec.Notification
	}
	return template.Spec.Notification
}

func shouldSendNotification(cfg *v1alpha1.DebugSessionNotificationConfig, event notificationEvent) bool {
	if cfg == nil {
		return true
	}
	if !cfg.Enabled {
		return false
	}
	switch event {
	case notificationEventRequest:
		return cfg.NotifyOnRequest
	case notificationEventApproval:
		return cfg.NotifyOnApproval
	case notificationEventExpiry:
		return cfg.NotifyOnExpiry
	default:
		return true
	}
}

func buildNotificationRecipients(base []string, cfg *v1alpha1.DebugSessionNotificationConfig) []string {
	if cfg == nil && len(base) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(base))
	var recipients []string
	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		recipients = append(recipients, addr)
	}

	for _, addr := range base {
		add(addr)
	}
	if cfg != nil {
		for _, addr := range cfg.AdditionalRecipients {
			add(addr)
		}
		if cfg.ExcludedRecipients != nil && len(cfg.ExcludedRecipients.Users) > 0 {
			excluded := make(map[string]struct{}, len(cfg.ExcludedRecipients.Users))
			for _, u := range cfg.ExcludedRecipients.Users {
				excluded[u] = struct{}{}
			}
			filtered := recipients[:0]
			for _, addr := range recipients {
				if _, blocked := excluded[addr]; blocked {
					continue
				}
				filtered = append(filtered, addr)
			}
			recipients = filtered
		}
	}

	return recipients
}

func (c *DebugSessionAPIController) resolveNotificationConfigForSession(ctx context.Context, session *v1alpha1.DebugSession) *v1alpha1.DebugSessionNotificationConfig {
	if session == nil {
		return nil
	}

	if session.Spec.TemplateRef == "" {
		return nil
	}

	// Resolve template
	template := &v1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.TemplateRef}, template); err != nil {
		c.log.Debugw("Failed to load template for notification config", "template", session.Spec.TemplateRef, "error", err)
		return nil
	}

	// Resolve binding if referenced
	var binding *v1alpha1.DebugSessionClusterBinding
	if session.Spec.BindingRef != nil {
		resolved := &v1alpha1.DebugSessionClusterBinding{}
		if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: session.Spec.BindingRef.Name, Namespace: session.Spec.BindingRef.Namespace}, resolved); err != nil {
			c.log.Debugw("Failed to load binding for notification config", "binding", session.Spec.BindingRef.Name, "error", err)
		} else {
			binding = resolved
		}
	}

	return resolveNotificationConfig(template, binding)
}

// labelSetFromMap creates a labels.Set from a map for selector matching
func labelSetFromMap(m map[string]string) labels.Set {
	if m == nil {
		return labels.Set{}
	}
	return labels.Set(m)
}

// handleListPodTemplates returns available debug pod templates
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) handleListPodTemplates(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	templateList := &v1alpha1.DebugPodTemplateList{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.reader().List(apiCtx, templateList); err != nil {
		reqLog.Errorw("Failed to list debug pod templates", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list pod templates")
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
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) handleGetPodTemplate(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)
	name := ctx.Param("name")

	if name == "" {
		apiresponses.RespondBadRequest(ctx, "template name is required")
		return
	}

	template := &v1alpha1.DebugPodTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	if err := c.reader().Get(apiCtx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "pod template not found")
			return
		}
		reqLog.Errorw("Failed to get pod template", "name", name, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get pod template")
		return
	}

	// Build response using same flat format as list endpoint
	containerCount := 0
	if template.Spec.Template.Spec.Containers != nil {
		containerCount = len(template.Spec.Template.Spec.Containers)
	}
	resp := DebugPodTemplateResponse{
		Name:        template.Name,
		DisplayName: template.Spec.DisplayName,
		Description: template.Spec.Description,
		Containers:  containerCount,
	}

	ctx.JSON(http.StatusOK, resp)
}

// isUserAuthorizedToApprove checks if the user is authorized to approve/reject a debug session
// The user must be in one of the approver groups/users defined in the session's template or binding.
// Additionally, the requester of the session is not allowed to self-approve.
func (c *DebugSessionAPIController) isUserAuthorizedToApprove(ctx context.Context, session *v1alpha1.DebugSession, username string, userGroupsInterface interface{}) bool {
	// Block self-approval: the user who requested the session cannot approve it
	if session.Spec.RequestedBy == username {
		c.log.Infow("Blocking self-approval attempt",
			"session", session.Name, "requester", session.Spec.RequestedBy, "approver", username)
		return false
	}

	// First try to find the binding that granted this session - it may have its own approvers
	bindings := &v1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindings); err == nil {
		for i := range bindings.Items {
			binding := &bindings.Items[i]
			// Check if this binding applies to this session
			if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name == session.Spec.TemplateRef {
				// Check if this binding covers the session's cluster
				for _, cluster := range binding.Spec.Clusters {
					if matchPattern(cluster, session.Spec.Cluster) {
						// Found a matching binding - check if it has approvers
						if binding.Spec.Approvers != nil && (len(binding.Spec.Approvers.Users) > 0 || len(binding.Spec.Approvers.Groups) > 0) {
							return c.checkApproverAuthorization(binding.Spec.Approvers, username, userGroupsInterface)
						}
						break
					}
				}
			}
		}
	}

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

// matchPattern checks if a string matches a glob pattern.
// Supports patterns like:
//   - "*" matches everything
//   - "prefix*" matches strings starting with prefix
//   - "*suffix" matches strings ending with suffix
//   - "*.tst.*" matches strings containing ".tst."
//   - "dev-*" matches "dev-cluster1"
//
// Uses utils.GlobMatch for pattern matching. If the pattern is invalid (e.g., unclosed
// bracket), falls back to exact string comparison for backward compatibility.
func matchPattern(pattern, value string) bool {
	matched, err := utils.GlobMatch(pattern, value)
	if err != nil {
		// Invalid glob pattern — fall back to exact match for backward compatibility.
		// This preserves the previous behavior where patterns like "[unclosed" could
		// still match the literal string.
		return pattern == value
	}
	return matched
}

// convertSelectorTerms converts v1alpha1 selector terms to API response format
func convertSelectorTerms(terms []v1alpha1.NamespaceSelectorTerm) []NamespaceSelectorTermResponse {
	if len(terms) == 0 {
		return nil
	}
	result := make([]NamespaceSelectorTermResponse, 0, len(terms))
	for _, term := range terms {
		respTerm := NamespaceSelectorTermResponse{
			MatchLabels: term.MatchLabels,
		}
		if len(term.MatchExpressions) > 0 {
			respTerm.MatchExpressions = make([]NamespaceSelectorRequirementResponse, 0, len(term.MatchExpressions))
			for _, expr := range term.MatchExpressions {
				respTerm.MatchExpressions = append(respTerm.MatchExpressions, NamespaceSelectorRequirementResponse{
					Key:      expr.Key,
					Operator: string(expr.Operator),
					Values:   expr.Values,
				})
			}
		}
		result = append(result, respTerm)
	}
	return result
}

// resolveTargetNamespace validates and resolves the target namespace for debug pods.
// Returns the resolved namespace or an error if the requested namespace is not allowed.
// If a binding is provided and has namespace constraints, those constraints are used to extend
// or override the template's constraints (e.g., binding.AllowUserNamespace=true overrides template's false).
func (c *DebugSessionAPIController) resolveTargetNamespace(template *v1alpha1.DebugSessionTemplate, requestedNamespace string, binding *v1alpha1.DebugSessionClusterBinding) (string, error) {
	// Start with template's namespace constraints
	nc := template.Spec.NamespaceConstraints

	// If binding has namespace constraints, use them to extend/override template's
	if binding != nil && binding.Spec.NamespaceConstraints != nil {
		nc = c.mergeNamespaceConstraints(template.Spec.NamespaceConstraints, binding.Spec.NamespaceConstraints)
		c.log.Debugw("Merged namespace constraints from binding",
			"template", template.Name,
			"binding", binding.Name,
			"bindingNamespace", binding.Namespace,
			"mergedAllowUserNamespace", nc != nil && nc.AllowUserNamespace,
			"mergedDefaultNamespace", func() string {
				if nc != nil {
					return nc.DefaultNamespace
				}
				return ""
			}(),
		)
	}

	c.log.Debugw("Resolving target namespace",
		"template", template.Name,
		"requestedNamespace", requestedNamespace,
		"hasNamespaceConstraints", nc != nil,
	)

	// If no namespace constraints, use default behavior
	if nc == nil {
		if requestedNamespace != "" {
			c.log.Debugw("No namespace constraints, using requested namespace",
				"template", template.Name,
				"resolvedNamespace", requestedNamespace,
			)
			return requestedNamespace, nil
		}
		c.log.Debugw("No namespace constraints, using default",
			"template", template.Name,
			"resolvedNamespace", "breakglass-debug",
		)
		return "breakglass-debug", nil // Default namespace
	}

	c.log.Debugw("Namespace constraints found",
		"template", template.Name,
		"allowUserNamespace", nc.AllowUserNamespace,
		"defaultNamespace", nc.DefaultNamespace,
		"hasAllowedNamespaces", nc.AllowedNamespaces != nil && !nc.AllowedNamespaces.IsEmpty(),
		"hasDeniedNamespaces", nc.DeniedNamespaces != nil && !nc.DeniedNamespaces.IsEmpty(),
	)

	// If user didn't request a specific namespace, use the default
	if requestedNamespace == "" {
		if nc.DefaultNamespace != "" {
			c.log.Debugw("No namespace requested, using template default",
				"template", template.Name,
				"resolvedNamespace", nc.DefaultNamespace,
			)
			return nc.DefaultNamespace, nil
		}
		c.log.Debugw("No namespace requested and no template default, using fallback",
			"template", template.Name,
			"resolvedNamespace", "breakglass-debug",
		)
		return "breakglass-debug", nil
	}

	// If the requested namespace matches the default, allow it even when user namespace selection is disabled.
	// This handles the case where the frontend sends the default namespace value in the request.
	if nc.DefaultNamespace != "" && requestedNamespace == nc.DefaultNamespace {
		c.log.Debugw("Requested namespace matches default, allowing",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"defaultNamespace", nc.DefaultNamespace,
		)
		return nc.DefaultNamespace, nil
	}

	// Check if user is allowed to specify a namespace
	if !nc.AllowUserNamespace {
		c.log.Debugw("User-specified namespace not allowed by template",
			"template", template.Name,
			"requestedNamespace", requestedNamespace,
			"allowUserNamespace", nc.AllowUserNamespace,
		)
		return "", fmt.Errorf("template does not allow user-specified namespaces")
	}

	// Validate against allowed namespaces
	if nc.AllowedNamespaces != nil && !nc.AllowedNamespaces.IsEmpty() {
		if !matchNamespaceFilter(requestedNamespace, nc.AllowedNamespaces) {
			c.log.Debugw("Namespace not in allowed list",
				"template", template.Name,
				"requestedNamespace", requestedNamespace,
				"allowedPatterns", nc.AllowedNamespaces.Patterns,
			)
			return "", fmt.Errorf("namespace '%s' is not in the allowed namespaces", requestedNamespace)
		}
	}

	// Validate against denied namespaces
	if nc.DeniedNamespaces != nil && !nc.DeniedNamespaces.IsEmpty() {
		if matchNamespaceFilter(requestedNamespace, nc.DeniedNamespaces) {
			c.log.Debugw("Namespace is in denied list",
				"template", template.Name,
				"requestedNamespace", requestedNamespace,
				"deniedPatterns", nc.DeniedNamespaces.Patterns,
			)
			return "", fmt.Errorf("namespace '%s' is explicitly denied", requestedNamespace)
		}
	}

	return requestedNamespace, nil
}

// mergeNamespaceConstraints merges template and binding namespace constraints.
// Binding constraints can extend what template allows (e.g., enable user namespaces).
// Returns a new NamespaceConstraints with merged values.
func (c *DebugSessionAPIController) mergeNamespaceConstraints(
	templateNC, bindingNC *v1alpha1.NamespaceConstraints,
) *v1alpha1.NamespaceConstraints {
	// If both are nil, return nil
	if templateNC == nil && bindingNC == nil {
		return nil
	}

	// If only one exists, use it
	if templateNC == nil {
		return bindingNC.DeepCopy()
	}
	if bindingNC == nil {
		return templateNC.DeepCopy()
	}

	// Merge both - binding extends template
	merged := templateNC.DeepCopy()

	// AllowUserNamespace: binding can enable it even if template disables
	if bindingNC.AllowUserNamespace {
		merged.AllowUserNamespace = true
	}

	// DefaultNamespace: binding can override template's default
	if bindingNC.DefaultNamespace != "" {
		merged.DefaultNamespace = bindingNC.DefaultNamespace
	}

	// AllowedNamespaces: binding can add to allowed list
	if bindingNC.AllowedNamespaces != nil && !bindingNC.AllowedNamespaces.IsEmpty() {
		if merged.AllowedNamespaces == nil {
			merged.AllowedNamespaces = bindingNC.AllowedNamespaces.DeepCopy()
		} else {
			// Merge patterns (union)
			patternSet := make(map[string]bool)
			for _, p := range merged.AllowedNamespaces.Patterns {
				patternSet[p] = true
			}
			for _, p := range bindingNC.AllowedNamespaces.Patterns {
				if !patternSet[p] {
					merged.AllowedNamespaces.Patterns = append(merged.AllowedNamespaces.Patterns, p)
				}
			}
		}
	}

	// DeniedNamespaces: take the intersection (more permissive for the user)
	// For simplicity, if binding specifies denied namespaces, use binding's (override)
	if bindingNC.DeniedNamespaces != nil && !bindingNC.DeniedNamespaces.IsEmpty() {
		merged.DeniedNamespaces = bindingNC.DeniedNamespaces.DeepCopy()
	}

	return merged
}

// matchNamespaceFilter checks if a namespace matches a NamespaceFilter.
// Only evaluates patterns; label selector matching requires runtime access to namespaces.
func matchNamespaceFilter(namespace string, filter *v1alpha1.NamespaceFilter) bool {
	if filter == nil || filter.IsEmpty() {
		return false
	}

	// Check patterns
	for _, pattern := range filter.Patterns {
		if matchPattern(pattern, namespace) {
			return true
		}
	}

	// Note: SelectorTerms require runtime namespace label access
	// For now, if only selector terms are specified, we allow it
	// (actual validation happens at deployment time)
	if len(filter.Patterns) == 0 && filter.HasSelectorTerms() {
		return true // Defer to runtime validation
	}

	return false
}

// resolveSchedulingConstraints validates and resolves the scheduling constraints.
// It merges the template's and binding's base constraints with the selected scheduling option.
// When a binding is provided, its base constraints are treated as mandatory additions
// on top of the template, and its scheduling options take precedence over the template's.
// Returns the merged constraints, the selected option name, and any error.
func (c *DebugSessionAPIController) resolveSchedulingConstraints(
	template *v1alpha1.DebugSessionTemplate,
	selectedOption string,
	binding *v1alpha1.DebugSessionClusterBinding,
) (*v1alpha1.SchedulingConstraints, string, error) {
	// Start with the template's base scheduling constraints and merge in binding-level
	// base constraints (which are documented as mandatory additions on top of the template).
	baseConstraints := template.Spec.SchedulingConstraints
	if binding != nil && binding.Spec.SchedulingConstraints != nil {
		baseConstraints = mergeSchedulingConstraints(baseConstraints, binding.Spec.SchedulingConstraints)
	}

	// Resolve effective scheduling options: binding takes precedence over template
	var effectiveOpts *v1alpha1.SchedulingOptions
	if binding != nil && binding.Spec.SchedulingOptions != nil {
		effectiveOpts = binding.Spec.SchedulingOptions
	} else if template.Spec.SchedulingOptions != nil {
		effectiveOpts = template.Spec.SchedulingOptions
	}

	// If no scheduling options defined (in template or binding), just return base constraints
	// Ignore any user-selected option since neither the template nor binding supports them.
	// This handles cases where the frontend sends a stale scheduling option
	// after switching to a template that doesn't have scheduling options.
	if effectiveOpts == nil || len(effectiveOpts.Options) == 0 {
		if selectedOption != "" {
			c.log.Debugw("Ignoring scheduling option - no options defined in template or binding",
				"template", template.Name,
				"selectedOption", selectedOption,
			)
		}
		return baseConstraints, "", nil
	}

	opts := effectiveOpts

	// If required and no option selected, find the default
	if selectedOption == "" {
		if opts.Required {
			// Find the default option
			for _, opt := range opts.Options {
				if opt.Default {
					selectedOption = opt.Name
					break
				}
			}
			if selectedOption == "" {
				return nil, "", fmt.Errorf("scheduling option is required but none selected and no default defined")
			}
		} else {
			// Not required, no selection - use base constraints only
			return baseConstraints, "", nil
		}
	}

	// Find the selected option
	var selectedOpt *v1alpha1.SchedulingOption
	for i := range opts.Options {
		if opts.Options[i].Name == selectedOption {
			selectedOpt = &opts.Options[i]
			break
		}
	}

	if selectedOpt == nil {
		return nil, "", fmt.Errorf("scheduling option '%s' not found in template or binding", selectedOption)
	}

	// Merge base constraints with option's constraints
	merged := mergeSchedulingConstraints(baseConstraints, selectedOpt.SchedulingConstraints)

	return merged, selectedOption, nil
}

// mergeSchedulingConstraints merges base constraints with option constraints.
// Option constraints override base constraints for conflicting keys.
func mergeSchedulingConstraints(base, option *v1alpha1.SchedulingConstraints) *v1alpha1.SchedulingConstraints {
	if base == nil && option == nil {
		return nil
	}
	if base == nil {
		return option.DeepCopy()
	}
	if option == nil {
		return base.DeepCopy()
	}

	merged := base.DeepCopy()

	// Merge nodeSelector (option overrides base on conflict)
	if len(option.NodeSelector) > 0 {
		if merged.NodeSelector == nil {
			merged.NodeSelector = make(map[string]string)
		}
		for k, v := range option.NodeSelector {
			merged.NodeSelector[k] = v
		}
	}

	// Merge deniedNodes (additive)
	if len(option.DeniedNodes) > 0 {
		merged.DeniedNodes = append(merged.DeniedNodes, option.DeniedNodes...)
	}

	// Merge deniedNodeLabels (option overrides base on conflict)
	if len(option.DeniedNodeLabels) > 0 {
		if merged.DeniedNodeLabels == nil {
			merged.DeniedNodeLabels = make(map[string]string)
		}
		for k, v := range option.DeniedNodeLabels {
			merged.DeniedNodeLabels[k] = v
		}
	}

	// Merge tolerations (additive)
	if len(option.Tolerations) > 0 {
		merged.Tolerations = append(merged.Tolerations, option.Tolerations...)
	}

	// For node affinity, option's required affinity is ANDed with base
	if option.RequiredNodeAffinity != nil {
		if merged.RequiredNodeAffinity == nil {
			merged.RequiredNodeAffinity = option.RequiredNodeAffinity.DeepCopy()
		} else {
			// AND the node selector terms
			merged.RequiredNodeAffinity.NodeSelectorTerms = append(
				merged.RequiredNodeAffinity.NodeSelectorTerms,
				option.RequiredNodeAffinity.NodeSelectorTerms...,
			)
		}
	}

	// Preferred affinities are additive
	if len(option.PreferredNodeAffinity) > 0 {
		merged.PreferredNodeAffinity = append(merged.PreferredNodeAffinity, option.PreferredNodeAffinity...)
	}

	// Pod anti-affinity is additive
	if len(option.RequiredPodAntiAffinity) > 0 {
		merged.RequiredPodAntiAffinity = append(merged.RequiredPodAntiAffinity, option.RequiredPodAntiAffinity...)
	}
	if len(option.PreferredPodAntiAffinity) > 0 {
		merged.PreferredPodAntiAffinity = append(merged.PreferredPodAntiAffinity, option.PreferredPodAntiAffinity...)
	}

	return merged
}

// resolveClusterPatterns expands cluster patterns (e.g., "*", "prod-*") to actual cluster names.
// Returns empty slice if no clusters are available for resolution.
func resolveClusterPatterns(patterns []string, allClusters []string) []string {
	if len(patterns) == 0 {
		return nil
	}
	if len(allClusters) == 0 {
		// No clusters to resolve against - return empty instead of patterns
		// This ensures the frontend shows "no clusters available" instead of pattern strings
		return nil
	}

	// Use a map to deduplicate
	resolved := make(map[string]struct{})
	for _, pattern := range patterns {
		for _, cluster := range allClusters {
			if matchPattern(pattern, cluster) {
				resolved[cluster] = struct{}{}
			}
		}
	}

	// Convert map to sorted slice for consistent output
	result := make([]string, 0, len(resolved))
	for cluster := range resolved {
		result = append(result, cluster)
	}
	// Sort for consistent ordering
	sort.Strings(result)
	return result
}

// sendDebugSessionRequestEmail sends email notification to approvers when a debug session is created
func (c *DebugSessionAPIController) sendDebugSessionRequestEmail(ctx context.Context, session *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) {
	if c.disableEmail || c.mailService == nil || !c.mailService.IsEnabled() {
		return
	}

	notificationCfg := resolveNotificationConfig(template, binding)
	if !shouldSendNotification(notificationCfg, notificationEventRequest) {
		c.log.Debugw("Debug session request email disabled by notification settings", "session", session.Name)
		return
	}

	// Collect approver emails
	var approverEmails []string
	if template.Spec.Approvers != nil {
		approverEmails = append(approverEmails, template.Spec.Approvers.Users...)
	}

	approverEmails = buildNotificationRecipients(approverEmails, notificationCfg)

	if len(approverEmails) == 0 {
		c.log.Debugw("No approvers configured for debug session template, skipping request email", "session", session.Name, "template", template.Name)
		return
	}

	// Use display name if available, fallback to username
	requesterName := session.Spec.RequestedByDisplayName
	if requesterName == "" {
		requesterName = session.Spec.RequestedBy
	}

	// Use email if available, fallback to username
	requesterEmail := session.Spec.RequestedByEmail
	if requesterEmail == "" {
		requesterEmail = session.Spec.RequestedBy
	}

	params := mail.DebugSessionRequestMailParams{
		RequesterName:     requesterName,
		RequesterEmail:    requesterEmail,
		RequestedAt:       session.CreationTimestamp.Format(time.RFC3339),
		SessionID:         session.Name,
		Cluster:           session.Spec.Cluster,
		TemplateName:      session.Spec.TemplateRef,
		Namespace:         session.Namespace,
		RequestedDuration: session.Spec.RequestedDuration,
		Reason:            session.Spec.Reason,
		URL:               fmt.Sprintf("%s/debug-sessions", c.baseURL),
		BrandingName:      c.brandingName,
	}

	body, err := mail.RenderDebugSessionRequest(params)
	if err != nil {
		c.log.Errorw("Failed to render debug session request email", "session", session.Name, "error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Debug Session Request: %s on %s", c.brandingName, requesterName, session.Spec.Cluster)
	if err := c.mailService.Enqueue(session.Name, approverEmails, subject, body); err != nil {
		c.log.Errorw("Failed to enqueue debug session request email", "session", session.Name, "error", err)
	} else {
		c.log.Infow("Debug session request email queued", "session", session.Name, "approvers", len(approverEmails))
	}
}

// sendDebugSessionApprovalEmail sends email notification to requester when a debug session is approved
func (c *DebugSessionAPIController) sendDebugSessionApprovalEmail(ctx context.Context, session *v1alpha1.DebugSession) {
	if c.disableEmail || c.mailService == nil || !c.mailService.IsEnabled() {
		return
	}

	notificationCfg := c.resolveNotificationConfigForSession(ctx, session)
	if !shouldSendNotification(notificationCfg, notificationEventApproval) {
		c.log.Debugw("Debug session approval email disabled by notification settings", "session", session.Name)
		return
	}

	// Send to the requester - use email field if available, fallback to requestedBy
	recipientEmail := session.Spec.RequestedByEmail
	if recipientEmail == "" {
		recipientEmail = session.Spec.RequestedBy
	}
	// Skip if no valid email (must contain @)
	if !strings.Contains(recipientEmail, "@") {
		c.log.Warnw("Skipping approval email - no valid email address", "session", session.Name, "recipient", recipientEmail)
		return
	}
	recipients := buildNotificationRecipients([]string{recipientEmail}, notificationCfg)

	approvedAt := ""
	expiresAt := ""
	approverName := ""
	approvalReason := ""
	if session.Status.Approval != nil {
		if session.Status.Approval.ApprovedAt != nil {
			approvedAt = session.Status.Approval.ApprovedAt.Format(time.RFC3339)
		}
		approverName = session.Status.Approval.ApprovedBy
		approvalReason = session.Status.Approval.Reason
	}
	if session.Status.ExpiresAt != nil {
		expiresAt = session.Status.ExpiresAt.Format(time.RFC3339)
	}

	// Use display name if available, fallback to username
	requesterName := session.Spec.RequestedByDisplayName
	if requesterName == "" {
		requesterName = session.Spec.RequestedBy
	}

	params := mail.DebugSessionApprovedMailParams{
		RequesterName:  requesterName,
		RequesterEmail: recipientEmail,
		SessionID:      session.Name,
		Cluster:        session.Spec.Cluster,
		TemplateName:   session.Spec.TemplateRef,
		Namespace:      session.Namespace,
		ApproverName:   approverName,
		ApproverEmail:  approverName,
		ApprovedAt:     approvedAt,
		ApprovalReason: approvalReason,
		Duration:       session.Spec.RequestedDuration,
		ExpiresAt:      expiresAt,
		BrandingName:   c.brandingName,
	}

	body, err := mail.RenderDebugSessionApproved(params)
	if err != nil {
		c.log.Errorw("Failed to render debug session approval email", "session", session.Name, "error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Debug Session Approved: %s", c.brandingName, session.Name)
	if err := c.mailService.Enqueue(session.Name, recipients, subject, body); err != nil {
		c.log.Errorw("Failed to enqueue debug session approval email", "session", session.Name, "error", err)
	} else {
		c.log.Infow("Debug session approval email queued", "session", session.Name)
	}
}

// sendDebugSessionRejectionEmail sends email notification to requester when a debug session is rejected
func (c *DebugSessionAPIController) sendDebugSessionRejectionEmail(ctx context.Context, session *v1alpha1.DebugSession) {
	if c.disableEmail || c.mailService == nil || !c.mailService.IsEnabled() {
		return
	}

	notificationCfg := c.resolveNotificationConfigForSession(ctx, session)
	if !shouldSendNotification(notificationCfg, notificationEventApproval) {
		c.log.Debugw("Debug session rejection email disabled by notification settings", "session", session.Name)
		return
	}

	// Send to the requester - use email field if available, fallback to requestedBy
	recipientEmail := session.Spec.RequestedByEmail
	if recipientEmail == "" {
		recipientEmail = session.Spec.RequestedBy
	}
	// Skip if no valid email (must contain @)
	if !strings.Contains(recipientEmail, "@") {
		c.log.Warnw("Skipping rejection email - no valid email address", "session", session.Name, "recipient", recipientEmail)
		return
	}
	recipients := buildNotificationRecipients([]string{recipientEmail}, notificationCfg)

	rejectedAt := ""
	rejectorName := ""
	rejectionReason := ""
	if session.Status.Approval != nil {
		if session.Status.Approval.RejectedAt != nil {
			rejectedAt = session.Status.Approval.RejectedAt.Format(time.RFC3339)
		}
		rejectorName = session.Status.Approval.RejectedBy
		rejectionReason = session.Status.Approval.Reason
	}

	// Use display name if available, fallback to username
	requesterName := session.Spec.RequestedByDisplayName
	if requesterName == "" {
		requesterName = session.Spec.RequestedBy
	}

	params := mail.DebugSessionRejectedMailParams{
		RequesterName:   requesterName,
		RequesterEmail:  recipientEmail,
		SessionID:       session.Name,
		Cluster:         session.Spec.Cluster,
		TemplateName:    session.Spec.TemplateRef,
		Namespace:       session.Namespace,
		RejectorName:    rejectorName,
		RejectorEmail:   rejectorName,
		RejectedAt:      rejectedAt,
		RejectionReason: rejectionReason,
		BrandingName:    c.brandingName,
	}

	body, err := mail.RenderDebugSessionRejected(params)
	if err != nil {
		c.log.Errorw("Failed to render debug session rejection email", "session", session.Name, "error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Debug Session Rejected: %s", c.brandingName, session.Name)
	if err := c.mailService.Enqueue(session.Name, recipients, subject, body); err != nil {
		c.log.Errorw("Failed to enqueue debug session rejection email", "session", session.Name, "error", err)
	} else {
		c.log.Infow("Debug session rejection email queued", "session", session.Name)
	}
}

// sendDebugSessionCreatedEmail sends email confirmation to requester when a debug session is created
func (c *DebugSessionAPIController) sendDebugSessionCreatedEmail(ctx context.Context, session *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) {
	if c.disableEmail || c.mailService == nil || !c.mailService.IsEnabled() {
		return
	}

	notificationCfg := resolveNotificationConfig(template, binding)
	if !shouldSendNotification(notificationCfg, notificationEventRequest) {
		c.log.Debugw("Debug session created email disabled by notification settings", "session", session.Name)
		return
	}

	// Send to the requester - use email field if available, fallback to requestedBy
	recipientEmail := session.Spec.RequestedByEmail
	if recipientEmail == "" {
		recipientEmail = session.Spec.RequestedBy
	}
	// Skip if no valid email (must contain @)
	if !strings.Contains(recipientEmail, "@") {
		c.log.Warnw("Skipping session created email - no valid email address", "session", session.Name, "recipient", recipientEmail)
		return
	}
	recipients := buildNotificationRecipients([]string{recipientEmail}, notificationCfg)

	// Use display name if available, fallback to username
	requesterName := session.Spec.RequestedByDisplayName
	if requesterName == "" {
		requesterName = session.Spec.RequestedBy
	}

	params := mail.DebugSessionCreatedMailParams{
		RequesterName:     requesterName,
		RequesterEmail:    recipientEmail,
		SessionID:         session.Name,
		Cluster:           session.Spec.Cluster,
		TemplateName:      session.Spec.TemplateRef,
		Namespace:         session.Namespace,
		RequestedDuration: session.Spec.RequestedDuration,
		Reason:            session.Spec.Reason,
		RequestedAt:       session.CreationTimestamp.Format(time.RFC3339),
		RequiresApproval:  template.Spec.Approvers != nil && len(template.Spec.Approvers.Users) > 0,
		URL:               fmt.Sprintf("%s/debug-sessions/%s", c.baseURL, session.Name),
		BrandingName:      c.brandingName,
	}

	body, err := mail.RenderDebugSessionCreated(params)
	if err != nil {
		c.log.Errorw("Failed to render debug session created email", "session", session.Name, "error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Debug Session Created: %s", c.brandingName, session.Name)
	if err := c.mailService.Enqueue(session.Name, recipients, subject, body); err != nil {
		c.log.Errorw("Failed to enqueue debug session created email", "session", session.Name, "error", err)
	} else {
		c.log.Infow("Debug session created email queued", "session", session.Name, "requester", session.Spec.RequestedBy)
	}
}

// emitDebugSessionAuditEvent emits an audit event for debug session lifecycle changes
func (c *DebugSessionAPIController) emitDebugSessionAuditEvent(ctx context.Context, eventType audit.EventType, session *v1alpha1.DebugSession, user string, message string) {
	if c.auditService == nil || !c.auditService.IsEnabled() {
		return
	}

	event := &audit.Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Actor: audit.Actor{
			User:   user,
			Groups: nil, // Groups not available in this context
		},
		Target: audit.Target{
			Kind:      "DebugSession",
			Name:      session.Name,
			Namespace: session.Namespace,
			Cluster:   session.Spec.Cluster,
		},
		RequestContext: &audit.RequestContext{
			SessionName: session.Name,
		},
		Details: map[string]interface{}{
			"message":     message,
			"cluster":     session.Spec.Cluster,
			"templateRef": session.Spec.TemplateRef,
			"requestedBy": session.Spec.RequestedBy,
			"state":       string(session.Status.State),
		},
	}

	c.auditService.Emit(ctx, event)
}

// handleInjectEphemeralContainer injects a debug container into an existing pod
func (c *DebugSessionAPIController) handleInjectEphemeralContainer(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	sessionName := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	var req InjectEphemeralContainerRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	// Get the debug session
	session, err := c.getDebugSessionByName(apiCtx, sessionName, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Verify session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not active, current state: %s", session.Status.State))
		return
	}

	// Verify user is a participant
	if !c.isUserParticipant(session, currentUser.(string)) {
		apiresponses.RespondForbidden(ctx, "user is not a participant of this session")
		return
	}

	// Verify template supports kubectl-debug mode
	if session.Status.ResolvedTemplate == nil ||
		(session.Status.ResolvedTemplate.Mode != v1alpha1.DebugSessionModeKubectlDebug &&
			session.Status.ResolvedTemplate.Mode != v1alpha1.DebugSessionModeHybrid) {
		apiresponses.RespondBadRequest(ctx, "session template does not support kubectl-debug mode")
		return
	}

	// Create kubectl debug handler
	handler := NewKubectlDebugHandler(c.client, &clusterClientAdapter{ccProvider: c.ccProvider})

	// Validate the request
	capabilities := extractCapabilities(req.SecurityContext)
	runAsNonRoot := extractRunAsNonRoot(req.SecurityContext)
	if err := handler.ValidateEphemeralContainerRequest(apiCtx, session, req.Namespace, req.PodName, req.Image, capabilities, runAsNonRoot); err != nil {
		apiresponses.RespondForbidden(ctx, err.Error())
		return
	}

	// Inject the ephemeral container
	if err := handler.InjectEphemeralContainer(apiCtx, session, req.Namespace, req.PodName, req.ContainerName, req.Image, req.Command, req.SecurityContext, currentUser.(string)); err != nil {
		reqLog.Errorw("Failed to inject ephemeral container", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to inject ephemeral container")
		return
	}

	reqLog.Infow("Ephemeral container injected",
		"session", sessionName,
		"pod", req.PodName,
		"namespace", req.Namespace,
		"container", req.ContainerName,
		"user", currentUser)

	ctx.JSON(http.StatusOK, gin.H{
		"message":   "ephemeral container injected successfully",
		"pod":       req.PodName,
		"namespace": req.Namespace,
		"container": req.ContainerName,
	})
}

// handleCreatePodCopy creates a debug copy of an existing pod
func (c *DebugSessionAPIController) handleCreatePodCopy(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	sessionName := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	var req CreatePodCopyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	// Get the debug session
	session, err := c.getDebugSessionByName(apiCtx, sessionName, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Verify session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not active, current state: %s", session.Status.State))
		return
	}

	// Verify user is a participant
	if !c.isUserParticipant(session, currentUser.(string)) {
		apiresponses.RespondForbidden(ctx, "user is not a participant of this session")
		return
	}

	// Verify template supports kubectl-debug mode
	if session.Status.ResolvedTemplate == nil ||
		(session.Status.ResolvedTemplate.Mode != v1alpha1.DebugSessionModeKubectlDebug &&
			session.Status.ResolvedTemplate.Mode != v1alpha1.DebugSessionModeHybrid) {
		apiresponses.RespondBadRequest(ctx, "session template does not support kubectl-debug mode")
		return
	}

	// Create kubectl debug handler
	handler := NewKubectlDebugHandler(c.client, &clusterClientAdapter{ccProvider: c.ccProvider})

	// Create the pod copy
	pod, err := handler.CreatePodCopy(apiCtx, session, req.Namespace, req.PodName, req.DebugImage, currentUser.(string))
	if err != nil {
		reqLog.Errorw("Failed to create pod copy", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to create pod copy")
		return
	}

	reqLog.Infow("Pod copy created",
		"session", sessionName,
		"originalPod", req.PodName,
		"originalNamespace", req.Namespace,
		"copyName", pod.Name,
		"copyNamespace", pod.Namespace,
		"user", currentUser)

	ctx.JSON(http.StatusOK, gin.H{
		"message":           "pod copy created successfully",
		"copyName":          pod.Name,
		"copyNamespace":     pod.Namespace,
		"originalPod":       req.PodName,
		"originalNamespace": req.Namespace,
	})
}

// handleCreateNodeDebugPod creates a debug pod on a specific node
func (c *DebugSessionAPIController) handleCreateNodeDebugPod(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	sessionName := ctx.Param("name")
	namespaceHint := ctx.Query("namespace")

	var req CreateNodeDebugPodRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	// Get current user
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), APIContextTimeout)
	defer cancel()

	// Get the debug session
	session, err := c.getDebugSessionByName(apiCtx, sessionName, namespaceHint)
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		reqLog.Errorw("Failed to get debug session", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}

	// Verify session is active
	if session.Status.State != v1alpha1.DebugSessionStateActive {
		apiresponses.RespondBadRequest(ctx, fmt.Sprintf("session is not active, current state: %s", session.Status.State))
		return
	}

	// Verify user is a participant
	if !c.isUserParticipant(session, currentUser.(string)) {
		apiresponses.RespondForbidden(ctx, "user is not a participant of this session")
		return
	}

	// Verify template supports kubectl-debug mode
	if session.Status.ResolvedTemplate == nil ||
		(session.Status.ResolvedTemplate.Mode != v1alpha1.DebugSessionModeKubectlDebug &&
			session.Status.ResolvedTemplate.Mode != v1alpha1.DebugSessionModeHybrid) {
		apiresponses.RespondBadRequest(ctx, "session template does not support kubectl-debug mode")
		return
	}

	// Create kubectl debug handler
	handler := NewKubectlDebugHandler(c.client, &clusterClientAdapter{ccProvider: c.ccProvider})

	// Create the node debug pod
	pod, err := handler.CreateNodeDebugPod(apiCtx, session, req.NodeName, currentUser.(string))
	if err != nil {
		reqLog.Errorw("Failed to create node debug pod", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to create node debug pod")
		return
	}

	reqLog.Infow("Node debug pod created",
		"session", sessionName,
		"node", req.NodeName,
		"podName", pod.Name,
		"namespace", pod.Namespace,
		"user", currentUser)

	ctx.JSON(http.StatusOK, gin.H{
		"message":   "node debug pod created successfully",
		"podName":   pod.Name,
		"namespace": pod.Namespace,
		"node":      req.NodeName,
	})
}

// clusterClientAdapter adapts cluster.ClientProvider to ClientProviderInterface
type clusterClientAdapter struct {
	ccProvider *cluster.ClientProvider
}

func (a *clusterClientAdapter) GetClient(ctx context.Context, clusterName string) (ctrlclient.Client, error) {
	restCfg, err := a.ccProvider.GetRESTConfig(ctx, clusterName)
	if err != nil {
		return nil, err
	}
	return ctrlclient.New(restCfg, ctrlclient.Options{})
}

// isUserParticipant checks if the user is a participant of the session
func (c *DebugSessionAPIController) isUserParticipant(session *v1alpha1.DebugSession, user string) bool {
	// Owner is always a participant
	if session.Spec.RequestedBy == user {
		return true
	}

	// Check participants list
	for _, p := range session.Status.Participants {
		if p.User == user && p.LeftAt == nil {
			return true
		}
	}

	return false
}

// extractCapabilities extracts capability names from a security context
func extractCapabilities(sc *corev1.SecurityContext) []string {
	if sc == nil || sc.Capabilities == nil {
		return nil
	}
	var caps []string
	for _, c := range sc.Capabilities.Add {
		caps = append(caps, string(c))
	}
	return caps
}

// extractRunAsNonRoot extracts the runAsNonRoot value from a security context
func extractRunAsNonRoot(sc *corev1.SecurityContext) bool {
	if sc == nil || sc.RunAsNonRoot == nil {
		return false
	}
	return *sc.RunAsNonRoot
}

// checkBindingSessionLimits verifies that creating a new session won't exceed the binding's session limits.
// Returns nil if the session can be created, or an error describing the limit violation.
func (c *DebugSessionAPIController) checkBindingSessionLimits(ctx context.Context, binding *v1alpha1.DebugSessionClusterBinding, userEmail string) error {
	if binding == nil {
		return nil
	}

	// Get current active sessions for this binding
	sessionList := &v1alpha1.DebugSessionList{}
	if err := c.client.List(ctx, sessionList); err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	// Count active sessions for this binding
	var totalActive int32
	var userActive int32
	for i := range sessionList.Items {
		session := &sessionList.Items[i]
		// Check if session uses this binding
		if session.Spec.BindingRef == nil ||
			session.Spec.BindingRef.Name != binding.Name ||
			session.Spec.BindingRef.Namespace != binding.Namespace {
			continue
		}

		// Check if session is active (pending or approved, not expired/terminated/failed)
		if session.Status.State == v1alpha1.DebugSessionStateTerminated ||
			session.Status.State == v1alpha1.DebugSessionStateExpired ||
			session.Status.State == v1alpha1.DebugSessionStateFailed {
			continue
		}

		totalActive++
		if session.Spec.RequestedByEmail == userEmail || session.Spec.RequestedBy == userEmail {
			userActive++
		}
	}

	// Check per-user limit
	if binding.Spec.MaxActiveSessionsPerUser != nil {
		if userActive >= *binding.Spec.MaxActiveSessionsPerUser {
			return fmt.Errorf("session limit reached: maximum %d active sessions per user allowed via this binding", *binding.Spec.MaxActiveSessionsPerUser)
		}
	}

	// Check total limit
	if binding.Spec.MaxActiveSessionsTotal != nil {
		if totalActive >= *binding.Spec.MaxActiveSessionsTotal {
			return fmt.Errorf("session limit reached: maximum %d total active sessions allowed via this binding", *binding.Spec.MaxActiveSessionsTotal)
		}
	}

	return nil
}

// ClusterAllowedResult contains the result of checking if a cluster is allowed
type ClusterAllowedResult struct {
	Allowed         bool
	AllowedBySource string                                // "template" or "binding:<ns>/<name>"
	MatchingBinding *v1alpha1.DebugSessionClusterBinding  // Non-nil if allowed by binding
	AllBindings     []v1alpha1.DebugSessionClusterBinding // All bindings that allow this cluster
}

// isClusterAllowedByTemplateOrBinding checks if a cluster is allowed by the template's allowed.clusters
// or by any active binding that references this template.
// This function requires the caller to pass in the bindings and clusterConfigs.
// If the template has no allowed.clusters, cluster access depends on bindings.
// If there are no bindings either, access is implicitly allowed (backward compatibility).
func (c *DebugSessionAPIController) isClusterAllowedByTemplateOrBinding(
	template *v1alpha1.DebugSessionTemplate,
	clusterName string,
	bindings []v1alpha1.DebugSessionClusterBinding,
	clusterConfigs map[string]*v1alpha1.ClusterConfig,
) ClusterAllowedResult {
	result := ClusterAllowedResult{}

	hasTemplateClusterRestriction := template.Spec.Allowed != nil && len(template.Spec.Allowed.Clusters) > 0

	c.log.Debugw("isClusterAllowedByTemplateOrBinding starting",
		"template", template.Name,
		"cluster", clusterName,
		"hasTemplateClusterRestriction", hasTemplateClusterRestriction,
		"totalBindingsProvided", len(bindings),
		"totalClusterConfigs", len(clusterConfigs),
	)

	// Check if clusterName exists in clusterConfigs
	if _, exists := clusterConfigs[clusterName]; !exists {
		c.log.Warnw("Requested cluster not found in ClusterConfig map",
			"cluster", clusterName,
			"availableClusters", func() []string {
				names := make([]string, 0, len(clusterConfigs))
				for name := range clusterConfigs {
					names = append(names, name)
				}
				return names
			}(),
		)
	}

	// 1. Check if allowed by template's allowed.clusters
	if hasTemplateClusterRestriction {
		for _, pattern := range template.Spec.Allowed.Clusters {
			if matchPattern(pattern, clusterName) {
				c.log.Debugw("Cluster allowed by template pattern",
					"cluster", clusterName,
					"pattern", pattern,
				)
				result.Allowed = true
				result.AllowedBySource = "template"
				return result
			}
		}
		c.log.Debugw("Cluster not allowed by template patterns",
			"cluster", clusterName,
			"templatePatterns", template.Spec.Allowed.Clusters,
		)
	}

	// 2. Check if allowed by any binding that references this template
	applicableBindings := c.findBindingsForTemplate(template, bindings)
	c.log.Debugw("Found bindings for template",
		"template", template.Name,
		"applicableBindingsCount", len(applicableBindings),
		"applicableBindingNames", func() []string {
			names := make([]string, len(applicableBindings))
			for i, b := range applicableBindings {
				names[i] = fmt.Sprintf("%s/%s", b.Namespace, b.Name)
			}
			return names
		}(),
	)

	for i := range applicableBindings {
		binding := &applicableBindings[i]
		bindingClusters := c.resolveClustersFromBinding(binding, clusterConfigs)
		c.log.Debugw("Binding cluster resolution",
			"binding", fmt.Sprintf("%s/%s", binding.Namespace, binding.Name),
			"resolvedClusters", bindingClusters,
			"lookingFor", clusterName,
		)
		for _, bc := range bindingClusters {
			if bc == clusterName {
				result.AllBindings = append(result.AllBindings, *binding)
				if !result.Allowed {
					result.Allowed = true
					result.AllowedBySource = fmt.Sprintf("binding:%s/%s", binding.Namespace, binding.Name)
					result.MatchingBinding = binding
					c.log.Debugw("Cluster allowed by binding",
						"cluster", clusterName,
						"binding", fmt.Sprintf("%s/%s", binding.Namespace, binding.Name),
					)
				}
			}
		}
	}

	// 3. If template has no cluster restriction and no bindings provide explicit access,
	// the template is effectively unavailable (no clusters can be deployed to).
	// This is different from the old "backward compatibility" behavior that allowed all clusters.
	if !result.Allowed && !hasTemplateClusterRestriction && len(applicableBindings) == 0 {
		c.log.Debugw("Cluster denied - template has no cluster restrictions and no bindings (unavailable template)",
			"cluster", clusterName,
			"template", template.Name,
		)
		// result.Allowed remains false
	}

	c.log.Debugw("isClusterAllowedByTemplateOrBinding result",
		"cluster", clusterName,
		"allowed", result.Allowed,
		"source", result.AllowedBySource,
	)

	return result
}
