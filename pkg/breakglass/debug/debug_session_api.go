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

package debug

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/naming"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	mailService  breakglass.MailEnqueuer
	auditService breakglass.AuditEmitter
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
func (c *DebugSessionAPIController) WithMailService(mailService breakglass.MailEnqueuer, brandingName, baseURL string) *DebugSessionAPIController {
	c.mailService = mailService
	c.brandingName = brandingName
	c.baseURL = baseURL
	return c
}

// WithAuditService sets the audit service for emitting audit events
func (c *DebugSessionAPIController) WithAuditService(auditService breakglass.AuditEmitter) *DebugSessionAPIController {
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
	rg.GET("", breakglass.InstrumentedHandler("handleListDebugSessions", c.handleListDebugSessions))
	rg.GET(":name", breakglass.InstrumentedHandler("handleGetDebugSession", c.handleGetDebugSession))
	rg.POST("", breakglass.InstrumentedHandler("handleCreateDebugSession", c.handleCreateDebugSession))
	rg.POST(":name/join", breakglass.InstrumentedHandler("handleJoinDebugSession", c.handleJoinDebugSession))
	rg.POST(":name/leave", breakglass.InstrumentedHandler("handleLeaveDebugSession", c.handleLeaveDebugSession))
	rg.POST(":name/renew", breakglass.InstrumentedHandler("handleRenewDebugSession", c.handleRenewDebugSession))
	rg.POST(":name/terminate", breakglass.InstrumentedHandler("handleTerminateDebugSession", c.handleTerminateDebugSession))
	rg.POST(":name/approve", breakglass.InstrumentedHandler("handleApproveDebugSession", c.handleApproveDebugSession))
	rg.POST(":name/reject", breakglass.InstrumentedHandler("handleRejectDebugSession", c.handleRejectDebugSession))

	// Kubectl-debug mode endpoints
	rg.POST(":name/injectEphemeralContainer", breakglass.InstrumentedHandler("handleInjectEphemeralContainer", c.handleInjectEphemeralContainer))
	rg.POST(":name/createPodCopy", breakglass.InstrumentedHandler("handleCreatePodCopy", c.handleCreatePodCopy))
	rg.POST(":name/createNodeDebugPod", breakglass.InstrumentedHandler("handleCreateNodeDebugPod", c.handleCreateNodeDebugPod))

	// Template endpoints
	rg.GET("templates", breakglass.InstrumentedHandler("handleListTemplates", c.handleListTemplates))
	rg.GET("templates/:name", breakglass.InstrumentedHandler("handleGetTemplate", c.handleGetTemplate))
	rg.GET("templates/:name/clusters", breakglass.InstrumentedHandler("handleGetTemplateClusters", c.handleGetTemplateClusters))
	rg.GET("podTemplates", breakglass.InstrumentedHandler("handleListPodTemplates", c.handleListPodTemplates))
	rg.GET("podTemplates/:name", breakglass.InstrumentedHandler("handleGetPodTemplate", c.handleGetPodTemplate))
	return nil
}

// getDebugSessionByName finds a debug session by name across all namespaces
// or optionally in a specific namespace if provided via query param.
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) getDebugSessionByName(ctx context.Context, name, namespaceHint string) (*breakglassv1alpha1.DebugSession, error) {
	reader := c.reader()
	// If namespace hint provided, try that first
	if namespaceHint != "" {
		session := &breakglassv1alpha1.DebugSession{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: name, Namespace: namespaceHint}, session); err == nil {
			return session, nil
		}
	}

	// Search across all namespaces using label selector
	sessionList := &breakglassv1alpha1.DebugSessionList{}
	if err := reader.List(ctx, sessionList, ctrlclient.MatchingLabels{DebugSessionLabelKey: name}); err != nil {
		return nil, err
	}

	if len(sessionList.Items) == 0 {
		// Fallback: try default namespace
		session := &breakglassv1alpha1.DebugSession{}
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
	Name                   string                                   `json:"name"`
	TemplateRef            string                                   `json:"templateRef"`
	Cluster                string                                   `json:"cluster"`
	RequestedBy            string                                   `json:"requestedBy"`
	RequestedByDisplayName string                                   `json:"requestedByDisplayName,omitempty"`
	State                  breakglassv1alpha1.DebugSessionState     `json:"state"`
	StatusMessage          string                                   `json:"statusMessage,omitempty"`
	StartsAt               *metav1.Time                             `json:"startsAt,omitempty"`
	ExpiresAt              *metav1.Time                             `json:"expiresAt,omitempty"`
	Participants           int                                      `json:"participants"`
	IsParticipant          bool                                     `json:"isParticipant"`
	AllowedPods            int                                      `json:"allowedPods"`
	AllowedPodOperations   *breakglassv1alpha1.AllowedPodOperations `json:"allowedPodOperations,omitempty"`
}

// DebugSessionDetailResponse represents the detailed debug session response
type DebugSessionDetailResponse struct {
	breakglassv1alpha1.DebugSession
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

	sessionList := &breakglassv1alpha1.DebugSessionList{}
	listOpts := []ctrlclient.ListOption{}

	// Note: cluster/state/user filters are applied client-side after fetching
	// Field selectors would require additional indexer setup

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()

	if err := c.reader().List(apiCtx, sessionList, listOpts...); err != nil {
		reqLog.Errorw("Failed to list debug sessions", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to list debug sessions")
		return
	}

	// Apply filters
	var filtered []breakglassv1alpha1.DebugSession
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
		// Compute isParticipant and activeParticipants in a single pass
		isParticipant := false
		activeParticipants := 0
		for _, p := range s.Status.Participants {
			if p.LeftAt == nil {
				activeParticipants++
				if !isParticipant && (p.User == currentUserStr || p.Email == currentUserStr) {
					isParticipant = true
				}
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
			Participants:           activeParticipants,
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

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
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
		sanitized, err := breakglass.SanitizeReasonText(req.Reason)
		if err != nil {
			reqLog.Warnw("Failed to sanitize reason, using empty string", "error", err)
			req.Reason = "" // Use empty string as safe fallback
		} else {
			req.Reason = sanitized
		}
	}

	// Validate template exists
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
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
	var bindingList breakglassv1alpha1.DebugSessionClusterBindingList
	var clusterConfigList breakglassv1alpha1.ClusterConfigList
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
	clusterMap := make(map[string]*breakglassv1alpha1.ClusterConfig, len(clusterConfigList.Items))
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
		req.ExtraDeployValues = breakglassv1alpha1.CoerceExtraDeployValues(req.ExtraDeployValues, template.Spec.ExtraDeployVariables)
	}

	// Validate extraDeployValues against template's extraDeployVariables
	// This includes checking allowedGroups on variables and options
	if len(req.ExtraDeployValues) > 0 || len(template.Spec.ExtraDeployVariables) > 0 {
		valErrs := breakglassv1alpha1.ValidateExtraDeployValuesWithGroups(
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
		clusterConfigs := &breakglassv1alpha1.ClusterConfigList{}
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
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sessionName,
			Namespace: namespace,
			Labels: map[string]string{
				DebugSessionLabelKey:  sessionName,
				DebugTemplateLabelKey: req.TemplateRef,
				DebugClusterLabelKey:  req.Cluster,
			},
		},
		Spec: breakglassv1alpha1.DebugSessionSpec{
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
	var resolvedBinding *breakglassv1alpha1.DebugSessionClusterBinding
	if req.BindingRef != "" {
		parts := strings.SplitN(req.BindingRef, "/", 2)
		if len(parts) == 2 {
			session.Spec.BindingRef = &breakglassv1alpha1.BindingReference{
				Name:      parts[1],
				Namespace: parts[0],
			}
			// Fetch the binding for limit checking
			resolvedBinding = &breakglassv1alpha1.DebugSessionClusterBinding{}
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
			if !breakglass.IsBindingActive(resolvedBinding) {
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

	// Design Decision (#382): Using Create() instead of SSA for DebugSession creation.
	//
	// We evaluated replacing Create() with a pre-check Get() + SSA Apply pattern for
	// consistency with the reconciler's SSA approach. The decision is to keep Create()
	// because:
	//
	// 1. Native conflict detection — Create() returns AlreadyExists natively, giving us
	//    HTTP 409 Conflict without an extra round-trip. A pre-check Get() would add
	//    latency and introduce a small race window between Get and Apply.
	//
	// 2. Semantic correctness — SSA Apply is designed for idempotent reconciliation
	//    (create-or-update). Debug session creation is intentionally a one-shot operation;
	//    silently updating an existing session would violate the expected API contract.
	//
	// 3. No multi-owner benefit — SSA's field ownership tracking adds value when multiple
	//    controllers manage the same object. Debug sessions are created by the API server
	//    and then managed exclusively by the reconciler. There is no ownership conflict.
	//
	// 4. Simplicity — The current code is straightforward and well-tested. Adding a
	//    pre-check Get() increases complexity without a concrete benefit.
	//
	// The reconciler continues to use SSA for status updates and lifecycle management,
	// which is the correct boundary: Create() for API-driven creation, SSA for
	// controller-driven reconciliation.
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
