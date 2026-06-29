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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/jsonutil"
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
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const debugSessionNamePrefix = "debug"

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
// or in the exact namespace provided via query param.
// Uses the uncached apiReader if configured, for consistent reads after writes.
func (c *DebugSessionAPIController) getDebugSessionByName(ctx context.Context, name, namespaceHint string) (*breakglassv1alpha1.DebugSession, error) {
	reader := c.reader()
	if namespaceHint != "" {
		session := &breakglassv1alpha1.DebugSession{}
		if err := reader.Get(ctx, ctrlclient.ObjectKey{Name: name, Namespace: namespaceHint}, session); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, apierrors.NewNotFound(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, name)
			}
			return nil, err
		}
		return session, nil
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
			if apierrors.IsNotFound(err) {
				return nil, apierrors.NewNotFound(schema.GroupResource{Group: breakglassv1alpha1.GroupVersion.Group, Resource: "debugsessions"}, name)
			}
			return nil, err
		}
		return session, nil
	}

	return &sessionList.Items[0], nil
}

func isControllerOwnedDebugSessionLabel(key string) bool {
	return key == DebugSessionLabelKey || key == DebugTemplateLabelKey || key == DebugClusterLabelKey
}

// CreateDebugSessionRequest represents the request body for creating a debug session
type CreateDebugSessionRequest struct {
	TemplateRef              string                          `json:"templateRef" binding:"required"`
	Cluster                  string                          `json:"cluster" binding:"required"`
	BindingRef               string                          `json:"bindingRef,omitempty"` // Optional: explicit binding selection as "namespace/name" (when multiple match)
	RequestedDuration        string                          `json:"requestedDuration,omitempty"`
	NodeSelector             map[string]string               `json:"nodeSelector,omitempty"`
	Namespace                string                          `json:"namespace,omitempty"` // Deprecated: alias for targetNamespace
	Reason                   string                          `json:"reason,omitempty"`
	InvitedParticipants      []string                        `json:"invitedParticipants,omitempty"`
	TargetNamespace          string                          `json:"targetNamespace,omitempty"`          // User-selected namespace (if allowed by template)
	SelectedSchedulingOption string                          `json:"selectedSchedulingOption,omitempty"` // User-selected scheduling option
	ExtraDeployValues        map[string]apiextensionsv1.JSON `json:"extraDeployValues,omitempty"`        // User-provided values for template variables
}

func normalizeCreateDebugSessionNamespace(req *CreateDebugSessionRequest) error {
	if req.Namespace == "" {
		return nil
	}
	if req.TargetNamespace != "" && req.TargetNamespace != req.Namespace {
		return fmt.Errorf("namespace is deprecated alias for targetNamespace and must match targetNamespace when both are set")
	}
	req.TargetNamespace = req.Namespace
	return nil
}

// JoinDebugSessionRequest represents the request to join an existing debug session
type JoinDebugSessionRequest struct {
	Role string `json:"role,omitempty"` // "viewer" or "participant"
}

// RenewDebugSessionRequest represents the request to extend session duration
type RenewDebugSessionRequest struct {
	ExtendBy string `json:"extendBy" binding:"required"` // Duration like "1h", "30m"
}

func validateRenewDebugSessionRequest(req RenewDebugSessionRequest) error {
	if req.ExtendBy == "" {
		return fmt.Errorf("extendBy is required")
	}
	return nil
}

// ApprovalRequest represents the request body for approve/reject actions
type ApprovalRequest struct {
	Reason string `json:"reason,omitempty"`
}

func decodeDebugJSONStrict(r io.Reader, dest interface{}) error {
	return jsonutil.DecodeStrict(r, dest)
}

func validateCreateDebugSessionRequest(req CreateDebugSessionRequest) error {
	if req.TemplateRef == "" {
		return fmt.Errorf("templateRef is required")
	}
	if req.Cluster == "" {
		return fmt.Errorf("cluster is required")
	}
	return nil
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

func validateInjectEphemeralContainerRequest(req InjectEphemeralContainerRequest) error {
	switch {
	case req.Namespace == "":
		return fmt.Errorf("namespace is required")
	case req.PodName == "":
		return fmt.Errorf("podName is required")
	case req.ContainerName == "":
		return fmt.Errorf("containerName is required")
	case req.Image == "":
		return fmt.Errorf("image is required")
	default:
		return nil
	}
}

// CreatePodCopyRequest represents the request to create a debug copy of a pod
type CreatePodCopyRequest struct {
	Namespace  string `json:"namespace" binding:"required"`
	PodName    string `json:"podName" binding:"required"`
	DebugImage string `json:"debugImage,omitempty"` // Optional debug container image
}

func validateCreatePodCopyRequest(req CreatePodCopyRequest) error {
	switch {
	case req.Namespace == "":
		return fmt.Errorf("namespace is required")
	case req.PodName == "":
		return fmt.Errorf("podName is required")
	default:
		return nil
	}
}

// CreateNodeDebugPodRequest represents the request to create a node debug pod
type CreateNodeDebugPodRequest struct {
	NodeName string `json:"nodeName" binding:"required"`
}

func validateCreateNodeDebugPodRequest(req CreateNodeDebugPodRequest) error {
	if req.NodeName == "" {
		return fmt.Errorf("nodeName is required")
	}
	return nil
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

type debugSessionReadIdentity struct {
	username string
	email    string
	groups   []string
}

func debugSessionRequestIdentity(ctx *gin.Context) (debugSessionReadIdentity, bool) {
	usernameValue, exists := ctx.Get("username")
	if !exists || usernameValue == nil {
		return debugSessionReadIdentity{}, false
	}
	username, ok := usernameValue.(string)
	if !ok || username == "" {
		return debugSessionReadIdentity{}, false
	}

	identity := debugSessionReadIdentity{username: username}
	if emailValue, exists := ctx.Get("email"); exists && emailValue != nil {
		if email, ok := emailValue.(string); ok {
			identity.email = email
		}
	}
	if groupsValue, exists := ctx.Get("groups"); exists && groupsValue != nil {
		identity.groups = debugSessionGroupsFromContext(groupsValue)
	}
	return identity, true
}

func debugSessionGroupsFromContext(groupsValue interface{}) []string {
	switch groups := groupsValue.(type) {
	case []string:
		return groups
	case []interface{}:
		out := make([]string, 0, len(groups))
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				out = append(out, groupStr)
			}
		}
		return out
	default:
		return nil
	}
}

func debugSessionIdentityMatches(identity debugSessionReadIdentity, values ...string) bool {
	for _, value := range values {
		if value == "" {
			continue
		}
		if value == identity.username || (identity.email != "" && value == identity.email) {
			return true
		}
	}
	return false
}

// handleListDebugSessions returns a list of debug sessions
func (c *DebugSessionAPIController) handleListDebugSessions(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
		return
	}

	// Get query parameters for filtering
	cluster := ctx.Query("cluster")
	// Accept repeated ?state= params (e.g. ?state=Active&state=Pending) as well as
	// a legacy single comma-separated value (e.g. ?state=Active,Pending).
	// Comparison is case-insensitive so both "Active" and "active" match.
	var states []string
	for _, v := range ctx.QueryArray("state") {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				states = append(states, s)
			}
		}
	}
	// Validate each requested state value against the canonical set.
	for _, st := range states {
		if !isValidDebugSessionState(st) {
			apiresponses.RespondBadRequest(ctx, fmt.Sprintf("invalid state value: '%s'", st))
			return
		}
	}
	user := ctx.Query("user")
	mine := ctx.Query("mine") == "true"

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
	readAuthorizer := c.newDebugSessionReadAuthorizer(identity)
	for i := range sessionList.Items {
		s := &sessionList.Items[i]
		canRead, err := readAuthorizer.canRead(apiCtx, s)
		if err != nil {
			reqLog.Errorw("Failed to evaluate debug session read authorization",
				"session", s.Name,
				"namespace", s.Namespace,
				"error", err)
			apiresponses.RespondInternalErrorSimple(ctx, "failed to evaluate debug session read authorization")
			return
		}
		if !canRead {
			continue
		}
		// Cluster filter
		if cluster != "" && s.Spec.Cluster != cluster {
			continue
		}
		// State filter
		if len(states) > 0 {
			matched := false
			for _, st := range states {
				if strings.EqualFold(string(s.Status.State), st) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		// User filter
		if user != "" && !debugSessionIdentityMatches(debugSessionReadIdentity{username: user, email: user}, s.Spec.RequestedBy, s.Spec.RequestedByEmail) {
			continue
		}
		// Mine filter
		if mine && !debugSessionIdentityMatches(identity, s.Spec.RequestedBy, s.Spec.RequestedByEmail) {
			continue
		}
		filtered = append(filtered, *s)
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
				if !isParticipant && debugSessionIdentityMatches(identity, p.User, p.Email) {
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

	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
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

	canRead, err := c.canReadDebugSession(apiCtx, session, identity)
	if err != nil {
		reqLog.Errorw("Failed to evaluate debug session read authorization",
			"name", name,
			"namespace", session.Namespace,
			"error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to evaluate debug session read authorization")
		return
	}
	if !canRead {
		apiresponses.RespondForbidden(ctx, "user is not authorized to read this debug session")
		return
	}

	ctx.JSON(http.StatusOK, DebugSessionDetailResponse{DebugSession: *session})
}

// handleCreateDebugSession creates a new debug session
func (c *DebugSessionAPIController) handleCreateDebugSession(ctx *gin.Context) {
	reqLog := system.GetReqLogger(ctx, c.log)

	var req CreateDebugSessionRequest
	if err := decodeDebugJSONStrict(ctx.Request.Body, &req); err != nil {
		reqLog.Warnw("Failed to parse CreateDebugSession request", "error", err)
		apiresponses.RespondBadRequest(ctx, "invalid request body: "+err.Error())
		return
	}
	if err := validateCreateDebugSessionRequest(req); err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}
	if err := normalizeCreateDebugSessionNamespace(&req); err != nil {
		reqLog.Warnw("Conflicting debug session namespace fields",
			"namespace", req.Namespace,
			"targetNamespace", req.TargetNamespace,
			"error", err,
		)
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
		req.Reason = breakglass.SanitizeReasonText(req.Reason)
	}

	// Get current user from context before authorization checks.
	currentUser, exists := ctx.Get("username")
	if !exists || currentUser == nil {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	currentUserStr, ok := currentUser.(string)
	if !ok {
		apiresponses.RespondInternalErrorSimple(ctx, "invalid user context type")
		return
	}
	if strings.TrimSpace(currentUserStr) == "" {
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

	// Validate template exists
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
	defer cancel()
	authorizationReader := c.reader()

	if err := authorizationReader.Get(apiCtx, ctrlclient.ObjectKey{Name: req.TemplateRef}, template); err != nil {
		if apierrors.IsNotFound(err) {
			reqLog.Warnw("Template not found", "templateRef", req.TemplateRef)
			apiresponses.RespondBadRequest(ctx, fmt.Sprintf("template '%s' not found", req.TemplateRef))
			return
		}
		reqLog.Errorw("Failed to get template", "template", req.TemplateRef, "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to validate template")
		return
	}

	// Fetch bindings and cluster configs to check if cluster is allowed via template or binding.
	// ClusterConfig readiness and existence errors are returned only after template/binding
	// and requester authorization succeeds, so unauthorized callers cannot probe cluster state.
	var bindingList breakglassv1alpha1.DebugSessionClusterBindingList
	var clusterConfigList breakglassv1alpha1.ClusterConfigList
	if err := authorizationReader.List(apiCtx, &bindingList); err != nil {
		reqLog.Errorw("Failed to list bindings for cluster validation", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to validate cluster access")
		return
	}
	if err := authorizationReader.List(apiCtx, &clusterConfigList); err != nil {
		reqLog.Errorw("Failed to list cluster configs for cluster validation", "error", err)
		apiresponses.RespondInternalErrorSimple(ctx, "failed to validate cluster access")
		return
	}

	requestedClusterConfig, clusterAmbiguity := findDebugClusterConfigByNameOrTenant(clusterConfigList.Items, req.Cluster)
	authorizationClusters := []string{req.Cluster}
	if requestedClusterConfig != nil {
		authorizationClusters = append([]string{requestedClusterConfig.Name}, authorizationClusters...)
	}
	ambiguousClusterName := req.Cluster
	if requestedClusterConfig != nil && clusterAmbiguity == debugClusterConfigAmbiguityName {
		ambiguousClusterName = requestedClusterConfig.Name
	}
	clusterMap := debugClusterConfigMap(clusterConfigList.Items)

	// Check if cluster is allowed by template or any binding
	var resolvedBinding *breakglassv1alpha1.DebugSessionClusterBinding
	var allowedResult ClusterAllowedResult
	if req.BindingRef != "" {
		bindingNamespace, bindingName, validBindingRef := parseDebugSessionBindingRef(req.BindingRef)
		if !validBindingRef {
			reqLog.Warnw("Invalid bindingRef format", "bindingRef", req.BindingRef)
			apiresponses.RespondBadRequest(ctx, "bindingRef must use namespace/name format")
			return
		}

		resolvedBinding = &breakglassv1alpha1.DebugSessionClusterBinding{}
		if err := authorizationReader.Get(apiCtx, ctrlclient.ObjectKey{Name: bindingName, Namespace: bindingNamespace}, resolvedBinding); err != nil {
			if apierrors.IsNotFound(err) {
				reqLog.Warnw("Binding not found", "bindingRef", req.BindingRef)
				apiresponses.RespondBadRequest(ctx, fmt.Sprintf("binding '%s' not found", req.BindingRef))
				return
			}
			reqLog.Errorw("Failed to get binding", "binding", req.BindingRef, "error", err)
			apiresponses.RespondInternalErrorSimple(ctx, "failed to validate binding")
			return
		}

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

		if len(c.findBindingsForTemplate(template, []breakglassv1alpha1.DebugSessionClusterBinding{*resolvedBinding})) == 0 {
			reqLog.Warnw("Binding does not reference requested template",
				"bindingRef", req.BindingRef,
				"templateRef", req.TemplateRef,
			)
			apiresponses.RespondForbidden(ctx, "binding does not grant access to the requested template")
			return
		}

		bindingClusters := c.resolveClustersFromBinding(resolvedBinding, clusterMap)
		bindingAllowsRequestedCluster := false
		for _, authorizationCluster := range authorizationClusters {
			if stringInSlice(authorizationCluster, bindingClusters) {
				bindingAllowsRequestedCluster = true
				break
			}
		}
		if !bindingAllowsRequestedCluster &&
			clusterAmbiguity == debugClusterConfigAmbiguityName &&
			bindingReferencesAmbiguousClusterName(resolvedBinding, ambiguousClusterName, clusterConfigList.Items) {
			bindingAllowsRequestedCluster = true
		}
		if !bindingAllowsRequestedCluster {
			reqLog.Warnw("Binding does not grant requested cluster",
				"bindingRef", req.BindingRef,
				"requestedCluster", req.Cluster,
				"bindingClusters", bindingClusters,
			)
			apiresponses.RespondForbidden(ctx, "binding does not grant access to the requested cluster")
			return
		}

		allowedResult = ClusterAllowedResult{
			Allowed:         true,
			AllowedBySource: fmt.Sprintf("binding:%s/%s", resolvedBinding.Namespace, resolvedBinding.Name),
			MatchingBinding: resolvedBinding,
			AllBindings:     []breakglassv1alpha1.DebugSessionClusterBinding{*resolvedBinding},
		}
	} else {
		for _, authorizationCluster := range authorizationClusters {
			allowedResult = c.isClusterAllowedByTemplateOrBinding(template, authorizationCluster, bindingList.Items, clusterMap, clusterConfigList.Items)
			if allowedResult.Allowed {
				break
			}
		}
	}
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
	if !isDebugSessionRequesterAllowed(effectiveDebugSessionAllowed(template, allowedResult.MatchingBinding), currentUserStr, userEmail, userGroups) {
		reqLog.Warnw("User is not allowed to request debug session",
			"templateRef", req.TemplateRef,
			"bindingRef", req.BindingRef,
			"user", currentUserStr,
			"groupCount", len(userGroups),
		)
		apiresponses.RespondForbidden(ctx, "user is not allowed to request this debug session")
		return
	}
	if clusterAmbiguity == debugClusterConfigAmbiguityName {
		reqLog.Warnw("ClusterConfig name is ambiguous for debug session creation",
			"cluster", req.Cluster,
			"clusterConfig", ambiguousClusterName,
		)
		apiresponses.RespondConflict(ctx, fmt.Sprintf("cluster '%s' matches multiple ClusterConfig names", ambiguousClusterName))
		return
	}
	if clusterAmbiguity == debugClusterConfigAmbiguityTenant {
		reqLog.Warnw("ClusterConfig tenant alias is ambiguous for debug session creation", "cluster", req.Cluster)
		apiresponses.RespondForbidden(ctx, fmt.Sprintf("cluster '%s' matches multiple ClusterConfig tenants", req.Cluster))
		return
	}
	if requestedClusterConfig == nil {
		reqLog.Warnw("ClusterConfig not found for debug session creation", "cluster", req.Cluster)
		apiresponses.RespondForbidden(ctx, fmt.Sprintf("cluster '%s' is not configured for debug sessions", req.Cluster))
		return
	}
	if !isDebugClusterConfigReady(requestedClusterConfig) {
		reqLog.Warnw("ClusterConfig is not ready for debug session creation",
			"cluster", req.Cluster,
			"namespace", requestedClusterConfig.Namespace,
			"clusterConfig", requestedClusterConfig.Name,
		)
		apiresponses.RespondForbidden(ctx, fmt.Sprintf("cluster '%s' is not ready for debug sessions", req.Cluster))
		return
	}
	if req.Cluster != requestedClusterConfig.Name {
		reqLog.Debugw("Resolved debug session cluster alias",
			"requestedCluster", req.Cluster,
			"clusterConfig", requestedClusterConfig.Name,
			"tenant", requestedClusterConfig.Spec.Tenant,
		)
		req.Cluster = requestedClusterConfig.Name
	}
	reqLog.Debugw("Cluster access validated",
		"requestedCluster", req.Cluster,
		"allowedBySource", allowedResult.AllowedBySource,
	)

	resolvedBinding, err := selectEffectiveDebugSessionBinding(req.BindingRef, allowedResult)
	if err != nil {
		reqLog.Warnw("Requested binding is not valid for debug session",
			"bindingRef", req.BindingRef,
			"cluster", req.Cluster,
			"templateRef", req.TemplateRef,
			"error", err)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	effectiveConstraints := effectiveDebugSessionConstraints(template, resolvedBinding)
	if err := validateRequestedDebugSessionDuration(req.RequestedDuration, effectiveConstraints); err != nil {
		reqLog.Warnw("Requested debug session duration is invalid",
			"templateRef", req.TemplateRef,
			"bindingRef", req.BindingRef,
			"requestedDuration", req.RequestedDuration,
			"error", err)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	effectiveRequestReason := effectiveDebugRequestReasonConfig(template, resolvedBinding)
	if err := validateDebugRequestReason(req.Reason, effectiveRequestReason); err != nil {
		reqLog.Warnw("Debug session request reason is invalid",
			"templateRef", req.TemplateRef,
			"bindingRef", req.BindingRef,
			"error", err)
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}

	effectiveApprovalReason := effectiveDebugApprovalReasonConfig(template, resolvedBinding)

	// Track warnings for defaults that were applied
	var warnings []string

	// Validate and resolve target namespace (pass binding for constraint override)
	targetNamespace, err := c.resolveTargetNamespace(template, req.TargetNamespace, resolvedBinding)
	if err != nil {
		// Provide more context about namespace constraints when validation fails
		var effectiveAllowUserNs bool
		var effectiveDefault string
		if resolvedBinding != nil && resolvedBinding.Spec.NamespaceConstraints != nil {
			effectiveAllowUserNs = resolvedBinding.Spec.NamespaceConstraints.AllowUserNamespace
			effectiveDefault = resolvedBinding.Spec.NamespaceConstraints.DefaultNamespace
		} else if template.Spec.NamespaceConstraints != nil {
			effectiveAllowUserNs = template.Spec.NamespaceConstraints.AllowUserNamespace
			effectiveDefault = template.Spec.NamespaceConstraints.DefaultNamespace
		}
		reqLog.Warnw("Target namespace validation failed",
			"templateRef", req.TemplateRef,
			"requestedNamespace", req.TargetNamespace,
			"allowUserNamespace", effectiveAllowUserNs,
			"defaultNamespace", effectiveDefault,
			"bindingUsed", resolvedBinding != nil,
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
	resolvedScheduling, selectedOption, err := c.resolveSchedulingConstraints(template, req.SelectedSchedulingOption, resolvedBinding, schedulingOptionRequester{
		Username: currentUserStr,
		Email:    userEmail,
		Groups:   userGroups,
	})
	if err != nil {
		reqLog.Warnw("Scheduling option validation failed",
			"templateRef", req.TemplateRef,
			"selectedSchedulingOption", req.SelectedSchedulingOption,
			"error", err,
		)
		var accessErr *schedulingOptionAccessError
		if errors.As(err, &accessErr) {
			apiresponses.RespondForbidden(ctx, err.Error())
			return
		}
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
			(resolvedBinding != nil && resolvedBinding.Spec.SchedulingOptions != nil && len(resolvedBinding.Spec.SchedulingOptions.Options) > 0)
		if !hasOptions {
			warnings = append(warnings, fmt.Sprintf("Scheduling option '%s' was ignored (template has no scheduling options)", req.SelectedSchedulingOption))
			reqLog.Debugw("Scheduling option ignored", "ignoredOption", req.SelectedSchedulingOption)
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
				"userGroupCount", len(userGroups),
				"errors", errMessages,
			)
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error":  "extraDeployValues validation failed",
				"errors": errMessages,
			})
			return
		}
	}

	sessionName := buildDebugSessionName(currentUserStr, req.Cluster, time.Now())

	// DebugSessions live in the namespace of the ready ClusterConfig selected above.
	namespace := requestedClusterConfig.Namespace

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
	if resolvedBinding != nil {
		session.Spec.BindingRef = &breakglassv1alpha1.BindingReference{
			Name:      resolvedBinding.Name,
			Namespace: resolvedBinding.Namespace,
		}
	}

	// Copy reason configurations as snapshots so session is self-contained
	// This avoids needing to look up the template or binding later.
	if effectiveRequestReason != nil {
		session.Spec.RequestReasonConfig = effectiveRequestReason.DeepCopy()
	}
	if effectiveApprovalReason != nil {
		session.Spec.ApprovalReasonConfig = effectiveApprovalReason.DeepCopy()
	}

	// Check binding session limits if a binding is resolved
	if resolvedBinding != nil {
		if err := c.checkBindingSessionLimits(apiCtx, resolvedBinding, debugSessionReadIdentity{
			username: currentUserStr,
			email:    userEmail,
		}); err != nil {
			reqLog.Warnw("Binding session limits exceeded",
				"bindingRef", req.BindingRef,
				"user", currentUserStr,
				"userEmail", userEmail,
				"error", err,
			)
			apiresponses.RespondForbidden(ctx, err.Error())
			return
		}

		// Apply binding labels to the session
		if len(resolvedBinding.Spec.Labels) > 0 {
			for k, v := range resolvedBinding.Spec.Labels {
				if isControllerOwnedDebugSessionLabel(k) {
					continue
				}
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

func buildDebugSessionName(user, cluster string, now time.Time) string {
	suffix := strconv.FormatInt(now.UnixNano(), 36)
	userPart, clusterPart := fitDebugSessionNameParts(
		naming.ToRFC1123Label(user),
		naming.ToRFC1123Label(cluster),
		suffix,
	)
	return fmt.Sprintf("%s-%s-%s-%s", debugSessionNamePrefix, userPart, clusterPart, suffix)
}

func fitDebugSessionNameParts(userPart, clusterPart, suffix string) (string, string) {
	partsBudget := validation.LabelValueMaxLength - len(debugSessionNamePrefix) - len(suffix) - 3
	if partsBudget < 2 {
		return "x", "x"
	}

	userBudget := partsBudget / 2
	clusterBudget := partsBudget - userBudget
	if len(userPart) < userBudget {
		clusterBudget += userBudget - len(userPart)
		userBudget = len(userPart)
	}
	if len(clusterPart) < clusterBudget {
		userBudget += clusterBudget - len(clusterPart)
		clusterBudget = len(clusterPart)
	}

	return truncateDebugSessionNamePart(userPart, userBudget), truncateDebugSessionNamePart(clusterPart, clusterBudget)
}

func truncateDebugSessionNamePart(part string, maxLen int) string {
	if maxLen <= 0 {
		return "x"
	}
	if len(part) > maxLen {
		part = part[:maxLen]
	}
	part = strings.Trim(part, "-.")
	if part == "" {
		return "x"
	}
	return part
}

// validDebugSessionStates is the canonical set of allowed DebugSession state values
// used to validate the ?state= query parameter in handleListDebugSessions.
//
// A parallel map (canonicalDebugSessionStates) exists in pkg/bgctl/client for
// client-side normalisation of user-supplied state strings (lowercase → canonical).
// The two maps cannot be unified: they live in different packages, serve different
// purposes (server validation vs. client normalisation), and merging them would
// introduce a circular import. Both derive from the same breakglassv1alpha1
// constants, so they remain structurally in sync as new states are added.
var validDebugSessionStates = map[string]struct{}{
	string(breakglassv1alpha1.DebugSessionStatePending):         {},
	string(breakglassv1alpha1.DebugSessionStatePendingApproval): {},
	string(breakglassv1alpha1.DebugSessionStateActive):          {},
	string(breakglassv1alpha1.DebugSessionStateExpired):         {},
	string(breakglassv1alpha1.DebugSessionStateTerminated):      {},
	string(breakglassv1alpha1.DebugSessionStateFailed):          {},
}

// isValidDebugSessionState returns true when val (case-insensitive) matches
// one of the canonical DebugSessionState values.
func isValidDebugSessionState(val string) bool {
	for k := range validDebugSessionStates {
		if strings.EqualFold(k, val) {
			return true
		}
	}
	return false
}

func parseDebugSessionBindingRef(bindingRef string) (string, string, bool) {
	if strings.Count(bindingRef, "/") != 1 {
		return "", "", false
	}
	parts := strings.SplitN(bindingRef, "/", 2)
	if parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func effectiveDebugSessionAllowed(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglassv1alpha1.DebugSessionAllowed {
	if binding != nil && binding.Spec.Allowed != nil &&
		(len(binding.Spec.Allowed.Users) > 0 || len(binding.Spec.Allowed.Groups) > 0) {
		return binding.Spec.Allowed
	}
	if template == nil {
		return nil
	}
	return template.Spec.Allowed
}

func isDebugSessionRequesterAllowed(allowed *breakglassv1alpha1.DebugSessionAllowed, username, email string, userGroups []string) bool {
	if allowed == nil || (len(allowed.Users) == 0 && len(allowed.Groups) == 0) {
		return true
	}
	for _, allowedUser := range allowed.Users {
		if matchPattern(allowedUser, username) || (email != "" && matchPattern(allowedUser, email)) {
			return true
		}
	}
	for _, allowedGroup := range allowed.Groups {
		for _, userGroup := range userGroups {
			if matchPattern(allowedGroup, userGroup) {
				return true
			}
		}
	}
	return false
}

type debugSessionReadAuthorizer struct {
	controller        *DebugSessionAPIController
	identity          debugSessionReadIdentity
	bindingApprovers  map[ctrlclient.ObjectKey]*breakglassv1alpha1.DebugSessionApprovers
	templateApprovers map[string]*breakglassv1alpha1.DebugSessionApprovers
}

func (c *DebugSessionAPIController) newDebugSessionReadAuthorizer(identity debugSessionReadIdentity) *debugSessionReadAuthorizer {
	return &debugSessionReadAuthorizer{
		controller:        c,
		identity:          identity,
		bindingApprovers:  map[ctrlclient.ObjectKey]*breakglassv1alpha1.DebugSessionApprovers{},
		templateApprovers: map[string]*breakglassv1alpha1.DebugSessionApprovers{},
	}
}

func (c *DebugSessionAPIController) canReadDebugSession(ctx context.Context, session *breakglassv1alpha1.DebugSession, identity debugSessionReadIdentity) (bool, error) {
	return c.newDebugSessionReadAuthorizer(identity).canRead(ctx, session)
}

func (a *debugSessionReadAuthorizer) canRead(ctx context.Context, session *breakglassv1alpha1.DebugSession) (bool, error) {
	identity := a.identity
	if debugSessionIdentityMatches(identity, session.Spec.RequestedBy, session.Spec.RequestedByEmail) {
		return true, nil
	}
	for _, participant := range session.Status.Participants {
		if participant.LeftAt == nil && debugSessionIdentityMatches(identity, participant.User, participant.Email) {
			return true, nil
		}
	}
	for _, invitee := range session.Spec.InvitedParticipants {
		if debugSessionIdentityMatches(identity, invitee) {
			return true, nil
		}
	}
	if session.Status.Approval != nil &&
		debugSessionIdentityMatches(identity, session.Status.Approval.ApprovedBy, session.Status.Approval.RejectedBy) {
		return true, nil
	}
	return a.isExplicitDebugSessionApprover(ctx, session)
}

func (a *debugSessionReadAuthorizer) isExplicitDebugSessionApprover(ctx context.Context, session *breakglassv1alpha1.DebugSession) (bool, error) {
	approvers, err := a.readApproversFromBinding(ctx, session)
	if err != nil {
		return false, err
	}
	if debugSessionApproversConfigured(approvers) {
		return a.approverAuthorizationMatches(approvers), nil
	}
	if session.Status.ResolvedTemplate != nil &&
		debugSessionApproversConfigured(session.Status.ResolvedTemplate.Approvers) {
		return a.approverAuthorizationMatches(session.Status.ResolvedTemplate.Approvers), nil
	}

	approvers, err = a.readApproversFromTemplate(ctx, session)
	if err != nil {
		return false, err
	}
	return debugSessionApproversConfigured(approvers) &&
		a.approverAuthorizationMatches(approvers), nil
}

func (a *debugSessionReadAuthorizer) approverAuthorizationMatches(approvers *breakglassv1alpha1.DebugSessionApprovers) bool {
	identity := a.identity
	if a.controller.checkApproverAuthorization(approvers, identity.username, identity.groups) {
		return true
	}
	return identity.email != "" &&
		identity.email != identity.username &&
		a.controller.checkApproverAuthorization(approvers, identity.email, identity.groups)
}

func (a *debugSessionReadAuthorizer) readApproversFromBinding(ctx context.Context, session *breakglassv1alpha1.DebugSession) (*breakglassv1alpha1.DebugSessionApprovers, error) {
	if session.Spec.BindingRef == nil {
		return nil, nil
	}
	key := ctrlclient.ObjectKey{Name: session.Spec.BindingRef.Name, Namespace: session.Spec.BindingRef.Namespace}
	if approvers, ok := a.bindingApprovers[key]; ok {
		return approvers, nil
	}

	binding := &breakglassv1alpha1.DebugSessionClusterBinding{}
	if err := a.controller.reader().Get(ctx, key, binding); err != nil {
		if !apierrors.IsNotFound(err) {
			a.controller.log.Warnw("Could not fetch binding while checking debug session read authorization",
				"session", session.Name, "binding", key.String(), "error", err)
			return nil, fmt.Errorf("fetch debug session binding %s: %w", key.String(), err)
		}
		a.bindingApprovers[key] = nil
		return nil, nil
	}
	a.bindingApprovers[key] = binding.Spec.Approvers
	return binding.Spec.Approvers, nil
}

func (a *debugSessionReadAuthorizer) readApproversFromTemplate(ctx context.Context, session *breakglassv1alpha1.DebugSession) (*breakglassv1alpha1.DebugSessionApprovers, error) {
	templateRef := session.Spec.TemplateRef
	if templateRef == "" {
		return nil, nil
	}
	if approvers, ok := a.templateApprovers[templateRef]; ok {
		return approvers, nil
	}

	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := a.controller.reader().Get(ctx, ctrlclient.ObjectKey{Name: templateRef}, template); err != nil {
		if !apierrors.IsNotFound(err) {
			a.controller.log.Warnw("Could not fetch template while checking debug session read authorization",
				"session", session.Name, "template", templateRef, "error", err)
			return nil, fmt.Errorf("fetch debug session template %s: %w", templateRef, err)
		}
		a.templateApprovers[templateRef] = nil
		return nil, nil
	}
	a.templateApprovers[templateRef] = template.Spec.Approvers
	return template.Spec.Approvers, nil
}

func debugSessionApproversConfigured(approvers *breakglassv1alpha1.DebugSessionApprovers) bool {
	return approvers != nil && (len(approvers.Users) > 0 || len(approvers.Groups) > 0)
}

func effectiveDebugRequestReasonConfig(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglassv1alpha1.DebugRequestReasonConfig {
	if binding != nil && binding.Spec.RequestReason != nil {
		return binding.Spec.RequestReason
	}
	if template != nil {
		return template.Spec.RequestReason
	}
	return nil
}

func effectiveDebugApprovalReasonConfig(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) *breakglassv1alpha1.DebugApprovalReasonConfig {
	if binding != nil && binding.Spec.ApprovalReason != nil {
		return binding.Spec.ApprovalReason
	}
	if template != nil {
		return template.Spec.ApprovalReason
	}
	return nil
}

func validateDebugRequestReason(reason string, cfg *breakglassv1alpha1.DebugRequestReasonConfig) error {
	if cfg == nil {
		return nil
	}
	reason = strings.TrimSpace(reason)
	if cfg.Mandatory && reason == "" {
		return errors.New("missing required request reason")
	}
	return validateDebugReasonLength(reason, cfg.MinLength, cfg.MaxLength)
}

func validateDebugApprovalReason(reason string, cfg *breakglassv1alpha1.DebugApprovalReasonConfig, rejection bool) error {
	if cfg == nil {
		return nil
	}
	reason = strings.TrimSpace(reason)
	required := cfg.Mandatory || (rejection && cfg.MandatoryForRejection)
	if required && reason == "" {
		if rejection {
			return errors.New("missing required rejection reason")
		}
		return errors.New("missing required approval reason")
	}
	return validateDebugReasonLength(reason, cfg.MinLength, 0)
}

func validateDebugReasonLength(reason string, minLength, maxLength int32) error {
	if reason == "" {
		return nil
	}
	reasonLength := len([]rune(reason))
	if minLength > 0 && reasonLength < int(minLength) {
		return fmt.Errorf("reason must be at least %d characters", minLength)
	}
	if maxLength > 0 && reasonLength > int(maxLength) {
		return fmt.Errorf("reason must be at most %d characters", maxLength)
	}
	return nil
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
