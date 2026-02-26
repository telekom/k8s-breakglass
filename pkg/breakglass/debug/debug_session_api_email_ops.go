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
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/system"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func (c *DebugSessionAPIController) sendDebugSessionRequestEmail(ctx context.Context, session *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) {
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
func (c *DebugSessionAPIController) sendDebugSessionApprovalEmail(ctx context.Context, session *breakglassv1alpha1.DebugSession) {
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
func (c *DebugSessionAPIController) sendDebugSessionRejectionEmail(ctx context.Context, session *breakglassv1alpha1.DebugSession) {
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
func (c *DebugSessionAPIController) sendDebugSessionCreatedEmail(ctx context.Context, session *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) {
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
func (c *DebugSessionAPIController) emitDebugSessionAuditEvent(ctx context.Context, eventType audit.EventType, session *breakglassv1alpha1.DebugSession, user string, message string) {
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

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
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
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
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
		(session.Status.ResolvedTemplate.Mode != breakglassv1alpha1.DebugSessionModeKubectlDebug &&
			session.Status.ResolvedTemplate.Mode != breakglassv1alpha1.DebugSessionModeHybrid) {
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

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
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
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
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
		(session.Status.ResolvedTemplate.Mode != breakglassv1alpha1.DebugSessionModeKubectlDebug &&
			session.Status.ResolvedTemplate.Mode != breakglassv1alpha1.DebugSessionModeHybrid) {
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

	apiCtx, cancel := context.WithTimeout(ctx.Request.Context(), breakglass.APIContextTimeout)
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
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive {
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
		(session.Status.ResolvedTemplate.Mode != breakglassv1alpha1.DebugSessionModeKubectlDebug &&
			session.Status.ResolvedTemplate.Mode != breakglassv1alpha1.DebugSessionModeHybrid) {
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
func (c *DebugSessionAPIController) isUserParticipant(session *breakglassv1alpha1.DebugSession, user string) bool {
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
func (c *DebugSessionAPIController) checkBindingSessionLimits(ctx context.Context, binding *breakglassv1alpha1.DebugSessionClusterBinding, userEmail string) error {
	if binding == nil {
		return nil
	}

	// Get current active sessions for this binding
	sessionList := &breakglassv1alpha1.DebugSessionList{}
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
		if session.Status.State == breakglassv1alpha1.DebugSessionStateTerminated ||
			session.Status.State == breakglassv1alpha1.DebugSessionStateExpired ||
			session.Status.State == breakglassv1alpha1.DebugSessionStateFailed {
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
	AllowedBySource string                                          // "template" or "binding:<ns>/<name>"
	MatchingBinding *breakglassv1alpha1.DebugSessionClusterBinding  // Non-nil if allowed by binding
	AllBindings     []breakglassv1alpha1.DebugSessionClusterBinding // All bindings that allow this cluster
}

// isClusterAllowedByTemplateOrBinding checks if a cluster is allowed by the template's allowed.clusters
// or by any active binding that references this template.
// This function requires the caller to pass in the bindings and clusterConfigs.
// If the template has no allowed.clusters, cluster access depends on bindings.
// If there are no bindings either, access is implicitly allowed (backward compatibility).
func (c *DebugSessionAPIController) isClusterAllowedByTemplateOrBinding(
	template *breakglassv1alpha1.DebugSessionTemplate,
	clusterName string,
	bindings []breakglassv1alpha1.DebugSessionClusterBinding,
	clusterConfigs map[string]*breakglassv1alpha1.ClusterConfig,
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
