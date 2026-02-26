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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DebugSessionLabelKey is used to identify debug pods
	DebugSessionLabelKey = "breakglass.telekom.com/debug-session"
	// DebugTemplateLabelKey identifies the template used
	DebugTemplateLabelKey = "breakglass.telekom.com/debug-template"
	// DebugClusterLabelKey identifies the target cluster
	DebugClusterLabelKey = "breakglass.telekom.com/debug-cluster"

	// DefaultDebugSessionRequeue is the default requeue interval
	DefaultDebugSessionRequeue = 30 * time.Second
	// ExpiredSessionRequeue is requeue for cleanup
	ExpiredSessionRequeue = 5 * time.Second
)

// DebugSessionController manages DebugSession lifecycle
type DebugSessionController struct {
	log          *zap.SugaredLogger
	client       ctrlclient.Client
	ccProvider   *cluster.ClientProvider
	auditManager *audit.Manager
	mailService  breakglass.MailEnqueuer
	auxiliaryMgr *AuxiliaryResourceManager
	brandingName string
	baseURL      string
	disableEmail bool
}

// NewDebugSessionController creates a new DebugSessionController
func NewDebugSessionController(log *zap.SugaredLogger, client ctrlclient.Client, ccProvider *cluster.ClientProvider) *DebugSessionController {
	return &DebugSessionController{
		log:          log,
		client:       client,
		ccProvider:   ccProvider,
		auxiliaryMgr: NewAuxiliaryResourceManager(log.Named("auxiliary"), client),
	}
}

// WithAuditManager sets the audit manager for the controller
func (c *DebugSessionController) WithAuditManager(am *audit.Manager) *DebugSessionController {
	c.auditManager = am
	return c
}

// WithMailService sets the mail service for sending failure notifications
func (c *DebugSessionController) WithMailService(mailService breakglass.MailEnqueuer, brandingName, baseURL string, disableEmail bool) *DebugSessionController {
	c.mailService = mailService
	c.brandingName = brandingName
	c.baseURL = baseURL
	c.disableEmail = disableEmail
	return c
}

// SetupWithManager sets up the controller with the Manager
func (c *DebugSessionController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DebugSession{}).
		Complete(c)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessions,verbs=get;list;watch;create;update;patch;delete;deletecollection
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessions/finalizers,verbs=update
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessiontemplates,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessiontemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugpodtemplates,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugpodtemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile handles DebugSession state transitions
func (c *DebugSessionController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := c.log.With("debugSession", req.NamespacedName)

	ds := &breakglassv1alpha1.DebugSession{}
	if err := c.client.Get(ctx, req.NamespacedName, ds); err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("DebugSession not found, ignoring")
			return ctrl.Result{}, nil
		}
		log.Errorw("Failed to get DebugSession", "error", err)
		return ctrl.Result{}, err
	}

	// Perform structural validation using shared validation function.
	// This catches malformed resources that somehow bypassed the admission webhook.
	validationResult := breakglassv1alpha1.ValidateDebugSession(ds)
	if !validationResult.IsValid() {
		log.Warnw("DebugSession failed structural validation, skipping reconciliation",
			"errors", validationResult.ErrorMessage())

		// Update status condition to reflect validation failure
		ds.Status.State = breakglassv1alpha1.DebugSessionStateFailed
		ds.Status.Message = fmt.Sprintf("Validation failed: %s", validationResult.ErrorMessage())
		if statusErr := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); statusErr != nil {
			log.Errorw("Failed to update DebugSession status after validation failure", "error", statusErr)
		}

		// Return nil error to skip requeue - malformed resource won't fix itself
		return ctrl.Result{}, nil
	}

	log = log.With("state", ds.Status.State, "cluster", ds.Spec.Cluster)

	switch ds.Status.State {
	case "", breakglassv1alpha1.DebugSessionStatePending:
		return c.handlePending(ctx, ds)
	case breakglassv1alpha1.DebugSessionStatePendingApproval:
		return c.handlePendingApproval(ctx, ds)
	case breakglassv1alpha1.DebugSessionStateActive:
		return c.handleActive(ctx, ds)
	case breakglassv1alpha1.DebugSessionStateExpired, breakglassv1alpha1.DebugSessionStateTerminated:
		return c.handleCleanup(ctx, ds)
	case breakglassv1alpha1.DebugSessionStateFailed:
		// Terminal state, no action needed
		return ctrl.Result{}, nil
	default:
		log.Warnw("Unknown debug session state", "state", ds.Status.State)
		return ctrl.Result{}, nil
	}
}

// handlePending processes a newly created debug session
func (c *DebugSessionController) handlePending(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Resolve the template
	template, err := c.getTemplate(ctx, ds.Spec.TemplateRef)
	if err != nil {
		log.Errorw("Failed to get DebugSessionTemplate", "template", ds.Spec.TemplateRef, "error", err)
		return c.failSession(ctx, ds, fmt.Sprintf("template not found: %s", ds.Spec.TemplateRef))
	}

	// Cache the resolved template in status
	ds.Status.ResolvedTemplate = &template.Spec

	// Find binding early so we can check its approvers for the approval decision
	// This ensures bindings with approvers properly trigger approval workflow
	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if ds.Spec.BindingRef != nil {
		binding, err = c.getBinding(ctx, ds.Spec.BindingRef.Name, ds.Spec.BindingRef.Namespace)
		if err != nil {
			log.Warnw("Failed to get binding by ref, will try auto-discovery",
				"binding", ds.Spec.BindingRef.Name,
				"namespace", ds.Spec.BindingRef.Namespace,
				"error", err)
		}
	}
	if binding == nil {
		binding, _ = c.findBindingForSession(ctx, template, ds.Spec.Cluster)
		if binding != nil {
			log.Infow("Auto-discovered binding for session",
				"binding", binding.Name,
				"namespace", binding.Namespace)
		}
	}

	// Check if approval is required (checks both template and binding approvers)
	requiresApproval := c.requiresApproval(template, binding, ds)
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{
		Required: requiresApproval,
	}

	if requiresApproval {
		ds.Status.State = breakglassv1alpha1.DebugSessionStatePendingApproval
		ds.Status.Message = "Waiting for approval"
		if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
			return ctrl.Result{}, err
		}
		metrics.DebugSessionsCreated.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
		return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
	}

	// Auto-approved, transition to active
	return c.activateSession(ctx, ds, template, binding)
}

// handlePendingApproval checks for approval status
func (c *DebugSessionController) handlePendingApproval(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	// If approved, activate
	if ds.Status.Approval != nil && ds.Status.Approval.ApprovedAt != nil {
		template, err := c.getTemplate(ctx, ds.Spec.TemplateRef)
		if err != nil {
			return c.failSession(ctx, ds, fmt.Sprintf("template not found: %s", ds.Spec.TemplateRef))
		}
		// Find binding for merging allowed pod operations
		var binding *breakglassv1alpha1.DebugSessionClusterBinding
		if ds.Spec.BindingRef != nil {
			binding, _ = c.getBinding(ctx, ds.Spec.BindingRef.Name, ds.Spec.BindingRef.Namespace)
		}
		if binding == nil {
			binding, _ = c.findBindingForSession(ctx, template, ds.Spec.Cluster)
		}
		return c.activateSession(ctx, ds, template, binding)
	}

	// If rejected, mark as terminated
	if ds.Status.Approval != nil && ds.Status.Approval.RejectedAt != nil {
		ds.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		ds.Status.Message = fmt.Sprintf("Rejected by %s: %s", ds.Status.Approval.RejectedBy, ds.Status.Approval.Reason)
		return ctrl.Result{}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
	}

	// Still waiting for approval
	return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
}

// handleActive manages an active debug session
func (c *DebugSessionController) handleActive(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Emit expiring-soon status message when within grace period
	if ds.Status.ExpiresAt != nil && ds.Status.ResolvedTemplate != nil && ds.Status.ResolvedTemplate.GracePeriodBeforeExpiry != "" {
		grace, err := time.ParseDuration(ds.Status.ResolvedTemplate.GracePeriodBeforeExpiry)
		if err == nil {
			until := time.Until(ds.Status.ExpiresAt.Time)
			if until > 0 && until <= grace && ds.Status.Message != "Session expiring soon" {
				ds.Status.Message = "Session expiring soon"
				if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
					return ctrl.Result{}, err
				}
			}
		}
	}

	// Check expiration
	if ds.Status.ExpiresAt != nil && time.Now().After(ds.Status.ExpiresAt.Time) {
		log.Info("Debug session expired")
		if ds.Status.ResolvedTemplate != nil && ds.Status.ResolvedTemplate.ExpirationBehavior == "notify-only" {
			ds.Status.Message = "Session expired (notify-only)"
			ds.Status.ExpiresAt = nil
			if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		ds.Status.State = breakglassv1alpha1.DebugSessionStateExpired
		ds.Status.Message = "Session expired"
		if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
			return ctrl.Result{}, err
		}
		metrics.DebugSessionsActive.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Dec()
		return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, nil
	}

	// Update allowed pods list from deployed workloads
	if err := c.updateAllowedPods(ctx, ds); err != nil {
		log.Warnw("Failed to update allowed pods", "error", err)
	}

	// Calculate next requeue based on expiration
	if ds.Status.ExpiresAt != nil {
		until := time.Until(ds.Status.ExpiresAt.Time)
		if until > 0 && until < DefaultDebugSessionRequeue {
			return ctrl.Result{RequeueAfter: until + time.Second}, nil
		}
	}

	return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
}

// handleCleanup removes deployed resources for expired/terminated sessions
func (c *DebugSessionController) handleCleanup(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	if err := c.cleanupResources(ctx, ds); err != nil {
		log.Errorw("Failed to cleanup debug session resources", "error", err)
		// Requeue to retry cleanup
		return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, nil
	}

	// Record metrics
	if ds.Status.StartsAt != nil {
		duration := time.Since(ds.Status.StartsAt.Time).Seconds()
		metrics.DebugSessionDuration.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Observe(duration)
	}

	// Update template status to decrement active session count
	if ds.Spec.TemplateRef != "" {
		template, err := c.getTemplate(ctx, ds.Spec.TemplateRef)
		if err == nil {
			if err := c.updateTemplateStatus(ctx, template, false); err != nil {
				log.Warnw("Failed to update template status during cleanup", "template", ds.Spec.TemplateRef, "error", err)
				// Non-fatal: cleanup still succeeds
			}
		}
	}

	log.Info("Debug session cleanup complete")
	return ctrl.Result{}, nil
}

// activateSession deploys debug resources and marks session as active
func (c *DebugSessionController) activateSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Only deploy workloads for workload or hybrid mode
	mode := template.Spec.Mode
	if mode == "" {
		mode = breakglassv1alpha1.DebugSessionModeWorkload
	}

	if mode == breakglassv1alpha1.DebugSessionModeWorkload || mode == breakglassv1alpha1.DebugSessionModeHybrid {
		if err := c.deployDebugResources(ctx, ds, template); err != nil {
			log.Errorw("Failed to deploy debug resources", "error", err)
			return c.failSession(ctx, ds, fmt.Sprintf("failed to deploy resources: %v", err))
		}
	}

	// Calculate expiration
	duration := c.parseDuration(ds.Spec.RequestedDuration, template.Spec.Constraints)
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(duration))

	ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
	ds.Status.StartsAt = &now
	ds.Status.ExpiresAt = &expiresAt
	ds.Status.Message = "Debug session active"

	// Cache AllowedPodOperations merged from template and binding for webhook enforcement
	// Binding can only be more restrictive than template
	var bindingOps *breakglassv1alpha1.AllowedPodOperations
	if binding != nil {
		bindingOps = binding.Spec.AllowedPodOperations
	}
	ds.Status.AllowedPodOperations = breakglassv1alpha1.MergeAllowedPodOperations(template.Spec.AllowedPodOperations, bindingOps)

	// Add the requesting user as owner participant
	ds.Status.Participants = []breakglassv1alpha1.DebugSessionParticipant{{
		User:        ds.Spec.RequestedBy,
		Email:       ds.Spec.RequestedByEmail,
		DisplayName: ds.Spec.RequestedByDisplayName,
		Role:        breakglassv1alpha1.ParticipantRoleOwner,
		JoinedAt:    now,
	}}

	// Setup terminal sharing if enabled
	if template.Spec.TerminalSharing != nil && template.Spec.TerminalSharing.Enabled {
		ds.Status.TerminalSharing = c.setupTerminalSharing(ds, template)
	}

	if err := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); err != nil {
		return ctrl.Result{}, err
	}

	metrics.DebugSessionsCreated.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
	metrics.DebugSessionsActive.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()

	// Update template status to reflect active session
	if err := c.updateTemplateStatus(ctx, template, true); err != nil {
		log.Warnw("Failed to update template status", "template", template.Name, "error", err)
		// Non-fatal: session activation still succeeds
	}

	log.Infow("Debug session activated",
		"expiresAt", expiresAt.Time,
		"duration", duration.String(),
		"mode", mode,
		"terminalSharing", ds.Status.TerminalSharing != nil)

	return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
}

// failSession marks a session as failed and logs the failure
func (c *DebugSessionController) failSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession, reason string) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace, "cluster", ds.Spec.Cluster)

	// Best-effort cleanup of any partially deployed resources on the target cluster.
	// Short-circuit if the session never deployed anything to avoid noisy cross-cluster calls.
	hasDeployedResources := len(ds.Status.DeployedResources) > 0 ||
		len(ds.Status.AuxiliaryResourceStatuses) > 0 ||
		len(ds.Status.PodTemplateResourceStatuses) > 0 ||
		len(ds.Status.AllowedPods) > 0
	if hasDeployedResources {
		if cleanupErr := c.cleanupResources(ctx, ds); cleanupErr != nil {
			log.Warnw("Best-effort cleanup of partially deployed resources failed during session failure",
				"cleanupError", cleanupErr)
		}
	}

	// Log the failure with full context
	log.Errorw("Debug session failed",
		"reason", reason,
		"template", ds.Spec.TemplateRef,
		"requestedBy", ds.Spec.RequestedBy,
		"previousState", ds.Status.State,
	)

	// Emit audit event if audit is enabled for this session
	if c.shouldEmitAudit(ds) && c.auditManager != nil {
		c.auditManager.DebugSessionFailed(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster, reason, map[string]interface{}{
			"template":       ds.Spec.TemplateRef,
			"requested_by":   ds.Spec.RequestedBy,
			"previous_state": string(ds.Status.State),
		})
		// Send to webhook destinations if configured
		c.sendToWebhookDestinations(ctx, ds, "DebugSessionFailed", map[string]interface{}{
			"session":   ds.Name,
			"namespace": ds.Namespace,
			"cluster":   ds.Spec.Cluster,
			"reason":    reason,
		})
	}

	ds.Status.State = breakglassv1alpha1.DebugSessionStateFailed
	ds.Status.Message = reason

	// Send failure notification email to requester
	c.sendDebugSessionFailedEmail(ds, reason)

	// Increment failure metric
	metrics.DebugSessionsFailed.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()

	return ctrl.Result{}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
}

// sendDebugSessionFailedEmail sends email notification to requester when a debug session fails
func (c *DebugSessionController) sendDebugSessionFailedEmail(ds *breakglassv1alpha1.DebugSession, reason string) {
	if c.disableEmail || c.mailService == nil || !c.mailService.IsEnabled() {
		return
	}

	recipients := []string{ds.Spec.RequestedBy}

	params := mail.DebugSessionFailedMailParams{
		RequesterName:  ds.Spec.RequestedBy,
		RequesterEmail: ds.Spec.RequestedBy,
		SessionID:      ds.Name,
		Cluster:        ds.Spec.Cluster,
		TemplateName:   ds.Spec.TemplateRef,
		Namespace:      ds.Namespace,
		FailedAt:       time.Now().Format(time.RFC3339),
		FailureReason:  reason,
		URL:            fmt.Sprintf("%s/debug-sessions", c.baseURL),
		BrandingName:   c.brandingName,
	}

	body, err := mail.RenderDebugSessionFailed(params)
	if err != nil {
		c.log.Errorw("Failed to render debug session failed email", "session", ds.Name, "error", err)
		return
	}

	subject := fmt.Sprintf("[%s] Debug Session Failed: %s", c.brandingName, ds.Name)
	if err := c.mailService.Enqueue(ds.Name, recipients, subject, body); err != nil {
		c.log.Errorw("Failed to enqueue debug session failed email", "session", ds.Name, "error", err)
	} else {
		c.log.Infow("Debug session failed email queued", "session", ds.Name, "requester", ds.Spec.RequestedBy)
	}
}

// shouldEmitAudit checks if audit events should be emitted for this session
// based on the template's audit configuration.
func (c *DebugSessionController) shouldEmitAudit(ds *breakglassv1alpha1.DebugSession) bool {
	if ds.Status.ResolvedTemplate == nil {
		return true // Default to emit audit if no template resolved yet
	}
	if ds.Status.ResolvedTemplate.Audit == nil {
		return true // Default to enabled if not configured
	}
	return ds.Status.ResolvedTemplate.Audit.Enabled
}

// sendToWebhookDestinations sends audit events to configured webhook destinations
// from the debug session template's audit config.
func (c *DebugSessionController) sendToWebhookDestinations(ctx context.Context, ds *breakglassv1alpha1.DebugSession, eventType string, payload map[string]interface{}) {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.Audit == nil {
		return
	}

	for _, dest := range ds.Status.ResolvedTemplate.Audit.Destinations {
		if dest.Type != "webhook" || dest.URL == "" {
			continue
		}

		go func(destination breakglassv1alpha1.AuditDestination) {
			if err := c.sendWebhookEvent(ctx, destination, eventType, ds, payload); err != nil {
				c.log.Warnw("Failed to send audit event to webhook destination",
					"url", destination.URL,
					"eventType", eventType,
					"session", ds.Name,
					"error", err)
			}
		}(dest)
	}
}

// sendWebhookEvent sends an audit event to a webhook destination.
func (c *DebugSessionController) sendWebhookEvent(ctx context.Context, dest breakglassv1alpha1.AuditDestination, eventType string, ds *breakglassv1alpha1.DebugSession, payload map[string]interface{}) error {
	// Build the full payload
	fullPayload := map[string]interface{}{
		"eventType": eventType,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"session": map[string]interface{}{
			"name":        ds.Name,
			"namespace":   ds.Namespace,
			"cluster":     ds.Spec.Cluster,
			"templateRef": ds.Spec.TemplateRef,
			"requestedBy": ds.Spec.RequestedBy,
			"state":       string(ds.Status.State),
		},
		"details": payload,
	}

	jsonData, err := json.Marshal(fullPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.URL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range dest.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// getTemplate retrieves a DebugSessionTemplate by name
func (c *DebugSessionController) getTemplate(ctx context.Context, name string) (*breakglassv1alpha1.DebugSessionTemplate, error) {
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		return nil, err
	}
	return template, nil
}

// getPodTemplate retrieves a DebugPodTemplate by name
func (c *DebugSessionController) getPodTemplate(ctx context.Context, name string) (*breakglassv1alpha1.DebugPodTemplate, error) {
	template := &breakglassv1alpha1.DebugPodTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		return nil, err
	}
	return template, nil
}

// getBinding retrieves a DebugSessionClusterBinding by name and namespace
func (c *DebugSessionController) getBinding(ctx context.Context, name, namespace string) (*breakglassv1alpha1.DebugSessionClusterBinding, error) {
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: name, Namespace: namespace}, binding); err != nil {
		return nil, err
	}
	return binding, nil
}

// findBindingForSession finds a DebugSessionClusterBinding that matches the session's template and cluster.
// This enables binding configuration to be applied even when BindingRef is not explicitly set.
// Returns nil if no matching binding is found.
func (c *DebugSessionController) findBindingForSession(ctx context.Context, template *breakglassv1alpha1.DebugSessionTemplate, clusterName string) (*breakglassv1alpha1.DebugSessionClusterBinding, error) {
	bindingList := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindingList); err != nil {
		return nil, fmt.Errorf("failed to list cluster bindings: %w", err)
	}

	// Get cluster config for label-based matching
	var clusterConfig *breakglassv1alpha1.ClusterConfig
	clusterConfigList := &breakglassv1alpha1.ClusterConfigList{}
	if err := c.client.List(ctx, clusterConfigList); err == nil {
		for i := range clusterConfigList.Items {
			if clusterConfigList.Items[i].Name == clusterName {
				clusterConfig = &clusterConfigList.Items[i]
				break
			}
		}
	}

	for i := range bindingList.Items {
		binding := &bindingList.Items[i]
		if !breakglass.IsBindingActive(binding) {
			continue
		}

		// Check if binding references this template
		if !c.bindingMatchesTemplate(binding, template) {
			continue
		}

		// Check if binding matches this cluster
		if !c.bindingMatchesCluster(binding, clusterName, clusterConfig) {
			continue
		}

		// Found a matching binding
		return binding, nil
	}

	return nil, nil // No matching binding found (not an error)
}

// bindingMatchesTemplate checks if a binding references the given template
func (c *DebugSessionController) bindingMatchesTemplate(binding *breakglassv1alpha1.DebugSessionClusterBinding, template *breakglassv1alpha1.DebugSessionTemplate) bool {
	// Check templateRef
	if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name == template.Name {
		return true
	}
	// Check templateSelector
	if binding.Spec.TemplateSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
		if err == nil {
			templateLabels := labels.Set(template.Labels)
			if selector.Matches(templateLabels) {
				return true
			}
		}
	}
	return false
}

// bindingMatchesCluster checks if a binding applies to the given cluster
func (c *DebugSessionController) bindingMatchesCluster(binding *breakglassv1alpha1.DebugSessionClusterBinding, clusterName string, clusterConfig *breakglassv1alpha1.ClusterConfig) bool {
	// Check explicit cluster list
	for _, cluster := range binding.Spec.Clusters {
		if cluster == clusterName {
			return true
		}
	}

	// Check clusterSelector
	if binding.Spec.ClusterSelector != nil && clusterConfig != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err == nil {
			clusterLabels := labels.Set(clusterConfig.Labels)
			if selector.Matches(clusterLabels) {
				return true
			}
		}
	}

	return false
}

// resolveImpersonationConfig determines the impersonation configuration for a session.
// Binding impersonation overrides template impersonation.
func (c *DebugSessionController) resolveImpersonationConfig(
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
) *breakglassv1alpha1.ImpersonationConfig {
	// Binding takes precedence
	if binding != nil && binding.Spec.Impersonation != nil {
		return binding.Spec.Impersonation
	}
	// Fall back to template
	if template != nil && template.Spec.Impersonation != nil {
		return template.Spec.Impersonation
	}
	return nil
}

// createImpersonatedClient creates a spoke cluster client that impersonates the specified ServiceAccount.
// The SA is expected to exist in the spoke cluster, not the hub.
func (c *DebugSessionController) createImpersonatedClient(
	ctx context.Context,
	clusterName string,
	impConfig *breakglassv1alpha1.ImpersonationConfig,
) (ctrlclient.Client, error) {
	// Get base REST config for spoke cluster
	restCfg, err := c.ccProvider.GetRESTConfig(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get REST config for cluster %s: %w", clusterName, err)
	}

	// If impersonation is configured, set up impersonation
	if impConfig != nil && impConfig.ServiceAccountRef != nil {
		// Impersonate the spoke cluster's ServiceAccount
		// Format: system:serviceaccount:<namespace>:<name>
		restCfg.Impersonate = rest.ImpersonationConfig{
			UserName: fmt.Sprintf("system:serviceaccount:%s:%s",
				impConfig.ServiceAccountRef.Namespace,
				impConfig.ServiceAccountRef.Name),
		}
	}

	client, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create client for cluster %s: %w", clusterName, err)
	}
	return client, nil
}

// validateSpokeServiceAccount checks if the ServiceAccount exists in the spoke cluster.
// This is a runtime validation that cannot happen at webhook time.
func (c *DebugSessionController) validateSpokeServiceAccount(
	ctx context.Context,
	spokeClient ctrlclient.Client,
	saRef *breakglassv1alpha1.ServiceAccountReference,
) error {
	sa := &corev1.ServiceAccount{}
	err := spokeClient.Get(ctx, ctrlclient.ObjectKey{
		Name:      saRef.Name,
		Namespace: saRef.Namespace,
	}, sa)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("impersonation ServiceAccount %s/%s not found in spoke cluster",
				saRef.Namespace, saRef.Name)
		}
		return fmt.Errorf("failed to validate impersonation ServiceAccount: %w", err)
	}
	return nil
}

// requiresApproval checks if the session requires approval.
// It checks both the template and the binding for approvers configuration.
// Approval is required if either the template or binding specifies approvers
// (unless auto-approve conditions are met).
func (c *DebugSessionController) requiresApproval(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, ds *breakglassv1alpha1.DebugSession) bool {
	// Check if binding has approvers configured (takes precedence)
	if binding != nil && binding.Spec.Approvers != nil {
		if len(binding.Spec.Approvers.Users) > 0 || len(binding.Spec.Approvers.Groups) > 0 {
			c.log.Infow("Approval required by binding",
				"session", ds.Name,
				"binding", binding.Name,
				"bindingNamespace", binding.Namespace)
			// Check binding auto-approve conditions
			if binding.Spec.Approvers.AutoApproveFor != nil {
				if c.checkAutoApprove(binding.Spec.Approvers.AutoApproveFor, ds) {
					return false
				}
			}
			return true
		}
	}

	// Check if template has approvers configured
	if template.Spec.Approvers == nil {
		return false // No approvers configured = auto-approve
	}

	// Check if template has actual approvers (not just auto-approve rules)
	if len(template.Spec.Approvers.Users) == 0 && len(template.Spec.Approvers.Groups) == 0 {
		return false // No actual approvers configured
	}

	// Check template auto-approve conditions
	if template.Spec.Approvers.AutoApproveFor != nil {
		if c.checkAutoApprove(template.Spec.Approvers.AutoApproveFor, ds) {
			return false
		}
	}

	return true
}

// checkAutoApprove checks if auto-approve conditions are met for the session
func (c *DebugSessionController) checkAutoApprove(autoApprove *breakglassv1alpha1.AutoApproveConfig, ds *breakglassv1alpha1.DebugSession) bool {
	// Auto-approve for specific clusters
	for _, pattern := range autoApprove.Clusters {
		if matched, _ := filepath.Match(pattern, ds.Spec.Cluster); matched {
			c.log.Infow("Auto-approving debug session based on cluster match",
				"session", ds.Name,
				"cluster", ds.Spec.Cluster,
				"pattern", pattern)
			return true
		}
	}

	// Auto-approve for specific groups
	if len(autoApprove.Groups) > 0 && len(ds.Spec.UserGroups) > 0 {
		for _, autoApproveGroup := range autoApprove.Groups {
			for _, userGroup := range ds.Spec.UserGroups {
				if userGroup == autoApproveGroup {
					c.log.Infow("Auto-approving debug session based on group match",
						"session", ds.Name,
						"user", ds.Spec.RequestedBy,
						"matchedGroup", userGroup)
					return true
				}
			}
		}
	}

	return false
}

// deployDebugResources creates the debug workload on the target cluster
