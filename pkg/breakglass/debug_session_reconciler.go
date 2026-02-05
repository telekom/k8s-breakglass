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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
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
	mailService  MailEnqueuer
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
func (c *DebugSessionController) WithMailService(mailService MailEnqueuer, brandingName, baseURL string, disableEmail bool) *DebugSessionController {
	c.mailService = mailService
	c.brandingName = brandingName
	c.baseURL = baseURL
	c.disableEmail = disableEmail
	return c
}

// SetupWithManager sets up the controller with the Manager
func (c *DebugSessionController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.DebugSession{}).
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

	ds := &v1alpha1.DebugSession{}
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
	validationResult := v1alpha1.ValidateDebugSession(ds)
	if !validationResult.IsValid() {
		log.Warnw("DebugSession failed structural validation, skipping reconciliation",
			"errors", validationResult.ErrorMessage())

		// Update status condition to reflect validation failure
		ds.Status.State = v1alpha1.DebugSessionStateFailed
		ds.Status.Message = fmt.Sprintf("Validation failed: %s", validationResult.ErrorMessage())
		if statusErr := applyDebugSessionStatus(ctx, c.client, ds); statusErr != nil {
			log.Errorw("Failed to update DebugSession status after validation failure", "error", statusErr)
		}

		// Return nil error to skip requeue - malformed resource won't fix itself
		return ctrl.Result{}, nil
	}

	log = log.With("state", ds.Status.State, "cluster", ds.Spec.Cluster)

	switch ds.Status.State {
	case "", v1alpha1.DebugSessionStatePending:
		return c.handlePending(ctx, ds)
	case v1alpha1.DebugSessionStatePendingApproval:
		return c.handlePendingApproval(ctx, ds)
	case v1alpha1.DebugSessionStateActive:
		return c.handleActive(ctx, ds)
	case v1alpha1.DebugSessionStateExpired, v1alpha1.DebugSessionStateTerminated:
		return c.handleCleanup(ctx, ds)
	case v1alpha1.DebugSessionStateFailed:
		// Terminal state, no action needed
		return ctrl.Result{}, nil
	default:
		log.Warnw("Unknown debug session state", "state", ds.Status.State)
		return ctrl.Result{}, nil
	}
}

// handlePending processes a newly created debug session
func (c *DebugSessionController) handlePending(ctx context.Context, ds *v1alpha1.DebugSession) (ctrl.Result, error) {
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
	var binding *v1alpha1.DebugSessionClusterBinding
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
	ds.Status.Approval = &v1alpha1.DebugSessionApproval{
		Required: requiresApproval,
	}

	if requiresApproval {
		ds.Status.State = v1alpha1.DebugSessionStatePendingApproval
		ds.Status.Message = "Waiting for approval"
		if err := applyDebugSessionStatus(ctx, c.client, ds); err != nil {
			return ctrl.Result{}, err
		}
		metrics.DebugSessionsCreated.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
		return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
	}

	// Auto-approved, transition to active
	return c.activateSession(ctx, ds, template, binding)
}

// handlePendingApproval checks for approval status
func (c *DebugSessionController) handlePendingApproval(ctx context.Context, ds *v1alpha1.DebugSession) (ctrl.Result, error) {
	// If approved, activate
	if ds.Status.Approval != nil && ds.Status.Approval.ApprovedAt != nil {
		template, err := c.getTemplate(ctx, ds.Spec.TemplateRef)
		if err != nil {
			return c.failSession(ctx, ds, fmt.Sprintf("template not found: %s", ds.Spec.TemplateRef))
		}
		// Find binding for merging allowed pod operations
		var binding *v1alpha1.DebugSessionClusterBinding
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
		ds.Status.State = v1alpha1.DebugSessionStateTerminated
		ds.Status.Message = fmt.Sprintf("Rejected by %s: %s", ds.Status.Approval.RejectedBy, ds.Status.Approval.Reason)
		return ctrl.Result{}, applyDebugSessionStatus(ctx, c.client, ds)
	}

	// Still waiting for approval
	return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
}

// handleActive manages an active debug session
func (c *DebugSessionController) handleActive(ctx context.Context, ds *v1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Emit expiring-soon status message when within grace period
	if ds.Status.ExpiresAt != nil && ds.Status.ResolvedTemplate != nil && ds.Status.ResolvedTemplate.GracePeriodBeforeExpiry != "" {
		grace, err := time.ParseDuration(ds.Status.ResolvedTemplate.GracePeriodBeforeExpiry)
		if err == nil {
			until := time.Until(ds.Status.ExpiresAt.Time)
			if until > 0 && until <= grace && ds.Status.Message != "Session expiring soon" {
				ds.Status.Message = "Session expiring soon"
				if err := applyDebugSessionStatus(ctx, c.client, ds); err != nil {
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
			if err := applyDebugSessionStatus(ctx, c.client, ds); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		ds.Status.State = v1alpha1.DebugSessionStateExpired
		ds.Status.Message = "Session expired"
		if err := applyDebugSessionStatus(ctx, c.client, ds); err != nil {
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
func (c *DebugSessionController) handleCleanup(ctx context.Context, ds *v1alpha1.DebugSession) (ctrl.Result, error) {
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
func (c *DebugSessionController) activateSession(ctx context.Context, ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Only deploy workloads for workload or hybrid mode
	mode := template.Spec.Mode
	if mode == "" {
		mode = v1alpha1.DebugSessionModeWorkload
	}

	if mode == v1alpha1.DebugSessionModeWorkload || mode == v1alpha1.DebugSessionModeHybrid {
		if err := c.deployDebugResources(ctx, ds, template); err != nil {
			log.Errorw("Failed to deploy debug resources", "error", err)
			return c.failSession(ctx, ds, fmt.Sprintf("failed to deploy resources: %v", err))
		}
	}

	// Calculate expiration
	duration := c.parseDuration(ds.Spec.RequestedDuration, template.Spec.Constraints)
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(duration))

	ds.Status.State = v1alpha1.DebugSessionStateActive
	ds.Status.StartsAt = &now
	ds.Status.ExpiresAt = &expiresAt
	ds.Status.Message = "Debug session active"

	// Cache AllowedPodOperations merged from template and binding for webhook enforcement
	// Binding can only be more restrictive than template
	var bindingOps *v1alpha1.AllowedPodOperations
	if binding != nil {
		bindingOps = binding.Spec.AllowedPodOperations
	}
	ds.Status.AllowedPodOperations = v1alpha1.MergeAllowedPodOperations(template.Spec.AllowedPodOperations, bindingOps)

	// Add the requesting user as owner participant
	ds.Status.Participants = []v1alpha1.DebugSessionParticipant{{
		User:        ds.Spec.RequestedBy,
		Email:       ds.Spec.RequestedByEmail,
		DisplayName: ds.Spec.RequestedByDisplayName,
		Role:        v1alpha1.ParticipantRoleOwner,
		JoinedAt:    now,
	}}

	// Setup terminal sharing if enabled
	if template.Spec.TerminalSharing != nil && template.Spec.TerminalSharing.Enabled {
		ds.Status.TerminalSharing = c.setupTerminalSharing(ds, template)
	}

	if err := applyDebugSessionStatus(ctx, c.client, ds); err != nil {
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
func (c *DebugSessionController) failSession(ctx context.Context, ds *v1alpha1.DebugSession, reason string) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace, "cluster", ds.Spec.Cluster)

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

	ds.Status.State = v1alpha1.DebugSessionStateFailed
	ds.Status.Message = reason

	// Send failure notification email to requester
	c.sendDebugSessionFailedEmail(ds, reason)

	// Increment failure metric
	metrics.DebugSessionsFailed.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()

	return ctrl.Result{}, applyDebugSessionStatus(ctx, c.client, ds)
}

// sendDebugSessionFailedEmail sends email notification to requester when a debug session fails
func (c *DebugSessionController) sendDebugSessionFailedEmail(ds *v1alpha1.DebugSession, reason string) {
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
func (c *DebugSessionController) shouldEmitAudit(ds *v1alpha1.DebugSession) bool {
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
func (c *DebugSessionController) sendToWebhookDestinations(ctx context.Context, ds *v1alpha1.DebugSession, eventType string, payload map[string]interface{}) {
	if ds.Status.ResolvedTemplate == nil || ds.Status.ResolvedTemplate.Audit == nil {
		return
	}

	for _, dest := range ds.Status.ResolvedTemplate.Audit.Destinations {
		if dest.Type != "webhook" || dest.URL == "" {
			continue
		}

		go func(destination v1alpha1.AuditDestination) {
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
func (c *DebugSessionController) sendWebhookEvent(ctx context.Context, dest v1alpha1.AuditDestination, eventType string, ds *v1alpha1.DebugSession, payload map[string]interface{}) error {
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
func (c *DebugSessionController) getTemplate(ctx context.Context, name string) (*v1alpha1.DebugSessionTemplate, error) {
	template := &v1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		return nil, err
	}
	return template, nil
}

// getPodTemplate retrieves a DebugPodTemplate by name
func (c *DebugSessionController) getPodTemplate(ctx context.Context, name string) (*v1alpha1.DebugPodTemplate, error) {
	template := &v1alpha1.DebugPodTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: name}, template); err != nil {
		return nil, err
	}
	return template, nil
}

// getBinding retrieves a DebugSessionClusterBinding by name and namespace
func (c *DebugSessionController) getBinding(ctx context.Context, name, namespace string) (*v1alpha1.DebugSessionClusterBinding, error) {
	binding := &v1alpha1.DebugSessionClusterBinding{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: name, Namespace: namespace}, binding); err != nil {
		return nil, err
	}
	return binding, nil
}

// findBindingForSession finds a DebugSessionClusterBinding that matches the session's template and cluster.
// This enables binding configuration to be applied even when BindingRef is not explicitly set.
// Returns nil if no matching binding is found.
func (c *DebugSessionController) findBindingForSession(ctx context.Context, template *v1alpha1.DebugSessionTemplate, clusterName string) (*v1alpha1.DebugSessionClusterBinding, error) {
	bindingList := &v1alpha1.DebugSessionClusterBindingList{}
	if err := c.client.List(ctx, bindingList); err != nil {
		return nil, fmt.Errorf("failed to list cluster bindings: %w", err)
	}

	// Get cluster config for label-based matching
	var clusterConfig *v1alpha1.ClusterConfig
	clusterConfigList := &v1alpha1.ClusterConfigList{}
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
		if !IsBindingActive(binding) {
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
func (c *DebugSessionController) bindingMatchesTemplate(binding *v1alpha1.DebugSessionClusterBinding, template *v1alpha1.DebugSessionTemplate) bool {
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
func (c *DebugSessionController) bindingMatchesCluster(binding *v1alpha1.DebugSessionClusterBinding, clusterName string, clusterConfig *v1alpha1.ClusterConfig) bool {
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
	template *v1alpha1.DebugSessionTemplate,
	binding *v1alpha1.DebugSessionClusterBinding,
) *v1alpha1.ImpersonationConfig {
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
	impConfig *v1alpha1.ImpersonationConfig,
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
	saRef *v1alpha1.ServiceAccountReference,
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
func (c *DebugSessionController) requiresApproval(template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding, ds *v1alpha1.DebugSession) bool {
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
func (c *DebugSessionController) checkAutoApprove(autoApprove *v1alpha1.AutoApproveConfig, ds *v1alpha1.DebugSession) bool {
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
func (c *DebugSessionController) deployDebugResources(ctx context.Context, ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	// Get pod template if referenced
	var podTemplate *v1alpha1.DebugPodTemplate
	if template.Spec.PodTemplateRef != nil {
		var err error
		podTemplate, err = c.getPodTemplate(ctx, template.Spec.PodTemplateRef.Name)
		if err != nil {
			return fmt.Errorf("failed to get pod template: %w", err)
		}
	}

	// Get binding if session was created via a binding
	var binding *v1alpha1.DebugSessionClusterBinding
	if ds.Spec.BindingRef != nil {
		var err error
		binding, err = c.getBinding(ctx, ds.Spec.BindingRef.Name, ds.Spec.BindingRef.Namespace)
		if err != nil {
			log.Warnw("Failed to get binding by ref, will try auto-discovery",
				"binding", ds.Spec.BindingRef.Name,
				"namespace", ds.Spec.BindingRef.Namespace,
				"error", err)
			// Non-fatal: try auto-discovery below
		}
	}

	// Auto-discover binding if not found via BindingRef
	// This enables binding configuration to apply even when sessions are created
	// without explicitly setting BindingRef (e.g., via the unified API)
	if binding == nil {
		discoveredBinding, err := c.findBindingForSession(ctx, template, ds.Spec.Cluster)
		if err != nil {
			log.Warnw("Failed to auto-discover binding, continuing without binding config",
				"error", err)
		} else if discoveredBinding != nil {
			log.Infow("Auto-discovered binding for session",
				"binding", discoveredBinding.Name,
				"namespace", discoveredBinding.Namespace)
			binding = discoveredBinding
		}
	}

	// Cache resolved binding info in session status for observability
	if binding != nil {
		displayName := v1alpha1.GetEffectiveDisplayName(binding, template.Spec.DisplayName, template.Name)
		ds.Status.ResolvedBinding = &v1alpha1.ResolvedBindingRef{
			Name:        binding.Name,
			Namespace:   binding.Namespace,
			DisplayName: displayName,
		}
	}

	// Resolve impersonation configuration (binding overrides template)
	impConfig := c.resolveImpersonationConfig(template, binding)

	// Get target cluster client (with or without impersonation)
	var targetClient ctrlclient.Client
	var err error

	// First, resolve the target namespace (needed for per-session SA creation)
	targetNs := ds.Spec.TargetNamespace
	if targetNs == "" {
		targetNs = template.Spec.TargetNamespace
	}
	if targetNs == "" {
		// Check namespaceConstraints for default
		if template.Spec.NamespaceConstraints != nil && template.Spec.NamespaceConstraints.DefaultNamespace != "" {
			targetNs = template.Spec.NamespaceConstraints.DefaultNamespace
		}
	}
	if targetNs == "" {
		targetNs = "breakglass-debug"
	}

	// Create base client for spoke cluster (no impersonation yet)
	baseRestCfg, restErr := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if restErr != nil {
		return fmt.Errorf("failed to get REST config for cluster %s: %w", ds.Spec.Cluster, restErr)
	}
	baseClient, baseErr := ctrlclient.New(baseRestCfg, ctrlclient.Options{})
	if baseErr != nil {
		return fmt.Errorf("failed to create base client for cluster %s: %w", ds.Spec.Cluster, baseErr)
	}

	// Handle impersonation configuration
	if impConfig != nil && impConfig.ServiceAccountRef != nil {
		// Use existing ServiceAccount - validate it exists
		if err := c.validateSpokeServiceAccount(ctx, baseClient, impConfig.ServiceAccountRef); err != nil {
			return fmt.Errorf("impersonation validation failed: %w", err)
		}

		// Create impersonated client
		targetClient, err = c.createImpersonatedClient(ctx, ds.Spec.Cluster, impConfig)
		if err != nil {
			return fmt.Errorf("failed to create impersonated client: %w", err)
		}

		log.Infow("Using impersonation for deployment",
			"serviceAccount", fmt.Sprintf("%s/%s",
				impConfig.ServiceAccountRef.Namespace,
				impConfig.ServiceAccountRef.Name))
	} else {
		// No impersonation - use controller's own credentials
		targetClient = baseClient
	}

	// Ensure target namespace exists
	ns := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: targetNs}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			if template.Spec.FailMode == "open" {
				log.Warnw("Target namespace does not exist, fail-open mode", "namespace", targetNs)
				return nil
			}
			return fmt.Errorf("target namespace %s does not exist", targetNs)
		}
		return fmt.Errorf("failed to check namespace: %w", err)
	}

	// Deploy ResourceQuota if configured
	if template.Spec.ResourceQuota != nil {
		rq, rqErr := c.buildResourceQuota(ds, template, binding, targetNs)
		if rqErr != nil {
			return fmt.Errorf("failed to build resource quota: %w", rqErr)
		}
		if rq != nil {
			gvk := rq.GetObjectKind().GroupVersionKind()
			if err := targetClient.Create(ctx, rq); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					return fmt.Errorf("failed to create resource quota: %w", err)
				}
				log.Infow("ResourceQuota already exists", "name", rq.Name)
			}
			ds.Status.DeployedResources = append(ds.Status.DeployedResources, v1alpha1.DeployedResourceRef{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       gvk.Kind,
				Name:       rq.Name,
				Namespace:  rq.Namespace,
				Source:     "debug-resourcequota",
			})
		}
	}

	// Deploy PodDisruptionBudget if configured
	if template.Spec.PodDisruptionBudget != nil && template.Spec.PodDisruptionBudget.Enabled {
		pdb, pdbErr := c.buildPodDisruptionBudget(ds, template, binding, targetNs)
		if pdbErr != nil {
			return fmt.Errorf("failed to build pod disruption budget: %w", pdbErr)
		}
		if pdb != nil {
			gvk := pdb.GetObjectKind().GroupVersionKind()
			if err := targetClient.Create(ctx, pdb); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					return fmt.Errorf("failed to create pod disruption budget: %w", err)
				}
				log.Infow("PodDisruptionBudget already exists", "name", pdb.Name)
			}
			ds.Status.DeployedResources = append(ds.Status.DeployedResources, v1alpha1.DeployedResourceRef{
				APIVersion: gvk.GroupVersion().String(),
				Kind:       gvk.Kind,
				Name:       pdb.Name,
				Namespace:  pdb.Namespace,
				Source:     "debug-pdb",
			})
		}
	}

	// Build and deploy workload
	workload, podTemplateResources, err := c.buildWorkload(ds, template, binding, podTemplate, targetNs)
	if err != nil {
		return fmt.Errorf("failed to build workload: %w", err)
	}

	// Deploy additional resources from multi-document pod templates BEFORE the workload
	// (e.g., PVCs, ConfigMaps, Secrets that the pod needs)
	if len(podTemplateResources) > 0 {
		log.Infow("Deploying pod template resources",
			"count", len(podTemplateResources),
			"debugSession", ds.Name)
		for _, res := range podTemplateResources {
			if err := c.deployPodTemplateResource(ctx, targetClient, ds, res, targetNs); err != nil {
				return fmt.Errorf("failed to deploy pod template resource %s/%s: %w", res.GetKind(), res.GetName(), err)
			}
		}
	}

	// Capture GVK before Create call as Kubernetes client clears TypeMeta after creation
	gvk := workload.GetObjectKind().GroupVersionKind()

	if err := targetClient.Create(ctx, workload); err != nil {
		if apierrors.IsAlreadyExists(err) {
			log.Infow("Debug workload already exists", "name", workload.GetName())
			// Update deployed resources reference
		} else {
			return fmt.Errorf("failed to create workload: %w", err)
		}
	}

	// Record deployed resource using captured GVK
	ds.Status.DeployedResources = append(ds.Status.DeployedResources, v1alpha1.DeployedResourceRef{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Name:       workload.GetName(),
		Namespace:  targetNs,
		Source:     "debug-pod",
	})

	log.Infow("Deployed debug workload",
		"name", workload.GetName(),
		"namespace", targetNs,
		"kind", gvk.Kind)

	// Deploy auxiliary resources if configured
	if c.auxiliaryMgr != nil && len(template.Spec.AuxiliaryResources) > 0 {
		auxStatuses, auxErr := c.auxiliaryMgr.DeployAuxiliaryResources(ctx, ds, &template.Spec, binding, targetClient, targetNs)
		if auxErr != nil {
			// Log but don't fail the session - auxiliary resources are optional
			log.Warnw("Failed to deploy some auxiliary resources", "error", auxErr)
		}
		// Add deployed auxiliary resources to status
		ds.Status.AuxiliaryResourceStatuses = auxStatuses
	}

	return nil
}

// buildWorkload creates the DaemonSet or Deployment for debug pods.
// It also returns any additional resources from multi-document pod templates
// that should be deployed alongside the workload.
func (c *DebugSessionController) buildWorkload(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding, podTemplate *v1alpha1.DebugPodTemplate, targetNs string) (ctrlclient.Object, []*unstructured.Unstructured, error) {
	workloadName := fmt.Sprintf("debug-%s", ds.Name)
	podSpec, additionalResources, err := c.buildPodSpec(ds, template, podTemplate)
	if err != nil {
		return nil, nil, err
	}

	labels := map[string]string{
		DebugSessionLabelKey:  ds.Name,
		DebugTemplateLabelKey: ds.Spec.TemplateRef,
		DebugClusterLabelKey:  ds.Spec.Cluster,
	}

	labels = mergeStringMaps(labels, template.Spec.Labels, bindingLabels(binding), podTemplateLabels(podTemplate))
	for k, v := range ds.Labels {
		if k == DebugSessionLabelKey || k == DebugTemplateLabelKey || k == DebugClusterLabelKey {
			continue
		}
		labels[k] = v
	}

	annotations := mergeStringMaps(nil, template.Spec.Annotations, bindingAnnotations(binding), podTemplateAnnotations(podTemplate))
	if len(ds.Annotations) > 0 {
		if annotations == nil {
			annotations = make(map[string]string)
		}
		for k, v := range ds.Annotations {
			annotations[k] = v
		}
	}

	workloadType := template.Spec.WorkloadType
	if workloadType == "" {
		workloadType = v1alpha1.DebugWorkloadDaemonSet
	}

	// Enforce RestartPolicy: Always for DaemonSets and Deployments
	// These workload types require Always restart policy
	if workloadType == v1alpha1.DebugWorkloadDaemonSet || workloadType == v1alpha1.DebugWorkloadDeployment {
		if podSpec.RestartPolicy != corev1.RestartPolicyAlways {
			c.log.Debugw("Overriding RestartPolicy to Always for workload type",
				"workloadType", workloadType,
				"originalPolicy", podSpec.RestartPolicy,
				"debugSession", ds.Name,
			)
			podSpec.RestartPolicy = corev1.RestartPolicyAlways
		}
	}

	switch workloadType {
	case v1alpha1.DebugWorkloadDaemonSet:
		return &appsv1.DaemonSet{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "DaemonSet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        workloadName,
				Namespace:   targetNs,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						DebugSessionLabelKey: ds.Name,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels:      labels,
						Annotations: annotations,
					},
					Spec: podSpec,
				},
			},
		}, additionalResources, nil

	case v1alpha1.DebugWorkloadDeployment:
		replicas := int32(1)
		if template.Spec.Replicas != nil {
			replicas = *template.Spec.Replicas
		}
		if template.Spec.ResourceQuota != nil && template.Spec.ResourceQuota.MaxPods != nil && replicas > *template.Spec.ResourceQuota.MaxPods {
			return nil, nil, fmt.Errorf("replicas (%d) exceed resourceQuota.maxPods (%d)", replicas, *template.Spec.ResourceQuota.MaxPods)
		}
		return &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:        workloadName,
				Namespace:   targetNs,
				Labels:      labels,
				Annotations: annotations,
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						DebugSessionLabelKey: ds.Name,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels:      labels,
						Annotations: annotations,
					},
					Spec: podSpec,
				},
			},
		}, additionalResources, nil

	default:
		return nil, nil, fmt.Errorf("unsupported workload type: %s", workloadType)
	}
}

// deployPodTemplateResource deploys a single resource from a multi-document pod template.
// It applies standard labels/annotations for tracking and uses Server-Side Apply for idempotency.
func (c *DebugSessionController) deployPodTemplateResource(
	ctx context.Context,
	targetClient ctrlclient.Client,
	ds *v1alpha1.DebugSession,
	obj *unstructured.Unstructured,
	targetNs string,
) error {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Set namespace if not specified
	if obj.GetNamespace() == "" {
		obj.SetNamespace(targetNs)
	}

	// Apply standard labels
	labels := obj.GetLabels()
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["app.kubernetes.io/managed-by"] = "breakglass"
	labels["breakglass.t-caas.telekom.com/session"] = ds.Name
	labels["breakglass.t-caas.telekom.com/session-cluster"] = ds.Spec.Cluster
	labels["breakglass.t-caas.telekom.com/pod-template-resource"] = "true"
	obj.SetLabels(labels)

	// Apply standard annotations
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["breakglass.t-caas.telekom.com/source-session"] = fmt.Sprintf("%s/%s", ds.Namespace, ds.Name)
	obj.SetAnnotations(annotations)

	// Deploy using Server-Side Apply for idempotency
	obj.SetManagedFields(nil)
	//nolint:staticcheck // SA1019: client.Apply for Patch is still required for unstructured objects
	if err := targetClient.Patch(ctx, obj, ctrlclient.Apply, ctrlclient.FieldOwner("breakglass-controller"), ctrlclient.ForceOwnership); err != nil {
		return fmt.Errorf("SSA apply failed: %w", err)
	}

	// Track in session status
	status := v1alpha1.PodTemplateResourceStatus{
		Kind:         obj.GetKind(),
		APIVersion:   obj.GetAPIVersion(),
		ResourceName: obj.GetName(),
		Namespace:    obj.GetNamespace(),
		Source:       "podTemplateString",
		Created:      true,
	}
	now := time.Now().UTC().Format(time.RFC3339)
	status.CreatedAt = &now
	ds.Status.PodTemplateResourceStatuses = append(ds.Status.PodTemplateResourceStatuses, status)

	// Add to deployed resources list
	ds.Status.DeployedResources = append(ds.Status.DeployedResources, v1alpha1.DeployedResourceRef{
		APIVersion: obj.GetAPIVersion(),
		Kind:       obj.GetKind(),
		Name:       obj.GetName(),
		Namespace:  obj.GetNamespace(),
		Source:     "pod-template",
	})

	log.Infow("Deployed pod template resource",
		"kind", obj.GetKind(),
		"name", obj.GetName(),
		"namespace", obj.GetNamespace())

	return nil
}

// buildPodSpec creates the pod spec from templates and overrides.
// Supports both structured podTemplate and Go-templated podTemplateString.
// Now supports multi-document YAML where the first document is the PodSpec
// and subsequent documents are additional K8s resources to deploy.
func (c *DebugSessionController) buildPodSpec(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, podTemplate *v1alpha1.DebugPodTemplate) (corev1.PodSpec, []*unstructured.Unstructured, error) {
	var spec corev1.PodSpec
	var additionalResources []*unstructured.Unstructured

	// Build render context for template rendering (podTemplateString, podOverridesTemplate)
	renderCtx := c.buildPodRenderContext(ds, template)

	// Determine pod spec source: podTemplateString takes priority over podTemplateRef
	if template.Spec.PodTemplateString != "" {
		// Render podTemplateString as Go template (from DebugSessionTemplate)
		result, err := c.renderPodTemplateStringMultiDoc(template.Spec.PodTemplateString, renderCtx)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed to render podTemplateString: %w", err)
		}
		spec = result.PodSpec
		additionalResources = result.AdditionalResources
	} else if podTemplate != nil {
		// Use DebugPodTemplate - check for templateString first, then structured template
		if podTemplate.Spec.TemplateString != "" {
			// Render DebugPodTemplate's templateString as Go template
			result, err := c.renderPodTemplateStringMultiDoc(podTemplate.Spec.TemplateString, renderCtx)
			if err != nil {
				return corev1.PodSpec{}, nil, fmt.Errorf("failed to render DebugPodTemplate templateString: %w", err)
			}
			spec = result.PodSpec
			additionalResources = result.AdditionalResources
		} else if podTemplate.Spec.Template != nil {
			// Use structured pod template (no multi-doc support for structured templates)
			spec = c.convertDebugPodSpec(podTemplate.Spec.Template.Spec)
		} else {
			return corev1.PodSpec{}, nil, fmt.Errorf("DebugPodTemplate %s has neither template nor templateString", podTemplate.Name)
		}
	}

	// Apply podOverridesTemplate if specified (Go template producing overrides YAML)
	if template.Spec.PodOverridesTemplate != "" {
		overrides, err := c.renderPodOverridesTemplate(template.Spec.PodOverridesTemplate, renderCtx)
		if err != nil {
			return corev1.PodSpec{}, nil, fmt.Errorf("failed to render podOverridesTemplate: %w", err)
		}
		c.applyPodOverridesStruct(&spec, overrides)
	}

	// Apply static overrides from session template (legacy support)
	if template.Spec.PodOverrides != nil && template.Spec.PodOverrides.Spec != nil {
		overrides := template.Spec.PodOverrides.Spec
		if overrides.HostNetwork != nil {
			spec.HostNetwork = *overrides.HostNetwork
		}
		if overrides.HostPID != nil {
			spec.HostPID = *overrides.HostPID
		}
		if overrides.HostIPC != nil {
			spec.HostIPC = *overrides.HostIPC
		}
	}

	// Apply affinity overrides
	if template.Spec.AffinityOverrides != nil {
		spec.Affinity = template.Spec.AffinityOverrides
	}

	// Add tolerations
	if len(template.Spec.AdditionalTolerations) > 0 {
		spec.Tolerations = append(spec.Tolerations, template.Spec.AdditionalTolerations...)
	}

	// Merge node selector from session request
	if len(ds.Spec.NodeSelector) > 0 {
		if spec.NodeSelector == nil {
			spec.NodeSelector = make(map[string]string)
		}
		for k, v := range ds.Spec.NodeSelector {
			spec.NodeSelector[k] = v
		}
	}

	// Apply resolved scheduling constraints from session
	// These are computed at session creation time and take precedence
	if ds.Spec.ResolvedSchedulingConstraints != nil {
		c.applySchedulingConstraints(&spec, ds.Spec.ResolvedSchedulingConstraints)
	} else if template.Spec.SchedulingConstraints != nil {
		// Fallback to template constraints if session doesn't have resolved constraints
		c.applySchedulingConstraints(&spec, template.Spec.SchedulingConstraints)
	}

	if template.Spec.ResourceQuota != nil {
		if err := enforceContainerResources(template.Spec.ResourceQuota, spec.Containers, spec.InitContainers); err != nil {
			return corev1.PodSpec{}, nil, err
		}
	}

	// Verify if terminal sharing is enabled and inject multiplexer command
	if template.Spec.TerminalSharing != nil && template.Spec.TerminalSharing.Enabled && len(spec.Containers) > 0 {
		container := &spec.Containers[0]

		provider := template.Spec.TerminalSharing.Provider
		if provider == "" {
			provider = "tmux"
		}

		sessionName := fmt.Sprintf("debug-%s", ds.Name)
		if len(sessionName) > 32 {
			sessionName = sessionName[:32]
		}

		// Only wrap if explicit command is set, otherwise we risk masking entrypoint
		if len(container.Command) > 0 {
			// Construct child command
			childCmd := make([]string, 0, len(container.Command)+len(container.Args))
			childCmd = append(childCmd, container.Command...)
			childCmd = append(childCmd, container.Args...)

			if provider == "tmux" {
				// tmux new-session -A -s <name> <cmd...>
				// -A: attach to existing session if it exists
				container.Command = []string{"tmux", "new-session", "-A", "-s", sessionName}
				container.Args = childCmd
			} else if provider == "screen" {
				// screen -xRR -S <name> <cmd...>
				// -xRR: Attach to existing, or create new (multi-display mode)
				container.Command = []string{"screen", "-xRR", "-S", sessionName}
				container.Args = childCmd
			}
		}
	}

	return spec, additionalResources, nil
}

// buildPodRenderContext creates the render context for pod templates.
// This is a subset of AuxiliaryResourceContext, focused on pod rendering.
func (c *DebugSessionController) buildPodRenderContext(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate) v1alpha1.AuxiliaryResourceContext {
	ctx := v1alpha1.AuxiliaryResourceContext{
		Session: v1alpha1.AuxiliaryResourceSessionContext{
			Name:        ds.Name,
			Namespace:   ds.Namespace,
			Cluster:     ds.Spec.Cluster,
			RequestedBy: ds.Spec.RequestedBy,
			Reason:      ds.Spec.Reason,
		},
		Target: v1alpha1.AuxiliaryResourceTargetContext{
			Namespace:   ds.Spec.TargetNamespace,
			ClusterName: ds.Spec.Cluster,
		},
		Template: v1alpha1.AuxiliaryResourceTemplateContext{
			Name:        ds.Spec.TemplateRef,
			DisplayName: template.Spec.DisplayName,
		},
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":                  "breakglass",
			"breakglass.t-caas.telekom.com/session":         ds.Name,
			"breakglass.t-caas.telekom.com/session-cluster": ds.Spec.Cluster,
		},
		Annotations: map[string]string{
			"breakglass.t-caas.telekom.com/created-by": ds.Spec.RequestedBy,
		},
		Now: time.Now().UTC().Format(time.RFC3339),
	}

	if ds.Status.Approval != nil {
		ctx.Session.ApprovedBy = ds.Status.Approval.ApprovedBy
	}
	if ds.Status.ExpiresAt != nil {
		ctx.Session.ExpiresAt = ds.Status.ExpiresAt.Format(time.RFC3339)
	}
	if template.Spec.TargetNamespace != "" && ctx.Target.Namespace == "" {
		ctx.Target.Namespace = template.Spec.TargetNamespace
	}

	// Build Vars from extraDeployValues with defaults from template
	ctx.Vars = c.buildVarsFromSession(ds, &template.Spec)

	return ctx
}

// buildVarsFromSession extracts user-provided variable values from session spec
// and applies defaults from template definition.
func (c *DebugSessionController) buildVarsFromSession(
	ds *v1alpha1.DebugSession,
	templateSpec *v1alpha1.DebugSessionTemplateSpec,
) map[string]string {
	vars := make(map[string]string)

	// Apply defaults from template variable definitions
	if templateSpec != nil {
		for _, varDef := range templateSpec.ExtraDeployVariables {
			if varDef.Default != nil && len(varDef.Default.Raw) > 0 {
				vars[varDef.Name] = extractJSONValueForPod(varDef.Default.Raw)
			}
		}
	}

	// Override with user-provided values
	for name, jsonVal := range ds.Spec.ExtraDeployValues {
		vars[name] = extractJSONValueForPod(jsonVal.Raw)
	}

	return vars
}

// extractJSONValueForPod extracts string representation from JSON.
// Local copy to avoid import cycles.
func extractJSONValueForPod(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	var strVal string
	if err := json.Unmarshal(raw, &strVal); err == nil {
		return strVal
	}

	var boolVal bool
	if err := json.Unmarshal(raw, &boolVal); err == nil {
		return fmt.Sprintf("%t", boolVal)
	}

	var numVal float64
	if err := json.Unmarshal(raw, &numVal); err == nil {
		if numVal == float64(int64(numVal)) {
			return fmt.Sprintf("%d", int64(numVal))
		}
		return fmt.Sprintf("%g", numVal)
	}

	var arrVal []string
	if err := json.Unmarshal(raw, &arrVal); err == nil {
		return strings.Join(arrVal, ",")
	}

	return string(raw)
}

// PodTemplateRenderResult contains the result of rendering a multi-document pod template.
type PodTemplateRenderResult struct {
	// PodSpec is the parsed PodSpec from the first YAML document.
	PodSpec corev1.PodSpec

	// AdditionalResources are parsed K8s resources from subsequent YAML documents.
	AdditionalResources []*unstructured.Unstructured
}

// renderPodTemplateString renders a podTemplateString Go template and returns a PodSpec.
// For backward compatibility, this returns only the PodSpec (first document).
// Use renderPodTemplateStringMultiDoc for full multi-document support.
func (c *DebugSessionController) renderPodTemplateString(templateStr string, ctx v1alpha1.AuxiliaryResourceContext) (corev1.PodSpec, error) {
	result, err := c.renderPodTemplateStringMultiDoc(templateStr, ctx)
	if err != nil {
		return corev1.PodSpec{}, err
	}
	return result.PodSpec, nil
}

// renderPodTemplateStringMultiDoc renders a podTemplateString Go template with multi-document support.
// The first YAML document MUST be a PodSpec (required).
// Subsequent documents can be any Kubernetes resource (ConfigMaps, Secrets, PVCs, etc.)
// that will be deployed alongside the debug pod.
func (c *DebugSessionController) renderPodTemplateStringMultiDoc(templateStr string, ctx v1alpha1.AuxiliaryResourceContext) (*PodTemplateRenderResult, error) {
	renderer := NewTemplateRenderer()
	documents, err := renderer.RenderMultiDocumentTemplate(templateStr, ctx)
	if err != nil {
		return nil, fmt.Errorf("template rendering failed: %w", err)
	}

	if len(documents) == 0 {
		return nil, fmt.Errorf("pod template produced no documents")
	}

	result := &PodTemplateRenderResult{}

	// First document MUST be a PodSpec
	if err := yaml.Unmarshal(documents[0], &result.PodSpec); err != nil {
		return nil, fmt.Errorf("failed to parse first document as PodSpec: %w", err)
	}

	// Subsequent documents are additional K8s resources
	for i := 1; i < len(documents); i++ {
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(documents[i], &obj.Object); err != nil {
			return nil, fmt.Errorf("failed to parse document %d as Kubernetes resource: %w", i+1, err)
		}

		// Validate it looks like a K8s resource
		if obj.GetAPIVersion() == "" || obj.GetKind() == "" {
			return nil, fmt.Errorf("document %d is not a valid Kubernetes resource (missing apiVersion or kind)", i+1)
		}

		result.AdditionalResources = append(result.AdditionalResources, obj)
	}

	return result, nil
}

// renderPodOverridesTemplate renders podOverridesTemplate and returns structured overrides.
func (c *DebugSessionController) renderPodOverridesTemplate(templateStr string, ctx v1alpha1.AuxiliaryResourceContext) (*v1alpha1.DebugPodSpecOverrides, error) {
	renderer := NewTemplateRenderer()
	rendered, err := renderer.RenderTemplateString(templateStr, ctx)
	if err != nil {
		return nil, fmt.Errorf("template rendering failed: %w", err)
	}

	var overrides v1alpha1.DebugPodSpecOverrides
	if err := yaml.Unmarshal(rendered, &overrides); err != nil {
		return nil, fmt.Errorf("failed to parse rendered overrides YAML: %w", err)
	}

	return &overrides, nil
}

// applyPodOverridesStruct applies rendered overrides to a pod spec.
func (c *DebugSessionController) applyPodOverridesStruct(spec *corev1.PodSpec, overrides *v1alpha1.DebugPodSpecOverrides) {
	if overrides == nil {
		return
	}
	if overrides.HostNetwork != nil {
		spec.HostNetwork = *overrides.HostNetwork
	}
	if overrides.HostPID != nil {
		spec.HostPID = *overrides.HostPID
	}
	if overrides.HostIPC != nil {
		spec.HostIPC = *overrides.HostIPC
	}
}

func mergeStringMaps(base map[string]string, maps ...map[string]string) map[string]string {
	var merged map[string]string
	if len(base) > 0 {
		merged = make(map[string]string, len(base))
		for k, v := range base {
			merged[k] = v
		}
	}
	for _, m := range maps {
		if len(m) == 0 {
			continue
		}
		if merged == nil {
			merged = make(map[string]string)
		}
		for k, v := range m {
			merged[k] = v
		}
	}
	return merged
}

func bindingLabels(binding *v1alpha1.DebugSessionClusterBinding) map[string]string {
	if binding == nil {
		return nil
	}
	return binding.Spec.Labels
}

func bindingAnnotations(binding *v1alpha1.DebugSessionClusterBinding) map[string]string {
	if binding == nil {
		return nil
	}
	return binding.Spec.Annotations
}

func podTemplateLabels(podTemplate *v1alpha1.DebugPodTemplate) map[string]string {
	if podTemplate == nil || podTemplate.Spec.Template == nil || podTemplate.Spec.Template.Metadata == nil {
		return nil
	}
	return podTemplate.Spec.Template.Metadata.Labels
}

func podTemplateAnnotations(podTemplate *v1alpha1.DebugPodTemplate) map[string]string {
	if podTemplate == nil || podTemplate.Spec.Template == nil || podTemplate.Spec.Template.Metadata == nil {
		return nil
	}
	return podTemplate.Spec.Template.Metadata.Annotations
}

func enforceContainerResources(cfg *v1alpha1.DebugResourceQuotaConfig, containers []corev1.Container, initContainers []corev1.Container) error {
	if cfg == nil {
		return nil
	}
	needsRequests := cfg.EnforceResourceRequests
	needsLimits := cfg.EnforceResourceLimits
	if !needsRequests && !needsLimits {
		return nil
	}

	requiredResources := []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory}
	if cfg.MaxStorage != "" {
		requiredResources = append(requiredResources, corev1.ResourceEphemeralStorage)
	}

	check := func(c corev1.Container) error {
		if needsRequests {
			for _, r := range requiredResources {
				if c.Resources.Requests == nil {
					return fmt.Errorf("container %s is missing resource requests", c.Name)
				}
				if _, ok := c.Resources.Requests[r]; !ok {
					return fmt.Errorf("container %s is missing request for %s", c.Name, r)
				}
			}
		}
		if needsLimits {
			for _, r := range requiredResources {
				if c.Resources.Limits == nil {
					return fmt.Errorf("container %s is missing resource limits", c.Name)
				}
				if _, ok := c.Resources.Limits[r]; !ok {
					return fmt.Errorf("container %s is missing limit for %s", c.Name, r)
				}
			}
		}
		return nil
	}

	for _, c := range containers {
		if err := check(c); err != nil {
			return err
		}
	}
	for _, c := range initContainers {
		if err := check(c); err != nil {
			return err
		}
	}

	return nil
}

func (c *DebugSessionController) buildResourceQuota(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding, targetNs string) (*corev1.ResourceQuota, error) {
	if template.Spec.ResourceQuota == nil {
		return nil, nil
	}

	hard := corev1.ResourceList{}
	if template.Spec.ResourceQuota.MaxPods != nil {
		hard[corev1.ResourcePods] = *resource.NewQuantity(int64(*template.Spec.ResourceQuota.MaxPods), resource.DecimalSI)
	}
	if template.Spec.ResourceQuota.MaxCPU != "" {
		qty, err := resource.ParseQuantity(template.Spec.ResourceQuota.MaxCPU)
		if err != nil {
			return nil, fmt.Errorf("invalid maxCPU: %w", err)
		}
		hard[corev1.ResourceRequestsCPU] = qty
		hard[corev1.ResourceLimitsCPU] = qty
	}
	if template.Spec.ResourceQuota.MaxMemory != "" {
		qty, err := resource.ParseQuantity(template.Spec.ResourceQuota.MaxMemory)
		if err != nil {
			return nil, fmt.Errorf("invalid maxMemory: %w", err)
		}
		hard[corev1.ResourceRequestsMemory] = qty
		hard[corev1.ResourceLimitsMemory] = qty
	}
	if template.Spec.ResourceQuota.MaxStorage != "" {
		qty, err := resource.ParseQuantity(template.Spec.ResourceQuota.MaxStorage)
		if err != nil {
			return nil, fmt.Errorf("invalid maxStorage: %w", err)
		}
		hard[corev1.ResourceRequestsEphemeralStorage] = qty
		hard[corev1.ResourceLimitsEphemeralStorage] = qty
	}
	if len(hard) == 0 {
		return nil, nil
	}

	labels := map[string]string{
		DebugSessionLabelKey:  ds.Name,
		DebugTemplateLabelKey: ds.Spec.TemplateRef,
		DebugClusterLabelKey:  ds.Spec.Cluster,
	}
	labels = mergeStringMaps(labels, template.Spec.Labels, bindingLabels(binding), ds.Labels)

	annotations := mergeStringMaps(nil, template.Spec.Annotations, bindingAnnotations(binding))
	if len(ds.Annotations) > 0 {
		annotations = mergeStringMaps(annotations, ds.Annotations)
	}

	return &corev1.ResourceQuota{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ResourceQuota",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("debug-%s-rq", ds.Name),
			Namespace:   targetNs,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.ResourceQuotaSpec{Hard: hard},
	}, nil
}

func (c *DebugSessionController) buildPodDisruptionBudget(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, binding *v1alpha1.DebugSessionClusterBinding, targetNs string) (*policyv1.PodDisruptionBudget, error) {
	if template.Spec.PodDisruptionBudget == nil || !template.Spec.PodDisruptionBudget.Enabled {
		return nil, nil
	}
	if template.Spec.PodDisruptionBudget.MinAvailable == nil && template.Spec.PodDisruptionBudget.MaxUnavailable == nil {
		return nil, nil
	}

	labels := map[string]string{
		DebugSessionLabelKey:  ds.Name,
		DebugTemplateLabelKey: ds.Spec.TemplateRef,
		DebugClusterLabelKey:  ds.Spec.Cluster,
	}
	labels = mergeStringMaps(labels, template.Spec.Labels, bindingLabels(binding), ds.Labels)

	annotations := mergeStringMaps(nil, template.Spec.Annotations, bindingAnnotations(binding))
	if len(ds.Annotations) > 0 {
		annotations = mergeStringMaps(annotations, ds.Annotations)
	}

	pdb := &policyv1.PodDisruptionBudget{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "policy/v1",
			Kind:       "PodDisruptionBudget",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("debug-%s-pdb", ds.Name),
			Namespace:   targetNs,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					DebugSessionLabelKey: ds.Name,
				},
			},
		},
	}

	if template.Spec.PodDisruptionBudget.MinAvailable != nil {
		pdb.Spec.MinAvailable = &intstr.IntOrString{Type: intstr.Int, IntVal: *template.Spec.PodDisruptionBudget.MinAvailable}
	}
	if template.Spec.PodDisruptionBudget.MaxUnavailable != nil {
		pdb.Spec.MaxUnavailable = &intstr.IntOrString{Type: intstr.Int, IntVal: *template.Spec.PodDisruptionBudget.MaxUnavailable}
	}

	return pdb, nil
}

// applySchedulingConstraints applies SchedulingConstraints to a PodSpec.
// This merges the constraints with any existing scheduling configuration.
func (c *DebugSessionController) applySchedulingConstraints(spec *corev1.PodSpec, constraints *v1alpha1.SchedulingConstraints) {
	if constraints == nil {
		return
	}

	// Apply node selector (merge, constraints take precedence)
	if len(constraints.NodeSelector) > 0 {
		if spec.NodeSelector == nil {
			spec.NodeSelector = make(map[string]string)
		}
		for k, v := range constraints.NodeSelector {
			spec.NodeSelector[k] = v
		}
	}

	// Apply tolerations (additive)
	if len(constraints.Tolerations) > 0 {
		spec.Tolerations = append(spec.Tolerations, constraints.Tolerations...)
	}

	// Apply node affinity
	if constraints.RequiredNodeAffinity != nil || len(constraints.PreferredNodeAffinity) > 0 {
		if spec.Affinity == nil {
			spec.Affinity = &corev1.Affinity{}
		}
		if spec.Affinity.NodeAffinity == nil {
			spec.Affinity.NodeAffinity = &corev1.NodeAffinity{}
		}

		// Merge required node affinity (AND logic)
		if constraints.RequiredNodeAffinity != nil {
			if spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
				spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = constraints.RequiredNodeAffinity.DeepCopy()
			} else {
				// AND the node selector terms
				spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = append(
					spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms,
					constraints.RequiredNodeAffinity.NodeSelectorTerms...,
				)
			}
		}

		// Add preferred node affinity
		if len(constraints.PreferredNodeAffinity) > 0 {
			spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(
				spec.Affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
				constraints.PreferredNodeAffinity...,
			)
		}
	}

	// Apply pod anti-affinity
	if len(constraints.RequiredPodAntiAffinity) > 0 || len(constraints.PreferredPodAntiAffinity) > 0 {
		if spec.Affinity == nil {
			spec.Affinity = &corev1.Affinity{}
		}
		if spec.Affinity.PodAntiAffinity == nil {
			spec.Affinity.PodAntiAffinity = &corev1.PodAntiAffinity{}
		}

		if len(constraints.RequiredPodAntiAffinity) > 0 {
			spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution = append(
				spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
				constraints.RequiredPodAntiAffinity...,
			)
		}
		if len(constraints.PreferredPodAntiAffinity) > 0 {
			spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(
				spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
				constraints.PreferredPodAntiAffinity...,
			)
		}
	}

	// Apply topology spread constraints (additive)
	if len(constraints.TopologySpreadConstraints) > 0 {
		spec.TopologySpreadConstraints = append(spec.TopologySpreadConstraints, constraints.TopologySpreadConstraints...)
	}

	// Note: deniedNodes and deniedNodeLabels are advisory constraints
	// They should be enforced via admission webhooks or node anti-affinity rules
	// Here we convert them to node anti-affinity expressions
	if len(constraints.DeniedNodes) > 0 || len(constraints.DeniedNodeLabels) > 0 {
		c.log.Debugw("Denied nodes/labels configured",
			"deniedNodes", constraints.DeniedNodes,
			"deniedNodeLabels", constraints.DeniedNodeLabels)
		// These are enforced at the admission webhook level for hard blocks
		// For soft enforcement, we could add them as preferredNodeAffinity with negative weight
	}
}

// convertDebugPodSpec converts our DebugPodSpecInner to corev1.PodSpec
func (c *DebugSessionController) convertDebugPodSpec(dps v1alpha1.DebugPodSpecInner) corev1.PodSpec {
	spec := corev1.PodSpec{
		Containers:                dps.Containers,
		InitContainers:            dps.InitContainers,
		Volumes:                   dps.Volumes,
		Tolerations:               dps.Tolerations,
		Affinity:                  dps.Affinity,
		NodeSelector:              dps.NodeSelector,
		HostNetwork:               dps.HostNetwork,
		HostPID:                   dps.HostPID,
		HostIPC:                   dps.HostIPC,
		DNSPolicy:                 dps.DNSPolicy,
		DNSConfig:                 dps.DNSConfig,
		RestartPolicy:             dps.RestartPolicy,
		TopologySpreadConstraints: dps.TopologySpreadConstraints,
		HostAliases:               dps.HostAliases,
		ImagePullSecrets:          dps.ImagePullSecrets,
		Overhead:                  dps.Overhead,
	}

	if dps.SecurityContext != nil {
		spec.SecurityContext = dps.SecurityContext
	}
	if dps.AutomountServiceAccountToken != nil {
		spec.AutomountServiceAccountToken = dps.AutomountServiceAccountToken
	}
	if dps.ServiceAccountName != "" {
		spec.ServiceAccountName = dps.ServiceAccountName
	}
	if dps.TerminationGracePeriodSeconds != nil {
		spec.TerminationGracePeriodSeconds = dps.TerminationGracePeriodSeconds
	}
	if dps.PriorityClassName != "" {
		spec.PriorityClassName = dps.PriorityClassName
	}
	if dps.RuntimeClassName != nil {
		spec.RuntimeClassName = dps.RuntimeClassName
	}
	if dps.PreemptionPolicy != nil {
		spec.PreemptionPolicy = dps.PreemptionPolicy
	}
	if dps.ShareProcessNamespace != nil {
		spec.ShareProcessNamespace = dps.ShareProcessNamespace
	}
	if dps.EnableServiceLinks != nil {
		spec.EnableServiceLinks = dps.EnableServiceLinks
	}
	if dps.SchedulerName != "" {
		spec.SchedulerName = dps.SchedulerName
	}

	return spec
}

// updateAllowedPods updates the list of pods users can exec into and monitors pod health
func (c *DebugSessionController) updateAllowedPods(ctx context.Context, ds *v1alpha1.DebugSession) error {
	if c.ccProvider == nil {
		return nil
	}

	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace, "cluster", ds.Spec.Cluster)

	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		return err
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return err
	}

	// List pods with debug session label
	podList := &corev1.PodList{}
	labelSelector := labels.SelectorFromSet(map[string]string{
		DebugSessionLabelKey: ds.Name,
	})
	if err := targetClient.List(ctx, podList, &ctrlclient.ListOptions{
		LabelSelector: labelSelector,
	}); err != nil {
		return err
	}

	allowedPods := make([]v1alpha1.AllowedPodRef, 0, len(podList.Items))
	for _, pod := range podList.Items {
		ready := false
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				ready = true
				break
			}
		}

		// Monitor pod phase for failures
		c.monitorPodHealth(ctx, ds, &pod, log)

		// Build container status for detailed information
		containerStatus := buildContainerStatus(&pod)

		allowedPods = append(allowedPods, v1alpha1.AllowedPodRef{
			Namespace:       pod.Namespace,
			Name:            pod.Name,
			NodeName:        pod.Spec.NodeName,
			Ready:           ready,
			Phase:           string(pod.Status.Phase),
			ContainerStatus: containerStatus,
		})
	}

	ds.Status.AllowedPods = allowedPods
	return applyDebugSessionStatus(ctx, c.client, ds)
}

// monitorPodHealth checks pod status and emits audit events for failures/restarts
func (c *DebugSessionController) monitorPodHealth(ctx context.Context, ds *v1alpha1.DebugSession, pod *corev1.Pod, log *zap.SugaredLogger) {
	// Check for pod phase failures
	if pod.Status.Phase == corev1.PodFailed {
		reason := pod.Status.Reason
		message := pod.Status.Message
		if reason == "" {
			reason = "Unknown"
		}
		if message == "" {
			message = "Pod failed without message"
		}

		log.Warnw("Debug session pod failed",
			"pod", pod.Name,
			"podNamespace", pod.Namespace,
			"reason", reason,
			"message", message,
			"node", pod.Spec.NodeName,
		)

		if c.shouldEmitAudit(ds) && c.auditManager != nil {
			c.auditManager.DebugSessionPodFailed(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, reason, message)
			c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodFailed", map[string]interface{}{
				"pod":       pod.Name,
				"namespace": pod.Namespace,
				"reason":    reason,
				"message":   message,
			})
		}
		metrics.DebugSessionPodFailures.WithLabelValues(ds.Spec.Cluster, ds.Name, reason).Inc()
	}

	// Check container statuses for restarts and failures
	for _, cs := range pod.Status.ContainerStatuses {
		// Check for container restarts
		if cs.RestartCount > 0 {
			lastTerminationReason := ""
			if cs.LastTerminationState.Terminated != nil {
				lastTerminationReason = cs.LastTerminationState.Terminated.Reason
				if lastTerminationReason == "" {
					lastTerminationReason = fmt.Sprintf("ExitCode=%d", cs.LastTerminationState.Terminated.ExitCode)
				}
			}

			log.Warnw("Debug session container has restarted",
				"pod", pod.Name,
				"podNamespace", pod.Namespace,
				"container", cs.Name,
				"restartCount", cs.RestartCount,
				"lastTerminationReason", lastTerminationReason,
			)

			if c.shouldEmitAudit(ds) && c.auditManager != nil {
				c.auditManager.DebugSessionPodRestarted(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, cs.RestartCount, lastTerminationReason)
				c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodRestarted", map[string]interface{}{
					"pod":                   pod.Name,
					"namespace":             pod.Namespace,
					"container":             cs.Name,
					"restartCount":          cs.RestartCount,
					"lastTerminationReason": lastTerminationReason,
				})
			}
			metrics.DebugSessionPodRestarts.WithLabelValues(ds.Spec.Cluster, ds.Name).Inc()
		}

		// Check for waiting state issues (CrashLoopBackOff, ImagePullBackOff, etc.)
		if cs.State.Waiting != nil {
			waitingReason := cs.State.Waiting.Reason
			waitingMessage := cs.State.Waiting.Message

			// Log significant waiting states
			if waitingReason == "CrashLoopBackOff" ||
				waitingReason == "ImagePullBackOff" ||
				waitingReason == "ErrImagePull" ||
				waitingReason == "CreateContainerConfigError" ||
				waitingReason == "CreateContainerError" {
				log.Warnw("Debug session container in problematic waiting state",
					"pod", pod.Name,
					"podNamespace", pod.Namespace,
					"container", cs.Name,
					"waitingReason", waitingReason,
					"waitingMessage", waitingMessage,
				)

				if c.shouldEmitAudit(ds) && c.auditManager != nil {
					c.auditManager.DebugSessionPodFailed(ctx, ds.Name, ds.Namespace, pod.Name, pod.Namespace, waitingReason, waitingMessage)
					c.sendToWebhookDestinations(ctx, ds, "DebugSessionPodFailed", map[string]interface{}{
						"pod":       pod.Name,
						"namespace": pod.Namespace,
						"container": cs.Name,
						"reason":    waitingReason,
						"message":   waitingMessage,
					})
				}
				metrics.DebugSessionPodFailures.WithLabelValues(ds.Spec.Cluster, ds.Name, waitingReason).Inc()
			}
		}
	}
}

// buildContainerStatus extracts detailed container state information from a pod
func buildContainerStatus(pod *corev1.Pod) *v1alpha1.PodContainerStatus {
	if len(pod.Status.ContainerStatuses) == 0 {
		return nil
	}

	// Look for the most interesting container status (one with problems)
	var status *v1alpha1.PodContainerStatus
	for _, cs := range pod.Status.ContainerStatuses {
		// Check for waiting state issues
		if cs.State.Waiting != nil {
			waitingReason := cs.State.Waiting.Reason
			// Prioritize problematic waiting states
			if waitingReason == "CrashLoopBackOff" ||
				waitingReason == "ImagePullBackOff" ||
				waitingReason == "ErrImagePull" ||
				waitingReason == "CreateContainerConfigError" ||
				waitingReason == "CreateContainerError" ||
				waitingReason == "ContainerCreating" {
				status = &v1alpha1.PodContainerStatus{
					WaitingReason:  waitingReason,
					WaitingMessage: cs.State.Waiting.Message,
					RestartCount:   cs.RestartCount,
				}
				// Get last termination reason if available
				if cs.LastTerminationState.Terminated != nil {
					status.LastTerminationReason = cs.LastTerminationState.Terminated.Reason
					if status.LastTerminationReason == "" {
						status.LastTerminationReason = fmt.Sprintf("ExitCode=%d", cs.LastTerminationState.Terminated.ExitCode)
					}
				}
				// CrashLoopBackOff is most important, return immediately
				if waitingReason == "CrashLoopBackOff" {
					return status
				}
			}
		}

		// Track restart counts even for running containers
		if cs.RestartCount > 0 && status == nil {
			status = &v1alpha1.PodContainerStatus{
				RestartCount: cs.RestartCount,
			}
			if cs.LastTerminationState.Terminated != nil {
				status.LastTerminationReason = cs.LastTerminationState.Terminated.Reason
				if status.LastTerminationReason == "" {
					status.LastTerminationReason = fmt.Sprintf("ExitCode=%d", cs.LastTerminationState.Terminated.ExitCode)
				}
			}
		}
	}

	return status
}

// cleanupResources removes deployed resources from the target cluster
func (c *DebugSessionController) cleanupResources(ctx context.Context, ds *v1alpha1.DebugSession) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	if c.ccProvider == nil {
		return nil
	}

	// Clean up kubectl-debug resources (if any)
	kubectlHandler := NewKubectlDebugHandler(c.client, &clusterClientAdapter{ccProvider: c.ccProvider})
	if err := kubectlHandler.CleanupKubectlDebugResources(ctx, ds); err != nil {
		// Check if the error is due to missing ClusterConfig - if so, treat as cleanup complete
		if errors.Is(err, cluster.ErrClusterConfigNotFound) {
			log.Warnw("ClusterConfig no longer exists, treating cleanup as complete (orphaned session)",
				"cluster", ds.Spec.Cluster)
			// Clear deployed resources since we can't clean them up anyway
			ds.Status.DeployedResources = nil
			ds.Status.AllowedPods = nil
			return applyDebugSessionStatus(ctx, c.client, ds)
		}
		log.Errorw("Failed to cleanup kubectl-debug resources", "error", err)
		// Continue to clean up deployed resources even if this fails
	}

	// Get spoke cluster client for cleanup
	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		// Check if the error is due to missing ClusterConfig - if so, treat as cleanup complete
		if errors.Is(err, cluster.ErrClusterConfigNotFound) {
			log.Warnw("ClusterConfig no longer exists, treating cleanup as complete (orphaned session)",
				"cluster", ds.Spec.Cluster)
			// Clear deployed resources since we can't clean them up anyway
			ds.Status.DeployedResources = nil
			ds.Status.AllowedPods = nil
			return applyDebugSessionStatus(ctx, c.client, ds)
		}
		return fmt.Errorf("failed to get REST config: %w", err)
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Cleanup auxiliary resources first using the manager
	if c.auxiliaryMgr != nil && len(ds.Status.AuxiliaryResourceStatuses) > 0 {
		if err := c.auxiliaryMgr.CleanupAuxiliaryResources(ctx, ds, targetClient); err != nil {
			log.Warnw("Failed to cleanup auxiliary resources", "error", err)
			// Continue to clean up main workloads
		}
	}

	// Cleanup pod template resources (from multi-doc pod templates)
	if len(ds.Status.PodTemplateResourceStatuses) > 0 {
		if err := c.cleanupPodTemplateResources(ctx, ds, targetClient); err != nil {
			log.Warnw("Failed to cleanup pod template resources", "error", err)
			// Continue to clean up main workloads
		}
	}

	if len(ds.Status.DeployedResources) == 0 {
		return nil
	}

	// Cleanup main workloads (DaemonSet/Deployment)
	for _, ref := range ds.Status.DeployedResources {
		// Skip auxiliary resources - already cleaned up by manager
		if strings.HasPrefix(ref.Source, "auxiliary:") {
			continue
		}
		// Skip pod-template resources - already cleaned up above
		if ref.Source == "pod-template" {
			continue
		}

		var obj ctrlclient.Object

		switch ref.Kind {
		case "DaemonSet":
			obj = &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		case "Deployment":
			obj = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		case "ResourceQuota":
			obj = &corev1.ResourceQuota{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		case "PodDisruptionBudget":
			obj = &policyv1.PodDisruptionBudget{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ref.Name,
					Namespace: ref.Namespace,
				},
			}
		default:
			log.Warnw("Unknown resource type, skipping cleanup", "kind", ref.Kind, "name", ref.Name)
			continue
		}

		if err := targetClient.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			log.Warnw("Failed to delete debug resource", "kind", ref.Kind, "name", ref.Name, "error", err)
		} else {
			log.Infow("Deleted debug resource", "kind", ref.Kind, "name", ref.Name)
		}
	}

	// Clear deployed resources from status
	ds.Status.DeployedResources = nil
	ds.Status.AllowedPods = nil
	ds.Status.PodTemplateResourceStatuses = nil
	return applyDebugSessionStatus(ctx, c.client, ds)
}

// cleanupPodTemplateResources removes resources deployed from multi-document pod templates.
func (c *DebugSessionController) cleanupPodTemplateResources(ctx context.Context, ds *v1alpha1.DebugSession, targetClient ctrlclient.Client) error {
	log := c.log.With("debugSession", ds.Name, "cluster", ds.Spec.Cluster)

	for i := range ds.Status.PodTemplateResourceStatuses {
		status := &ds.Status.PodTemplateResourceStatuses[i]

		// Skip if already deleted
		if status.Deleted {
			continue
		}

		// Skip if not created
		if !status.Created {
			continue
		}

		// Create unstructured object for deletion
		gvk, err := parseGVK(status.APIVersion, status.Kind)
		if err != nil {
			log.Warnw("Failed to parse GVK for pod template resource",
				"apiVersion", status.APIVersion,
				"kind", status.Kind,
				"error", err)
			status.Error = fmt.Sprintf("failed to parse GVK: %v", err)
			continue
		}

		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		obj.SetName(status.ResourceName)
		obj.SetNamespace(status.Namespace)

		if err := targetClient.Delete(ctx, obj); err != nil {
			if apierrors.IsNotFound(err) {
				log.Debugw("Pod template resource already deleted",
					"kind", status.Kind,
					"name", status.ResourceName)
			} else {
				log.Warnw("Failed to delete pod template resource",
					"kind", status.Kind,
					"name", status.ResourceName,
					"error", err)
				status.Error = fmt.Sprintf("delete failed: %v", err)
				continue
			}
		} else {
			log.Infow("Deleted pod template resource",
				"kind", status.Kind,
				"name", status.ResourceName,
				"namespace", status.Namespace)
		}

		status.Deleted = true
		now := time.Now().UTC().Format(time.RFC3339)
		status.DeletedAt = &now
	}

	return nil
}

// parseDuration parses the requested duration with template constraints.
// Supports day units (e.g., "1d", "7d") in addition to standard Go duration units.
func (c *DebugSessionController) parseDuration(requested string, constraints *v1alpha1.DebugSessionConstraints) time.Duration {
	defaultDur := time.Hour
	maxDur := 4 * time.Hour

	if constraints != nil {
		if d, err := v1alpha1.ParseDuration(constraints.DefaultDuration); err == nil {
			defaultDur = d
		}
		if d, err := v1alpha1.ParseDuration(constraints.MaxDuration); err == nil {
			maxDur = d
		}
	}

	if requested == "" {
		return defaultDur
	}

	dur, err := v1alpha1.ParseDuration(requested)
	if err != nil {
		return defaultDur
	}

	if dur > maxDur {
		return maxDur
	}
	return dur
}

// setupTerminalSharing configures terminal sharing status for the session
func (c *DebugSessionController) setupTerminalSharing(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate) *v1alpha1.TerminalSharingStatus {
	if template.Spec.TerminalSharing == nil || !template.Spec.TerminalSharing.Enabled {
		return nil
	}

	provider := template.Spec.TerminalSharing.Provider
	if provider == "" {
		provider = "tmux"
	}

	// Generate a unique session name
	sessionName := fmt.Sprintf("debug-%s", ds.Name)
	if len(sessionName) > 32 {
		sessionName = sessionName[:32]
	}

	// Build attach command based on provider
	var attachCommand string
	switch provider {
	case "tmux":
		attachCommand = fmt.Sprintf("tmux attach-session -t %s", sessionName)
	case "screen":
		attachCommand = fmt.Sprintf("screen -x %s", sessionName)
	default:
		attachCommand = fmt.Sprintf("tmux attach-session -t %s", sessionName)
	}

	c.log.Infow("Terminal sharing configured",
		"debugSession", ds.Name,
		"provider", provider,
		"sessionName", sessionName)

	return &v1alpha1.TerminalSharingStatus{
		Enabled:       true,
		SessionName:   sessionName,
		AttachCommand: attachCommand,
	}
}

// IsPodInDebugSession checks if a pod belongs to an active debug session
func IsPodInDebugSession(namespace, name string, allowedPods []v1alpha1.AllowedPodRef) bool {
	for _, pod := range allowedPods {
		if pod.Namespace == namespace && pod.Name == name {
			return true
		}
	}
	return false
}

// updateTemplateStatus updates the DebugSessionTemplate and DebugPodTemplate status
// to reflect active session counts and usage tracking.
// incrementActive: true when activating a session, false when deactivating (cleanup/expiry)
func (c *DebugSessionController) updateTemplateStatus(ctx context.Context, template *v1alpha1.DebugSessionTemplate, incrementActive bool) error {
	log := c.log.With("template", template.Name)

	// Re-fetch template to get latest version
	currentTemplate := &v1alpha1.DebugSessionTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: template.Name}, currentTemplate); err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	// Update active session count
	if incrementActive {
		currentTemplate.Status.ActiveSessionCount++
		now := metav1.Now()
		currentTemplate.Status.LastUsedAt = &now
	} else {
		if currentTemplate.Status.ActiveSessionCount > 0 {
			currentTemplate.Status.ActiveSessionCount--
		}
	}

	// Update the template status using SSA
	if err := ssa.ApplyDebugSessionTemplateStatus(ctx, c.client, currentTemplate); err != nil {
		return fmt.Errorf("failed to update template status: %w", err)
	}

	log.Debugw("Updated template status",
		"activeSessionCount", currentTemplate.Status.ActiveSessionCount,
		"lastUsedAt", currentTemplate.Status.LastUsedAt,
		"incrementActive", incrementActive)

	// Also update the DebugPodTemplate.status.usedBy if a pod template is referenced
	if currentTemplate.Spec.PodTemplateRef != nil && currentTemplate.Spec.PodTemplateRef.Name != "" {
		if err := c.updatePodTemplateUsedBy(ctx, currentTemplate.Spec.PodTemplateRef.Name, template.Name); err != nil {
			log.Warnw("Failed to update pod template usedBy", "podTemplate", currentTemplate.Spec.PodTemplateRef.Name, "error", err)
			// Non-fatal
		}
	}

	return nil
}

// updatePodTemplateUsedBy ensures the DebugPodTemplate.status.usedBy list includes
// the given DebugSessionTemplate name.
func (c *DebugSessionController) updatePodTemplateUsedBy(ctx context.Context, podTemplateName, sessionTemplateName string) error {
	podTemplate := &v1alpha1.DebugPodTemplate{}
	if err := c.client.Get(ctx, ctrlclient.ObjectKey{Name: podTemplateName}, podTemplate); err != nil {
		return fmt.Errorf("failed to get pod template: %w", err)
	}

	// Check if already in usedBy list
	for _, name := range podTemplate.Status.UsedBy {
		if name == sessionTemplateName {
			return nil // Already tracked
		}
	}

	// Add to usedBy list
	podTemplate.Status.UsedBy = append(podTemplate.Status.UsedBy, sessionTemplateName)

	// Update using SSA
	if err := ssa.ApplyDebugPodTemplateStatus(ctx, c.client, podTemplate); err != nil {
		return fmt.Errorf("failed to update pod template status: %w", err)
	}

	c.log.Debugw("Updated pod template usedBy",
		"podTemplate", podTemplateName,
		"addedSessionTemplate", sessionTemplateName,
		"usedBy", podTemplate.Status.UsedBy)

	return nil
}

// Ensure DebugSessionController is a valid interface type
var _ interface {
	GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
} = (*cluster.ClientProvider)(nil)
