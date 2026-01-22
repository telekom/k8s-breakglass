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
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
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
	brandingName string
	baseURL      string
	disableEmail bool
}

// NewDebugSessionController creates a new DebugSessionController
func NewDebugSessionController(log *zap.SugaredLogger, client ctrlclient.Client, ccProvider *cluster.ClientProvider) *DebugSessionController {
	return &DebugSessionController{
		log:        log,
		client:     client,
		ccProvider: ccProvider,
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
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

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
		if statusErr := c.client.Status().Update(ctx, ds); statusErr != nil {
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

	// Check if approval is required
	requiresApproval := c.requiresApproval(template, ds)
	ds.Status.Approval = &v1alpha1.DebugSessionApproval{
		Required: requiresApproval,
	}

	if requiresApproval {
		ds.Status.State = v1alpha1.DebugSessionStatePendingApproval
		ds.Status.Message = "Waiting for approval"
		if err := c.client.Status().Update(ctx, ds); err != nil {
			return ctrl.Result{}, err
		}
		metrics.DebugSessionsCreated.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
		return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
	}

	// Auto-approved, transition to active
	return c.activateSession(ctx, ds, template)
}

// handlePendingApproval checks for approval status
func (c *DebugSessionController) handlePendingApproval(ctx context.Context, ds *v1alpha1.DebugSession) (ctrl.Result, error) {
	// If approved, activate
	if ds.Status.Approval != nil && ds.Status.Approval.ApprovedAt != nil {
		template, err := c.getTemplate(ctx, ds.Spec.TemplateRef)
		if err != nil {
			return c.failSession(ctx, ds, fmt.Sprintf("template not found: %s", ds.Spec.TemplateRef))
		}
		return c.activateSession(ctx, ds, template)
	}

	// If rejected, mark as terminated
	if ds.Status.Approval != nil && ds.Status.Approval.RejectedAt != nil {
		ds.Status.State = v1alpha1.DebugSessionStateTerminated
		ds.Status.Message = fmt.Sprintf("Rejected by %s: %s", ds.Status.Approval.RejectedBy, ds.Status.Approval.Reason)
		return ctrl.Result{}, c.client.Status().Update(ctx, ds)
	}

	// Still waiting for approval
	return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
}

// handleActive manages an active debug session
func (c *DebugSessionController) handleActive(ctx context.Context, ds *v1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	// Check expiration
	if ds.Status.ExpiresAt != nil && time.Now().After(ds.Status.ExpiresAt.Time) {
		log.Info("Debug session expired")
		ds.Status.State = v1alpha1.DebugSessionStateExpired
		ds.Status.Message = "Session expired"
		if err := c.client.Status().Update(ctx, ds); err != nil {
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

	log.Info("Debug session cleanup complete")
	return ctrl.Result{}, nil
}

// activateSession deploys debug resources and marks session as active
func (c *DebugSessionController) activateSession(ctx context.Context, ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate) (ctrl.Result, error) {
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

	if err := c.client.Status().Update(ctx, ds); err != nil {
		return ctrl.Result{}, err
	}

	metrics.DebugSessionsCreated.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
	metrics.DebugSessionsActive.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()

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

	return ctrl.Result{}, c.client.Status().Update(ctx, ds)
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

// requiresApproval checks if the session requires approval
func (c *DebugSessionController) requiresApproval(template *v1alpha1.DebugSessionTemplate, ds *v1alpha1.DebugSession) bool {
	if template.Spec.Approvers == nil {
		return false // No approvers configured = auto-approve
	}

	// Check auto-approve conditions
	if template.Spec.Approvers.AutoApproveFor != nil {
		autoApprove := template.Spec.Approvers.AutoApproveFor

		// Auto-approve for specific clusters
		for _, pattern := range autoApprove.Clusters {
			if matched, _ := filepath.Match(pattern, ds.Spec.Cluster); matched {
				c.log.Infow("Auto-approving debug session based on cluster match",
					"session", ds.Name,
					"cluster", ds.Spec.Cluster,
					"pattern", pattern)
				return false
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
						return false
					}
				}
			}
		}
	}

	return true
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

	// Get target cluster client
	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		return fmt.Errorf("failed to get REST config for cluster %s: %w", ds.Spec.Cluster, err)
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return fmt.Errorf("failed to create client for cluster %s: %w", ds.Spec.Cluster, err)
	}

	// Ensure target namespace exists
	targetNs := template.Spec.TargetNamespace
	if targetNs == "" {
		targetNs = "breakglass-debug"
	}

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

	// Build and deploy workload
	workload, err := c.buildWorkload(ds, template, podTemplate, targetNs)
	if err != nil {
		return fmt.Errorf("failed to build workload: %w", err)
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
	})

	log.Infow("Deployed debug workload",
		"name", workload.GetName(),
		"namespace", targetNs,
		"kind", gvk.Kind)

	return nil
}

// buildWorkload creates the DaemonSet or Deployment for debug pods
func (c *DebugSessionController) buildWorkload(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, podTemplate *v1alpha1.DebugPodTemplate, targetNs string) (ctrlclient.Object, error) {
	workloadName := fmt.Sprintf("debug-%s", ds.Name)
	podSpec := c.buildPodSpec(ds, template, podTemplate)

	labels := map[string]string{
		DebugSessionLabelKey:  ds.Name,
		DebugTemplateLabelKey: ds.Spec.TemplateRef,
		DebugClusterLabelKey:  ds.Spec.Cluster,
	}

	// Add pod template labels if present
	if podTemplate != nil && podTemplate.Spec.Template.Metadata != nil {
		for k, v := range podTemplate.Spec.Template.Metadata.Labels {
			labels[k] = v
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
				Name:      workloadName,
				Namespace: targetNs,
				Labels:    labels,
			},
			Spec: appsv1.DaemonSetSpec{
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						DebugSessionLabelKey: ds.Name,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: labels,
					},
					Spec: podSpec,
				},
			},
		}, nil

	case v1alpha1.DebugWorkloadDeployment:
		replicas := int32(1)
		if template.Spec.Replicas != nil {
			replicas = *template.Spec.Replicas
		}
		return &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      workloadName,
				Namespace: targetNs,
				Labels:    labels,
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
						Labels: labels,
					},
					Spec: podSpec,
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported workload type: %s", workloadType)
	}
}

// buildPodSpec creates the pod spec from templates and overrides
func (c *DebugSessionController) buildPodSpec(ds *v1alpha1.DebugSession, template *v1alpha1.DebugSessionTemplate, podTemplate *v1alpha1.DebugPodTemplate) corev1.PodSpec {
	var spec corev1.PodSpec

	// Start with pod template if available
	if podTemplate != nil {
		spec = c.convertDebugPodSpec(podTemplate.Spec.Template.Spec)
	}

	// Apply overrides from session template
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

	return spec
}

// convertDebugPodSpec converts our DebugPodSpecInner to corev1.PodSpec
func (c *DebugSessionController) convertDebugPodSpec(dps v1alpha1.DebugPodSpecInner) corev1.PodSpec {
	spec := corev1.PodSpec{
		Containers:     dps.Containers,
		InitContainers: dps.InitContainers,
		Volumes:        dps.Volumes,
		Tolerations:    dps.Tolerations,
		Affinity:       dps.Affinity,
		NodeSelector:   dps.NodeSelector,
		HostNetwork:    dps.HostNetwork,
		HostPID:        dps.HostPID,
		HostIPC:        dps.HostIPC,
		DNSPolicy:      dps.DNSPolicy,
		RestartPolicy:  dps.RestartPolicy,
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
	return c.client.Status().Update(ctx, ds)
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
		log.Errorw("Failed to cleanup kubectl-debug resources", "error", err)
		// Continue to clean up deployed resources even if this fails
	}

	if len(ds.Status.DeployedResources) == 0 {
		return nil
	}

	restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
	if err != nil {
		return fmt.Errorf("failed to get REST config: %w", err)
	}
	targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	for _, ref := range ds.Status.DeployedResources {
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
	return c.client.Status().Update(ctx, ds)
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

// Ensure DebugSessionController is a valid interface type
var _ interface {
	GetRESTConfig(ctx context.Context, name string) (*rest.Config, error)
} = (*cluster.ClientProvider)(nil)
