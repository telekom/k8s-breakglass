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
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	breakglass "github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DebugSessionLabelKey is used to identify debug pods
	DebugSessionLabelKey = "breakglass.telekom.com/debug-session"
	// DebugSessionUIDLabelKey identifies the concrete DebugSession instance.
	// Jobs use this label in their manual selector so a recreated session with
	// the same name can never adopt pods from the previous instance.
	DebugSessionUIDLabelKey = "breakglass.telekom.com/debug-session-uid"
	// DebugSessionUIDAnnotationKey is persisted on session-owned auxiliary
	// resources so cleanup can detect replacement by another object/session.
	DebugSessionUIDAnnotationKey = "breakglass.telekom.com/debug-session-uid"
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
	log                    *zap.SugaredLogger
	client                 ctrlclient.Client
	ccProvider             *cluster.ClientProvider
	auditService           *audit.Service
	auditManager           *audit.Manager
	mailService            breakglass.MailEnqueuer
	auxiliaryMgr           *AuxiliaryResourceManager
	terminalRecordingImage string
	brandingName           string
	baseURL                string
	disableEmail           bool
}

// NewDebugSessionController creates a new DebugSessionController
func NewDebugSessionController(log *zap.SugaredLogger, client ctrlclient.Client, ccProvider *cluster.ClientProvider) *DebugSessionController {
	c := &DebugSessionController{
		log:                    log,
		client:                 client,
		ccProvider:             ccProvider,
		auxiliaryMgr:           NewAuxiliaryResourceManager(log.Named("auxiliary"), client),
		terminalRecordingImage: strings.TrimSpace(os.Getenv("BREAKGLASS_TERMINAL_RECORDING_IMAGE")),
	}
	c.auxiliaryMgr.SetInventoryPersister(func(ctx context.Context, session *breakglassv1alpha1.DebugSession) error {
		return breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, session, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.DeployedResources = session.Status.DeployedResources
		})
	})
	return c
}

// WithTerminalRecordingSidecarImage configures the deployment-supplied image
// implementing the terminal recording sidecar contract. The controller never
// selects an internal or mutable image implicitly.
func (c *DebugSessionController) WithTerminalRecordingSidecarImage(image string) *DebugSessionController {
	c.terminalRecordingImage = strings.TrimSpace(image)
	return c
}

// WithAuditManager sets the audit manager for the controller
func (c *DebugSessionController) WithAuditManager(am *audit.Manager) *DebugSessionController {
	c.auditManager = am
	c.auditService = nil
	if c.auxiliaryMgr != nil {
		c.auxiliaryMgr.SetAuditManager(am)
	}
	return c
}

// WithAuditService sets the reloadable audit service for the controller.
func (c *DebugSessionController) WithAuditService(auditService *audit.Service) *DebugSessionController {
	c.auditService = auditService
	if c.auxiliaryMgr != nil {
		c.auxiliaryMgr.SetAuditManagerProvider(c.currentAuditManager)
	}
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

func (c *DebugSessionController) currentAuditManager() *audit.Manager {
	if c.auditService != nil {
		return c.auditService.Manager()
	}
	return c.auditManager
}

// SetupWithManager sets up the controller with the Manager
func (c *DebugSessionController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DebugSession{}).
		Complete(c)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessions,verbs=get;list;watch;create;update;patch;delete
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

			releaseSessionMetricSeries(req.Name)

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
		breakglass.SetDebugSessionRetainedUntil(ds, time.Now())
		if statusErr := breakglass.ApplyDebugSessionStatus(ctx, c.client, ds); statusErr != nil {
			log.Errorw("Failed to update DebugSession status after validation failure", "error", statusErr)
		}
		if c.shouldEmitAudit(ds) && !validationFailureAuditRecorded(ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				auditManager.DebugSessionValidationFailed(ctx, ds.Name, ds.Namespace, ds.Spec.RequestedBy, ds.Spec.Cluster, "structural_validation_failed")
			}
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
	case breakglassv1alpha1.DebugSessionStateExpired, breakglassv1alpha1.DebugSessionStateIdleExpired,
		breakglassv1alpha1.DebugSessionStateTerminated, breakglassv1alpha1.DebugSessionStateRejected:
		return c.handleCleanup(ctx, ds)
	case breakglassv1alpha1.DebugSessionStateFailed:
		// Terminal state — but only once the spoke cluster is actually clean.
		// failSession does best-effort cleanup, logs any failure and then sets
		// Failed, which never requeues; a cleanup error there therefore leaked the
		// spoke resources permanently. Retry while anything is still tracked.
		return c.handleFailedCleanup(ctx, ds)
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

	// Find binding early so we can check its approvers for the approval decision
	// This ensures bindings with approvers properly trigger approval workflow.
	//
	// An explicit BindingRef that cannot be resolved is INDETERMINATE, not "absent".
	// The binding is what carries the approver configuration, so silently falling
	// through to auto-discovery here would let requiresApproval() see no approvers
	// and activate the session with no approval at all — a fail-OPEN on a transient
	// API/cache error. We requeue instead: the session stays Pending (nothing is
	// granted, nothing is denied) until the ref resolves or an operator corrects it.
	var binding *breakglassv1alpha1.DebugSessionClusterBinding
	if ds.Spec.BindingRef != nil {
		binding, err = c.getBinding(ctx, ds.Spec.BindingRef.Name, ds.Spec.BindingRef.Namespace)
		if err != nil {
			return c.deferOnUnresolvedBinding(ctx, ds, err)
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
	effectiveTemplate, err := effectiveTemplateForBinding(template, binding, ds.Spec.ExtraDeployValues)
	if err != nil {
		log.Warnw("Rejecting session because binding variable constraints are invalid", "error", err)
		return c.failSession(ctx, ds, "invalid binding extra deploy variable constraints")
	}

	// Cache the resolved template in status after applying binding-level duration overrides.
	resolvedTemplate := effectiveTemplate.Spec.DeepCopy()
	resolvedTemplate.Constraints = effectiveDebugSessionConstraints(template, binding)
	ds.Status.ResolvedTemplate = resolvedTemplate

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
		// Find binding for merging allowed pod operations.
		// Same indeterminate-vs-absent reasoning as handlePending: the binding can only
		// narrow AllowedPodOperations, so activating without it would grant a strictly
		// wider set than the approver saw. Requeue instead of guessing.
		var binding *breakglassv1alpha1.DebugSessionClusterBinding
		if ds.Spec.BindingRef != nil {
			var bErr error
			binding, bErr = c.getBinding(ctx, ds.Spec.BindingRef.Name, ds.Spec.BindingRef.Namespace)
			if bErr != nil {
				return c.deferOnUnresolvedBinding(ctx, ds, bErr)
			}
		}
		if binding == nil {
			binding, _ = c.findBindingForSession(ctx, template, ds.Spec.Cluster)
		}
		return c.activateSession(ctx, ds, template, binding)
	}

	// If rejected, preserve the explicit rejection terminal state.
	if ds.Status.Approval != nil && ds.Status.Approval.RejectedAt != nil {
		ds.Status.State = breakglassv1alpha1.DebugSessionStateRejected
		ds.Status.Message = fmt.Sprintf("Rejected by %s: %s", ds.Status.Approval.RejectedBy, ds.Status.Approval.Reason)
		breakglass.SetDebugSessionRetainedUntil(ds, time.Now())
		return ctrl.Result{}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
	}

	// Check if approval has timed out
	timeout := breakglass.DebugSessionApprovalTimeoutFor(ds)
	if ds.CreationTimestamp.Add(timeout).Before(time.Now()) {
		reason := fmt.Sprintf("Approval timed out after %s", timeout)
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.State = breakglassv1alpha1.DebugSessionStateFailed
			status.Message = reason
			breakglass.SetDebugSessionRetainedUntil(ds, time.Now())
			status.RetainedUntil = ds.Status.RetainedUntil
		}); err != nil {
			if apierrors.IsConflict(err) {
				c.log.Debugw("skipping approval-timeout status update after concurrent debug session change", "error", err)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		c.log.Errorw("Debug session approval timed out",
			"debugSession", ds.Name, "namespace", ds.Namespace,
			"reason", reason)

		if c.shouldEmitAudit(ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				auditManager.DebugSessionApprovalTimeout(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster)
			}
		}
		c.sendDebugSessionFailedEmail(ds, reason)
		metrics.DebugSessionsFailed.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()

		return ctrl.Result{}, nil
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
				if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
					status.Message = "Session expiring soon"
				}); err != nil {
					if apierrors.IsConflict(err) {
						log.Debugw("skipping expiring-soon status update after concurrent debug session change", "error", err)
						return ctrl.Result{}, nil
					}
					return ctrl.Result{}, err
				}
			}
		}
	}

	// Check expiration
	if idleTimeout := breakglass.DebugSessionIdleTimeoutFor(ds); breakglass.DebugSessionIdleExpired(ds, time.Now()) {
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.State = breakglassv1alpha1.DebugSessionStateIdleExpired
			status.Message = fmt.Sprintf("Session expired after %s of inactivity", idleTimeout)
			breakglass.SetDebugSessionRetainedUntil(ds, time.Now())
			status.RetainedUntil = ds.Status.RetainedUntil
		}); err != nil {
			if apierrors.IsConflict(err) {
				log.Debugw("skipping idle expiration status update after concurrent debug session change", "error", err)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		metrics.DebugSessionsActive.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Dec()
		return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, nil
	}

	if ds.Status.ExpiresAt != nil && time.Now().After(ds.Status.ExpiresAt.Time) {
		if ds.Status.ResolvedTemplate != nil && ds.Status.ResolvedTemplate.ExpirationBehavior == "notify-only" {
			if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
				status.Message = "Session expired (notify-only)"
				status.ExpiresAt = nil
			}); err != nil {
				if apierrors.IsConflict(err) {
					log.Debugw("skipping notify-only expiration status update after concurrent debug session change", "error", err)
					return ctrl.Result{}, nil
				}
				return ctrl.Result{}, err
			}
			log.Info("Debug session expired")
			return ctrl.Result{}, nil
		}
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.State = breakglassv1alpha1.DebugSessionStateExpired
			status.Message = "Session expired"
			breakglass.SetDebugSessionRetainedUntil(ds, time.Now())
			status.RetainedUntil = ds.Status.RetainedUntil
		}); err != nil {
			if apierrors.IsConflict(err) {
				log.Debugw("skipping expiration status update after concurrent debug session change", "error", err)
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		log.Info("Debug session expired")
		if c.shouldEmitAudit(ds) {
			if auditManager := c.currentAuditManager(); auditManager != nil {
				auditManager.DebugSessionExpired(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster)
			}
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

// handleFailedCleanup finishes cleanup for a session already in the terminal
// Failed state.
//
// failSession performs a best-effort cleanup, logs any error and then sets Failed.
// Failed used to return an empty Result, which never requeues, so a cleanup error
// on that path leaked the spoke-cluster resources permanently (#237). Failed
// remains terminal for state-machine purposes — the state is never changed here —
// but reconciliation keeps retrying the delete until the status lists are empty.
func (c *DebugSessionController) handleFailedCleanup(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	if !hasTrackedSpokeResources(ds) {
		if err := c.clearCleanupFailure(ctx, ds); err != nil {
			return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, err
		}
		releaseSessionMetricSeries(ds.Name)
		return ctrl.Result{}, nil // Nothing left on the spoke: genuinely terminal.
	}

	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace, "cluster", ds.Spec.Cluster)

	if err := c.cleanupResources(ctx, ds); err != nil {
		log.Warnw("Retrying cleanup of spoke resources for a failed debug session",
			"error", err)
		c.emitCleanupFailureAudit(ctx, ds, err)
		// Requeue rather than returning the error: the reason for the failure is
		// already recorded in status and a hard error would only add log noise on a
		// path that is expected to retry.
		return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, nil
	}
	// cleanupResources clears the status lists as it succeeds. If anything is still
	// tracked, the cleanup was incomplete even though it reported no error, so the
	// session is not yet safe to abandon.
	if hasTrackedSpokeResources(ds) {
		log.Warnw("Cleanup reported success but spoke resources are still tracked; will retry")
		return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, nil
	}

	log.Infow("Cleanup of spoke resources completed for failed debug session")
	releaseSessionMetricSeries(ds.Name)
	return ctrl.Result{}, nil
}

// hasTrackedSpokeResources reports whether the session status still references
// anything that was deployed to the spoke cluster.
func hasTrackedSpokeResources(ds *breakglassv1alpha1.DebugSession) bool {
	return len(ds.Status.DeployedResources) > 0 ||
		len(ds.Status.AuxiliaryResourceStatuses) > 0 ||
		len(ds.Status.PodTemplateResourceStatuses) > 0 ||
		len(ds.Status.AllowedPods) > 0 ||
		ds.Status.KubectlDebugStatus != nil
}

// handleCleanup removes deployed resources for expired/terminated sessions
func (c *DebugSessionController) handleCleanup(ctx context.Context, ds *breakglassv1alpha1.DebugSession) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)

	if err := c.cleanupResources(ctx, ds); err != nil {
		log.Errorw("Failed to cleanup debug session resources", "error", err)
		c.emitCleanupFailureAudit(ctx, ds, err)
		// Requeue to retry cleanup
		return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, nil
	}
	if ds.Status.Recording != nil && ds.Status.Recording.Enabled && ds.Status.Recording.State != breakglassv1alpha1.TerminalRecordingStateFailed {
		if err := breakglass.PatchDebugSessionStatusWithOptimisticLock(ctx, c.client, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			if status.Recording == nil {
				return
			}
			status.Recording.State = breakglassv1alpha1.TerminalRecordingStateRetained
			now := metav1.Now()
			status.Recording.CompletedAt = &now
		}); err != nil {
			return ctrl.Result{RequeueAfter: ExpiredSessionRequeue}, err
		}
		ds.Status.Recording.State = breakglassv1alpha1.TerminalRecordingStateRetained
		c.emitRecordingAudit(ctx, audit.EventDebugSessionRecordingReady, ds, map[string]interface{}{"state": string(ds.Status.Recording.State)})
	}

	// Decrement active gauge for terminated sessions. Expired sessions are
	// already decremented in handleActive before entering cleanup.
	if ds.Status.State == breakglassv1alpha1.DebugSessionStateTerminated {
		metrics.DebugSessionsActive.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Dec()
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

	// Release the per-session metric series. The "session" label is unique per
	// DebugSession, so without an explicit release these series accumulate for the
	// lifetime of the process and the heap grows monotonically with the number of
	// sessions ever created. The DeletePartialMatch on NotFound in Reconcile only
	// fires if a delete event is actually observed, which is not guaranteed (missed
	// watch event, restart, or a session that is never deleted at all).
	releaseSessionMetricSeries(ds.Name)

	log.Info("Debug session cleanup complete")
	return ctrl.Result{}, nil
}

// releaseSessionMetricSeries drops every metric series labelled with a specific
// DebugSession name. Safe to call more than once and safe before metric
// registration.
func releaseSessionMetricSeries(sessionName string) {
	if sessionName == "" {
		return
	}
	labels := map[string]string{"session": sessionName}
	if metrics.DebugSessionParticipants != nil {
		metrics.DebugSessionParticipants.DeletePartialMatch(labels)
	}
	if metrics.DebugSessionPodRestarts != nil {
		metrics.DebugSessionPodRestarts.DeletePartialMatch(labels)
	}
	if metrics.DebugSessionPodFailures != nil {
		metrics.DebugSessionPodFailures.DeletePartialMatch(labels)
	}
}

func (c *DebugSessionController) emitCleanupFailureAudit(ctx context.Context, ds *breakglassv1alpha1.DebugSession, cause error) {
	if !c.shouldEmitAudit(ds) {
		return
	}
	auditManager := c.currentAuditManager()
	if auditManager == nil {
		return
	}
	reason := "cleanup_failed"
	if errors.Is(cause, cluster.ErrClusterConfigNotFound) {
		reason = "cluster_config_not_found"
	} else if errors.Is(cause, context.DeadlineExceeded) {
		reason = "timeout"
	}
	auditManager.DebugSessionCleanupFailed(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster, reason, trackedResourceCount(ds))
}

func trackedResourceCount(ds *breakglassv1alpha1.DebugSession) int {
	count := len(ds.Status.DeployedResources) +
		len(ds.Status.AuxiliaryResourceStatuses) +
		len(ds.Status.PodTemplateResourceStatuses) +
		len(ds.Status.AllowedPods)
	if ds.Status.KubectlDebugStatus != nil {
		count++
	}
	return count
}

func validationFailureAuditRecorded(ds *breakglassv1alpha1.DebugSession) bool {
	return ds.Status.State == breakglassv1alpha1.DebugSessionStateFailed &&
		strings.HasPrefix(ds.Status.Message, "Validation failed:")
}

// activateSession deploys debug resources and marks session as active
func (c *DebugSessionController) activateSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession, template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace)
	effectiveTemplate, err := effectiveTemplateForBinding(template, binding, ds.Spec.ExtraDeployValues)
	if err != nil {
		log.Warnw("Rejecting session because binding variable constraints are invalid", "error", err)
		return c.failSession(ctx, ds, "invalid binding extra deploy variable constraints")
	}
	template = effectiveTemplate
	if template.Spec.Audit != nil && template.Spec.Audit.EnableTerminalRecording && (ds.Status.Recording == nil || !ds.Status.Recording.Enabled) {
		now := metav1.Now()
		ds.Status.Recording = &breakglassv1alpha1.TerminalRecordingStatus{
			Enabled:       true,
			State:         breakglassv1alpha1.TerminalRecordingStateStarting,
			Format:        TerminalRecordingFormat,
			CorrelationID: recordingCorrelationID(ds.Namespace, ds.Name),
			Retention:     defaultRecordingRetention(template.Spec.Audit.RecordingRetention),
			StartedAt:     &now,
		}
	}

	// Only deploy workloads for workload or hybrid mode
	mode := template.Spec.Mode
	if mode == "" {
		mode = breakglassv1alpha1.DebugSessionModeWorkload
	}
	if template.Spec.Audit != nil && template.Spec.Audit.EnableTerminalRecording &&
		mode != breakglassv1alpha1.DebugSessionModeWorkload && mode != breakglassv1alpha1.DebugSessionModeHybrid {
		return c.failSession(ctx, ds, "terminal recording requires a workload or hybrid debug session mode")
	}

	if mode == breakglassv1alpha1.DebugSessionModeWorkload || mode == breakglassv1alpha1.DebugSessionModeHybrid {
		if err := c.deployDebugResources(ctx, ds, template); err != nil {
			log.Errorw("Failed to deploy debug resources", "error", err)
			return c.failSession(ctx, ds, fmt.Sprintf("failed to deploy resources: %v", err))
		}
	}
<<<<<<< HEAD
	if c.shouldEmitAudit(ds) {
		if auditManager := c.currentAuditManager(); auditManager != nil {
			for _, resource := range ds.Status.DeployedResources {
				// Auxiliary resources emit their own resource-level event at the
				// point of deployment. Avoid duplicate records here.
				if strings.HasPrefix(resource.Source, "auxiliary:") {
					continue
				}
				auditManager.DebugSessionResourceDeployed(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster,
					resource.Kind, resource.Name, resource.Namespace)
			}
		}
	}
	if ds.Status.Recording != nil && ds.Status.Recording.Enabled {
		ds.Status.Recording.State = breakglassv1alpha1.TerminalRecordingStateRecording
		c.emitRecordingAudit(ctx, audit.EventDebugSessionRecordingStarted, ds, map[string]interface{}{
			"format":    ds.Status.Recording.Format,
			"retention": ds.Status.Recording.Retention,
		})
	}

	// Calculate expiration
	duration := c.parseDuration(ds.Spec.RequestedDuration, effectiveDebugSessionConstraints(template, binding))
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(duration))

	ds.Status.State = breakglassv1alpha1.DebugSessionStateActive
	ds.Status.StartsAt = &now
	ds.Status.ExpiresAt = &expiresAt
	ds.Status.LastActivity = &now
	ds.Status.ActivityCount = 1
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
	if c.shouldEmitAudit(ds) {
		if auditManager := c.currentAuditManager(); auditManager != nil {
			auditManager.Emit(ctx, &audit.Event{
				Type:     audit.EventDebugSessionStarted,
				Severity: audit.SeverityInfo,
				Actor:    audit.Actor{User: "system"},
				Target:   audit.Target{Kind: "DebugSession", Name: ds.Name, Namespace: ds.Namespace, Cluster: ds.Spec.Cluster},
				Details: map[string]interface{}{
					"mode":          mode,
					"duration":      duration.String(),
					"resourceCount": len(ds.Status.DeployedResources),
				},
				RequestContext: &audit.RequestContext{DebugSessionName: ds.Name},
			})
		}
	}

	return ctrl.Result{RequeueAfter: DefaultDebugSessionRequeue}, nil
}

// effectiveTemplateForBinding applies binding variable constraints at the
// controller boundary as well as at API admission. Sessions can be approved
// or reconciled after either object changes, so rendering must fail closed and
// use the same narrowed definition that was used for request validation.
func effectiveTemplateForBinding(
	template *breakglassv1alpha1.DebugSessionTemplate,
	binding *breakglassv1alpha1.DebugSessionClusterBinding,
	values map[string]apiextensionsv1.JSON,
) (*breakglassv1alpha1.DebugSessionTemplate, error) {
	var constraints []breakglassv1alpha1.ExtraDeployVariableConstraint
	if binding != nil {
		constraints = binding.Spec.ExtraDeployVariables
	}
	effectiveVariables, err := breakglassv1alpha1.EffectiveExtraDeployVariables(template.Spec.ExtraDeployVariables, constraints)
	if err != nil {
		return nil, err
	}
	nameErrs := breakglassv1alpha1.ValidateExtraDeployValueNames(values, effectiveVariables, len(constraints) > 0, field.NewPath("extraDeployValues"))
	if len(nameErrs) > 0 {
		return nil, fmt.Errorf("extra deploy values are not allowed by binding: %s", nameErrs[0].Error())
	}
	result := template.DeepCopy()
	result.Spec.ExtraDeployVariables = effectiveVariables
	return result, nil
}

// failSession marks a session as failed and logs the failure
func (c *DebugSessionController) failSession(ctx context.Context, ds *breakglassv1alpha1.DebugSession, reason string) (ctrl.Result, error) {
	log := c.log.With("debugSession", ds.Name, "namespace", ds.Namespace, "cluster", ds.Spec.Cluster)

	// Best-effort cleanup of any partially deployed resources on the target cluster.
	// Short-circuit if the session never deployed anything to avoid noisy cross-cluster calls.
	//
	// A failure here is not fatal: the session still transitions to Failed, and the
	// Failed branch of Reconcile retries the cleanup for as long as the status
	// still tracks spoke resources (see handleFailedCleanup), so a transient spoke
	// outage no longer leaks resources permanently.
	if hasTrackedSpokeResources(ds) {
		if cleanupErr := c.cleanupResources(ctx, ds); cleanupErr != nil {
			log.Warnw("Best-effort cleanup of partially deployed resources failed during session failure; "+
				"cleanup will be retried on subsequent reconciles",
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
	if c.shouldEmitAudit(ds) {
		if auditManager := c.currentAuditManager(); auditManager != nil {
			auditManager.DebugSessionFailed(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster, failureAuditCategory(reason), map[string]interface{}{
				"template":       ds.Spec.TemplateRef,
				"requested_by":   ds.Spec.RequestedBy,
				"previous_state": string(ds.Status.State),
			})
			// Send to webhook destinations if configured
			c.sendToWebhookDestinations(ctx, ds, "DebugSessionFailed", map[string]interface{}{
				"session":   ds.Name,
				"namespace": ds.Namespace,
				"cluster":   ds.Spec.Cluster,
				"reason":    failureAuditCategory(reason),
			})
		}
	}

	ds.Status.State = breakglassv1alpha1.DebugSessionStateFailed
	ds.Status.Message = reason
	breakglass.SetDebugSessionRetainedUntil(ds, time.Now())
	if ds.Status.Recording != nil && ds.Status.Recording.Enabled {
		ds.Status.Recording.State = breakglassv1alpha1.TerminalRecordingStateFailed
		ds.Status.Recording.Error = safeRecordingFailure(reason)
		c.emitRecordingAudit(ctx, audit.EventDebugSessionRecordingFailed, ds, map[string]interface{}{
			"reason": ds.Status.Recording.Error,
		})
	}

	// Send failure notification email to requester
	c.sendDebugSessionFailedEmail(ds, reason)

	// Increment failure metric
	metrics.DebugSessionsFailed.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()

	// Failed is terminal and never requeues, so release the per-session series now.
	releaseSessionMetricSeries(ds.Name)

	return ctrl.Result{}, breakglass.ApplyDebugSessionStatus(ctx, c.client, ds)
}

// failureAuditCategory keeps raw Kubernetes/client errors out of audit sinks.
// Operators can correlate the bounded category with controller logs using the
// DebugSession name without duplicating error payloads in durable audit data.
func failureAuditCategory(reason string) string {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "template"):
		return "template_unavailable"
	case strings.Contains(lower, "deploy") || strings.Contains(lower, "resource"):
		return "deployment_failed"
	case strings.Contains(lower, "approval"):
		return "approval_failed"
	case strings.Contains(lower, "binding"):
		return "binding_unavailable"
	default:
		return "reconciliation_failed"
	}
}

// sendDebugSessionFailedEmail sends email notification to requester when a debug session fails
func (c *DebugSessionController) sendDebugSessionFailedEmail(ds *breakglassv1alpha1.DebugSession, reason string) {
	if c.disableEmail || c.mailService == nil || !c.mailService.IsEnabled() {
		return
	}

	requesterEmail := strings.TrimSpace(ds.Spec.RequestedByEmail)
	if requesterEmail == "" {
		requesterEmail = strings.TrimSpace(ds.Spec.RequestedBy)
	}
	if !isSafeDebugSessionFailureRecipient(requesterEmail) {
		c.log.Warnw("Skipping debug session failed email - no valid email address", "session", ds.Name)
		return
	}
	recipients := []string{requesterEmail}

	requesterName := ds.Spec.RequestedByDisplayName
	if requesterName == "" {
		requesterName = ds.Spec.RequestedBy
		if strings.EqualFold(requesterName, requesterEmail) {
			requesterName = ""
		}
	}

	params := mail.DebugSessionFailedMailParams{
		RequesterName:  requesterName,
		RequesterEmail: requesterEmail,
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

func isSafeDebugSessionFailureRecipient(recipient string) bool {
	if recipient == "" || !strings.Contains(recipient, "@") {
		return false
	}
	return strings.IndexFunc(recipient, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r) || strings.ContainsRune(",;<>", r)
	}) == -1
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

func (c *DebugSessionController) emitRecordingAudit(ctx context.Context, eventType audit.EventType, ds *breakglassv1alpha1.DebugSession, details map[string]interface{}) {
	if !c.shouldEmitAudit(ds) {
		return
	}
	manager := c.currentAuditManager()
	if manager == nil || ds.Status.Recording == nil {
		return
	}
	manager.DebugSessionRecording(ctx, eventType, ds.Name, ds.Namespace, ds.Spec.Cluster, ds.Status.Recording.CorrelationID, details)
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
	redactedPayload := sanitizeDebugSessionWebhookDetails(payload)
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
		"details": redactedPayload,
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

// sanitizeDebugSessionWebhookDetails keeps the legacy per-template webhook
// path subject to the same audit boundary as pkg/audit. Webhook payloads must
// never become an alternate channel for request bodies, commands, environment
// values, credentials, or raw pod/API errors.
func sanitizeDebugSessionWebhookDetails(payload map[string]interface{}) map[string]interface{} {
	if len(payload) == 0 {
		return nil
	}
	result := make(map[string]interface{}, min(len(payload), 32))
	count := 0
	for key, value := range payload {
		if count >= 32 {
			break
		}
		lowerKey := strings.ToLower(key)
		if lowerKey == "authorization" || lowerKey == "body" || lowerKey == "command" ||
			lowerKey == "credentials" || lowerKey == "env" || lowerKey == "environment" ||
			lowerKey == "error" || lowerKey == "headers" || lowerKey == "message" ||
			lowerKey == "output" || lowerKey == "password" || lowerKey == "raw" ||
			lowerKey == "reason" || lowerKey == "request" || lowerKey == "requestbody" ||
			lowerKey == "secret" || lowerKey == "token" {
			result[key] = "[REDACTED]"
		} else if text, ok := value.(string); ok {
			result[key] = audit.SanitizeDebugSessionAuditDetail(text)
		} else {
			result[key] = value
		}
		count++
	}
	return result
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

// deferOnUnresolvedBinding handles the case where a DebugSession names an explicit
// BindingRef that cannot be resolved.
//
// Failure modes here are asymmetric, so the design is deliberately "indeterminate",
// not "deny":
//
//   - Silently auto-discovering (the previous behaviour) fails OPEN: the binding
//     carries the approver set, so losing it makes requiresApproval() return false and
//     the session activates with no approval on a transient API error.
//   - Failing the session outright would fail CLOSED but destructively: DebugSessionStateFailed
//     is terminal and never requeues, so a two-second apiserver blip during an incident
//     would permanently kill an operator's emergency session and force a manual re-request.
//
// So we do neither. The session stays in its current state (Pending / PendingApproval —
// no access granted, nothing terminal) and we requeue. A NotFound on a mistyped ref will
// keep requeueing and remain visible via the audit event, the Error log and the
// breakglass_debug_session_binding_unresolved_total metric; the existing approval-timeout
// path still bounds how long a PendingApproval session can linger. No NEW lockout path is
// introduced: every state that previously activated either still activates or is retried.
func (c *DebugSessionController) deferOnUnresolvedBinding(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	cause error,
) (ctrl.Result, error) {
	bindingName, bindingNamespace := "", ""
	if ds.Spec.BindingRef != nil {
		bindingName = ds.Spec.BindingRef.Name
		bindingNamespace = ds.Spec.BindingRef.Namespace
	}

	reason := "binding_lookup_failed"
	if apierrors.IsNotFound(cause) {
		reason = "binding_not_found"
	}

	c.log.Errorw("Refusing to evaluate debug session: explicit bindingRef is unresolvable, "+
		"approval requirement is indeterminate; not falling back to auto-discovery",
		"debugSession", ds.Name,
		"namespace", ds.Namespace,
		"cluster", ds.Spec.Cluster,
		"state", string(ds.Status.State),
		"binding", bindingName,
		"bindingNamespace", bindingNamespace,
		"reason", reason,
		"error", cause)

	metrics.DebugSessionBindingUnresolved.WithLabelValues(ds.Spec.Cluster, reason).Inc()

	if c.shouldEmitAudit(ds) {
		if auditManager := c.currentAuditManager(); auditManager != nil {
			auditManager.DebugSessionBindingUnresolved(ctx, ds.Name, ds.Namespace,
				ds.Spec.Cluster, bindingName, bindingNamespace, reason)
		}
	}

	// Return the error so controller-runtime applies its exponential backoff rather
	// than our fixed requeue interval; the session state is left untouched.
	return ctrl.Result{}, fmt.Errorf("resolve bindingRef %s/%s for debug session %s/%s: %w",
		bindingNamespace, bindingName, ds.Namespace, ds.Name, cause)
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
	// Get base REST config for spoke cluster.
	//
	// GetRESTConfig returns the *shared* cached *rest.Config pointer held in the
	// ClientProvider cache for this spoke. It MUST NOT be mutated in place: every
	// other consumer of that cluster's cached config (webhook SAR checks, cleanup,
	// workload deployment, clientsets) would inherit whatever we wrote until the
	// cache entry expires, and concurrent reconciles would race on the same struct.
	// Always copy before touching any field. See group_checker.go and
	// session_controller_approval_utils.go for the same pattern.
	sharedCfg, err := c.ccProvider.GetRESTConfig(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get REST config for cluster %s: %w", clusterName, err)
	}
	restCfg := rest.CopyConfig(sharedCfg)

	// If impersonation is configured, set up impersonation.
	//
	// Note that the resulting wire format is unchanged from before constrained
	// impersonation existed: KEP-5284 adds no headers, and a ServiceAccount target
	// with only the username set is exactly what the API server needs to select
	// `serviceaccount` mode. So on a spoke that supports the feature this request is
	// automatically constrained, and on an older spoke it is the same legacy
	// impersonation it has always been — the same bytes either way.
	// GetRESTConfig returns a POINTER INTO THE PROVIDER'S TTL CACHE, shared by every
	// caller for this spoke — the webhook's RBAC probe and session SAR checks
	// included. Writing Impersonate onto it would poison all of them for the rest of
	// the cache TTL, silently running unrelated requests as the impersonated
	// identity. Copy before mutating.
	if impConfig != nil {
		restCfg = rest.CopyConfig(restCfg)
		if err := c.applyImpersonation(ctx, restCfg, clusterName, impConfig); err != nil {
			return nil, err
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
// Binding approvers replace template approvers when present; otherwise template
// approvers are used. Approval is required when the effective approver set has
// users or groups, unless auto-approve conditions are met.
func (c *DebugSessionController) requiresApproval(template *breakglassv1alpha1.DebugSessionTemplate, binding *breakglassv1alpha1.DebugSessionClusterBinding, ds *breakglassv1alpha1.DebugSession) bool {
	// Binding approvers replace template approvers when the field is present,
	// even if the binding intentionally sets an empty approver list.
	if binding != nil && binding.Spec.Approvers != nil {
		if !debugSessionApproversConfigured(binding.Spec.Approvers) {
			return false
		}
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

	// Check if template has approvers configured
	if template == nil || !debugSessionApproversConfigured(template.Spec.Approvers) {
		return false // No approvers configured = auto-approve
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
						"matchedGroupHint", system.RedactGroupName(userGroup))
					return true
				}
			}
		}
	}

	return false
}

// deployDebugResources creates the debug workload on the target cluster
