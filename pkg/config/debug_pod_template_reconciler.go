package config

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
)

// DebugPodTemplate condition types
const (
	DebugPodTemplateConditionReady = "Ready"
	DebugPodTemplateConditionValid = "Valid"
)

// DebugPodTemplateReconciler watches DebugPodTemplate CRs and validates their configuration,
// updating status conditions to reflect validation state.
type DebugPodTemplateReconciler struct {
	client client.Client
	logger *zap.SugaredLogger
}

// NewDebugPodTemplateReconciler creates a new DebugPodTemplateReconciler instance.
func NewDebugPodTemplateReconciler(c client.Client, logger *zap.SugaredLogger) *DebugPodTemplateReconciler {
	return &DebugPodTemplateReconciler{
		client: c,
		logger: logger,
	}
}

func (r *DebugPodTemplateReconciler) applyStatus(ctx context.Context, template *breakglassv1alpha1.DebugPodTemplate) error {
	return ssa.ApplyDebugPodTemplateStatus(ctx, r.client, template)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugpodtemplates/status,verbs=get;update;patch

// Reconcile validates the DebugPodTemplate and updates its status conditions.
func (r *DebugPodTemplateReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling DebugPodTemplate", "name", req.Name)

	// Fetch the DebugPodTemplate
	template := &breakglassv1alpha1.DebugPodTemplate{}
	if err := r.client.Get(ctx, req.NamespacedName, template); err != nil {
		r.logger.Warnw("Failed to fetch DebugPodTemplate", "error", err)
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	now := metav1.Now()

	// Validate the template configuration using the webhook validation
	validationResult := breakglassv1alpha1.ValidateDebugPodTemplate(template)

	if !validationResult.IsValid() {
		// Set Valid condition to false
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugPodTemplateConditionValid,
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            fmt.Sprintf("Template validation failed: %v", validationResult.Errors),
			LastTransitionTime: now,
		})
		// Set Ready condition to false
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugPodTemplateConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            "Template validation failed",
			LastTransitionTime: now,
		})

		r.logger.Warnw("DebugPodTemplate validation failed",
			"template", template.Name,
			"errors", validationResult.Errors)
	} else {
		// Set Valid condition to true
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugPodTemplateConditionValid,
			Status:             metav1.ConditionTrue,
			Reason:             "ValidationSucceeded",
			Message:            "Template configuration is valid",
			LastTransitionTime: now,
		})
		// Set Ready condition to true
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugPodTemplateConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             "Ready",
			Message:            "Template is valid and ready for use",
			LastTransitionTime: now,
		})
	}

	// Apply status update
	if err := r.applyStatus(ctx, template); err != nil {
		r.logger.Warnw("Failed to update DebugPodTemplate status",
			"template", template.Name,
			"error", err)
		return reconcile.Result{}, err
	}

	r.logger.Debugw("Successfully reconciled DebugPodTemplate",
		"name", req.Name,
		"valid", validationResult.IsValid())

	return reconcile.Result{}, nil
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *DebugPodTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate to filter events - reconcile on spec changes
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldTemplate := e.ObjectOld.(*breakglassv1alpha1.DebugPodTemplate)
			newTemplate := e.ObjectNew.(*breakglassv1alpha1.DebugPodTemplate)
			// Only trigger reconcile if generation changed (spec change)
			return oldTemplate.Generation != newTemplate.Generation
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DebugPodTemplate{}).
		WithEventFilter(specChangePredicate).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
