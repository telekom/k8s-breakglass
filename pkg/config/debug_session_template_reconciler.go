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

// DebugSessionTemplate condition types
const (
	DebugSessionTemplateConditionReady            = "Ready"
	DebugSessionTemplateConditionPodTemplateValid = "PodTemplateRefValid"
)

// DebugSessionTemplateReconciler watches DebugSessionTemplate CRs and validates their configuration,
// updating status conditions to reflect validation state.
type DebugSessionTemplateReconciler struct {
	client client.Client
	logger *zap.SugaredLogger
}

// NewDebugSessionTemplateReconciler creates a new DebugSessionTemplateReconciler instance.
func NewDebugSessionTemplateReconciler(c client.Client, logger *zap.SugaredLogger) *DebugSessionTemplateReconciler {
	return &DebugSessionTemplateReconciler{
		client: c,
		logger: logger,
	}
}

func (r *DebugSessionTemplateReconciler) applyStatus(ctx context.Context, template *breakglassv1alpha1.DebugSessionTemplate) error {
	return ssa.ApplyDebugSessionTemplateStatus(ctx, r.client, template)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessiontemplates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugpodtemplates,verbs=get

// Reconcile validates the DebugSessionTemplate and updates its status conditions.
func (r *DebugSessionTemplateReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling DebugSessionTemplate", "name", req.Name)

	// Fetch the DebugSessionTemplate
	template := &breakglassv1alpha1.DebugSessionTemplate{}
	if err := r.client.Get(ctx, req.NamespacedName, template); err != nil {
		r.logger.Warnw("Failed to fetch DebugSessionTemplate", "error", err)
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	now := metav1.Now()
	allValid := true

	// Validate the template configuration using the webhook validation
	validationResult := breakglassv1alpha1.ValidateDebugSessionTemplate(template)
	if !validationResult.IsValid() {
		allValid = false
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugSessionTemplateConditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            fmt.Sprintf("Template validation failed: %v", validationResult.Errors),
			LastTransitionTime: now,
		})
	}

	// Validate PodTemplateRef exists if specified
	if template.Spec.PodTemplateRef != nil && template.Spec.PodTemplateRef.Name != "" {
		podTemplate := &breakglassv1alpha1.DebugPodTemplate{}
		if err := r.client.Get(ctx, client.ObjectKey{Name: template.Spec.PodTemplateRef.Name}, podTemplate); err != nil {
			allValid = false
			apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
				Type:               DebugSessionTemplateConditionPodTemplateValid,
				Status:             metav1.ConditionFalse,
				Reason:             "PodTemplateNotFound",
				Message:            fmt.Sprintf("Referenced DebugPodTemplate '%s' not found: %v", template.Spec.PodTemplateRef.Name, err),
				LastTransitionTime: now,
			})
		} else {
			apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
				Type:               DebugSessionTemplateConditionPodTemplateValid,
				Status:             metav1.ConditionTrue,
				Reason:             "PodTemplateFound",
				Message:            fmt.Sprintf("Referenced DebugPodTemplate '%s' exists", template.Spec.PodTemplateRef.Name),
				LastTransitionTime: now,
			})
		}
	} else {
		// No pod template ref - remove the condition if it exists
		apimeta.RemoveStatusCondition(&template.Status.Conditions, DebugSessionTemplateConditionPodTemplateValid)
	}

	// Set Ready condition
	if allValid {
		apimeta.SetStatusCondition(&template.Status.Conditions, metav1.Condition{
			Type:               DebugSessionTemplateConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             "Ready",
			Message:            "Template is valid and ready for use",
			LastTransitionTime: now,
		})
	}

	// Apply status update
	if err := r.applyStatus(ctx, template); err != nil {
		r.logger.Warnw("Failed to update DebugSessionTemplate status",
			"template", template.Name,
			"error", err)
		return reconcile.Result{}, err
	}

	r.logger.Debugw("Successfully reconciled DebugSessionTemplate",
		"name", req.Name,
		"valid", allValid)

	return reconcile.Result{}, nil
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *DebugSessionTemplateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate to filter events - reconcile on spec changes
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldTemplate := e.ObjectOld.(*breakglassv1alpha1.DebugSessionTemplate)
			newTemplate := e.ObjectNew.(*breakglassv1alpha1.DebugSessionTemplate)
			// Only trigger reconcile if generation changed (spec change)
			return oldTemplate.Generation != newTemplate.Generation
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DebugSessionTemplate{}).
		WithEventFilter(specChangePredicate).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
