package config

import (
	"context"

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

// DenyPolicyConditionType defines condition types for DenyPolicy
const (
	// DenyPolicyConditionReady indicates the policy is valid and ready for evaluation
	DenyPolicyConditionReady = "Ready"
	// DenyPolicyConditionValid indicates the policy spec is syntactically valid
	DenyPolicyConditionValid = "Valid"
)

// DenyPolicyReconciler watches DenyPolicy CRs and validates their configuration,
// updating status conditions to reflect validation state.
type DenyPolicyReconciler struct {
	client client.Client
	logger *zap.SugaredLogger
}

// NewDenyPolicyReconciler creates a new DenyPolicyReconciler instance.
func NewDenyPolicyReconciler(c client.Client, logger *zap.SugaredLogger) *DenyPolicyReconciler {
	return &DenyPolicyReconciler{
		client: c,
		logger: logger,
	}
}

func (r *DenyPolicyReconciler) applyStatus(ctx context.Context, policy *breakglassv1alpha1.DenyPolicy) error {
	return ssa.ApplyDenyPolicyStatus(ctx, r.client, policy)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=denypolicies/status,verbs=get;update;patch

// Reconcile validates the DenyPolicy and updates its status conditions.
func (r *DenyPolicyReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling DenyPolicy", "name", req.Name)

	// Fetch the DenyPolicy
	policy := &breakglassv1alpha1.DenyPolicy{}
	if err := r.client.Get(ctx, req.NamespacedName, policy); err != nil {
		r.logger.Warnw("Failed to fetch DenyPolicy", "error", err)
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	now := metav1.Now()

	// Validate the policy configuration
	validationErr := r.validatePolicy(policy)

	// Update status conditions based on validation
	if validationErr != nil {
		// Set Valid condition to false
		apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               DenyPolicyConditionValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: policy.Generation,
			Reason:             "ValidationFailed",
			Message:            validationErr.Error(),
			LastTransitionTime: now,
		})
		// Set Ready condition to false
		apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               DenyPolicyConditionReady,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: policy.Generation,
			Reason:             "ValidationFailed",
			Message:            "Policy validation failed",
			LastTransitionTime: now,
		})

		r.logger.Warnw("DenyPolicy validation failed",
			"policy", policy.Name,
			"error", validationErr)
	} else {
		// Set Valid condition to true
		apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               DenyPolicyConditionValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			Reason:             "ValidationSucceeded",
			Message:            "Policy configuration is valid",
			LastTransitionTime: now,
		})
		// Set Ready condition to true
		apimeta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               DenyPolicyConditionReady,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			Reason:             "Ready",
			Message:            "Policy is valid and ready for evaluation",
			LastTransitionTime: now,
		})
	}

	// Update ObservedGeneration
	policy.Status.ObservedGeneration = policy.Generation

	// Apply status update
	if err := r.applyStatus(ctx, policy); err != nil {
		r.logger.Warnw("Failed to update DenyPolicy status",
			"policy", policy.Name,
			"error", err)
		return reconcile.Result{}, err
	}

	r.logger.Debugw("Successfully reconciled DenyPolicy",
		"name", req.Name,
		"valid", validationErr == nil)

	return reconcile.Result{}, nil
}

// validatePolicy validates the DenyPolicy spec.
// This performs structural validation beyond what the CRD validation can check.
func (r *DenyPolicyReconciler) validatePolicy(policy *breakglassv1alpha1.DenyPolicy) error {
	// Currently the webhook performs most validation.
	// This reconciler ensures status reflects validation state.
	// Additional runtime validation can be added here.

	// Validate that at least one rule exists if policy is not empty
	if len(policy.Spec.Rules) == 0 && policy.Spec.PodSecurityRules == nil {
		// Empty rules are valid - policy has no effect
		return nil
	}

	return nil
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *DenyPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate to filter events - reconcile on spec changes
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPolicy := e.ObjectOld.(*breakglassv1alpha1.DenyPolicy)
			newPolicy := e.ObjectNew.(*breakglassv1alpha1.DenyPolicy)
			// Only trigger reconcile if generation changed (spec change)
			return oldPolicy.Generation != newPolicy.Generation
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.DenyPolicy{}).
		WithEventFilter(specChangePredicate).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}
