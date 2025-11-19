package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// EscalationReconciler watches BreakglassEscalation CRs and caches escalation→IDP mappings
// to enable efficient authorization checks without querying the APIServer on every request.
//
// Caching Strategy:
// - Maintains an in-memory map: { escalationName: [allowedIDP1, allowedIDP2, ...] }
// - Cache is updated whenever BreakglassEscalation CRs change
// - API calls use the cache to avoid DDoSing the Kubernetes APIServer
// - Cache is thread-safe using RWMutex
//
// Usage:
// - Call GetCachedEscalationIDPMapping() to retrieve the current mapping
// - Called by /api/config/idps endpoint to populate escalationIDPMapping response
type EscalationReconciler struct {
	client   client.Client
	logger   *zap.SugaredLogger
	recorder record.EventRecorder

	// onReload is called when BreakglassEscalation changes are detected
	onReload func(ctx context.Context) error
	// onError is called when reload fails (optional, for metrics/logging)
	onError func(ctx context.Context, err error)
	// resyncPeriod defines the full list reconciliation interval (default 10m)
	resyncPeriod time.Duration

	// Cache for escalation→IDP mapping to avoid APIServer queries
	escalationIDPMappingMutex sync.RWMutex
	escalationIDPMapping      map[string][]string // { escalationName: [idp1, idp2, ...] }
}

// NewEscalationReconciler creates a new EscalationReconciler instance.
func NewEscalationReconciler(
	c client.Client,
	logger *zap.SugaredLogger,
	recorder record.EventRecorder,
	onReload func(ctx context.Context) error,
	onError func(ctx context.Context, err error),
	resyncPeriod time.Duration,
) *EscalationReconciler {
	if resyncPeriod == 0 {
		resyncPeriod = 10 * time.Minute
	}
	return &EscalationReconciler{
		client:               c,
		logger:               logger,
		recorder:             recorder,
		onReload:             onReload,
		onError:              onError,
		resyncPeriod:         resyncPeriod,
		escalationIDPMapping: make(map[string][]string),
	}
}

// Reconcile implements controller-runtime's Reconciler interface.
// Called whenever a BreakglassEscalation CR changes.
func (r *EscalationReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling BreakglassEscalation",
		"name", req.Name,
		"namespace", req.Namespace)

	// Fetch and validate the specific escalation resource
	escalation := &breakglassv1alpha1.BreakglassEscalation{}
	if err := r.client.Get(ctx, req.NamespacedName, escalation); err != nil {
		r.logger.Warnw("Failed to fetch BreakglassEscalation for validation",
			"error", err)
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	// Validate escalation configuration and references
	now := metav1.Now()

	// Track validation errors to report all at once
	var validationErrors []struct {
		conditionType string
		reason        string
		message       string
		error         error
	}

	// Validate config structure
	if configErr := r.validateEscalationConfig(escalation); configErr != nil {
		validationErrors = append(validationErrors, struct {
			conditionType string
			reason        string
			message       string
			error         error
		}{
			conditionType: string(breakglassv1alpha1.BreakglassEscalationConditionConfigValidated),
			reason:        "ConfigValidationFailed",
			message:       configErr.Error(),
			error:         configErr,
		})
	}

	// Validate cluster reference
	if clusterErr := r.validateClusterRef(ctx, escalation); clusterErr != nil {
		validationErrors = append(validationErrors, struct {
			conditionType string
			reason        string
			message       string
			error         error
		}{
			conditionType: string(breakglassv1alpha1.BreakglassEscalationConditionClusterRefsValid),
			reason:        "ClusterRefValidationFailed",
			message:       clusterErr.Error(),
			error:         clusterErr,
		})
	}

	// Validate IDP references
	if idpErr := r.validateIDPRefs(ctx, escalation); idpErr != nil {
		validationErrors = append(validationErrors, struct {
			conditionType string
			reason        string
			message       string
			error         error
		}{
			conditionType: string(breakglassv1alpha1.BreakglassEscalationConditionIDPRefsValid),
			reason:        "IDPRefValidationFailed",
			message:       idpErr.Error(),
			error:         idpErr,
		})
	}

	// Validate deny policy references
	if denyPolicyErr := r.validateDenyPolicyRefs(ctx, escalation); denyPolicyErr != nil {
		validationErrors = append(validationErrors, struct {
			conditionType string
			reason        string
			message       string
			error         error
		}{
			conditionType: string(breakglassv1alpha1.BreakglassEscalationConditionDenyPolicyRefsValid),
			reason:        "DenyPolicyRefValidationFailed",
			message:       denyPolicyErr.Error(),
			error:         denyPolicyErr,
		})
	}

	// Update conditions based on validation results
	if len(validationErrors) > 0 {
		// Set failed conditions
		for _, ve := range validationErrors {
			condition := metav1.Condition{
				Type:               ve.conditionType,
				Status:             metav1.ConditionFalse,
				ObservedGeneration: escalation.Generation,
				Reason:             ve.reason,
				Message:            ve.message,
				LastTransitionTime: now,
			}
			apimeta.SetStatusCondition(&escalation.Status.Conditions, condition)

			if r.recorder != nil {
				r.recorder.Event(escalation, "Warning", ve.reason, ve.message)
			}
			r.logger.Warnw("Escalation validation failed",
				"escalation", escalation.Name,
				"conditionType", ve.conditionType,
				"error", ve.error)
		}

		if err := r.client.Status().Update(ctx, escalation); err != nil {
			r.logger.Warnw("Failed to update escalation status with validation errors",
				"escalation", escalation.Name,
				"error", err)
		}
		return reconcile.Result{}, validationErrors[0].error
	}

	// All validations passed - set all conditions to true
	for _, condType := range []breakglassv1alpha1.BreakglassEscalationConditionType{
		breakglassv1alpha1.BreakglassEscalationConditionConfigValidated,
		breakglassv1alpha1.BreakglassEscalationConditionClusterRefsValid,
		breakglassv1alpha1.BreakglassEscalationConditionIDPRefsValid,
		breakglassv1alpha1.BreakglassEscalationConditionDenyPolicyRefsValid,
	} {
		condition := metav1.Condition{
			Type:               string(condType),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: escalation.Generation,
			Reason:             "ValidationSucceeded",
			Message:            "Validation passed",
			LastTransitionTime: now,
		}
		apimeta.SetStatusCondition(&escalation.Status.Conditions, condition)
	}

	if r.recorder != nil {
		r.recorder.Event(escalation, "Normal", "ValidationSucceeded", "All escalation validations passed successfully")
	}

	if err := r.client.Status().Update(ctx, escalation); err != nil {
		r.logger.Warnw("Failed to update escalation status with success state",
			"escalation", escalation.Name,
			"error", err)
		return reconcile.Result{}, err
	}

	// Update the escalation→IDP mapping cache
	if err := r.updateEscalationIDPMapping(ctx); err != nil {
		r.logger.Errorw("Failed to update escalation→IDP mapping cache",
			"error", err)
		if r.onError != nil {
			r.onError(ctx, err)
		}
		// Requeue with backoff
		return reconcile.Result{RequeueAfter: 1 * time.Second}, err
	}

	// Call optional onReload callback
	if r.onReload != nil {
		if err := r.onReload(ctx); err != nil {
			r.logger.Errorw("onReload callback failed", "error", err)
			if r.onError != nil {
				r.onError(ctx, err)
			}
			return reconcile.Result{RequeueAfter: 1 * time.Second}, err
		}
	}

	r.logger.Debugw("Successfully reconciled BreakglassEscalation",
		"name", req.Name,
		"namespace", req.Namespace)
	return reconcile.Result{}, nil
}

// updateEscalationIDPMapping fetches all BreakglassEscalation CRs and builds the escalation→IDP mapping cache.
func (r *EscalationReconciler) updateEscalationIDPMapping(ctx context.Context) error {
	escalations := &breakglassv1alpha1.BreakglassEscalationList{}
	if err := r.client.List(ctx, escalations); err != nil {
		return fmt.Errorf("failed to list BreakglassEscalation CRs: %w", err)
	}

	// Build the mapping
	newMapping := make(map[string][]string)
	for i := range escalations.Items {
		esc := &escalations.Items[i]
		if len(esc.Spec.AllowedIdentityProviders) > 0 {
			// Copy the slice to avoid external modifications
			idps := make([]string, len(esc.Spec.AllowedIdentityProviders))
			copy(idps, esc.Spec.AllowedIdentityProviders)
			newMapping[esc.Name] = idps
		}
	}

	// Update cache atomically
	r.escalationIDPMappingMutex.Lock()
	r.escalationIDPMapping = newMapping
	r.escalationIDPMappingMutex.Unlock()

	r.logger.Debugw("Updated escalation→IDP mapping cache",
		"escalationCount", len(newMapping),
		"mapping", newMapping)

	return nil
}

// GetCachedEscalationIDPMapping returns a copy of the current escalation→IDP mapping.
// Safe for concurrent access - returns a copy to prevent external modifications.
func (r *EscalationReconciler) GetCachedEscalationIDPMapping() map[string][]string {
	r.escalationIDPMappingMutex.RLock()
	defer r.escalationIDPMappingMutex.RUnlock()

	// Return a copy to prevent external modifications
	result := make(map[string][]string, len(r.escalationIDPMapping))
	for k, v := range r.escalationIDPMapping {
		idps := make([]string, len(v))
		copy(idps, v)
		result[k] = idps
	}
	return result
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *EscalationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Helper function to compare two string slices
	slicesEqual := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// Predicate to filter events - only reconcile on spec changes, not status updates
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldEsc := e.ObjectOld.(*breakglassv1alpha1.BreakglassEscalation)
			newEsc := e.ObjectNew.(*breakglassv1alpha1.BreakglassEscalation)
			// Only trigger reconcile if spec changed
			return !slicesEqual(oldEsc.Spec.AllowedIdentityProviders, newEsc.Spec.AllowedIdentityProviders) ||
				oldEsc.DeletionTimestamp != newEsc.DeletionTimestamp
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.BreakglassEscalation{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1, // Process one escalation at a time
		}).
		WithEventFilter(specChangePredicate).
		Complete(r)
}

// validateEscalationConfig validates the escalation's configuration
func (r *EscalationReconciler) validateEscalationConfig(esc *breakglassv1alpha1.BreakglassEscalation) error {
	// IdentityProviders are optional - escalation will use cluster defaults if not specified
	return nil
}

// validateClusterRef validates that the referenced clusters exist and are accessible
func (r *EscalationReconciler) validateClusterRef(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	// Validate ClusterConfigRefs if specified
	for _, clusterName := range esc.Spec.ClusterConfigRefs {
		clusterKey := client.ObjectKey{Name: clusterName}
		cluster := &breakglassv1alpha1.ClusterConfig{}
		if err := r.client.Get(ctx, clusterKey, cluster); err != nil {
			return fmt.Errorf("referenced ClusterConfig '%s' not found: %w", clusterName, err)
		}
	}
	return nil
}

// validateIDPRefs validates that all referenced IDPs exist
func (r *EscalationReconciler) validateIDPRefs(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	// Helper to validate a list of IDP names
	validateIDPList := func(idpNames []string) error {
		for _, idpName := range idpNames {
			idpKey := client.ObjectKey{Name: idpName}
			idp := &breakglassv1alpha1.IdentityProvider{}
			if err := r.client.Get(ctx, idpKey, idp); err != nil {
				return fmt.Errorf("referenced IdentityProvider '%s' not found: %w", idpName, err)
			}
		}
		return nil
	}

	// Validate all IDP references
	if err := validateIDPList(esc.Spec.AllowedIdentityProviders); err != nil {
		return err
	}
	if err := validateIDPList(esc.Spec.AllowedIdentityProvidersForRequests); err != nil {
		return err
	}
	if err := validateIDPList(esc.Spec.AllowedIdentityProvidersForApprovers); err != nil {
		return err
	}
	return nil
}

// validateDenyPolicyRefs validates deny policy references if they exist
func (r *EscalationReconciler) validateDenyPolicyRefs(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	// Only validate if deny policies are configured
	for _, policyName := range esc.Spec.DenyPolicyRefs {
		policyKey := client.ObjectKey{Name: policyName}
		policy := &breakglassv1alpha1.DenyPolicy{}
		if err := r.client.Get(ctx, policyKey, policy); err != nil {
			return fmt.Errorf("referenced DenyPolicy '%s' not found: %w", policyName, err)
		}
	}
	return nil
}
