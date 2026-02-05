package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
)

// EscalationReconciler watches BreakglassEscalation CRs and validates their configuration.
//
// Data Access:
// - Uses controller-runtime's informer-based cache for reads (automatic sync)
// - GetEscalationIDPMapping() computes the mapping from the controller-runtime cache directly
// - No need for manual TTL-based caching - informers are event-driven and always up-to-date
//
// Usage:
// - Call GetEscalationIDPMapping(ctx) to retrieve the current mapping
// - Called by /api/config/idps endpoint to populate escalationIDPMapping response
type EscalationReconciler struct {
	client   client.Client
	logger   *zap.SugaredLogger
	recorder events.EventRecorder

	// onReload is called when BreakglassEscalation changes are detected
	onReload func(ctx context.Context) error
	// onError is called when reload fails (optional, for metrics/logging)
	onError func(ctx context.Context, err error)
	// resyncPeriod defines the full list reconciliation interval (default 10m)
	resyncPeriod time.Duration
}

func (r *EscalationReconciler) applyStatus(ctx context.Context, escalation *breakglassv1alpha1.BreakglassEscalation) error {
	return ssa.ApplyBreakglassEscalationStatus(ctx, r.client, escalation)
}

// NewEscalationReconciler creates a new EscalationReconciler instance.
func NewEscalationReconciler(
	c client.Client,
	logger *zap.SugaredLogger,
	recorder events.EventRecorder,
	onReload func(ctx context.Context) error,
	onError func(ctx context.Context, err error),
	resyncPeriod time.Duration,
) *EscalationReconciler {
	if resyncPeriod == 0 {
		resyncPeriod = 10 * time.Minute
	}
	return &EscalationReconciler{
		client:       c,
		logger:       logger,
		recorder:     recorder,
		onReload:     onReload,
		onError:      onError,
		resyncPeriod: resyncPeriod,
	}
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglassescalations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglassescalations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglassescalations/finalizers,verbs=update
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs/status,verbs=get
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=denypolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

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
		if apierrors.IsNotFound(err) {
			// Resource deleted - call onReload to refresh any dependent state
			if r.onReload != nil {
				_ = r.onReload(ctx)
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
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

	// Validate mail provider references
	if mailProviderErr := r.validateMailProviderRef(ctx, escalation); mailProviderErr != nil {
		validationErrors = append(validationErrors, struct {
			conditionType string
			reason        string
			message       string
			error         error
		}{
			conditionType: string(breakglassv1alpha1.BreakglassEscalationConditionMailProviderValid),
			reason:        "MailProviderValidationFailed",
			message:       mailProviderErr.Error(),
			error:         mailProviderErr,
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
				r.recorder.Eventf(escalation, nil, "Warning", ve.reason, ve.reason, "%s", ve.message)
			}
			r.logger.Warnw("Escalation validation failed",
				"escalation", escalation.Name,
				"conditionType", ve.conditionType,
				"error", ve.error)
		}

		// Update ObservedGeneration before applying status
		escalation.Status.ObservedGeneration = escalation.Generation
		if err := r.applyStatus(ctx, escalation); err != nil {
			r.logger.Warnw("Failed to update escalation status with validation errors",
				"escalation", escalation.Name,
				"error", err)
		}
		// Validation errors are persisted to status; avoid requeue storms for invalid resources.
		return reconcile.Result{}, nil
	}

	// All validations passed - set all conditions to true
	for _, condType := range []breakglassv1alpha1.BreakglassEscalationConditionType{
		breakglassv1alpha1.BreakglassEscalationConditionConfigValidated,
		breakglassv1alpha1.BreakglassEscalationConditionClusterRefsValid,
		breakglassv1alpha1.BreakglassEscalationConditionIDPRefsValid,
		breakglassv1alpha1.BreakglassEscalationConditionDenyPolicyRefsValid,
		breakglassv1alpha1.BreakglassEscalationConditionMailProviderValid,
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
		r.recorder.Eventf(escalation, nil, "Normal", "ValidationSucceeded", "ValidationSucceeded", "All escalation validations passed successfully")
	}

	// Update ObservedGeneration before applying status
	escalation.Status.ObservedGeneration = escalation.Generation
	if err := r.applyStatus(ctx, escalation); err != nil {
		r.logger.Warnw("Failed to update escalation status with success state",
			"escalation", escalation.Name,
			"error", err)
		return reconcile.Result{}, err
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

// GetEscalationIDPMapping returns the escalation→IDP mapping computed from the current state.
// This queries the controller-runtime informer cache directly (no APIServer call).
// The informer cache is automatically synced via watch events, so data is always up-to-date.
func (r *EscalationReconciler) GetEscalationIDPMapping(ctx context.Context) (map[string][]string, error) {
	if r.client == nil {
		return map[string][]string{}, nil
	}

	escalationList := &breakglassv1alpha1.BreakglassEscalationList{}
	if err := r.client.List(ctx, escalationList); err != nil {
		r.logger.Errorw("failed to list escalations for IDP mapping", "error", err)
		return nil, err
	}

	// Build the mapping from escalation name to allowed IDPs
	result := make(map[string][]string)
	for _, escalation := range escalationList.Items {
		if len(escalation.Spec.AllowedIdentityProviders) > 0 {
			idps := make([]string, len(escalation.Spec.AllowedIdentityProviders))
			copy(idps, escalation.Spec.AllowedIdentityProviders)
			result[escalation.Name] = idps
		}
	}

	return result, nil
}

// GetCachedEscalationIDPMapping returns the escalation→IDP mapping.
// Deprecated: Use GetEscalationIDPMapping(ctx) instead. This method exists for backward compatibility.
// It creates a background context internally which is not ideal for tracing/cancellation.
func (r *EscalationReconciler) GetCachedEscalationIDPMapping() map[string][]string {
	if r.logger == nil {
		// Handle case where reconciler was not properly initialized
		return map[string][]string{}
	}
	ctx := context.Background()
	mapping, err := r.GetEscalationIDPMapping(ctx)
	if err != nil {
		r.logger.Errorw("failed to get escalation IDP mapping", "error", err)
		return map[string][]string{}
	}
	return mapping
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

// validateEscalationConfig validates the escalation's configuration structure.
// Uses the shared validation function from api/v1alpha1/validation.go to ensure
// consistent validation between webhooks and reconcilers.
// This catches malformed resources that somehow bypassed the admission webhook.
func (r *EscalationReconciler) validateEscalationConfig(esc *breakglassv1alpha1.BreakglassEscalation) error {
	result := breakglassv1alpha1.ValidateBreakglassEscalation(esc)
	if !result.IsValid() {
		r.logger.Warnw("BreakglassEscalation failed structural validation",
			"name", esc.Name,
			"errors", result.ErrorMessage())
		return result.AsError()
	}
	return nil
}

// validateClusterRef validates that the referenced clusters exist and are accessible
func (r *EscalationReconciler) validateClusterRef(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	if len(esc.Spec.ClusterConfigRefs) == 0 {
		return nil
	}

	var missing []string
	for _, clusterName := range esc.Spec.ClusterConfigRefs {
		name := strings.TrimSpace(clusterName)
		if name == "" {
			continue
		}

		clusterKey := client.ObjectKey{Namespace: esc.Namespace, Name: name}
		cluster := &breakglassv1alpha1.ClusterConfig{}
		if err := r.client.Get(ctx, clusterKey, cluster); err != nil {
			if apierrors.IsNotFound(err) {
				missing = append(missing, fmt.Sprintf("%s/%s", esc.Namespace, name))
				continue
			}
			return fmt.Errorf("failed to fetch ClusterConfig %s/%s: %w", esc.Namespace, name, err)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("ClusterConfigRefs not found: %s", strings.Join(missing, ", "))
	}

	return nil
}

// validateIDPRefs validates that all referenced IDPs exist
func (r *EscalationReconciler) validateIDPRefs(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	checkLists := [][]string{
		esc.Spec.AllowedIdentityProviders,
		esc.Spec.AllowedIdentityProvidersForRequests,
		esc.Spec.AllowedIdentityProvidersForApprovers,
	}

	var missing []string
	var disabled []string
	for _, refs := range checkLists {
		for _, idpName := range refs {
			name := strings.TrimSpace(idpName)
			if name == "" {
				continue
			}

			idpKey := client.ObjectKey{Name: name}
			idp := &breakglassv1alpha1.IdentityProvider{}
			if err := r.client.Get(ctx, idpKey, idp); err != nil {
				if apierrors.IsNotFound(err) {
					missing = append(missing, name)
					continue
				}
				return fmt.Errorf("failed to fetch IdentityProvider %q: %w", name, err)
			}
			if idp.Spec.Disabled {
				disabled = append(disabled, name)
			}
		}
	}

	switch {
	case len(missing) > 0 && len(disabled) > 0:
		return fmt.Errorf("IdentityProvider refs invalid: missing [%s]; disabled [%s]", strings.Join(missing, ", "), strings.Join(disabled, ", "))
	case len(missing) > 0:
		return fmt.Errorf("IdentityProvider refs not found: %s", strings.Join(missing, ", "))
	case len(disabled) > 0:
		return fmt.Errorf("IdentityProvider refs disabled: %s", strings.Join(disabled, ", "))
	default:
		return nil
	}
}

// validateDenyPolicyRefs validates deny policy references if they exist
func (r *EscalationReconciler) validateDenyPolicyRefs(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	if len(esc.Spec.DenyPolicyRefs) == 0 {
		return nil
	}

	var missing []string
	for _, policyName := range esc.Spec.DenyPolicyRefs {
		name := strings.TrimSpace(policyName)
		if name == "" {
			continue
		}

		policyKey := client.ObjectKey{Name: name}
		policy := &breakglassv1alpha1.DenyPolicy{}
		if err := r.client.Get(ctx, policyKey, policy); err != nil {
			if apierrors.IsNotFound(err) {
				missing = append(missing, name)
				continue
			}
			return fmt.Errorf("failed to fetch DenyPolicy %q: %w", name, err)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("DenyPolicy refs not found: %s", strings.Join(missing, ", "))
	}

	return nil
}

// validateMailProviderRef validates that the referenced MailProvider exists and is enabled (if one is specified)
func (r *EscalationReconciler) validateMailProviderRef(ctx context.Context, esc *breakglassv1alpha1.BreakglassEscalation) error {
	name := strings.TrimSpace(esc.Spec.MailProvider)
	if name == "" {
		return nil
	}

	provider := &breakglassv1alpha1.MailProvider{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: name}, provider); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("MailProvider %q not found", name)
		}
		return fmt.Errorf("failed to fetch MailProvider %q: %w", name, err)
	}

	if provider.Spec.Disabled {
		return fmt.Errorf("MailProvider %q is disabled", name)
	}

	return nil
}
