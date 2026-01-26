package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// IdentityProviderReconciler implements controller-runtime's Reconciler interface
// to watch IdentityProvider CRs and reload configuration when changes are detected.
// This is the proper Kubernetes controller pattern and avoids polling loops.
//
// Benefits:
// - Event-driven: Only reconciles when IdentityProvider CRs change
// - Backoff strategy: Exponential backoff on errors (controller-runtime built-in)
// - No thundering herd: Uses work queue to deduplicate rapid changes
// - Finalization ready: Supports cleanup logic if needed
//
// Caching:
// - Maintains an in-memory cache of enabled IdentityProviders
// - Cache is updated whenever IdentityProvider CRs change
// - API calls use the cache to avoid DDoSing the Kubernetes APIServer
// - Cache is thread-safe using RWMutex
type IdentityProviderReconciler struct {
	client   client.Client
	logger   *zap.SugaredLogger
	recorder record.EventRecorder

	// onReload is called when IdentityProvider changes are detected
	onReload func(ctx context.Context) error
	// onError is called when reload fails (optional, for metrics/logging)
	onError func(ctx context.Context, err error)
	// resyncPeriod defines the full list reconciliation interval (default 10m)
	resyncPeriod time.Duration

	// Cache for enabled IdentityProviders to avoid APIServer queries
	// Protected by cacheMutex for thread-safe access
	idpCacheMutex sync.RWMutex
	idpCache      []*breakglassv1alpha1.IdentityProvider
}

// NewIdentityProviderReconciler creates a new controller-runtime reconciler for IdentityProvider
func NewIdentityProviderReconciler(
	kubeClient client.Client,
	logger *zap.SugaredLogger,
	reloadFn func(ctx context.Context) error,
) *IdentityProviderReconciler {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &IdentityProviderReconciler{
		client:       kubeClient,
		logger:       logger,
		onReload:     reloadFn,
		resyncPeriod: 10 * time.Minute, // Full list resync every 10 minutes
		idpCache:     []*breakglassv1alpha1.IdentityProvider{},
	}
}

// GetCachedIdentityProviders returns the cached list of enabled IdentityProviders
// This is used by the API to avoid querying the Kubernetes APIServer on every request
// The cache is automatically maintained by the reconciler when IdentityProviders change
func (r *IdentityProviderReconciler) GetCachedIdentityProviders() []*breakglassv1alpha1.IdentityProvider {
	r.idpCacheMutex.RLock()
	defer r.idpCacheMutex.RUnlock()
	// Return a copy to prevent external modifications
	result := make([]*breakglassv1alpha1.IdentityProvider, len(r.idpCache))
	copy(result, r.idpCache)
	return result
}

// updateIDPCache updates the cached list of identity providers
// Called during reconciliation when changes are detected
func (r *IdentityProviderReconciler) updateIDPCache(ctx context.Context) error {
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := r.client.List(ctx, idpList); err != nil {
		r.logger.Errorw("failed to list identity providers for cache update", "error", err)
		return err
	}

	// Filter to only enabled providers
	var enabledIDPs []*breakglassv1alpha1.IdentityProvider
	for i := range idpList.Items {
		if !idpList.Items[i].Spec.Disabled {
			enabledIDPs = append(enabledIDPs, &idpList.Items[i])
		}
	}

	// Update cache atomically
	r.idpCacheMutex.Lock()
	r.idpCache = enabledIDPs
	r.idpCacheMutex.Unlock()

	r.logger.Debugw("updated identity provider cache", "count", len(enabledIDPs))
	return nil
}

// WithErrorHandler sets the error callback function
func (r *IdentityProviderReconciler) WithErrorHandler(fn func(ctx context.Context, err error)) *IdentityProviderReconciler {
	r.onError = fn
	return r
}

// WithEventRecorder sets the event recorder for emitting Kubernetes events
func (r *IdentityProviderReconciler) WithEventRecorder(recorder record.EventRecorder) *IdentityProviderReconciler {
	r.recorder = recorder
	return r
}

// WithResyncPeriod sets the resync period for full list reconciliation
func (r *IdentityProviderReconciler) WithResyncPeriod(period time.Duration) *IdentityProviderReconciler {
	r.resyncPeriod = period
	return r
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=identityproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=identityproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=identityproviders/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile implements the Reconciler interface
// It reloads the IdentityProvider configuration when changes are detected
func (r *IdentityProviderReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("reconciling identity provider", "name", req.Name, "namespace", req.Namespace)

	// Load the IdentityProvider to verify it still exists
	idp := &breakglassv1alpha1.IdentityProvider{}
	if err := r.client.Get(ctx, req.NamespacedName, idp); err != nil {
		// Object not found - this is fine, we can ignore it
		// (controller-runtime handles deletion automatically)
		if client.IgnoreNotFound(err) == nil {
			r.logger.Infow("identity provider deleted", "name", req.Name)
			return reconcile.Result{}, nil
		}
		r.logger.Errorw("failed to fetch identity provider", "error", err, "name", req.Name)
		if r.onError != nil {
			r.onError(ctx, err)
		}
		// Return error to trigger controller-runtime's exponential backoff
		return reconcile.Result{}, err
	}

	// Perform structural validation using shared validation function.
	// This catches malformed resources that somehow bypassed the admission webhook.
	validationResult := breakglassv1alpha1.ValidateIdentityProvider(idp)
	if !validationResult.IsValid() {
		r.logger.Warnw("IdentityProvider failed structural validation, skipping reconciliation",
			"name", req.Name,
			"errors", validationResult.ErrorMessage())

		// Update status condition to reflect validation failure
		condition := metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionReady),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "ValidationFailed",
			Message:            fmt.Sprintf("Resource validation failed: %s", validationResult.ErrorMessage()),
		}
		idp.SetCondition(condition)
		idp.Status.ObservedGeneration = idp.Generation

		if statusErr := r.client.Status().Update(ctx, idp); statusErr != nil {
			r.logger.Errorw("failed to update identity provider status after validation failure", "error", statusErr, "name", req.Name)
		}

		// Emit event for validation failure
		if r.recorder != nil {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "ValidationFailed",
				fmt.Sprintf("Resource validation failed: %s", validationResult.ErrorMessage()))
		}

		if r.onError != nil {
			r.onError(ctx, validationResult.AsError())
		}

		// Return nil error to skip requeue - malformed resource won't fix itself
		// User must update the resource to fix validation errors
		return reconcile.Result{}, nil
	}

	// Note: We no longer skip based on recent status updates because each controller replica
	// needs to reload its own local config (onReload updates in-memory state).
	// Status update skipping is handled separately after the work is done.

	// Reload configuration when IdentityProvider changes
	if err := r.onReload(ctx); err != nil {
		r.logger.Errorw("failed to reload identity provider", "error", err, "name", req.Name)
		if r.onError != nil {
			r.onError(ctx, err)
		}

		// Update status to reflect error state via conditions
		condition := metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionReady),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "ConfigReloadFailed",
			Message:            fmt.Sprintf("Failed to reload configuration: %v", err),
		}
		idp.SetCondition(condition)
		idp.Status.ObservedGeneration = idp.Generation

		if statusErr := r.client.Status().Update(ctx, idp); statusErr != nil {
			r.logger.Errorw("failed to update identity provider status after reload failure", "error", statusErr, "name", req.Name)
		}

		// Update cache anyway - even if reload failed, we should still have the latest list
		if cacheErr := r.updateIDPCache(ctx); cacheErr != nil {
			r.logger.Warnw("failed to update IDP cache after reload failure", "error", cacheErr, "name", req.Name)
			// Update condition with cache error
			cacheCondition := metav1.Condition{
				Type:               string(breakglassv1alpha1.IdentityProviderConditionReady),
				Status:             metav1.ConditionFalse,
				ObservedGeneration: idp.Generation,
				LastTransitionTime: metav1.Now(),
				Reason:             "CacheUpdateFailed",
				Message:            fmt.Sprintf("Failed to update provider cache: %v", cacheErr),
			}
			idp.SetCondition(cacheCondition)
			if cacheStatusErr := r.client.Status().Update(ctx, idp); cacheStatusErr != nil {
				r.logger.Errorw("failed to update IDP cache error status", "error", cacheStatusErr, "name", req.Name)
			}
		}

		// Emit events for each failure type
		if r.recorder != nil {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "ConfigReloadFailed",
				fmt.Sprintf("Failed to reload configuration: %v", err))
		}

		// Return error to trigger controller-runtime's exponential backoff
		return reconcile.Result{}, err
	}

	r.logger.Infow("identity provider configuration reloaded successfully", "name", req.Name)

	// Set Ready condition to True on successful reload
	readyCondition := metav1.Condition{
		Type:               string(breakglassv1alpha1.IdentityProviderConditionReady),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: idp.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "ConfigReloadSuccess",
		Message:            "Identity provider configuration loaded successfully",
	}
	idp.SetCondition(readyCondition)
	idp.Status.ObservedGeneration = idp.Generation

	// Update cache with latest IDPs (for API to use)
	if err := r.updateIDPCache(ctx); err != nil {
		r.logger.Warnw("failed to update IDP cache after successful reload", "error", err, "name", req.Name)
		// Expose cache failure even on successful config reload via condition
		cacheCondition := metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionCacheUpdated),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "CacheUpdateFailed",
			Message:            fmt.Sprintf("Failed to update provider cache: %v", err),
		}
		idp.SetCondition(cacheCondition)
		idp.Status.ObservedGeneration = idp.Generation

		// Try to persist this cache error in status
		if cacheStatusErr := r.client.Status().Update(ctx, idp); cacheStatusErr != nil {
			r.logger.Errorw("failed to update IDP cache error status", "error", cacheStatusErr, "name", req.Name)
		}

		// Emit event for cache failure
		if r.recorder != nil {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "CacheUpdateFailed",
				fmt.Sprintf("Failed to update provider cache: %v", err))
		}
	} else {
		// Cache update successful - update condition
		readyCondition := metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionCacheUpdated),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "CacheUpdated",
			Message:            "Provider cache updated successfully",
		}
		idp.SetCondition(readyCondition)
		idp.Status.ObservedGeneration = idp.Generation
	}

	// Check group sync provider health if configured
	r.updateGroupSyncHealth(ctx, idp)

	// Re-fetch to get the latest status before checking if we should skip
	var latest breakglassv1alpha1.IdentityProvider
	if err := r.client.Get(ctx, req.NamespacedName, &latest); err != nil {
		if apierrors.IsNotFound(err) {
			r.logger.Debugw("IdentityProvider deleted before status update, skipping", "name", req.Name)
			return reconcile.Result{}, nil
		}
		r.logger.Errorw("Failed to re-fetch IdentityProvider for status update", "name", req.Name, "error", err)
		return reconcile.Result{}, err
	}

	// Use StatusCoordinator to check if we should skip the status update
	// This prevents multiple controller replicas from fighting over status updates
	coordinator := utils.NewStatusCoordinator()
	skipInfo := coordinator.ShouldSkipStatusUpdateDetailed(
		latest.Status.Conditions,
		string(breakglassv1alpha1.IdentityProviderConditionReady),
		metav1.ConditionTrue,
		"ConfigReloadSuccess",
	)
	if skipInfo.Skipped {
		r.logger.Debugw("IdentityProvider status recently updated, skipping status update",
			"name", req.Name,
			"skipReason", skipInfo.Reason,
			"lastUpdateAge", skipInfo.LastUpdateAge,
		)
		if r.recorder != nil {
			eventIdp := latest.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, corev1.EventTypeNormal, "StatusUpdateSkipped",
				fmt.Sprintf("Skipped status update: %s (last update %v ago)", skipInfo.Reason, skipInfo.LastUpdateAge.Truncate(time.Second)))
		}
		return reconcile.Result{RequeueAfter: r.resyncPeriod}, nil
	}

	// Merge our prepared conditions onto the latest version
	// This preserves any updates from other controllers while applying our changes
	for _, condition := range idp.Status.Conditions {
		latest.SetCondition(condition)
	}
	latest.Status.ObservedGeneration = idp.Status.ObservedGeneration

	// Persist status to API server
	if err := r.client.Status().Update(ctx, &latest); err != nil {
		// If the IdentityProvider was deleted, skip status update and event emission
		if apierrors.IsNotFound(err) {
			r.logger.Debugw("IdentityProvider deleted before status update, skipping", "name", req.Name)
			return reconcile.Result{}, nil
		}
		// Handle conflict - another controller likely updated it recently
		if apierrors.IsConflict(err) {
			r.logger.Debugw("Conflict updating IdentityProvider status, another controller likely handled it", "name", req.Name)
			// Requeue after a short delay to avoid tight loops
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
		// Status update failed - mark as error via condition since status persistence is critical
		r.logger.Errorw("failed to update IdentityProvider status after successful reload (will retry)", "error", err, "name", req.Name)
		errorCondition := metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionReady),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: latest.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "StatusUpdateFailed",
			Message:            fmt.Sprintf("Failed to persist status: %v", err),
		}
		latest.SetCondition(errorCondition)

		if statusErr := r.client.Status().Update(ctx, &latest); statusErr != nil {
			// If deleted during retry, skip silently
			if apierrors.IsNotFound(statusErr) {
				return reconcile.Result{}, nil
			}
			// If conflict on retry, another controller handled it
			if apierrors.IsConflict(statusErr) {
				r.logger.Debugw("Conflict on status update retry, another controller likely handled it", "name", req.Name)
				return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
			}
			r.logger.Errorw("failed to update error status on IdentityProvider (will retry via exponential backoff)", "error", statusErr, "name", req.Name)
		}
		// Emit warning event about status update failure
		if r.recorder != nil {
			eventIdp := latest.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "StatusUpdateFailed",
				fmt.Sprintf("Failed to persist status after successful reload: %v", err))
		}
		// Return error to trigger controller-runtime's exponential backoff
		return reconcile.Result{}, err
	}

	// Emit event on the IdentityProvider CR
	// Note: Empty namespace for cluster-scoped resources to prevent event reconciliation issues
	if r.recorder != nil {
		eventIdp := latest.DeepCopy()
		eventIdp.SetNamespace("")
		r.recorder.Event(eventIdp, "Normal", "ConfigReloadSuccess",
			"Configuration reloaded successfully and cached")
	}

	// Requeue periodically for safety (even if no changes detected)
	// This ensures we recover from transient failures
	return reconcile.Result{RequeueAfter: r.resyncPeriod}, nil
}

// updateGroupSyncHealth checks the health of the group sync provider (if configured)
// and updates the conditions accordingly. It also emits events on health status changes.
func (r *IdentityProviderReconciler) updateGroupSyncHealth(ctx context.Context, idp *breakglassv1alpha1.IdentityProvider) {
	// Get current GroupSyncHealthy condition to detect changes
	oldCondition := idp.GetCondition(string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy))

	if idp.Spec.GroupSyncProvider == "" {
		// GroupSync not configured - remove condition if it exists
		if oldCondition != nil {
			newConditions := make([]metav1.Condition, 0)
			for _, c := range idp.Status.Conditions {
				if c.Type != string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy) {
					newConditions = append(newConditions, c)
				}
			}
			idp.Status.Conditions = newConditions
		}
		return
	}

	if idp.Spec.GroupSyncProvider != breakglassv1alpha1.GroupSyncProviderKeycloak {
		// Unknown provider
		idp.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "UnknownProvider",
			Message:            fmt.Sprintf("Unknown group sync provider: %s", idp.Spec.GroupSyncProvider),
		})
		// Emit event for unknown provider
		if r.recorder != nil && (oldCondition == nil || oldCondition.Status == metav1.ConditionTrue) {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "GroupSyncUnknownProvider",
				fmt.Sprintf("Unknown group sync provider: %s", idp.Spec.GroupSyncProvider))
		}
		return
	}

	// Check Keycloak configuration
	if idp.Spec.Keycloak == nil {
		idp.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "KeycloakMissing",
			Message:            "Keycloak configuration is required when groupSyncProvider is Keycloak",
		})
		// Emit event for missing Keycloak config
		if r.recorder != nil && (oldCondition == nil || oldCondition.Status == metav1.ConditionTrue) {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "GroupSyncKeycloakMissing",
				"Keycloak configuration is required when groupSyncProvider is Keycloak")
		}
		return
	}

	// Check for incomplete Keycloak configuration
	if idp.Spec.Keycloak.BaseURL == "" || idp.Spec.Keycloak.Realm == "" || idp.Spec.Keycloak.ClientID == "" {
		idp.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "KeycloakIncomplete",
			Message:            "Keycloak configuration incomplete: missing baseURL, realm, or clientID",
		})
		// Emit event for incomplete config
		if r.recorder != nil && (oldCondition == nil || oldCondition.Status == metav1.ConditionTrue) {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "GroupSyncKeycloakConfigIncomplete",
				"Keycloak configuration incomplete: missing baseURL, realm, or clientID")
		}
		return
	}

	// Check Keycloak client secret reference
	if idp.Spec.Keycloak.ClientSecretRef.Name == "" || idp.Spec.Keycloak.ClientSecretRef.Namespace == "" {
		idp.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "ClientSecretRefInvalid",
			Message:            "Keycloak configuration incomplete: missing clientSecretRef name or namespace",
		})
		// Emit event for missing client secret ref
		if r.recorder != nil && (oldCondition == nil || oldCondition.Status == metav1.ConditionTrue) {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "GroupSyncClientSecretRefMissing",
				"Keycloak configuration incomplete: missing clientSecretRef name or namespace")
		}
		return
	}

	// Verify the client secret exists and is readable
	secretRef := idp.Spec.Keycloak.ClientSecretRef
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{
		Namespace: secretRef.Namespace,
		Name:      secretRef.Name,
	}

	if err := r.client.Get(ctx, secretKey, secret); err != nil {
		idp.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "SecretNotFound",
			Message: fmt.Sprintf("Failed to read client secret '%s' in namespace '%s': %v",
				secretRef.Name, secretRef.Namespace, err),
		})

		// Emit warning event for secret retrieval failure
		if r.recorder != nil && (oldCondition == nil || oldCondition.Status == metav1.ConditionTrue) {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "GroupSyncSecretNotFound",
				fmt.Sprintf("Failed to read Keycloak client secret '%s' in namespace '%s': %v",
					secretRef.Name, secretRef.Namespace, err))
		}
		return
	}

	// Check if the secret has the client secret key
	secretDataKey := secretRef.Key
	if secretDataKey == "" {
		secretDataKey = "value" // Default key if not specified
	}
	if _, exists := secret.Data[secretDataKey]; !exists {
		idp.SetCondition(metav1.Condition{
			Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "SecretKeyNotFound",
			Message: fmt.Sprintf("Keycloak client secret key '%s' not found in secret '%s'",
				secretDataKey, secretRef.Name),
		})

		// Emit warning event for missing secret key
		if r.recorder != nil && (oldCondition == nil || oldCondition.Status == metav1.ConditionTrue) {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Warning", "GroupSyncSecretKeyMissing",
				fmt.Sprintf("Keycloak client secret key '%s' not found in secret '%s'",
					secretDataKey, secretRef.Name))
		}
		return
	}

	// All checks passed - mark as healthy
	idp.SetCondition(metav1.Condition{
		Type:               string(breakglassv1alpha1.IdentityProviderConditionGroupSyncHealthy),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: idp.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "GroupSyncOperational",
		Message:            "Group sync provider is operational",
	})

	// Emit event if health status changed from unhealthy to healthy
	if oldCondition != nil && oldCondition.Status == metav1.ConditionFalse {
		if r.recorder != nil {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("")
			r.recorder.Event(eventIdp, "Normal", "GroupSyncHealthy",
				"Group sync provider is now healthy and reachable")
		}
		r.logger.Infow("group sync provider recovered to healthy state",
			"name", idp.Name, "provider", idp.Spec.GroupSyncProvider)
	}

	r.logger.Debugw("group sync provider health check passed", "name", idp.Name, "provider", idp.Spec.GroupSyncProvider)
}

// SetupWithManager sets up the controller with the manager (required for controller-runtime)
// This is called during manager initialization and registers the reconciler
func (r *IdentityProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.logger.Infow("setting up IdentityProvider reconciler",
		"resyncPeriod", r.resyncPeriod,
		"kind", "IdentityProvider")

	// Use predicate to filter events we care about
	// We only care about spec changes, not metadata updates
	specChangedPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldIDP, okOld := e.ObjectOld.(*breakglassv1alpha1.IdentityProvider)
			newIDP, okNew := e.ObjectNew.(*breakglassv1alpha1.IdentityProvider)

			if !okOld || !okNew {
				return false
			}

			// Reload if spec changed (ignore status and metadata-only changes)
			specChanged := oldIDP.Spec != newIDP.Spec

			if specChanged {
				r.logger.Debugw("IdentityProvider spec changed",
					"name", newIDP.Name,
					"oldGen", oldIDP.Generation,
					"newGen", newIDP.Generation)
				return true
			}

			return false
		},
		CreateFunc: func(e event.CreateEvent) bool {
			r.logger.Debugw("IdentityProvider created", "name", e.Object.GetName())
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			r.logger.Debugw("IdentityProvider deleted", "name", e.Object.GetName())
			return true
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.IdentityProvider{}).
		WithEventFilter(specChangedPredicate).
		WithOptions(controller.Options{
			// Use 1 worker by default - IDP changes are infrequent
			MaxConcurrentReconciles: 1,
		}).
		Complete(r)
}

// IdentityProviderSelector returns a NamespacedName for a specific IdentityProvider
// Useful for manual reconciliation requests
func IdentityProviderSelector(name string) types.NamespacedName {
	return types.NamespacedName{
		Name:      name,
		Namespace: "", // IdentityProvider is cluster-scoped
	}
}
