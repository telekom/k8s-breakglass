package config

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
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
