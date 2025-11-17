package config

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
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
	}
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
		// Requeue with exponential backoff (handled by controller-runtime)
		return reconcile.Result{RequeueAfter: 30 * time.Second}, err
	}

	// Reload configuration when IdentityProvider changes
	if err := r.onReload(ctx); err != nil {
		r.logger.Errorw("failed to reload identity provider", "error", err, "name", req.Name)
		if r.onError != nil {
			r.onError(ctx, err)
		}

		// Update status to reflect error state
		idp.Status.Phase = "Error"
		idp.Status.Message = fmt.Sprintf("Failed to reload configuration: %v", err)
		idp.Status.Connected = false
		if err := r.client.Status().Update(ctx, idp); err != nil {
			r.logger.Errorw("failed to update identity provider status after reload failure", "error", err, "name", req.Name)
		}

		// Emit event on the IdentityProvider CR
		// Note: Empty namespace for cluster-scoped resources to prevent event reconciliation issues
		if r.recorder != nil {
			eventIdp := idp.DeepCopy()
			eventIdp.SetNamespace("") // Ensure no namespace is set for cluster-scoped events
			r.recorder.Event(eventIdp, "Warning", "ReloadFailed", fmt.Sprintf("Failed to reload configuration: %v", err))
		}

		// Requeue with exponential backoff
		return reconcile.Result{RequeueAfter: 30 * time.Second}, err
	}

	r.logger.Infow("identity provider configuration reloaded successfully", "name", req.Name)

	// Update status to reflect success
	idp.Status.Phase = "Ready"
	idp.Status.Message = "Configuration reloaded successfully"
	idp.Status.Connected = true
	idp.Status.LastValidation = metav1.NewTime(time.Now())
	if err := r.client.Status().Update(ctx, idp); err != nil {
		r.logger.Errorw("failed to update IdentityProvider status", "error", err, "name", req.Name)
	}

	// Emit event on the IdentityProvider CR
	// Note: Empty namespace for cluster-scoped resources to prevent event reconciliation issues
	if r.recorder != nil {
		eventIdp := idp.DeepCopy()
		eventIdp.SetNamespace("") // Ensure no namespace is set for cluster-scoped events
		r.recorder.Event(eventIdp, "Normal", "ReloadSuccess", "Configuration reloaded successfully")
	}

	// Requeue periodically for safety (even if no changes detected)
	// This ensures we recover from transient failures
	return reconcile.Result{RequeueAfter: r.resyncPeriod}, nil
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
