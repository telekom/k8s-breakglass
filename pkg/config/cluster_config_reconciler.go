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

package config

import (
	"context"
	"errors"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ssa "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	// ClusterConfigFinalizer is the finalizer added to ClusterConfig resources
	// to ensure proper cleanup of associated sessions when the cluster is deleted.
	ClusterConfigFinalizer = "breakglass.t-caas.telekom.com/cluster-cleanup"

	clusterConfigDefaultRetainFor = 720 * time.Hour
)

// ClusterConfigReconciler reconciles ClusterConfig objects.
// It ensures that when a ClusterConfig is deleted, all associated sessions
// (BreakglassSessions and DebugSessions) targeting that cluster are properly
// terminated/expired to avoid orphaned sessions.
type ClusterConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    *zap.SugaredLogger
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglasssessions,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglasssessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessions,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessions/status,verbs=get;update;patch

// Reconcile handles ClusterConfig create/update/delete events.
// On creation: adds a finalizer to enable cleanup on deletion.
// On deletion: terminates all sessions for the cluster before allowing deletion.
func (r *ClusterConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("clusterconfig", req.NamespacedName)

	// Fetch the ClusterConfig instance
	clusterConfig := &breakglassv1alpha1.ClusterConfig{}
	if err := r.Get(ctx, req.NamespacedName, clusterConfig); err != nil {
		if apierrors.IsNotFound(err) {
			// Object not found, likely already deleted - nothing to do
			return ctrl.Result{}, nil
		}
		log.Errorw("Failed to get ClusterConfig", "error", err)
		return ctrl.Result{}, err
	}

	clusterName := clusterConfig.Name

	// Check if the ClusterConfig is being deleted
	if !clusterConfig.DeletionTimestamp.IsZero() {
		// ClusterConfig is being deleted - perform cleanup
		if controllerutil.ContainsFinalizer(clusterConfig, ClusterConfigFinalizer) {
			log.Infow("ClusterConfig is being deleted, cleaning up sessions", "cluster", clusterName)

			// Terminate all BreakglassSessions for this cluster
			if err := r.terminateBreakglassSessionsForCluster(ctx, clusterName, log); err != nil {
				log.Errorw("Failed to terminate BreakglassSessions for cluster", "cluster", clusterName, "error", err)
				// Requeue to retry cleanup
				return ctrl.Result{RequeueAfter: 10 * time.Second}, err
			}

			// Terminate all DebugSessions for this cluster
			if err := r.terminateDebugSessionsForCluster(ctx, clusterName, log); err != nil {
				log.Errorw("Failed to terminate DebugSessions for cluster", "cluster", clusterName, "error", err)
				// Requeue to retry cleanup
				return ctrl.Result{RequeueAfter: 10 * time.Second}, err
			}

			// Remove the finalizer to allow deletion (retry on conflict)
			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				latest := &breakglassv1alpha1.ClusterConfig{}
				if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
					return err
				}
				if !controllerutil.ContainsFinalizer(latest, ClusterConfigFinalizer) {
					return nil
				}
				controllerutil.RemoveFinalizer(latest, ClusterConfigFinalizer)
				patch := &breakglassv1alpha1.ClusterConfig{
					TypeMeta: metav1.TypeMeta{
						APIVersion: breakglassv1alpha1.GroupVersion.String(),
						Kind:       "ClusterConfig",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:       latest.Name,
						Namespace:  latest.Namespace,
						Finalizers: latest.Finalizers,
					},
				}
				return utils.ApplyObject(ctx, r.Client, patch)
			}); err != nil {
				log.Errorw("Failed to remove finalizer from ClusterConfig", "cluster", clusterName, "error", err)
				return ctrl.Result{}, err
			}

			log.Infow("ClusterConfig cleanup complete, finalizer removed", "cluster", clusterName)
			metrics.ClusterConfigsDeleted.WithLabelValues(clusterName).Inc()
		}
		return ctrl.Result{}, nil
	}

	// ClusterConfig is not being deleted - ensure finalizer is present
	if !controllerutil.ContainsFinalizer(clusterConfig, ClusterConfigFinalizer) {
		log.Debugw("Adding finalizer to ClusterConfig", "cluster", clusterName)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			latest := &breakglassv1alpha1.ClusterConfig{}
			if err := r.Get(ctx, req.NamespacedName, latest); err != nil {
				return err
			}
			if controllerutil.ContainsFinalizer(latest, ClusterConfigFinalizer) {
				return nil
			}
			controllerutil.AddFinalizer(latest, ClusterConfigFinalizer)
			patch := &breakglassv1alpha1.ClusterConfig{
				TypeMeta: metav1.TypeMeta{
					APIVersion: breakglassv1alpha1.GroupVersion.String(),
					Kind:       "ClusterConfig",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:       latest.Name,
					Namespace:  latest.Namespace,
					Finalizers: latest.Finalizers,
				},
			}
			return utils.ApplyObject(ctx, r.Client, patch)
		}); err != nil {
			log.Errorw("Failed to add finalizer to ClusterConfig", "cluster", clusterName, "error", err)
			return ctrl.Result{}, err
		}
		log.Infow("Finalizer added to ClusterConfig", "cluster", clusterName)
	}

	return ctrl.Result{}, nil
}

// terminateBreakglassSessionsForCluster finds all BreakglassSessions targeting the given cluster
// and terminates them by setting their state to Expired.
func (r *ClusterConfigReconciler) terminateBreakglassSessionsForCluster(ctx context.Context, clusterName string, log *zap.SugaredLogger) error {
	sessionList, err := r.listBreakglassSessionsForCluster(ctx, clusterName)
	if err != nil {
		return fmt.Errorf("failed to list BreakglassSessions for cluster %s: %w", clusterName, err)
	}

	now := metav1.Now()
	terminatedCount := 0
	var terminateErrs []error
	for i := range sessionList {
		session := &sessionList[i]
		// Skip already terminal sessions
		if session.Status.State == breakglassv1alpha1.SessionStateExpired ||
			session.Status.State == breakglassv1alpha1.SessionStateIdleExpired ||
			session.Status.State == breakglassv1alpha1.SessionStateRejected ||
			session.Status.State == breakglassv1alpha1.SessionStateWithdrawn ||
			session.Status.State == breakglassv1alpha1.SessionStateTimeout {
			continue
		}

		log.Infow("Terminating BreakglassSession due to cluster deletion",
			"session", session.Name, "namespace", session.Namespace, "cluster", clusterName,
			"previousState", session.Status.State)

		// Update the session status to Expired
		session.Status.State = breakglassv1alpha1.SessionStateExpired
		session.Status.ExpiresAt = now
		retainFor := parseClusterConfigRetainFor(session.Spec, log)
		session.Status.RetainedUntil = metav1.NewTime(now.Time.Add(retainFor))

		if err := ssa.ApplyBreakglassSessionStatus(ctx, r.Client, session); err != nil {
			log.Warnw("Failed to terminate BreakglassSession", "session", session.Name, "error", err)
			terminateErrs = append(terminateErrs, fmt.Errorf("terminate BreakglassSession %s/%s: %w", session.Namespace, session.Name, err))
			continue
		}
		terminatedCount++
		metrics.SessionExpired.WithLabelValues(clusterName).Inc()
	}

	if terminatedCount > 0 {
		log.Infow("Terminated BreakglassSessions for deleted cluster",
			"cluster", clusterName, "count", terminatedCount)
	}

	return errors.Join(terminateErrs...)
}

func (r *ClusterConfigReconciler) listBreakglassSessionsForCluster(ctx context.Context, clusterName string) ([]breakglassv1alpha1.BreakglassSession, error) {
	sessionsByName := make(map[types.NamespacedName]breakglassv1alpha1.BreakglassSession)
	for _, field := range []string{"spec.cluster", "spec.clusterConfigRef"} {
		sessionList := &breakglassv1alpha1.BreakglassSessionList{}
		if err := r.List(ctx, sessionList, client.MatchingFields{field: clusterName}); err != nil {
			return nil, fmt.Errorf("list BreakglassSessions by %s: %w", field, err)
		}
		for _, session := range sessionList.Items {
			sessionsByName[types.NamespacedName{Namespace: session.Namespace, Name: session.Name}] = session
		}
	}

	sessions := make([]breakglassv1alpha1.BreakglassSession, 0, len(sessionsByName))
	for _, session := range sessionsByName {
		sessions = append(sessions, session)
	}
	return sessions, nil
}

// terminateDebugSessionsForCluster finds all DebugSessions targeting the given cluster
// and terminates them. Terminated sessions are reconciled through the DebugSession
// cleanup path, so deployed debug pods and auxiliary resources are removed.
func (r *ClusterConfigReconciler) terminateDebugSessionsForCluster(ctx context.Context, clusterName string, log *zap.SugaredLogger) error {
	// List all DebugSessions for this cluster using the spec.cluster index
	sessionList := &breakglassv1alpha1.DebugSessionList{}
	if err := r.List(ctx, sessionList, client.MatchingFields{"spec.cluster": clusterName}); err != nil {
		return fmt.Errorf("failed to list DebugSessions for cluster %s: %w", clusterName, err)
	}

	terminatedCount := 0
	var terminateErrs []error
	for i := range sessionList.Items {
		session := &sessionList.Items[i]

		// Skip already terminal sessions
		if session.Status.State == breakglassv1alpha1.DebugSessionStateFailed ||
			session.Status.State == breakglassv1alpha1.DebugSessionStateTerminated ||
			session.Status.State == breakglassv1alpha1.DebugSessionStateExpired {
			continue
		}

		log.Infow("Terminating DebugSession due to cluster deletion",
			"session", session.Name, "namespace", session.Namespace, "cluster", clusterName,
			"previousState", session.Status.State)

		// Update the session status to Terminated so the debug-session reconciler
		// performs resource cleanup.
		session.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
		session.Status.Message = fmt.Sprintf("Session terminated: ClusterConfig %q was deleted", clusterName)

		if err := ssa.ApplyDebugSessionStatus(ctx, r.Client, session); err != nil {
			log.Warnw("Failed to terminate DebugSession", "session", session.Name, "error", err)
			terminateErrs = append(terminateErrs, fmt.Errorf("terminate DebugSession %s/%s: %w", session.Namespace, session.Name, err))
			continue
		}
		terminatedCount++
		metrics.DebugSessionsTerminated.WithLabelValues(clusterName, "cluster_deleted").Inc()
	}

	if terminatedCount > 0 {
		log.Infow("Terminated DebugSessions for deleted cluster",
			"cluster", clusterName, "count", terminatedCount)
	}

	return errors.Join(terminateErrs...)
}

func parseClusterConfigRetainFor(spec breakglassv1alpha1.BreakglassSessionSpec, log *zap.SugaredLogger) time.Duration {
	if spec.RetainFor == "" {
		return clusterConfigDefaultRetainFor
	}
	retainFor, err := breakglassv1alpha1.ParseDuration(spec.RetainFor)
	if err != nil || retainFor <= 0 {
		if log != nil {
			log.Warnw("Invalid BreakglassSession retainFor during ClusterConfig cleanup; falling back to default",
				"retainFor", spec.RetainFor,
				"default", clusterConfigDefaultRetainFor.String(),
				"error", err)
		}
		return clusterConfigDefaultRetainFor
	}
	return retainFor
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.ClusterConfig{}).
		Named("clusterconfig").
		Complete(r)
}
