package breakglass

import (
	"context"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
)

type CleanupRoutine struct {
	Log           *zap.SugaredLogger
	Manager       *SessionManager
	LeaderElected <-chan struct{} // Optional: signal when leadership acquired (nil = start immediately for backward compatibility)
}

const CleanupInterval = 5 * time.Minute

// DebugSessionRetentionPeriod defines how long terminated/expired debug sessions are kept
// for audit purposes before being deleted. This can be configured via environment variable
// DEBUG_SESSION_RETENTION_PERIOD (default: 168h = 7 days)
var DebugSessionRetentionPeriod = 168 * time.Hour // 7 days default

func (cr CleanupRoutine) CleanupRoutine(ctx context.Context) {
	// Wait for leadership signal if provided (enables multi-replica scaling with leader election)
	if cr.LeaderElected != nil {
		cr.Log.Info("Cleanup routine waiting for leadership signal before starting...")
		select {
		case <-ctx.Done():
			cr.Log.Infow("Cert-controller's manager stopping before acquiring leadership (context cancelled)")
			return
		case <-cr.LeaderElected:
			cr.Log.Info("Leadership acquired - starting cleanup routine")
		}
	}

	// run initial cleanup
	cr.clean()

	tick := time.Tick(CleanupInterval)
	for {
		select {
		case <-ctx.Done():
			cr.Log.Warnw("cleanup routine stopped (context cancelled)")
			return
		case <-tick:
			cr.clean()
		}
	}
}

func (cr CleanupRoutine) clean() {
	cr.Log.Info("Running breakglass session cleanup task")
	// Activate scheduled sessions first (before expiry checks)
	if cr.Manager != nil {
		activator := NewScheduledSessionActivator(cr.Log, cr.Manager)
		activator.ActivateScheduledSessions()

		ctrl := &BreakglassSessionController{log: cr.Log, sessionManager: cr.Manager}
		ctrl.ExpirePendingSessions()
		// Expire approved sessions whose ExpiresAt has passed
		ctrl.ExpireApprovedSessions()
	}
	cr.markCleanupExpiredSession(context.Background())
	// Cleanup expired debug sessions
	cr.cleanupExpiredDebugSessions(context.Background())
	cr.Log.Info("Finished breakglass session cleanup task")
}

// Marks sessions that are expired and removes those that should no longer be stored.
func (routine CleanupRoutine) markCleanupExpiredSession(ctx context.Context) {
	routine.Log.Debug("Starting expired session cleanup")
	var deletedCount int

	// List sessions across all namespaces
	bsl := telekomv1alpha1.BreakglassSessionList{}
	if err := routine.Manager.List(ctx, &bsl); err != nil {
		routine.Log.Error("error listing breakglass sessions for cleanup", zap.Error(err))
		return
	}
	sessions := bsl.Items

	now := time.Now()
	for _, ses := range sessions {
		routine.Log.Debugw("Checking session for expiration", system.NamespacedFields(ses.Name, ses.Namespace)...)
		routine.Log.Debugw("Checking session retainedUntil", "retainedUntil", ses.Status.RetainedUntil.Time)
		// Delete sessions that are past their retained-until timestamp
		if !ses.Status.RetainedUntil.IsZero() && now.After(ses.Status.RetainedUntil.Time) {
			if err := routine.Manager.DeleteBreakglassSession(ctx, &ses); err != nil {
				routine.Log.Errorw("error deleting expired breakglass session", append(system.NamespacedFields(ses.Name, ses.Namespace), "error", err)...)
				continue
			}
			// count expired session (DeleteBreakglassSession also increments deleted; expired counts here)
			metrics.SessionExpired.WithLabelValues(ses.Spec.Cluster).Inc()
			deletedCount++
			routine.Log.Debugw("Deleted expired breakglass session", system.NamespacedFields(ses.Name, ses.Namespace)...)
			continue
		}

		// Additionally, clean up sessions that do not have an OwnerReference (orphaned/legacy).
		// To avoid removing valid active sessions, only delete orphaned sessions when
		// they have no RetainedUntil set (zero value) and are not pending. Expired
		// sessions are handled above based on RetainedUntil.
		if len(ses.OwnerReferences) == 0 {
			if ses.Status.RetainedUntil.IsZero() && ses.Status.State != telekomv1alpha1.SessionStatePending {
				routine.Log.Infow("Deleting session without OwnerReferences (orphaned/legacy - no RetainedUntil)", system.NamespacedFields(ses.Name, ses.Namespace)...)
				if err := routine.Manager.DeleteBreakglassSession(ctx, &ses); err != nil {
					routine.Log.Errorw("error deleting orphaned breakglass session", append(system.NamespacedFields(ses.Name, ses.Namespace), "error", err)...)
					continue
				}
				// DeleteBreakglassSession already increments SessionDeleted
				deletedCount++
				routine.Log.Debugw("Deleted orphaned breakglass session", system.NamespacedFields(ses.Name, ses.Namespace)...)
				continue
			}
			routine.Log.Debugw("Skipping deletion of session without OwnerReferences (either pending or has RetainedUntil)", system.NamespacedFields(ses.Name, ses.Namespace)...)
		}
	}
	routine.Log.Infow("Expired breakglass sessions deletion completed", "deleted", deletedCount)
}

// cleanupExpiredDebugSessions marks debug sessions as expired when their ExpiresAt timestamp has passed.
// It also deletes terminated/expired debug sessions that are past their retention period.
func (routine CleanupRoutine) cleanupExpiredDebugSessions(ctx context.Context) {
	routine.Log.Debug("Starting expired debug session cleanup")
	var expiredCount, deletedCount int

	// List debug sessions across all namespaces
	dsl := telekomv1alpha1.DebugSessionList{}
	if err := routine.Manager.List(ctx, &dsl); err != nil {
		routine.Log.Error("error listing debug sessions for cleanup", zap.Error(err))
		return
	}

	now := time.Now()
	for _, ds := range dsl.Items {
		routine.Log.Debugw("Checking debug session for expiration",
			system.NamespacedFields(ds.Name, ds.Namespace)...)

		// Skip sessions that are already in terminal states (Expired, Terminated, Failed)
		if ds.Status.State == telekomv1alpha1.DebugSessionStateExpired ||
			ds.Status.State == telekomv1alpha1.DebugSessionStateTerminated ||
			ds.Status.State == telekomv1alpha1.DebugSessionStateFailed {
			// Check if session should be deleted after retention period
			// Use ExpiresAt or CreationTimestamp to determine retention eligibility
			retentionStart := ds.CreationTimestamp.Time
			if ds.Status.ExpiresAt != nil && !ds.Status.ExpiresAt.IsZero() {
				retentionStart = ds.Status.ExpiresAt.Time
			}

			if now.After(retentionStart.Add(DebugSessionRetentionPeriod)) {
				routine.Log.Infow("Deleting debug session past retention period",
					append(system.NamespacedFields(ds.Name, ds.Namespace),
						"state", ds.Status.State,
						"retentionPeriod", DebugSessionRetentionPeriod.String())...)

				if err := routine.Manager.Delete(ctx, &ds); err != nil {
					routine.Log.Errorw("error deleting debug session past retention",
						append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
					continue
				}
				deletedCount++
				continue
			}

			routine.Log.Debugw("Skipping terminal debug session (within retention period)",
				system.NamespacedFields(ds.Name, ds.Namespace)...)
			continue
		}

		// Check if active session has expired
		if ds.Status.State == telekomv1alpha1.DebugSessionStateActive {
			if ds.Status.ExpiresAt != nil && now.After(ds.Status.ExpiresAt.Time) {
				routine.Log.Infow("Debug session expired, marking as Expired",
					system.NamespacedFields(ds.Name, ds.Namespace)...)

				ds.Status.State = telekomv1alpha1.DebugSessionStateExpired
				ds.Status.Message = "Session expired (cleanup routine)"

				if err := routine.Manager.Status().Update(ctx, &ds); err != nil {
					routine.Log.Errorw("error updating expired debug session status",
						append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
					continue
				}
				expiredCount++
				metrics.DebugSessionsExpired.WithLabelValues(ds.Spec.Cluster).Inc()
			}
		}

		// Check pending approval sessions that have timed out
		if ds.Status.State == telekomv1alpha1.DebugSessionStatePendingApproval {
			// If approval times out (e.g., 24 hours), mark as failed
			if ds.Status.Approval != nil && ds.CreationTimestamp.Add(24*time.Hour).Before(now) {
				routine.Log.Infow("Debug session approval timed out, marking as Failed",
					system.NamespacedFields(ds.Name, ds.Namespace)...)

				ds.Status.State = telekomv1alpha1.DebugSessionStateFailed
				ds.Status.Message = "Approval timed out after 24 hours"

				if err := routine.Manager.Status().Update(ctx, &ds); err != nil {
					routine.Log.Errorw("error updating timed-out debug session status",
						append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
					continue
				}
				deletedCount++
			}
		}
	}

	routine.Log.Infow("Debug session cleanup completed",
		"expired", expiredCount,
		"timedOut", deletedCount)
}
