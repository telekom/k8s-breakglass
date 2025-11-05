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
	Log     *zap.SugaredLogger
	Manager *SessionManager
}

const CleanupInterval = 5 * time.Minute

func (cr CleanupRoutine) CleanupRoutine() {
	for {
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
		cr.Log.Info("Finished breakglass session cleanup task")
		time.Sleep(CleanupInterval)
	}
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
