package breakglass

import (
	"context"
	"time"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
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
		// Expire pending sessions before deleting expired ones
		if cr.Manager != nil {
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
		if now.After(ses.Status.RetainedUntil.Time) {
			if err := routine.Manager.Delete(ctx, &ses); err != nil {
				routine.Log.Errorw("error deleting expired breakglass session", append(system.NamespacedFields(ses.Name, ses.Namespace), "error", err)...)
				continue
			}
			deletedCount++
			routine.Log.Debugw("Deleted expired breakglass session", system.NamespacedFields(ses.Name, ses.Namespace)...)
		}
	}
	routine.Log.Infow("Expired breakglass sessions deletion completed", "deleted", deletedCount)
}
