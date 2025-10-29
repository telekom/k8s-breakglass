package breakglass

import (
	"context"
	"time"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	// List sessions across all namespaces
	bsl := telekomv1alpha1.BreakglassSessionList{}
	if err := routine.Manager.List(ctx, &bsl); err != nil {
		routine.Log.Error("error listing breakglass sessions for cleanup", zap.Error(err))
		return
	}
	sessions := bsl.Items

	now := time.Now()
	deletionLabel := map[string]string{"deletion": "true"}
	for _, ses := range sessions {
		routine.Log.Debugw("Checking session for expiration", system.NamespacedFields(ses.Name, ses.Namespace)...)
		routine.Log.Debugw("Checking session retainedUntil", "retainedUntil", ses.Status.RetainedUntil.Time)
		if now.After(ses.Status.RetainedUntil.Time) {
			routine.Log.Infow("Marking session for deletion", system.NamespacedFields(ses.Name, ses.Namespace)...)
			ses.SetLabels(deletionLabel)
			if err := routine.Manager.UpdateBreakglassSession(ctx, ses); err != nil {
				routine.Log.Errorw("error failed to set label", append(system.NamespacedFields(ses.Name, ses.Namespace), "error", err)...)
			} else {
				routine.Log.Debugw("Label set for deletion", system.NamespacedFields(ses.Name, ses.Namespace)...)
			}
		}
	}

	// Delete all marked sessions across all namespaces
	if err := routine.Manager.DeleteAllOf(ctx,
		&telekomv1alpha1.BreakglassSession{},
		&client.DeleteAllOfOptions{
			ListOptions: client.ListOptions{
				LabelSelector: labels.SelectorFromSet(deletionLabel),
			},
		}); err != nil {
		routine.Log.Error("error while deleting expired breakglass sessions", zap.Error(err))
	} else {
		routine.Log.Info("Expired breakglass sessions deleted successfully")
	}
}
