package breakglass

import (
	"context"
	"time"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CleanupRoutine struct {
	Log     *zap.SugaredLogger
	Manager *SessionManager
}

func (cr CleanupRoutine) CleanupRoutine() {
	for {
		cr.Log.Info("Running breakglass session cleanup task")
		cr.markClenaupExpiredSession(context.Background())
		cr.Log.Info("Finished breakglass session cleanup task")
		time.Sleep(WeekDuration)
	}
}

// Marks sessions that are expired and removes those that should no longer be stored.
func (routine CleanupRoutine) markClenaupExpiredSession(ctx context.Context) {
	sessions, err := routine.Manager.GetAllBreakglassSessions(ctx)
	if err != nil {
		routine.Log.Error("error listing breakglass sessions for cleanup", zap.Error(err))
		return
	}

	now := time.Now()
	deletionLabel := map[string]string{"deletion": "true"}
	for _, ses := range sessions {
		if now.After(ses.Status.RetainedUntil.Time) {
			ses.SetLabels(deletionLabel)
			if err := routine.Manager.UpdateBreakglassSession(ctx, ses); err != nil {
				routine.Log.Error("error failed to set label", zap.Error(err))
			}
		}
	}

	if err := routine.Manager.DeleteAllOf(ctx,
		&telekomv1alpha1.BreakglassSession{},
		&client.DeleteAllOfOptions{
			ListOptions: client.ListOptions{
				LabelSelector: labels.SelectorFromSet(deletionLabel),
			},
		}); err != nil {
		routine.Log.Error("error while deleting expired breakglass sessions", zap.Error(err))
	}
}
