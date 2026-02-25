package breakglass

import (
	"context"
	"fmt"
	"os"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
)

// ActivityCleaner is the interface for pruning orphaned activity tracker entries.
// Implemented by webhook.ActivityTracker.
type ActivityCleaner interface {
	Cleanup(activeSessionIDs map[types.NamespacedName]bool) int
}

const (
	// DefaultCleanupOperationTimeout is the timeout for cleanup operations to ensure
	// shutdown is predictable and we don't accumulate slow API calls
	DefaultCleanupOperationTimeout = 2 * time.Minute
)

type CleanupRoutine struct {
	Log             *zap.SugaredLogger
	Manager         *SessionManager
	AuditManager    *audit.Manager
	MailService     MailEnqueuer    // Mail service for sending expiration notifications
	BrandingName    string          // Branding name for email templates
	DisableEmail    bool            // Whether to disable email notifications
	LeaderElected   <-chan struct{} // Optional: signal when leadership acquired (nil = start immediately for backward compatibility)
	ActivityTracker ActivityCleaner // Optional: prune orphaned entries during cleanup
}

// CleanupInterval is the interval between cleanup routine runs.
// Can be configured via CLEANUP_INTERVAL environment variable (default: 5m).
// Use shorter intervals for testing (e.g., 10s for E2E tests).
var CleanupInterval = getCleanupInterval()

func getCleanupInterval() time.Duration {
	if envInterval := os.Getenv("CLEANUP_INTERVAL"); envInterval != "" {
		if d, err := time.ParseDuration(envInterval); err == nil {
			return d
		}
	}
	return 5 * time.Minute
}

// DebugSessionRetentionPeriod defines how long terminated/expired debug sessions are kept
// for audit purposes before being deleted. This can be configured via environment variable
// DEBUG_SESSION_RETENTION_PERIOD (default: 168h = 7 days)
var DebugSessionRetentionPeriod = getDebugSessionRetentionPeriod()

func getDebugSessionRetentionPeriod() time.Duration {
	const defaultRetention = 168 * time.Hour // 7 days
	if env := os.Getenv("DEBUG_SESSION_RETENTION_PERIOD"); env != "" {
		if d, err := time.ParseDuration(env); err == nil {
			return d
		}
	}
	return defaultRetention
}

// DebugSessionApprovalTimeout defines how long a debug session can wait in pending approval
// state before being automatically failed. This can be configured via environment variable
// DEBUG_SESSION_APPROVAL_TIMEOUT (default: 24h)
var DebugSessionApprovalTimeout = getDebugSessionApprovalTimeout()

func getDebugSessionApprovalTimeout() time.Duration {
	const defaultTimeout = 24 * time.Hour
	if env := os.Getenv("DEBUG_SESSION_APPROVAL_TIMEOUT"); env != "" {
		if d, err := time.ParseDuration(env); err == nil {
			return d
		}
	}
	return defaultTimeout
}

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
	cr.clean(ctx)

	// Use time.NewTicker instead of time.Tick to avoid memory leak.
	// time.Tick creates a ticker that is never garbage collected.
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			cr.Log.Warnw("cleanup routine stopped (context cancelled)")
			return
		case <-ticker.C:
			cr.clean(ctx)
		}
	}
}

func (cr CleanupRoutine) clean(ctx context.Context) {
	cr.Log.Info("Running breakglass session cleanup task")
	// Activate scheduled sessions first (before expiry checks)
	if cr.Manager != nil {
		activator := NewScheduledSessionActivator(cr.Log, cr.Manager).
			WithMailService(cr.MailService, cr.BrandingName, cr.DisableEmail)
		activator.ActivateScheduledSessions()
	}

	// Build session controller once for the expiry operations below.
	var sessionCtrl *BreakglassSessionController
	if cr.Manager != nil {
		sessionCtrl = &BreakglassSessionController{
			log:            cr.Log,
			sessionManager: cr.Manager,
			mailService:    cr.MailService,
			disableEmail:   cr.DisableEmail,
			config:         config.Config{Frontend: config.Frontend{BrandingName: cr.BrandingName}},
		}
		sessionCtrl.ExpirePendingSessions()
		// Expire approved sessions whose ExpiresAt has passed
		sessionCtrl.ExpireApprovedSessions()
	}

	cleanupCtx := ctx
	if cleanupCtx == nil {
		cleanupCtx = context.Background()
	}
	// Bound all cleanup operations under a single timeout so shutdown is
	// predictable and we don't accumulate slow API calls.
	opCtx, cancel := context.WithTimeout(cleanupCtx, DefaultCleanupOperationTimeout)
	defer cancel()

	if cr.Manager != nil {
		// Remove duplicate active sessions (same cluster/user/grantedGroup triple).
		// Duplicates can arise from TOCTOU races in multi-replica deployments.
		CleanupDuplicateSessions(opCtx, cr.Log, cr.Manager)
	}

	// Expire approved sessions that have been idle longer than their idleTimeout.
	// Uses the bounded opCtx to ensure idle-expiry checks are included in the
	// cleanup operation timeout and don't block shutdown.
	if sessionCtrl != nil {
		sessionCtrl.ExpireIdleSessions(opCtx)
	}

	// markCleanupExpiredSession and cleanupExpiredDebugSessions dereference
	// cr.Manager without a nil check; guard them to avoid a panic when the
	// session manager has not been initialised (e.g. breakglass disabled).
	if cr.Manager != nil {
		cr.markCleanupExpiredSession(opCtx)
		// Cleanup expired debug sessions
		cr.cleanupExpiredDebugSessions(opCtx)

		// Prune orphaned activity tracker entries.
		// Build a set of active (approved) sessions and let the tracker discard the rest.
		if cr.ActivityTracker != nil {
			cr.pruneActivityTracker(opCtx)
		}
	}
	cr.Log.Info("Finished breakglass session cleanup task")
}

// pruneActivityTracker builds a set of active (approved) session NamespacedNames
// and calls ActivityTracker.Cleanup() to remove entries for sessions that no longer exist.
// Uses the status.state field index (via GetSessionsByState) to only fetch Approved
// sessions instead of listing all sessions and filtering in Go.
func (cr CleanupRoutine) pruneActivityTracker(ctx context.Context) {
	approved, err := cr.Manager.GetSessionsByState(ctx, breakglassv1alpha1.SessionStateApproved)
	if err != nil {
		cr.Log.Warnw("Failed to list approved sessions for activity tracker pruning", "error", err)
		return
	}

	activeIDs := make(map[types.NamespacedName]bool, len(approved))
	for i := range approved {
		activeIDs[types.NamespacedName{
			Namespace: approved[i].Namespace,
			Name:      approved[i].Name,
		}] = true
	}

	cr.ActivityTracker.Cleanup(activeIDs)
}

// Marks sessions that are expired and removes those that should no longer be stored.
func (routine CleanupRoutine) markCleanupExpiredSession(ctx context.Context) {
	if routine.Manager == nil {
		return
	}
	routine.Log.Debug("Starting expired session cleanup")
	var deletedCount int

	// List sessions across all namespaces
	bsl := breakglassv1alpha1.BreakglassSessionList{}
	if err := routine.Manager.List(ctx, &bsl); err != nil {
		routine.Log.Error("error listing breakglass sessions for cleanup", zap.String("error", err.Error()))
		return
	}
	sessions := bsl.Items

	now := time.Now()
	for _, ses := range sessions {
		// Check for context cancellation to allow graceful shutdown
		select {
		case <-ctx.Done():
			routine.Log.Infow("Session cleanup interrupted by context cancellation", "processed", deletedCount)
			return
		default:
			// continue processing
		}

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
			if ses.Status.RetainedUntil.IsZero() && ses.Status.State != breakglassv1alpha1.SessionStatePending {
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
	if routine.Manager == nil {
		return
	}
	routine.Log.Debug("Starting expired debug session cleanup")
	var expiredCount, deletedCount int

	// List debug sessions across all namespaces
	dsl := breakglassv1alpha1.DebugSessionList{}
	if err := routine.Manager.List(ctx, &dsl); err != nil {
		routine.Log.Error("error listing debug sessions for cleanup", zap.String("error", err.Error()))
		return
	}

	now := time.Now()
	for _, ds := range dsl.Items {
		// Check for context cancellation to allow graceful shutdown
		select {
		case <-ctx.Done():
			routine.Log.Infow("Debug session cleanup interrupted by context cancellation",
				"expired", expiredCount, "deleted", deletedCount)
			return
		default:
			// continue processing
		}

		routine.Log.Debugw("Checking debug session for expiration",
			system.NamespacedFields(ds.Name, ds.Namespace)...)

		// Skip sessions that are already in terminal states (Expired, Terminated, Failed)
		if ds.Status.State == breakglassv1alpha1.DebugSessionStateExpired ||
			ds.Status.State == breakglassv1alpha1.DebugSessionStateTerminated ||
			ds.Status.State == breakglassv1alpha1.DebugSessionStateFailed {
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
		if ds.Status.State == breakglassv1alpha1.DebugSessionStateActive {
			if ds.Status.ExpiresAt != nil && now.After(ds.Status.ExpiresAt.Time) {
				routine.Log.Infow("Debug session expired, marking as Expired",
					append(system.NamespacedFields(ds.Name, ds.Namespace),
						"cluster", ds.Spec.Cluster,
						"template", ds.Spec.TemplateRef,
						"requestedBy", ds.Spec.RequestedBy,
						"startsAt", ds.Status.StartsAt,
						"expiresAt", ds.Status.ExpiresAt,
					)...)

				ds.Status.State = breakglassv1alpha1.DebugSessionStateExpired
				ds.Status.Message = "Session expired (cleanup routine)"

				if err := applyDebugSessionStatus(ctx, routine.Manager, &ds); err != nil {
					routine.Log.Errorw("error updating expired debug session status",
						append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
					continue
				}

				// Emit audit event for expired debug session
				if routine.AuditManager != nil {
					routine.AuditManager.DebugSessionExpired(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster)
				}

				// Send expiration email notification
				routine.sendDebugSessionExpiredEmail(ds)

				expiredCount++
				metrics.DebugSessionsExpired.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
			}
		}

		// Check pending approval sessions that have timed out
		if ds.Status.State == breakglassv1alpha1.DebugSessionStatePendingApproval {
			// If approval times out, mark as failed
			if ds.Status.Approval != nil && ds.CreationTimestamp.Add(DebugSessionApprovalTimeout).Before(now) {
				routine.Log.Infow("Debug session approval timed out, marking as Failed",
					append(system.NamespacedFields(ds.Name, ds.Namespace),
						"cluster", ds.Spec.Cluster,
						"template", ds.Spec.TemplateRef,
						"requestedBy", ds.Spec.RequestedBy,
						"createdAt", ds.CreationTimestamp,
						"approvalTimeout", DebugSessionApprovalTimeout.String(),
					)...)

				ds.Status.State = breakglassv1alpha1.DebugSessionStateFailed
				ds.Status.Message = fmt.Sprintf("Approval timed out after %s", DebugSessionApprovalTimeout)

				if err := applyDebugSessionStatus(ctx, routine.Manager, &ds); err != nil {
					routine.Log.Errorw("error updating timed-out debug session status",
						append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
					continue
				}

				// Emit audit event for approval timeout
				if routine.AuditManager != nil {
					routine.AuditManager.DebugSessionApprovalTimeout(ctx, ds.Name, ds.Namespace, ds.Spec.Cluster)
				}

				deletedCount++
				metrics.DebugSessionsFailed.WithLabelValues(ds.Spec.Cluster, ds.Spec.TemplateRef).Inc()
			}
		}
	}

	routine.Log.Infow("Debug session cleanup completed",
		"expired", expiredCount,
		"timedOut", deletedCount)
}

// sendDebugSessionExpiredEmail sends a notification when a debug session expires
func (routine CleanupRoutine) sendDebugSessionExpiredEmail(ds breakglassv1alpha1.DebugSession) {
	if routine.DisableEmail || routine.MailService == nil || !routine.MailService.IsEnabled() {
		return
	}

	if ds.Status.ResolvedTemplate != nil && ds.Status.ResolvedTemplate.Notification != nil {
		cfg := ds.Status.ResolvedTemplate.Notification
		if !cfg.Enabled || !cfg.NotifyOnExpiry {
			return
		}
	}

	startedAt := ""
	if ds.Status.StartsAt != nil {
		startedAt = ds.Status.StartsAt.Time.Format("2006-01-02 15:04:05 UTC")
	}

	var duration string
	if ds.Status.StartsAt != nil && ds.Status.ExpiresAt != nil {
		duration = ds.Status.ExpiresAt.Time.Sub(ds.Status.StartsAt.Time).String()
	}

	params := mail.DebugSessionExpiredMailParams{
		RequesterEmail: ds.Spec.RequestedBy,
		SessionID:      ds.Name,
		Cluster:        ds.Spec.Cluster,
		TemplateName:   ds.Spec.TemplateRef,
		Namespace:      ds.Namespace,
		StartedAt:      startedAt,
		ExpiredAt:      time.Now().Format("2006-01-02 15:04:05 UTC"),
		Duration:       duration,
		BrandingName:   routine.BrandingName,
	}

	body, err := mail.RenderDebugSessionExpired(params)
	if err != nil {
		routine.Log.Errorw("failed to render debug session expired email",
			append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
		return
	}

	subject := fmt.Sprintf("[%s] Debug Session Expired: %s", routine.BrandingName, ds.Name)
	recipients := buildDebugSessionNotificationRecipients(ds)
	if len(recipients) == 0 {
		routine.Log.Debugw("Skipping debug session expired email: no recipients",
			append(system.NamespacedFields(ds.Name, ds.Namespace), "cluster", ds.Spec.Cluster)...)
		return
	}
	if err := routine.MailService.Enqueue(ds.Name, recipients, subject, body); err != nil {
		routine.Log.Errorw("failed to enqueue debug session expired email",
			append(system.NamespacedFields(ds.Name, ds.Namespace), "error", err)...)
	}
}

func buildDebugSessionNotificationRecipients(ds breakglassv1alpha1.DebugSession) []string {
	base := []string{ds.Spec.RequestedBy}
	if ds.Spec.RequestedByEmail != "" {
		base = []string{ds.Spec.RequestedByEmail}
	}

	cfg := (*breakglassv1alpha1.DebugSessionNotificationConfig)(nil)
	if ds.Status.ResolvedTemplate != nil {
		cfg = ds.Status.ResolvedTemplate.Notification
	}
	if cfg == nil {
		return base
	}

	seen := make(map[string]struct{}, len(base))
	var recipients []string
	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		recipients = append(recipients, addr)
	}
	for _, addr := range base {
		add(addr)
	}
	for _, addr := range cfg.AdditionalRecipients {
		add(addr)
	}
	if cfg.ExcludedRecipients != nil && len(cfg.ExcludedRecipients.Users) > 0 {
		excluded := make(map[string]struct{}, len(cfg.ExcludedRecipients.Users))
		for _, u := range cfg.ExcludedRecipients.Users {
			excluded[u] = struct{}{}
		}
		filtered := recipients[:0]
		for _, addr := range recipients {
			if _, blocked := excluded[addr]; blocked {
				continue
			}
			filtered = append(filtered, addr)
		}
		recipients = filtered
	}
	return recipients
}
