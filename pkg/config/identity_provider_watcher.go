package config

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// IdentityProviderWatcher monitors ALL IdentityProvider CRs for changes and triggers reloads.
// Unlike the single-provider design it replaces, this watcher detects changes to ANY
// IdentityProvider CR in the cluster, allowing true multi-provider support.
// This allows the system to pick up configuration changes like:
// - Certificate rotations
// - Timeout adjustments
// - Authority URL changes
// - Secret updates (ClientSecret, ServiceAccountToken, etc.)
// - Provider switching or additions
type IdentityProviderWatcher struct {
	kubeClient client.Client
	logger     *zap.SugaredLogger
	// onReload is called whenever ANY IdentityProvider is updated
	onReload func(ctx context.Context) error
	// debounce prevents rapid successive reloads from multiple quick updates
	debounce time.Duration
	// lastReload tracks when the last reload occurred
	lastReload time.Time
	// lastResourceVersion tracks the most recent ResourceVersion of any IdentityProvider
	lastResourceVersion string
	// stopCh signals the watcher to stop
	stopCh chan struct{}
	// recorder for emitting Kubernetes events (optional)
	recorder record.EventRecorder
}

// NewIdentityProviderWatcher creates a new IdentityProvider watcher
func NewIdentityProviderWatcher(kubeClient client.Client, logger *zap.SugaredLogger) *IdentityProviderWatcher {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &IdentityProviderWatcher{
		kubeClient: kubeClient,
		logger:     logger,
		debounce:   1 * time.Second, // Default 1 second debounce
		stopCh:     make(chan struct{}),
	}
}

// WithDebounce sets the debounce duration to prevent thundering herd
// during rapid consecutive updates
func (w *IdentityProviderWatcher) WithDebounce(duration time.Duration) *IdentityProviderWatcher {
	w.debounce = duration
	return w
}

// WithReloadCallback sets the function to call when a reload is triggered
// This is typically a function that reloads the IDP config and updates the API server
func (w *IdentityProviderWatcher) WithReloadCallback(fn func(ctx context.Context) error) *IdentityProviderWatcher {
	w.onReload = fn
	return w
}

// WithEventRecorder sets the event recorder for emitting Kubernetes events
func (w *IdentityProviderWatcher) WithEventRecorder(recorder record.EventRecorder) *IdentityProviderWatcher {
	w.recorder = recorder
	return w
}

// Start begins watching for IdentityProvider changes in a background goroutine
// This should be called during application startup
// Returns a channel that closes when the watcher stops
func (w *IdentityProviderWatcher) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go w.watchLoop(ctx, done)
	return done
}

// Stop signals the watcher to stop
func (w *IdentityProviderWatcher) Stop() {
	close(w.stopCh)
}

// watchLoop periodically checks for IdentityProvider changes
// In production, this could be replaced with a controller-runtime EventHandler
// for more efficient event-driven updates
func (w *IdentityProviderWatcher) watchLoop(ctx context.Context, done chan struct{}) {
	defer close(done)

	// Initial delay to let API server stabilize
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("IdentityProvider watcher context cancelled")
			return
		case <-w.stopCh:
			w.logger.Info("IdentityProvider watcher stopped")
			return
		case <-ticker.C:
			// Check if reload is needed
			if w.shouldReload(ctx) {
				w.reload(ctx)
			}
		}
	}
}

// shouldReload checks if any IdentityProvider resource has changed since last check
// by comparing ResourceVersion of the most recent provider with stored version.
// Returns true if ANY provider has been modified, allowing true multi-provider support.
func (w *IdentityProviderWatcher) shouldReload(ctx context.Context) bool {
	// Get list of ALL IdentityProviders
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := w.kubeClient.List(ctx, idpList); err != nil {
		w.logger.Debugw("failed to list IdentityProviders during watch check", "error", err)
		return false
	}

	if len(idpList.Items) == 0 {
		w.logger.Debugw("no IdentityProviders found in cluster")
		return false
	}

	// Find the most recent ResourceVersion across all providers
	// This ensures we detect changes to ANY provider in the cluster
	maxResourceVersion := ""
	for _, idp := range idpList.Items {
		if idp.ResourceVersion > maxResourceVersion {
			maxResourceVersion = idp.ResourceVersion
		}
	}

	// If ResourceVersion changed, we need to reload
	if maxResourceVersion != w.lastResourceVersion {
		w.lastResourceVersion = maxResourceVersion
		w.logger.Debugw("detected IdentityProvider change", "newResourceVersion", maxResourceVersion)
		return true
	}

	return false
}

// updateProviderStatus updates the .status subresource of an IdentityProvider CR
// This is called after reload attempts to reflect the current state in the cluster
func (w *IdentityProviderWatcher) updateProviderStatus(ctx context.Context, providerName string, phase string, message string, configHash string, connected bool) error {
	// Get the IdentityProvider CR
	idp := &breakglassv1alpha1.IdentityProvider{}
	if err := w.kubeClient.Get(ctx, client.ObjectKey{Name: providerName}, idp); err != nil {
		w.logger.Warnw("failed to get IdentityProvider for status update", "provider", providerName, "error", err)
		return err
	}

	// Update status fields
	now := metav1.Now()
	idp.Status.Phase = phase
	idp.Status.Message = message
	idp.Status.LastValidation = now
	idp.Status.Connected = connected
	if configHash != "" {
		idp.Status.ConfigHash = configHash
	}

	// Set conditions based on phase
	if phase == "Active" {
		idp.SetCondition(metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: idp.Generation,
			Reason:             "ConfigValid",
			Message:            "Configuration is valid and provider is ready",
			LastTransitionTime: now,
		})
		idp.SetCondition(metav1.Condition{
			Type:               "Connected",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: idp.Generation,
			Reason:             "AuthenticationOK",
			Message:            "Successfully authenticated with provider",
			LastTransitionTime: now,
		})
	} else if phase == "Error" {
		idp.SetCondition(metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			Reason:             "ConfigError",
			Message:            message,
			LastTransitionTime: now,
		})
		idp.SetCondition(metav1.Condition{
			Type:               "Connected",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: idp.Generation,
			Reason:             "ConnectionFailed",
			Message:            message,
			LastTransitionTime: now,
		})
	}

	// Update the status subresource
	if err := w.kubeClient.Status().Update(ctx, idp); err != nil {
		w.logger.Errorw("failed to update IdentityProvider status", "provider", providerName, "error", err)
		return err
	}

	w.logger.Infow("updated IdentityProvider status", "provider", providerName, "phase", phase)
	return nil
}

// reload triggers a reload and applies debouncing
func (w *IdentityProviderWatcher) reload(ctx context.Context) {
	now := time.Now()
	timeSinceLastReload := now.Sub(w.lastReload)

	if timeSinceLastReload < w.debounce {
		w.logger.Debugw("skipping_reload_due_to_debounce", "timeSinceLastReload", timeSinceLastReload)
		return
	}

	w.logger.Infow("identity_provider_reload_started", "timeSinceLastReload", timeSinceLastReload)

	var reloadErr error
	if w.onReload != nil {
		if err := w.onReload(ctx); err != nil {
			w.logger.Errorw("identity_provider_reload_failed", "error", err)
			w.emitEvent(false, fmt.Sprintf("Failed to reload config: %v", err))
			reloadErr = err
		}
	}

	w.lastReload = now
	duration := time.Since(now)

	// Update status on all IdentityProvider CRs
	if err := w.updateAllProviderStatuses(ctx, reloadErr); err != nil {
		w.logger.Warnw("failed to update provider statuses", "error", err)
	}

	if reloadErr == nil {
		w.logger.Infow("identity_provider_reload_completed", "duration", duration)
		w.emitEvent(true, "Successfully reloaded identity provider configuration")
	}
}

// updateAllProviderStatuses updates the status on all IdentityProvider CRs in the cluster
func (w *IdentityProviderWatcher) updateAllProviderStatuses(ctx context.Context, reloadErr error) error {
	// Get list of all IdentityProviders
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := w.kubeClient.List(ctx, idpList); err != nil {
		w.logger.Debugw("failed to list IdentityProviders for status update", "error", err)
		return err
	}

	// Determine phase and message based on reload result
	phase := "Active"
	message := "Configuration successfully loaded"
	connected := true
	if reloadErr != nil {
		phase = "Error"
		message = fmt.Sprintf("Reload failed: %v", reloadErr)
		connected = false
	}

	// Update status for each provider
	for i := range idpList.Items {
		provider := &idpList.Items[i]
		// Note: We use empty configHash here; in production, compute hash of actual config
		if err := w.updateProviderStatus(ctx, provider.Name, phase, message, "", connected); err != nil {
			w.logger.Warnw("failed to update status for provider", "provider", provider.Name, "error", err)
			// Continue updating other providers despite error
		}
	}

	return nil
}

// emitEvent emits Kubernetes events on all IdentityProvider CRs to notify about reload operation
// This helps operators understand what triggered the reload and when
func (w *IdentityProviderWatcher) emitEvent(success bool, message string) {
	if w.recorder == nil {
		return
	}

	// Get all IdentityProviders to emit events on them
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	idpList := &breakglassv1alpha1.IdentityProviderList{}
	if err := w.kubeClient.List(ctx, idpList); err != nil {
		w.logger.Debugw("failed to list IdentityProviders for event emission", "error", err)
		return
	}

	eventType := "Normal"
	reason := "ConfigReloaded"
	if !success {
		eventType = "Warning"
		reason = "ConfigReloadFailed"
	}

	// Emit event on each IdentityProvider CR
	for i := range idpList.Items {
		w.recorder.Event(&idpList.Items[i], eventType, reason, message)
	}
}

// TriggerReload manually triggers a reload (useful for testing)
func (w *IdentityProviderWatcher) TriggerReload(ctx context.Context) error {
	if w.onReload == nil {
		return fmt.Errorf("reload callback not set")
	}
	return w.onReload(ctx)
}
