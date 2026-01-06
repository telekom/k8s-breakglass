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
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
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
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// AuditConfigReconciler watches AuditConfig CRs and manages audit system configuration.
// It aggregates sinks from ALL valid AuditConfigs instead of just the last reconciled one.
//
// The reconciler:
// - Watches for AuditConfig CR changes
// - Lists ALL AuditConfigs and validates each one
// - Aggregates sinks from all valid, enabled configs
// - Updates each AuditConfig status with validation results
// - Calls onReloadMultiple callback to reconfigure the audit manager with all sinks
type AuditConfigReconciler struct {
	client   client.Client
	logger   *zap.SugaredLogger
	recorder record.EventRecorder

	// onReloadMultiple is called when AuditConfig changes are detected
	// It receives all valid AuditConfigs to aggregate their sinks
	onReloadMultiple func(ctx context.Context, configs []*breakglassv1alpha1.AuditConfig) error
	// onError is called when reload fails (optional, for metrics/logging)
	onError func(ctx context.Context, err error)
	// getSinkHealth returns the current health status of all sinks (optional)
	getSinkHealth func() []SinkHealthInfo
	// resyncPeriod defines the full reconciliation interval (default 10m)
	resyncPeriod time.Duration

	// Cache for all active AuditConfigs
	configMutex   sync.RWMutex
	activeConfigs []*breakglassv1alpha1.AuditConfig
}

// SinkHealthInfo contains health information for a sink.
type SinkHealthInfo struct {
	Name                string
	Ready               bool
	CircuitState        string
	ConsecutiveFailures int64
	LastError           string
}

// NewAuditConfigReconciler creates a new AuditConfigReconciler instance.
func NewAuditConfigReconciler(
	c client.Client,
	logger *zap.SugaredLogger,
	recorder record.EventRecorder,
	onReloadMultiple func(ctx context.Context, configs []*breakglassv1alpha1.AuditConfig) error,
	onError func(ctx context.Context, err error),
	resyncPeriod time.Duration,
) *AuditConfigReconciler {
	if resyncPeriod == 0 {
		resyncPeriod = 10 * time.Minute
	}
	return &AuditConfigReconciler{
		client:           c,
		logger:           logger,
		recorder:         recorder,
		onReloadMultiple: onReloadMultiple,
		onError:          onError,
		resyncPeriod:     resyncPeriod,
	}
}

// SetSinkHealthProvider sets the callback to retrieve sink health information.
func (r *AuditConfigReconciler) SetSinkHealthProvider(fn func() []SinkHealthInfo) {
	r.getSinkHealth = fn
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=auditconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=auditconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=auditconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements controller-runtime's Reconciler interface.
// Called whenever an AuditConfig CR changes.
// This reconciler lists ALL AuditConfigs and aggregates their sinks together.
func (r *AuditConfigReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling AuditConfig (will aggregate all configs)",
		"trigger", req.Name)

	// List ALL AuditConfigs
	allConfigs := &breakglassv1alpha1.AuditConfigList{}
	if err := r.client.List(ctx, allConfigs); err != nil {
		r.logger.Errorw("Failed to list AuditConfigs", "error", err)
		return reconcile.Result{}, err
	}

	// Process each config: validate and update status
	var validConfigs []*breakglassv1alpha1.AuditConfig
	for i := range allConfigs.Items {
		config := &allConfigs.Items[i]

		// Perform structural validation
		validationResult := breakglassv1alpha1.ValidateAuditConfig(config)
		if !validationResult.IsValid() {
			r.logger.Warnw("AuditConfig failed structural validation",
				"name", config.Name,
				"errors", validationResult.ErrorMessage())

			// Update status with validation failure
			now := metav1.Now()
			condition := metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				ObservedGeneration: config.Generation,
				LastTransitionTime: now,
				Reason:             "ValidationFailed",
				Message:            fmt.Sprintf("Resource validation failed: %s", validationResult.ErrorMessage()),
			}
			apimeta.SetStatusCondition(&config.Status.Conditions, condition)
			if statusErr := r.client.Status().Update(ctx, config); statusErr != nil {
				r.logger.Errorw("Failed to update AuditConfig status", "name", config.Name, "error", statusErr)
			}

			if r.recorder != nil {
				r.recorder.Event(config, corev1.EventTypeWarning, "ValidationFailed",
					fmt.Sprintf("Resource validation failed: %s", validationResult.ErrorMessage()))
			}
			continue
		}

		// Validate the configuration (secret refs, etc.)
		validationErrors := r.validateConfig(ctx, config)

		// Update status based on validation
		if err := r.updateStatus(ctx, config, validationErrors); err != nil {
			r.logger.Errorw("Failed to update AuditConfig status", "name", config.Name, "error", err)
			// Continue processing other configs
			continue
		}

		// If validation failed, skip this config but continue with others
		if len(validationErrors) > 0 {
			r.logger.Warnw("AuditConfig validation failed, skipping",
				"name", config.Name,
				"errors", validationErrors)
			if r.recorder != nil {
				r.recorder.Event(config, corev1.EventTypeWarning, "ValidationFailed",
					fmt.Sprintf("AuditConfig validation failed: %v", validationErrors))
			}
			continue
		}

		// This config is valid - add to list
		if config.Spec.Enabled {
			validConfigs = append(validConfigs, config.DeepCopy())
			r.logger.Debugw("AuditConfig is valid and enabled, including in aggregation",
				"name", config.Name,
				"sinks", len(config.Spec.Sinks))
		} else {
			r.logger.Debugw("AuditConfig is valid but disabled, skipping",
				"name", config.Name)
		}
	}

	// Cache the active configs
	r.configMutex.Lock()
	r.activeConfigs = validConfigs
	r.configMutex.Unlock()

	// Call reload callback with ALL valid configs
	if r.onReloadMultiple != nil {
		if err := r.onReloadMultiple(ctx, validConfigs); err != nil {
			r.logger.Errorw("Failed to reload audit configuration with aggregated configs",
				"configCount", len(validConfigs),
				"error", err)
			if r.onError != nil {
				r.onError(ctx, err)
			}
			// Record failure event to each config that was part of the reload
			for _, cfg := range allConfigs.Items {
				if cfg.Spec.Enabled && r.isConfigInList(cfg.Name, validConfigs) {
					if r.recorder != nil {
						r.recorder.Event(&cfg, corev1.EventTypeWarning, "ReloadFailed",
							fmt.Sprintf("Failed to reload audit configuration: %v", err))
					}
				}
			}
			metrics.AuditConfigReloads.WithLabelValues("reload_failed").Inc()
			return reconcile.Result{RequeueAfter: 30 * time.Second}, err
		}
	}

	// Log summary
	var configNames []string
	totalSinks := 0
	for _, cfg := range validConfigs {
		configNames = append(configNames, cfg.Name)
		totalSinks += len(cfg.Spec.Sinks)
	}

	r.logger.Infow("AuditConfigs reconciled successfully (aggregated)",
		"validConfigs", len(validConfigs),
		"configNames", configNames,
		"totalSinks", totalSinks)

	// Send success event to each valid config
	for _, cfg := range allConfigs.Items {
		if cfg.Spec.Enabled && r.isConfigInList(cfg.Name, validConfigs) {
			if r.recorder != nil {
				r.recorder.Event(&cfg, corev1.EventTypeNormal, "Reconciled",
					fmt.Sprintf("AuditConfig %s reconciled successfully (aggregated with %d other configs)", cfg.Name, len(validConfigs)-1))
			}
		}
	}

	metrics.AuditConfigReloads.WithLabelValues("success").Inc()
	return reconcile.Result{RequeueAfter: r.resyncPeriod}, nil
}

// isConfigInList checks if a config name is in the valid configs list
func (r *AuditConfigReconciler) isConfigInList(name string, configs []*breakglassv1alpha1.AuditConfig) bool {
	for _, cfg := range configs {
		if cfg.Name == name {
			return true
		}
	}
	return false
}

// validateConfig validates the AuditConfig and returns a list of errors
func (r *AuditConfigReconciler) validateConfig(ctx context.Context, config *breakglassv1alpha1.AuditConfig) []string {
	var errors []string

	// Validate sinks
	for i, sink := range config.Spec.Sinks {
		sinkErrors := r.validateSink(ctx, sink, i)
		errors = append(errors, sinkErrors...)
	}

	return errors
}

// validateSink validates a single sink configuration
func (r *AuditConfigReconciler) validateSink(ctx context.Context, sink breakglassv1alpha1.AuditSinkConfig, index int) []string {
	var errors []string
	prefix := fmt.Sprintf("sink[%d](%s)", index, sink.Name)

	switch sink.Type {
	case breakglassv1alpha1.AuditSinkTypeKafka:
		if sink.Kafka == nil {
			errors = append(errors, fmt.Sprintf("%s: kafka config required for type=kafka", prefix))
		} else {
			// Validate Kafka config
			if len(sink.Kafka.Brokers) == 0 {
				errors = append(errors, fmt.Sprintf("%s: at least one broker required", prefix))
			}
			if sink.Kafka.Topic == "" {
				errors = append(errors, fmt.Sprintf("%s: topic required", prefix))
			}
			// Validate TLS secret references if TLS enabled
			if sink.Kafka.TLS != nil && sink.Kafka.TLS.Enabled {
				if sink.Kafka.TLS.CASecretRef != nil {
					if err := r.validateSecretExists(ctx, sink.Kafka.TLS.CASecretRef.Name, sink.Kafka.TLS.CASecretRef.Namespace); err != nil {
						errors = append(errors, fmt.Sprintf("%s: CA secret not found: %v", prefix, err))
					}
				}
				if sink.Kafka.TLS.ClientCertSecretRef != nil {
					if err := r.validateSecretExists(ctx, sink.Kafka.TLS.ClientCertSecretRef.Name, sink.Kafka.TLS.ClientCertSecretRef.Namespace); err != nil {
						errors = append(errors, fmt.Sprintf("%s: client cert secret not found: %v", prefix, err))
					}
				}
			}
			// Validate SASL secret reference
			if sink.Kafka.SASL != nil && sink.Kafka.SASL.CredentialsSecretRef.Name != "" {
				if err := r.validateSecretExists(ctx, sink.Kafka.SASL.CredentialsSecretRef.Name, sink.Kafka.SASL.CredentialsSecretRef.Namespace); err != nil {
					errors = append(errors, fmt.Sprintf("%s: SASL credentials secret not found: %v", prefix, err))
				}
			}
		}

	case breakglassv1alpha1.AuditSinkTypeWebhook:
		if sink.Webhook == nil {
			errors = append(errors, fmt.Sprintf("%s: webhook config required for type=webhook", prefix))
		} else {
			if sink.Webhook.URL == "" {
				errors = append(errors, fmt.Sprintf("%s: URL required", prefix))
			}
		}

	case breakglassv1alpha1.AuditSinkTypeLog:
		// Log sink is always valid (uses defaults)

	case breakglassv1alpha1.AuditSinkTypeKubernetes:
		// Kubernetes sink is always valid (uses defaults)

	default:
		errors = append(errors, fmt.Sprintf("%s: unknown sink type: %s", prefix, sink.Type))
	}

	return errors
}

// validateSecretExists checks if a secret exists
func (r *AuditConfigReconciler) validateSecretExists(ctx context.Context, name, namespace string) error {
	secret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, secret); err != nil {
		return err
	}
	return nil
}

// updateStatus updates the AuditConfig status
func (r *AuditConfigReconciler) updateStatus(ctx context.Context, config *breakglassv1alpha1.AuditConfig, validationErrors []string) error {
	// Build conditions based on validation
	var conditions []metav1.Condition

	if len(validationErrors) == 0 {
		conditions = append(conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "ConfigurationValid",
			Message:            "AuditConfig is valid and active",
			LastTransitionTime: metav1.Now(),
		})
	} else {
		conditions = append(conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ValidationFailed",
			Message:            fmt.Sprintf("Validation errors: %v", validationErrors),
			LastTransitionTime: metav1.Now(),
		})
	}

	// Set conditions using apimeta helper
	for _, cond := range conditions {
		apimeta.SetStatusCondition(&config.Status.Conditions, cond)
	}

	// Build list of active sink names
	var activeSinkNames []string
	for _, sink := range config.Spec.Sinks {
		activeSinkNames = append(activeSinkNames, sink.Name)
	}
	config.Status.ActiveSinks = activeSinkNames

	// Update sink health status if provider is available
	if r.getSinkHealth != nil {
		healthInfos := r.getSinkHealth()
		var sinkStatuses []breakglassv1alpha1.AuditSinkStatus
		for _, h := range healthInfos {
			status := breakglassv1alpha1.AuditSinkStatus{
				Name:  h.Name,
				Ready: h.Ready,
			}
			if h.LastError != "" {
				status.LastError = h.LastError
			}
			sinkStatuses = append(sinkStatuses, status)
		}
		config.Status.SinkStatuses = sinkStatuses

		// Add SinksHealthy condition
		allHealthy := true
		unhealthySinks := []string{}
		for _, h := range healthInfos {
			if !h.Ready {
				allHealthy = false
				unhealthySinks = append(unhealthySinks, h.Name)
			}
		}

		if allHealthy {
			apimeta.SetStatusCondition(&config.Status.Conditions, metav1.Condition{
				Type:               "SinksHealthy",
				Status:             metav1.ConditionTrue,
				Reason:             "AllSinksOperational",
				Message:            "All audit sinks are healthy and operational",
				LastTransitionTime: metav1.Now(),
			})
		} else {
			apimeta.SetStatusCondition(&config.Status.Conditions, metav1.Condition{
				Type:               "SinksHealthy",
				Status:             metav1.ConditionFalse,
				Reason:             "SinksUnhealthy",
				Message:            fmt.Sprintf("Unhealthy sinks: %v", unhealthySinks),
				LastTransitionTime: metav1.Now(),
			})
		}
	}

	return r.client.Status().Update(ctx, config)
}

// GetActiveConfig returns the first currently active AuditConfig (thread-safe).
// Deprecated: Use GetActiveConfigs to get all active configs.
func (r *AuditConfigReconciler) GetActiveConfig() *breakglassv1alpha1.AuditConfig {
	r.configMutex.RLock()
	defer r.configMutex.RUnlock()
	if len(r.activeConfigs) == 0 {
		return nil
	}
	return r.activeConfigs[0].DeepCopy()
}

// GetActiveConfigs returns all currently active AuditConfigs (thread-safe)
func (r *AuditConfigReconciler) GetActiveConfigs() []*breakglassv1alpha1.AuditConfig {
	r.configMutex.RLock()
	defer r.configMutex.RUnlock()
	result := make([]*breakglassv1alpha1.AuditConfig, len(r.activeConfigs))
	for i, cfg := range r.activeConfigs {
		result[i] = cfg.DeepCopy()
	}
	return result
}

// SetupWithManager registers this reconciler with the controller-runtime manager.
func (r *AuditConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Predicate to filter events - only reconcile on spec changes, not status updates
	specChangePredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldConfig := e.ObjectOld.(*breakglassv1alpha1.AuditConfig)
			newConfig := e.ObjectNew.(*breakglassv1alpha1.AuditConfig)
			// Only trigger reconcile if generation changed (spec changed)
			return oldConfig.Generation != newConfig.Generation
		},
		CreateFunc: func(e event.CreateEvent) bool { return true },
		DeleteFunc: func(e event.DeleteEvent) bool { return true },
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.AuditConfig{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1, // Process one config at a time
		}).
		WithEventFilter(specChangePredicate).
		Complete(r)
}
