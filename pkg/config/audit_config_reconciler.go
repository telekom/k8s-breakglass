/*
Copyright 2024.

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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
// It reloads the audit sinks when AuditConfig changes are detected.
//
// The reconciler:
// - Watches for AuditConfig CR changes
// - Validates sink configurations
// - Resolves secret references for Kafka TLS/SASL credentials
// - Updates AuditConfig status with validation results
// - Calls onReload callback to reconfigure the audit manager
type AuditConfigReconciler struct {
	client   client.Client
	logger   *zap.SugaredLogger
	recorder record.EventRecorder

	// onReload is called when AuditConfig changes are detected
	onReload func(ctx context.Context, config *breakglassv1alpha1.AuditConfig) error
	// onError is called when reload fails (optional, for metrics/logging)
	onError func(ctx context.Context, err error)
	// resyncPeriod defines the full reconciliation interval (default 10m)
	resyncPeriod time.Duration

	// Cache for the active AuditConfig
	configMutex  sync.RWMutex
	activeConfig *breakglassv1alpha1.AuditConfig
}

// NewAuditConfigReconciler creates a new AuditConfigReconciler instance.
func NewAuditConfigReconciler(
	c client.Client,
	logger *zap.SugaredLogger,
	recorder record.EventRecorder,
	onReload func(ctx context.Context, config *breakglassv1alpha1.AuditConfig) error,
	onError func(ctx context.Context, err error),
	resyncPeriod time.Duration,
) *AuditConfigReconciler {
	if resyncPeriod == 0 {
		resyncPeriod = 10 * time.Minute
	}
	return &AuditConfigReconciler{
		client:       c,
		logger:       logger,
		recorder:     recorder,
		onReload:     onReload,
		onError:      onError,
		resyncPeriod: resyncPeriod,
	}
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=auditconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=auditconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=auditconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements controller-runtime's Reconciler interface.
// Called whenever an AuditConfig CR changes.
func (r *AuditConfigReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugw("Reconciling AuditConfig",
		"name", req.Name,
		"namespace", req.Namespace)

	// Fetch the AuditConfig resource
	auditConfig := &breakglassv1alpha1.AuditConfig{}
	if err := r.client.Get(ctx, req.NamespacedName, auditConfig); err != nil {
		if apierrors.IsNotFound(err) {
			r.logger.Infow("AuditConfig deleted, disabling audit", "name", req.Name)
			r.configMutex.Lock()
			r.activeConfig = nil
			r.configMutex.Unlock()
			// Call onReload with nil to disable auditing
			if r.onReload != nil {
				if err := r.onReload(ctx, nil); err != nil {
					r.logger.Errorw("Failed to disable audit after config deletion", "error", err)
					if r.onError != nil {
						r.onError(ctx, err)
					}
				}
			}
			return reconcile.Result{}, nil
		}
		r.logger.Warnw("Failed to fetch AuditConfig", "error", err)
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	// Validate the configuration
	validationErrors := r.validateConfig(ctx, auditConfig)

	// Update status based on validation
	if err := r.updateStatus(ctx, auditConfig, validationErrors); err != nil {
		r.logger.Errorw("Failed to update AuditConfig status", "error", err)
		return reconcile.Result{}, err
	}

	// If validation failed, don't reload
	if len(validationErrors) > 0 {
		r.logger.Warnw("AuditConfig validation failed", "errors", validationErrors)
		if r.recorder != nil {
			r.recorder.Event(auditConfig, corev1.EventTypeWarning, "ValidationFailed",
				fmt.Sprintf("AuditConfig validation failed: %v", validationErrors))
		}
		metrics.AuditConfigReloads.WithLabelValues("validation_failed").Inc()
		return reconcile.Result{RequeueAfter: r.resyncPeriod}, nil
	}

	// Cache the active config
	r.configMutex.Lock()
	r.activeConfig = auditConfig.DeepCopy()
	r.configMutex.Unlock()

	// Call reload callback
	if r.onReload != nil {
		if err := r.onReload(ctx, auditConfig); err != nil {
			r.logger.Errorw("Failed to reload audit configuration", "error", err)
			if r.onError != nil {
				r.onError(ctx, err)
			}
			if r.recorder != nil {
				r.recorder.Event(auditConfig, corev1.EventTypeWarning, "ReloadFailed",
					fmt.Sprintf("Failed to reload audit configuration: %v", err))
			}
			metrics.AuditConfigReloads.WithLabelValues("reload_failed").Inc()
			return reconcile.Result{RequeueAfter: 30 * time.Second}, err
		}
	}

	r.logger.Infow("AuditConfig reconciled successfully", "name", auditConfig.Name, "enabled", auditConfig.Spec.Enabled)
	if r.recorder != nil {
		r.recorder.Event(auditConfig, corev1.EventTypeNormal, "Reconciled",
			fmt.Sprintf("AuditConfig %s reconciled successfully", auditConfig.Name))
	}
	metrics.AuditConfigReloads.WithLabelValues("success").Inc()

	return reconcile.Result{RequeueAfter: r.resyncPeriod}, nil
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

	return r.client.Status().Update(ctx, config)
}

// GetActiveConfig returns the currently active AuditConfig (thread-safe)
func (r *AuditConfigReconciler) GetActiveConfig() *breakglassv1alpha1.AuditConfig {
	r.configMutex.RLock()
	defer r.configMutex.RUnlock()
	if r.activeConfig == nil {
		return nil
	}
	return r.activeConfig.DeepCopy()
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
