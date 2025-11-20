package config

import (
	"context"
	"fmt"
	"net/smtp"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// MailProviderReconciler reconciles a MailProvider object
type MailProviderReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    *zap.SugaredLogger
	Loader *MailProviderLoader

	// Callbacks for notifying other components of changes
	OnMailProviderChange func(providerName string)
}

// Reconcile handles MailProvider create/update/delete events
func (r *MailProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("mailprovider", req.Name)
	log.Debug("Reconciling MailProvider")

	var mp breakglassv1alpha1.MailProvider
	if err := r.Get(ctx, req.NamespacedName, &mp); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("MailProvider deleted, invalidating cache")
			if r.Loader != nil {
				r.Loader.InvalidateCache(req.Name)
			}
			if r.OnMailProviderChange != nil {
				r.OnMailProviderChange(req.Name)
			}
			return reconcile.Result{}, nil
		}
		log.Errorw("Failed to get MailProvider", "error", err)
		return reconcile.Result{}, err
	}

	// Update metrics
	if mp.Spec.Disabled {
		metrics.MailProviderConfigured.WithLabelValues(mp.Name, "disabled").Set(0)
	} else {
		metrics.MailProviderConfigured.WithLabelValues(mp.Name, "enabled").Set(1)
	}

	// If disabled, just mark as not ready and return
	if mp.Spec.Disabled {
		return r.updateStatusDisabled(ctx, &mp)
	}

	// Perform health check
	healthy, healthErr := r.performHealthCheck(ctx, &mp)

	// Update status based on health check
	if healthy {
		return r.updateStatusHealthy(ctx, &mp)
	} else {
		return r.updateStatusUnhealthy(ctx, &mp, healthErr)
	}
}

// performHealthCheck checks if the mail provider is reachable and functional
func (r *MailProviderReconciler) performHealthCheck(ctx context.Context, mp *breakglassv1alpha1.MailProvider) (bool, error) {
	log := r.Log.With("mailprovider", mp.Name)

	// Load password if needed
	var password string
	if mp.Spec.SMTP.PasswordRef != nil {
		var err error
		password, err = r.getSecretValue(ctx, mp.Spec.SMTP.PasswordRef)
		if err != nil {
			log.Warnw("Failed to load SMTP password", "error", err)
			metrics.MailProviderHealthCheck.WithLabelValues(mp.Name, "password_load_failed").Inc()
			return false, fmt.Errorf("failed to load password: %w", err)
		}
	}

	// Try to connect to SMTP server
	addr := fmt.Sprintf("%s:%d", mp.Spec.SMTP.Host, mp.Spec.SMTP.Port)

	log.Debugw("Performing SMTP health check", "addr", addr)

	// Use a short timeout for health checks
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Simple connection test
	client, err := smtp.Dial(addr)
	if err != nil {
		log.Warnw("SMTP connection failed", "error", err)
		metrics.MailProviderHealthCheck.WithLabelValues(mp.Name, "connection_failed").Inc()
		return false, fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// Try STARTTLS if not using insecure
	if !mp.Spec.SMTP.InsecureSkipVerify {
		if err := client.StartTLS(nil); err != nil {
			// STARTTLS might not be supported, log but don't fail
			log.Debugw("STARTTLS not available", "error", err)
		}
	}

	// Try authentication if username is provided
	if mp.Spec.SMTP.Username != "" && password != "" {
		auth := smtp.PlainAuth("", mp.Spec.SMTP.Username, password, mp.Spec.SMTP.Host)
		if err := client.Auth(auth); err != nil {
			log.Warnw("SMTP authentication failed", "error", err)
			metrics.MailProviderHealthCheck.WithLabelValues(mp.Name, "auth_failed").Inc()
			return false, fmt.Errorf("authentication failed: %w", err)
		}
	}

	select {
	case <-checkCtx.Done():
		log.Warn("Health check timeout")
		metrics.MailProviderHealthCheck.WithLabelValues(mp.Name, "timeout").Inc()
		return false, fmt.Errorf("health check timeout")
	default:
	}

	log.Info("Health check passed")
	metrics.MailProviderHealthCheck.WithLabelValues(mp.Name, "success").Inc()

	// Invalidate cache to force reload with new config
	if r.Loader != nil {
		r.Loader.InvalidateCache(mp.Name)
	}

	// Notify other components
	if r.OnMailProviderChange != nil {
		r.OnMailProviderChange(mp.Name)
	}

	return true, nil
}

// updateStatusHealthy updates the status to indicate the provider is healthy
func (r *MailProviderReconciler) updateStatusHealthy(ctx context.Context, mp *breakglassv1alpha1.MailProvider) (ctrl.Result, error) {
	now := metav1.Now()

	mp.Status.LastHealthCheck = &now
	mp.Status.LastSendError = ""

	// Update conditions
	mp.Status.Conditions = r.updateCondition(mp.Status.Conditions,
		metav1.Condition{
			Type:               string(breakglassv1alpha1.MailProviderConditionReady),
			Status:             metav1.ConditionTrue,
			Reason:             "Configured",
			Message:            "MailProvider is configured and ready",
			LastTransitionTime: metav1.Now(),
		})

	mp.Status.Conditions = r.updateCondition(mp.Status.Conditions,
		metav1.Condition{
			Type:               string(breakglassv1alpha1.MailProviderConditionHealthy),
			Status:             metav1.ConditionTrue,
			Reason:             "HealthCheckPassed",
			Message:            "SMTP server is reachable and accepting connections",
			LastTransitionTime: metav1.Now(),
		})

	if mp.Spec.SMTP.PasswordRef != nil {
		mp.Status.Conditions = r.updateCondition(mp.Status.Conditions,
			metav1.Condition{
				Type:               string(breakglassv1alpha1.MailProviderConditionPasswordLoaded),
				Status:             metav1.ConditionTrue,
				Reason:             "SecretLoaded",
				Message:            "Password successfully loaded from secret",
				LastTransitionTime: metav1.Now(),
			})
	}

	if err := r.Status().Update(ctx, mp); err != nil {
		r.Log.Errorw("Failed to update status", "mailprovider", mp.Name, "error", err)
		return reconcile.Result{}, err
	}

	// Requeue for periodic health check (every 5 minutes)
	return reconcile.Result{RequeueAfter: 5 * time.Minute}, nil
}

// updateStatusUnhealthy updates the status to indicate the provider is unhealthy
func (r *MailProviderReconciler) updateStatusUnhealthy(ctx context.Context, mp *breakglassv1alpha1.MailProvider, healthErr error) (ctrl.Result, error) {
	mp.Status.LastSendError = healthErr.Error()

	mp.Status.Conditions = r.updateCondition(mp.Status.Conditions,
		metav1.Condition{
			Type:               string(breakglassv1alpha1.MailProviderConditionReady),
			Status:             metav1.ConditionFalse,
			Reason:             "HealthCheckFailed",
			Message:            fmt.Sprintf("Health check failed: %v", healthErr),
			LastTransitionTime: metav1.Now(),
		})

	mp.Status.Conditions = r.updateCondition(mp.Status.Conditions,
		metav1.Condition{
			Type:               string(breakglassv1alpha1.MailProviderConditionHealthy),
			Status:             metav1.ConditionFalse,
			Reason:             "Unhealthy",
			Message:            healthErr.Error(),
			LastTransitionTime: metav1.Now(),
		})

	if err := r.Status().Update(ctx, mp); err != nil {
		r.Log.Errorw("Failed to update status", "mailprovider", mp.Name, "error", err)
		return reconcile.Result{}, err
	}

	// Retry health check sooner when unhealthy (30 seconds)
	return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
}

// updateStatusDisabled updates the status to indicate the provider is disabled
func (r *MailProviderReconciler) updateStatusDisabled(ctx context.Context, mp *breakglassv1alpha1.MailProvider) (ctrl.Result, error) {
	mp.Status.Conditions = r.updateCondition(mp.Status.Conditions,
		metav1.Condition{
			Type:               string(breakglassv1alpha1.MailProviderConditionReady),
			Status:             metav1.ConditionFalse,
			Reason:             "Disabled",
			Message:            "MailProvider is disabled",
			LastTransitionTime: metav1.Now(),
		})

	if err := r.Status().Update(ctx, mp); err != nil {
		r.Log.Errorw("Failed to update status", "mailprovider", mp.Name, "error", err)
		return reconcile.Result{}, err
	}

	// No need to requeue disabled providers
	return reconcile.Result{}, nil
}

// updateCondition updates or adds a condition to the conditions list
func (r *MailProviderReconciler) updateCondition(conditions []metav1.Condition, newCondition metav1.Condition) []metav1.Condition {
	for i, condition := range conditions {
		if condition.Type == newCondition.Type {
			// Only update if status changed
			if condition.Status != newCondition.Status {
				conditions[i] = newCondition
			}
			return conditions
		}
	}
	// Condition not found, append
	return append(conditions, newCondition)
}

// getSecretValue retrieves a value from a Kubernetes Secret
func (r *MailProviderReconciler) getSecretValue(ctx context.Context, ref *breakglassv1alpha1.SecretKeyReference) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("secret reference is nil")
	}

	var secret corev1.Secret
	secretKey := client.ObjectKey{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}

	if err := r.Get(ctx, secretKey, &secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	key := ref.Key
	if key == "" {
		key = "password" // Default key
	}

	value, exists := secret.Data[key]
	if !exists {
		return "", fmt.Errorf("key %s not found in secret %s/%s", key, ref.Namespace, ref.Name)
	}

	return string(value), nil
}

// SetupWithManager sets up the controller with the Manager
func (r *MailProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&breakglassv1alpha1.MailProvider{}).
		Complete(r)
}
