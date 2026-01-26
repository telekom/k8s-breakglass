package breakglass

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterConfigChecker periodically validates that ClusterConfig resources reference
// a secret containing the expected `kubeconfig` key. It logs Info when configs are valid
// and Warn when a secret or the key is missing so operators can remediate.
type ClusterConfigChecker struct {
	Log           *zap.SugaredLogger
	Client        client.Client
	Interval      time.Duration
	Recorder      events.EventRecorder
	LeaderElected <-chan struct{} // Optional: signal when leadership acquired (nil = start immediately for backward compatibility)
}

const ClusterConfigCheckInterval = 10 * time.Minute

func (ccc ClusterConfigChecker) Start(ctx context.Context) {
	// Ensure we always have a logger to avoid nil deref
	lg := ccc.Log
	interval := ccc.Interval

	// Wait for leadership signal if provided (enables multi-replica scaling with leader election)
	if ccc.LeaderElected != nil {
		lg.Info("Cluster config checker waiting for leadership signal before starting...")
		select {
		case <-ctx.Done():
			lg.Info("Cluster config checker stopping before acquiring leadership (context cancelled)")
			return
		case <-ccc.LeaderElected:
			lg.Info("Leadership acquired - starting cluster config checker")
		}
	}

	if interval == 0 {
		interval = ClusterConfigCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			lg.Info("ClusterConfigChecker stopping (context canceled)")
			return
		default:
		}
		ccc.runOnce(ctx, lg)
		select {
		case <-ctx.Done():
			lg.Info("ClusterConfigChecker stopping (context canceled)")
			return
		case <-ticker.C:
		}
	}
}

func (ccc ClusterConfigChecker) runOnce(ctx context.Context, lg *zap.SugaredLogger) {
	lg.Debug("Running ClusterConfig validation check")
	list := telekomv1alpha1.ClusterConfigList{}
	if err := ccc.Client.List(ctx, &list); err != nil {
		lg.With("error", err).Error("Failed to list ClusterConfig resources for validation")
		return
	}
	for _, item := range list.Items {
		// take address of local copy to avoid pointer-to-loop-variable issue
		cc := item
		// metric: one check attempted (label by cluster name)
		metrics.ClusterConfigsChecked.WithLabelValues(cc.Name).Inc()

		// Perform structural validation using shared validation function.
		// This catches malformed resources that somehow bypassed the admission webhook.
		validationResult := telekomv1alpha1.ValidateClusterConfig(&cc)
		if !validationResult.IsValid() {
			msg := "ClusterConfig failed structural validation: " + validationResult.ErrorMessage()
			lg.Warnw(msg, "cluster", cc.Name)
			if err2 := ccc.setStatusAndEvent(ctx, &cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}

		// Determine auth type and validate accordingly
		authType := cc.Spec.AuthType
		if authType == "" {
			// Default to kubeconfig for backward compatibility
			authType = telekomv1alpha1.ClusterAuthTypeKubeconfig
		}

		var restCfg *rest.Config
		var authValidationErr error
		var successMsg string

		switch authType {
		case telekomv1alpha1.ClusterAuthTypeOIDC:
			restCfg, authValidationErr = ccc.validateOIDCAuth(ctx, &cc, lg)
			successMsg = "OIDC auth validated and cluster reachable"
		default:
			restCfg, authValidationErr = ccc.validateKubeconfigAuth(ctx, &cc, lg)
			successMsg = "Kubeconfig validated and cluster reachable"
		}

		if authValidationErr != nil {
			// Error already logged and status updated in validation function
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}

		// discovery client to attempt server version call
		if err := CheckClusterReachable(restCfg); err != nil {
			msg := "cluster unreachable: " + err.Error()
			lg.Warnw(msg, "cluster", cc.Name)
			if err2 := ccc.setStatusAndEvent(ctx, &cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			metrics.ClusterConfigsFailed.WithLabelValues(cc.Name).Inc()
			continue
		}

		// Success: update status Ready and emit Normal event
		if err2 := ccc.setStatusAndEvent(ctx, &cc, "Ready", successMsg, corev1.EventTypeNormal, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
	}
	lg.Debug("ClusterConfig validation check completed")
}

// validateKubeconfigAuth validates kubeconfig-based authentication and returns a rest.Config
func (ccc ClusterConfigChecker) validateKubeconfigAuth(ctx context.Context, cc *telekomv1alpha1.ClusterConfig, lg *zap.SugaredLogger) (*rest.Config, error) {
	ref := cc.Spec.KubeconfigSecretRef
	if ref == nil || ref.Name == "" || ref.Namespace == "" {
		msg := "ClusterConfig has no kubeconfigSecretRef configured"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"namespace", cc.Namespace)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}
	// fetch secret
	key := client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
	sec := corev1.Secret{}
	if err := ccc.Client.Get(ctx, key, &sec); err != nil {
		msg := "Referenced kubeconfig secret missing or unreadable"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"secret", ref.Name,
			"secretNamespace", ref.Namespace,
			"error", err)
		// update status and emit event
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg+": "+err.Error(), corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}
	// check for kubeconfig key (cluster-api provides key 'value')
	keyName := "value"
	if ref.Key != "" {
		keyName = ref.Key
	}
	if _, ok := sec.Data[keyName]; !ok {
		// If secret exists but missing key, warn with metadata
		msg := "Referenced kubeconfig secret missing key: " + keyName
		lg.Warnw(msg,
			"cluster", cc.Name,
			"secret", ref.Name,
			"secretNamespace", ref.Namespace,
			"secretCreation", sec.CreationTimestamp.Time.Format(time.RFC3339))
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}
	// Good: secret exists and has key
	lg.Debugw("ClusterConfig kubeconfig validated",
		"cluster", cc.Name,
		"secret", ref.Name,
		"secretNamespace", ref.Namespace)

	// Try to parse kubeconfig and attempt a simple discovery to verify reachability
	kubecfgBytes := sec.Data[keyName]
	// Build rest.Config from kubeconfig bytes via overridable function for testing
	restCfg, err := RestConfigFromKubeConfig(kubecfgBytes)
	if err != nil {
		msg := "kubeconfig parse failed: " + err.Error()
		lg.Warnw(msg, "cluster", cc.Name)
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}
	return restCfg, nil
}

// validateOIDCAuth validates OIDC-based authentication and returns a rest.Config.
// It supports both direct oidcAuth configuration and oidcFromIdentityProvider references.
func (ccc ClusterConfigChecker) validateOIDCAuth(ctx context.Context, cc *telekomv1alpha1.ClusterConfig, lg *zap.SugaredLogger) (*rest.Config, error) {
	// Check if we have either oidcAuth or oidcFromIdentityProvider
	hasOIDCAuth := cc.Spec.OIDCAuth != nil
	hasOIDCFromIDP := cc.Spec.OIDCFromIdentityProvider != nil

	if !hasOIDCAuth && !hasOIDCFromIDP {
		msg := "ClusterConfig has authType=oidc but neither oidcAuth nor oidcFromIdentityProvider configured"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"namespace", cc.Namespace)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Validate based on which config type is used
	if hasOIDCFromIDP {
		return ccc.validateOIDCFromIdentityProvider(ctx, cc, lg)
	}

	return ccc.validateDirectOIDCAuth(ctx, cc, lg)
}

// validateOIDCFromIdentityProvider validates OIDC config that references an IdentityProvider
func (ccc ClusterConfigChecker) validateOIDCFromIdentityProvider(ctx context.Context, cc *telekomv1alpha1.ClusterConfig, lg *zap.SugaredLogger) (*rest.Config, error) {
	ref := cc.Spec.OIDCFromIdentityProvider

	// Validate required fields
	if ref.Name == "" || ref.Server == "" {
		msg := "oidcFromIdentityProvider missing required fields (name or server)"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"identityProviderRef", ref.Name,
			"server", ref.Server)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Fetch and validate the referenced IdentityProvider
	idp := &telekomv1alpha1.IdentityProvider{}
	if err := ccc.Client.Get(ctx, client.ObjectKey{Name: ref.Name}, idp); err != nil {
		msg := fmt.Sprintf("Referenced IdentityProvider %q not found or unreadable", ref.Name)
		lg.Warnw(msg,
			"cluster", cc.Name,
			"identityProvider", ref.Name,
			"error", err)
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}

	// Check if IdentityProvider is disabled
	if idp.Spec.Disabled {
		msg := fmt.Sprintf("Referenced IdentityProvider %q is disabled", ref.Name)
		lg.Warnw(msg, "cluster", cc.Name, "identityProvider", ref.Name)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Determine which client secret to use
	secretRef := ref.ClientSecretRef
	if secretRef == nil && idp.Spec.Keycloak != nil {
		// Use Keycloak service account credentials if no explicit secret provided
		secretRef = &idp.Spec.Keycloak.ClientSecretRef
	}
	if secretRef == nil {
		msg := "oidcFromIdentityProvider requires clientSecretRef or IdentityProvider must have Keycloak service account configured"
		lg.Warnw(msg, "cluster", cc.Name, "identityProvider", ref.Name)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Validate client secret exists
	key := client.ObjectKey{Namespace: secretRef.Namespace, Name: secretRef.Name}
	sec := corev1.Secret{}
	if err := ccc.Client.Get(ctx, key, &sec); err != nil {
		msg := "Referenced OIDC client secret missing or unreadable"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"secret", secretRef.Name,
			"secretNamespace", secretRef.Namespace,
			"error", err)
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg+": "+err.Error(), corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}

	// Check for secret key
	keyName := secretRef.Key
	if keyName == "" {
		keyName = "client-secret"
	}
	if _, ok := sec.Data[keyName]; !ok {
		msg := "Referenced OIDC client secret missing key: " + keyName
		lg.Warnw(msg,
			"cluster", cc.Name,
			"secret", secretRef.Name,
			"secretNamespace", secretRef.Namespace)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Check cluster CA secret exists if configured
	// NOTE: We don't fail if the CA key is missing - the OIDCTokenProvider supports TOFU
	// (Trust On First Use) which will auto-discover the CA and persist it to the secret
	if ref.CASecretRef != nil {
		caKey := client.ObjectKey{Namespace: ref.CASecretRef.Namespace, Name: ref.CASecretRef.Name}
		caSec := corev1.Secret{}
		if err := ccc.Client.Get(ctx, caKey, &caSec); err != nil {
			// Secret doesn't exist at all - this is an error (we need a place to persist TOFU CA)
			msg := "Referenced cluster CA secret missing or unreadable"
			lg.Warnw(msg,
				"cluster", cc.Name,
				"secret", ref.CASecretRef.Name,
				"secretNamespace", ref.CASecretRef.Namespace,
				"error", err)
			if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg+": "+err.Error(), corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			return nil, err
		}
		// Note: We intentionally don't check if the CA key exists in the secret.
		// If the secret exists but the key is missing, TOFU will discover the CA
		// and persist it to this secret. See pkg/cluster/oidc.go configureTLS().
		caKeyName := ref.CASecretRef.Key
		if caKeyName == "" {
			caKeyName = "ca.crt"
		}
		if _, ok := caSec.Data[caKeyName]; !ok {
			lg.Infow("CA key not found in secret, TOFU will attempt to discover and persist",
				"cluster", cc.Name,
				"secret", ref.CASecretRef.Name,
				"secretNamespace", ref.CASecretRef.Namespace,
				"key", caKeyName)
		}
	}

	lg.Debugw("ClusterConfig OIDC from IdentityProvider validated",
		"cluster", cc.Name,
		"identityProvider", ref.Name,
		"server", ref.Server)

	// Use the OIDCTokenProvider to get a rest.Config - it handles resolving the IdentityProvider
	tokenProvider := cluster.NewOIDCTokenProvider(ccc.Client, lg)
	restCfg, err := tokenProvider.GetRESTConfig(ctx, cc)
	if err != nil {
		msg := "Failed to build OIDC rest config: " + err.Error()
		lg.Warnw(msg, "cluster", cc.Name)
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}

	return restCfg, nil
}

// validateDirectOIDCAuth validates direct oidcAuth configuration
func (ccc ClusterConfigChecker) validateDirectOIDCAuth(ctx context.Context, cc *telekomv1alpha1.ClusterConfig, lg *zap.SugaredLogger) (*rest.Config, error) {
	oidcConfig := cc.Spec.OIDCAuth

	// Validate required fields
	if oidcConfig.IssuerURL == "" || oidcConfig.ClientID == "" || oidcConfig.Server == "" {
		msg := "OIDC config missing required fields (issuerURL, clientID, or server)"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"issuerURL", oidcConfig.IssuerURL,
			"clientID", oidcConfig.ClientID,
			"server", oidcConfig.Server)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Fetch client secret if configured (required for client credentials flow)
	if oidcConfig.ClientSecretRef == nil {
		msg := "OIDC config missing clientSecretRef (required for client credentials flow)"
		lg.Warnw(msg, "cluster", cc.Name)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	secretRef := oidcConfig.ClientSecretRef
	key := client.ObjectKey{Namespace: secretRef.Namespace, Name: secretRef.Name}
	sec := corev1.Secret{}
	if err := ccc.Client.Get(ctx, key, &sec); err != nil {
		msg := "Referenced OIDC client secret missing or unreadable"
		lg.Warnw(msg,
			"cluster", cc.Name,
			"secret", secretRef.Name,
			"secretNamespace", secretRef.Namespace,
			"error", err)
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg+": "+err.Error(), corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}

	// Check for secret key
	keyName := secretRef.Key
	if keyName == "" {
		keyName = "client-secret"
	}
	if _, ok := sec.Data[keyName]; !ok {
		msg := "Referenced OIDC client secret missing key: " + keyName
		lg.Warnw(msg,
			"cluster", cc.Name,
			"secret", secretRef.Name,
			"secretNamespace", secretRef.Namespace)
		if err := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err)
		}
		return nil, errors.New(msg)
	}

	// Check CA certificate secret exists if configured
	// NOTE: We don't fail if the CA key is missing - the OIDCTokenProvider supports TOFU
	// (Trust On First Use) which will auto-discover the CA and persist it to the secret
	if oidcConfig.CASecretRef != nil {
		caKey := client.ObjectKey{Namespace: oidcConfig.CASecretRef.Namespace, Name: oidcConfig.CASecretRef.Name}
		caSec := corev1.Secret{}
		if err := ccc.Client.Get(ctx, caKey, &caSec); err != nil {
			// Secret doesn't exist at all - this is an error (we need a place to persist TOFU CA)
			msg := "Referenced cluster CA secret missing or unreadable"
			lg.Warnw(msg,
				"cluster", cc.Name,
				"secret", oidcConfig.CASecretRef.Name,
				"secretNamespace", oidcConfig.CASecretRef.Namespace,
				"error", err)
			if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg+": "+err.Error(), corev1.EventTypeWarning, lg); err2 != nil {
				lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
			}
			return nil, err
		}
		// Note: We intentionally don't check if the CA key exists in the secret.
		// If the secret exists but the key is missing, TOFU will discover the CA
		// and persist it to this secret. See pkg/cluster/oidc.go configureTLS().
		caKeyName := oidcConfig.CASecretRef.Key
		if caKeyName == "" {
			caKeyName = "ca.crt"
		}
		if _, ok := caSec.Data[caKeyName]; !ok {
			lg.Infow("CA key not found in secret, TOFU will attempt to discover and persist",
				"cluster", cc.Name,
				"secret", oidcConfig.CASecretRef.Name,
				"secretNamespace", oidcConfig.CASecretRef.Namespace,
				"key", caKeyName)
		}
	}

	lg.Debugw("ClusterConfig OIDC config validated",
		"cluster", cc.Name,
		"issuerURL", oidcConfig.IssuerURL,
		"clientID", oidcConfig.ClientID,
		"server", oidcConfig.Server)

	// Use the OIDCTokenProvider to get a rest.Config and validate we can get a token
	tokenProvider := cluster.NewOIDCTokenProvider(ccc.Client, lg)
	restCfg, err := tokenProvider.GetRESTConfig(ctx, cc)
	if err != nil {
		msg := "Failed to build OIDC rest config: " + err.Error()
		lg.Warnw(msg, "cluster", cc.Name)
		if err2 := ccc.setStatusAndEvent(ctx, cc, "Failed", msg, corev1.EventTypeWarning, lg); err2 != nil {
			lg.Warnw("failed to persist status/event for ClusterConfig", "cluster", cc.Name, "error", err2)
		}
		return nil, err
	}

	return restCfg, nil
}

func (ccc ClusterConfigChecker) setStatusAndEvent(ctx context.Context, cc *telekomv1alpha1.ClusterConfig, phase, message, eventType string, lg *zap.SugaredLogger) error {
	// Determine condition status and reason first for skip check
	isSuccess := phase == "Ready"
	failureType := ""
	if !isSuccess {
		failureType = determineClusterConfigFailureType(message)
	}

	// Determine if this is OIDC auth
	authType := cc.Spec.AuthType
	isOIDC := authType == telekomv1alpha1.ClusterAuthTypeOIDC

	// Determine condition status and reason
	var conditionStatus metav1.ConditionStatus
	var conditionReason telekomv1alpha1.ClusterConfigConditionReason

	if isSuccess {
		conditionStatus = metav1.ConditionTrue
		if isOIDC {
			conditionReason = telekomv1alpha1.ClusterConfigReasonOIDCValidated
		} else {
			conditionReason = telekomv1alpha1.ClusterConfigReasonKubeconfigValidated
		}
	} else {
		conditionStatus = metav1.ConditionFalse
		switch failureType {
		// OIDC-specific reasons
		case "oidc_discovery":
			conditionReason = telekomv1alpha1.ClusterConfigReasonOIDCDiscoveryFailed
		case "oidc_token":
			conditionReason = telekomv1alpha1.ClusterConfigReasonOIDCTokenFailed
		case "oidc_refresh":
			conditionReason = telekomv1alpha1.ClusterConfigReasonOIDCRefreshFailed
		case "oidc_config":
			conditionReason = telekomv1alpha1.ClusterConfigReasonOIDCConfigMissing
		case "oidc_ca_missing":
			conditionReason = telekomv1alpha1.ClusterConfigReasonOIDCCAMissing
		case "tofu":
			conditionReason = telekomv1alpha1.ClusterConfigReasonTOFUFailed
		// Kubeconfig-specific reasons
		case "secret_missing":
			conditionReason = telekomv1alpha1.ClusterConfigReasonSecretMissing
		case "secret_key_missing":
			conditionReason = telekomv1alpha1.ClusterConfigReasonSecretKeyMissing
		case "parse":
			conditionReason = telekomv1alpha1.ClusterConfigReasonKubeconfigInvalid
		case "connection":
			conditionReason = telekomv1alpha1.ClusterConfigReasonClusterUnreachable
		default:
			conditionReason = telekomv1alpha1.ClusterConfigReasonValidationFailed
		}
	}

	// Re-fetch the object to get the latest version and check if we should skip
	var latest telekomv1alpha1.ClusterConfig
	if err := ccc.Client.Get(ctx, client.ObjectKeyFromObject(cc), &latest); err != nil {
		if apierrors.IsNotFound(err) {
			lg.Debugw("ClusterConfig deleted before status update, skipping", "cluster", cc.Name)
			return nil
		}
		lg.Warnw("Failed to re-fetch ClusterConfig for status update", "cluster", cc.Name, "error", err)
		return err
	}

	// Use StatusCoordinator to check if we should skip the status update
	coordinator := utils.NewStatusCoordinator()
	skipInfo := coordinator.ShouldSkipStatusUpdateDetailed(
		latest.Status.Conditions,
		string(telekomv1alpha1.ClusterConfigConditionReady),
		conditionStatus,
		string(conditionReason),
	)
	if skipInfo.Skipped {
		lg.Debugw("ClusterConfig status recently updated, skipping",
			"cluster", cc.Name,
			"skipReason", skipInfo.Reason,
			"lastUpdateAge", skipInfo.LastUpdateAge,
		)
		if ccc.Recorder != nil {
			ccc.Recorder.Eventf(&latest, nil, corev1.EventTypeNormal, "StatusUpdateSkipped", "StatusUpdateSkipped",
				"Skipped status update: %s (last update %v ago)", skipInfo.Reason, skipInfo.LastUpdateAge.Truncate(time.Second))
		}
		return nil
	}

	// update status with conditions
	now := metav1.Now()

	// Update condition with typed constant
	condition := metav1.Condition{
		Type:               string(telekomv1alpha1.ClusterConfigConditionReady),
		Status:             conditionStatus,
		ObservedGeneration: latest.Generation,
		Reason:             string(conditionReason),
		Message:            message,
		LastTransitionTime: now,
	}
	apimeta.SetStatusCondition(&latest.Status.Conditions, condition)
	latest.Status.ObservedGeneration = latest.Generation

	// Persist status using Status().Update() since ClusterConfig has status subresource enabled.
	// When the status subresource is enabled, the main Update() endpoint ignores status changes.
	if err := ccc.Client.Status().Update(ctx, &latest); err != nil {
		if apierrors.IsConflict(err) {
			lg.Debugw("Conflict updating ClusterConfig status, another controller likely handled it", "cluster", cc.Name)
			return nil
		}
		lg.Warnw("failed to update ClusterConfig status", "cluster", cc.Name, "error", err)
		return err
	}
	lg.Debugw("ClusterConfig status updated successfully", "cluster", cc.Name, "ready", isSuccess)
	// emit event if recorder present
	if ccc.Recorder != nil {
		eventReason := "ClusterConfigValidationFailed"
		if isSuccess {
			eventReason = "ClusterConfigValidationSucceeded"
			lg.Debugw("Emitting Normal event for ClusterConfig", "cluster", cc.Name, "message", message)
		} else {
			lg.Debugw("Emitting Warning event for ClusterConfig", "cluster", cc.Name, "message", message)
		}
		ccc.Recorder.Eventf(&latest, nil, eventType, eventReason, eventReason, "%s", message)
	} else {
		lg.Warnw("No Event recorder configured; skipping Kubernetes Event emission", "cluster", cc.Name)
	}
	return nil
}

// checkClusterReachable tries to perform a simple discovery (server version) to ensure the cluster is reachable
func checkClusterReachable(cfg *rest.Config) error {
	d, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return err
	}
	_, err = d.ServerVersion()
	return err
}

// StatusUpdateHelper provides methods to update ClusterConfig status with complete state exposure
type StatusUpdateHelper struct {
	message   string
	eventType string // "Normal" or "Warning"
	phase     string // "Ready" or "Failed"
}

// NewStatusUpdateHelper creates a new helper for standardized status updates
func NewStatusUpdateHelper(phase, message, eventType string) *StatusUpdateHelper {
	return &StatusUpdateHelper{
		phase:     phase,
		message:   message,
		eventType: eventType,
	}
}

// DescribeFailure provides a human-readable description of what failed and why
func DescribeFailure(failureType, message string) (failureCategory, advice string) {
	switch failureType {
	// OIDC-specific failures
	case "oidc_discovery":
		return "oidc_discovery_failed", fmt.Sprintf("OIDC discovery failed. Check issuer URL is correct and reachable. Error: %s", message)
	case "oidc_token":
		return "oidc_token_failed", fmt.Sprintf("Failed to obtain OIDC token. Check client ID/secret and issuer configuration. Error: %s", message)
	case "oidc_refresh":
		return "oidc_refresh_failed", fmt.Sprintf("Failed to refresh OIDC token. Token may have been revoked. Error: %s", message)
	case "oidc_config":
		return "oidc_config_missing", "OIDC configuration is incomplete. Ensure issuerURL, clientID, and server are set."
	case "oidc_ca_missing":
		return "oidc_ca_secret_missing", "Referenced cluster CA secret doesn't exist or is inaccessible. Check caSecretRef."
	case "tofu":
		return "tofu_failed", fmt.Sprintf("TOFU (Trust On First Use) failed. Could not fetch API server certificate. Error: %s", message)
	// Kubeconfig-specific failures
	case "connection":
		return "connection_failed", fmt.Sprintf("Cluster is unreachable. Check network connectivity and cluster status. Error: %s", message)
	case "parse":
		return "kubeconfig_parse_error", fmt.Sprintf("Kubeconfig is invalid or malformed. Verify the secret data. Error: %s", message)
	case "secret_missing":
		return "secret_not_found", "Referenced kubeconfig secret doesn't exist or is inaccessible. Check secret name and namespace."
	case "secret_key_missing":
		return "secret_key_missing", "Kubeconfig secret exists but is missing the required key. Check secret data keys."
	case "not_configured":
		return "not_configured", "ClusterConfig.spec.kubeconfigSecretRef is not configured. Configure the secret reference."
	default:
		return "validation_failed", fmt.Sprintf("Configuration validation failed: %s", message)
	}
}

// determineClusterConfigFailureType categorizes the failure message to populate appropriate status fields
func determineClusterConfigFailureType(message string) string {
	lowerMsg := strings.ToLower(message)
	switch {
	// OIDC-specific failures
	case strings.Contains(lowerMsg, "oidc") && strings.Contains(lowerMsg, "discovery"):
		return "oidc_discovery"
	case strings.Contains(lowerMsg, "oidc") && strings.Contains(lowerMsg, "token"):
		return "oidc_token"
	case strings.Contains(lowerMsg, "refresh"):
		return "oidc_refresh"
	case strings.Contains(lowerMsg, "tofu"):
		return "tofu"
	case strings.Contains(lowerMsg, "oidc") && strings.Contains(lowerMsg, "config"):
		return "oidc_config"
	case strings.Contains(lowerMsg, "ca secret") || (strings.Contains(lowerMsg, "ca") && strings.Contains(lowerMsg, "missing")):
		return "oidc_ca_missing"
	// Kubeconfig-specific failures
	case strings.Contains(message, "secret missing") || strings.Contains(message, "not found"):
		return "secret_missing"
	case strings.Contains(message, "missing key"):
		return "secret_key_missing"
	case strings.Contains(message, "parse failed"):
		return "parse"
	case strings.Contains(message, "unreachable") || strings.Contains(message, "dial"):
		return "connection"
	default:
		return "validation"
	}
}

// overridable function variables for unit testing
var RestConfigFromKubeConfig = clientcmd.RESTConfigFromKubeConfig
var CheckClusterReachable = func(cfg *rest.Config) error { return checkClusterReachable(cfg) }

// Fallback: attempt to build rest.Config via clientcmd
