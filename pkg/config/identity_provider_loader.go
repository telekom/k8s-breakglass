package config

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
)

// ConversionErrorMetricsRecorder is a callback to record conversion failure metrics
// idpName: name of the IdentityProvider that failed conversion
// failureReason: categorized reason (missing_field, invalid_config, parse_error, etc.)
type ConversionErrorMetricsRecorder func(idpName, failureReason string)

// IdentityProviderLoader handles loading identity provider configuration from Kubernetes CRs
type IdentityProviderLoader struct {
	kubeClient      client.Client
	logger          *zap.SugaredLogger
	metricsRecorder ConversionErrorMetricsRecorder
}

// NewIdentityProviderLoader creates a new IdentityProviderLoader
func NewIdentityProviderLoader(kubeClient client.Client) *IdentityProviderLoader {
	return &IdentityProviderLoader{
		kubeClient:      kubeClient,
		logger:          zap.NewNop().Sugar(),                   // No-op logger by default
		metricsRecorder: func(idpName, failureReason string) {}, // No-op recorder by default
	}
}

// WithMetricsRecorder sets the metrics recorder callback
func (l *IdentityProviderLoader) WithMetricsRecorder(recorder ConversionErrorMetricsRecorder) *IdentityProviderLoader {
	l.metricsRecorder = recorder
	return l
}

// WithLogger sets the logger for debug output
func (l *IdentityProviderLoader) WithLogger(logger *zap.SugaredLogger) *IdentityProviderLoader {
	l.logger = logger
	return l
}

// ValidateIdentityProviderExists checks that at least one enabled IdentityProvider exists
// This is called during startup to check configuration status
// Returns error if no providers exist or all are disabled (caller decides severity)
func (l *IdentityProviderLoader) ValidateIdentityProviderExists(ctx context.Context) error {
	l.logger.Debug("Validating IdentityProvider configuration exists")

	idpList := &breakglassv1alpha1.IdentityProviderList{}
	err := l.kubeClient.List(ctx, idpList)
	if err != nil {
		l.logger.Errorw("Failed to list IdentityProvider resources during validation", "error", err)
		return fmt.Errorf("failed to validate IdentityProvider configuration: %w", err)
	}

	if len(idpList.Items) == 0 {
		l.logger.Warn("No IdentityProvider resources found - session/escalation features will be limited until one is created")
		return fmt.Errorf("no IdentityProvider resources found")
	}

	// Check that at least one is enabled
	for _, idp := range idpList.Items {
		if !idp.Spec.Disabled {
			l.logger.Debugw("Found enabled IdentityProvider", "name", idp.Name, "primary", idp.Spec.Primary)
			return nil
		}
	}

	l.logger.Warn("All IdentityProvider resources are disabled - session/escalation features will be limited")
	return fmt.Errorf("all IdentityProvider resources are disabled")
}

// LoadIdentityProvider loads the primary identity provider configuration from IdentityProvider CR
// Returns the runtime config or an error if not found/invalid
func (l *IdentityProviderLoader) LoadIdentityProvider(ctx context.Context) (*IdentityProviderConfig, error) {
	l.logger.Debug("Loading primary IdentityProvider resource")

	// List all IdentityProvider resources (cluster-scoped)
	idpList := &breakglassv1alpha1.IdentityProviderList{}
	err := l.kubeClient.List(ctx, idpList)
	if err != nil {
		l.logger.Errorw("Failed to list IdentityProvider resources", "error", err)
		return nil, fmt.Errorf("failed to list IdentityProvider resources: %w", err)
	}

	l.logger.Debugw("Listed IdentityProvider resources", "count", len(idpList.Items))

	if len(idpList.Items) == 0 {
		l.logger.Error("No IdentityProvider resources found - this is a required configuration")
		return nil, fmt.Errorf("no IdentityProvider resources found; IdentityProvider is MANDATORY for operation")
	}

	// Find the primary identity provider
	var primaryIDP *breakglassv1alpha1.IdentityProvider
	for i := range idpList.Items {
		idp := &idpList.Items[i]
		if !idp.Spec.Disabled && idp.Spec.Primary {
			l.logger.Debugw("Found primary IdentityProvider", "name", idp.Name)
			primaryIDP = idp
			break
		}
	}

	// If no primary found, use the first non-disabled one
	if primaryIDP == nil {
		l.logger.Debug("No primary IdentityProvider found, looking for first enabled one")
		for i := range idpList.Items {
			idp := &idpList.Items[i]
			if !idp.Spec.Disabled {
				l.logger.Debugw("Using first enabled IdentityProvider", "name", idp.Name)
				primaryIDP = idp
				break
			}
		}
	}

	if primaryIDP == nil {
		l.logger.Error("No enabled IdentityProvider resources found - IdentityProvider configuration is MANDATORY")
		return nil, fmt.Errorf("no enabled IdentityProvider resources found; at least one enabled provider is required")
	}

	return l.convertToRuntimeConfig(ctx, primaryIDP)
}

// LoadIdentityProviderByName loads a specific IdentityProvider by name (cluster-scoped)
func (l *IdentityProviderLoader) LoadIdentityProviderByName(ctx context.Context, name string) (*IdentityProviderConfig, error) {
	l.logger.Debugw("Loading specific IdentityProvider resource", "name", name)

	idp := &breakglassv1alpha1.IdentityProvider{}
	err := l.kubeClient.Get(ctx, types.NamespacedName{
		Name: name,
	}, idp)
	if err != nil {
		l.logger.Errorw("Failed to get IdentityProvider", "name", name, "error", err)
		return nil, fmt.Errorf("failed to get IdentityProvider %s: %w", name, err)
	}

	l.logger.Debugw("Loaded IdentityProvider", "name", name, "displayName", idp.Spec.DisplayName)
	return l.convertToRuntimeConfig(ctx, idp)
}

// convertToRuntimeConfig converts a IdentityProvider CRD to runtime configuration
func (l *IdentityProviderLoader) convertToRuntimeConfig(ctx context.Context, idp *breakglassv1alpha1.IdentityProvider) (*IdentityProviderConfig, error) {
	l.logger.Debugw("Converting IdentityProvider to runtime config", "name", idp.Name)

	runtimeConfig := &IdentityProviderConfig{
		Name:                 idp.Name,
		Issuer:               idp.Spec.Issuer,
		Type:                 "OIDC",
		Authority:            idp.Spec.OIDC.Authority,
		ClientID:             idp.Spec.OIDC.ClientID,
		CertificateAuthority: idp.Spec.OIDC.CertificateAuthority,
		InsecureSkipVerify:   idp.Spec.OIDC.InsecureSkipVerify,
	}

	l.logger.Debugw("OIDC config loaded",
		"authority", idp.Spec.OIDC.Authority,
		"clientID", idp.Spec.OIDC.ClientID,
		"issuer", idp.Spec.Issuer)

	// Setup group sync if configured
	if idp.Spec.GroupSyncProvider == breakglassv1alpha1.GroupSyncProviderKeycloak && idp.Spec.Keycloak != nil {
		l.logger.Debugw("Setting up Keycloak group sync",
			"baseURL", idp.Spec.Keycloak.BaseURL,
			"realm", idp.Spec.Keycloak.Realm,
			"clientID", idp.Spec.Keycloak.ClientID)

		keycloakConfig := &KeycloakRuntimeConfig{
			BaseURL:              idp.Spec.Keycloak.BaseURL,
			Realm:                idp.Spec.Keycloak.Realm,
			ClientID:             idp.Spec.Keycloak.ClientID,
			CacheTTL:             idp.Spec.Keycloak.CacheTTL,
			RequestTimeout:       idp.Spec.Keycloak.RequestTimeout,
			InsecureSkipVerify:   idp.Spec.Keycloak.InsecureSkipVerify,
			CertificateAuthority: idp.Spec.Keycloak.CertificateAuthority,
		}

		// Load client secret from secret reference
		if idp.Spec.Keycloak.ClientSecretRef.Name != "" {
			l.logger.Debugw("Loading Keycloak client secret",
				"secretName", idp.Spec.Keycloak.ClientSecretRef.Name,
				"secretKey", idp.Spec.Keycloak.ClientSecretRef.Key)

			secret, err := l.getSecretValue(ctx, &idp.Spec.Keycloak.ClientSecretRef)
			if err != nil {
				l.logger.Errorw("Failed to load Keycloak client secret", "error", err)
				return nil, fmt.Errorf("failed to load Keycloak client secret: %w", err)
			}
			keycloakConfig.ClientSecret = secret
			l.logger.Debug("Keycloak client secret loaded successfully")
		} else {
			l.logger.Warn("No Keycloak client secret configured")
		}

		runtimeConfig.Keycloak = keycloakConfig
	} else if idp.Spec.GroupSyncProvider != "" {
		l.logger.Warnw("Unknown group sync provider configured", "provider", idp.Spec.GroupSyncProvider)
	} else {
		l.logger.Debug("No group sync provider configured")
	}

	return runtimeConfig, nil
}

// getSecretValue retrieves a specific key from a Secret
func (l *IdentityProviderLoader) getSecretValue(ctx context.Context, secretRef *breakglassv1alpha1.SecretKeyReference) (string, error) {
	if secretRef == nil || secretRef.Name == "" {
		return "", fmt.Errorf("secret reference is empty")
	}

	// Cluster-scoped resources use the namespace specified in the secret ref or the configured default namespace
	namespace := secretRef.Namespace
	if namespace == "" {
		return "", fmt.Errorf("secret reference must specify a namespace for cluster-scoped resources")
	}

	secret := &corev1.Secret{}
	err := l.kubeClient.Get(ctx, types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretRef.Name, err)
	}

	key := secretRef.Key
	if key == "" {
		key = "value"
	}

	value, exists := secret.Data[key]
	if !exists {
		return "", fmt.Errorf("key %s not found in secret %s/%s", key, namespace, secretRef.Name)
	}

	return string(value), nil
}

// LoadAllIdentityProviders returns all enabled identity providers as a map of name -> config
// Only includes providers where Disabled=false
// Note: If any enabled IDPs fail to convert, they are skipped with logged warnings
func (l *IdentityProviderLoader) LoadAllIdentityProviders(ctx context.Context) (map[string]*IdentityProviderConfig, error) {
	l.logger.Debug("Loading all enabled IdentityProviders")

	idpList := &breakglassv1alpha1.IdentityProviderList{}
	err := l.kubeClient.List(ctx, idpList)
	if err != nil {
		l.logger.Errorw("Failed to list IdentityProvider resources", "error", err)
		return nil, fmt.Errorf("failed to list IdentityProvider resources: %w", err)
	}

	result := make(map[string]*IdentityProviderConfig)
	var conversionErrors []string
	for i := range idpList.Items {
		idp := &idpList.Items[i]
		if !idp.Spec.Disabled {
			config, err := l.convertToRuntimeConfig(ctx, idp)
			if err != nil {
				// Log conversion error with full context for troubleshooting
				l.logger.Warnw("Failed to convert IdentityProvider, skipping",
					"name", idp.Name,
					"namespace", idp.Namespace,
					"displayName", idp.Spec.DisplayName,
					"error", err)
				// Update the IdentityProvider CR status to mark conversion failure
				// This makes the error visible in kubectl describe for operators
				l.updateConversionFailureStatus(ctx, idp, err)
				conversionErrors = append(conversionErrors, fmt.Sprintf("%s: %v", idp.Name, err))
				continue // Skip problematic configs
			}
			result[idp.Name] = config
		}
	}

	if len(conversionErrors) > 0 {
		// Log with ERROR level to make skipped IDPs more visible in logs
		l.logger.Errorw("Some IdentityProviders were skipped due to conversion errors - users may be unable to authenticate with these providers",
			"count", len(conversionErrors),
			"skipped_idps", conversionErrors)
		// Emit metrics to track IDP conversion failures for alerting
		for _, errStr := range conversionErrors {
			parts := strings.SplitN(errStr, ":", 2)
			if len(parts) >= 1 {
				idpName := strings.TrimSpace(parts[0])
				reason := "conversion_error"
				if len(parts) >= 2 {
					// Categorize the error reason
					errMsg := strings.ToLower(parts[1])
					switch {
					case strings.Contains(errMsg, "missing"):
						reason = "missing_field"
					case strings.Contains(errMsg, "invalid"):
						reason = "invalid_config"
					case strings.Contains(errMsg, "parse"):
						reason = "parse_error"
					case strings.Contains(errMsg, "secret"):
						reason = "secret_error"
					case strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connect"):
						reason = "network_error"
					}
				}
				metrics.IdentityProviderConversionErrors.WithLabelValues(idpName, reason).Inc()
			}
		}
	}

	l.logger.Debugw("Loaded enabled IdentityProviders", "count", len(result))
	return result, nil
}

// LoadIdentityProviderByIssuer loads an IdentityProvider by its issuer URL
// This is used to determine which provider authenticated a user based on JWT iss claim
// Returns error if no provider with matching issuer is found
func (l *IdentityProviderLoader) LoadIdentityProviderByIssuer(ctx context.Context, issuer string) (*IdentityProviderConfig, error) {
	l.logger.Debugw("Loading IdentityProvider by issuer", "issuer", issuer)

	if issuer == "" {
		return nil, fmt.Errorf("issuer cannot be empty")
	}

	idpList := &breakglassv1alpha1.IdentityProviderList{}
	err := l.kubeClient.List(ctx, idpList)
	if err != nil {
		l.logger.Errorw("Failed to list IdentityProvider resources", "error", err)
		return nil, fmt.Errorf("failed to list IdentityProvider resources: %w", err)
	}

	for i := range idpList.Items {
		idp := &idpList.Items[i]
		if !idp.Spec.Disabled && idp.Spec.Issuer == issuer {
			l.logger.Debugw("Found IdentityProvider by issuer", "name", idp.Name, "issuer", issuer)
			return l.convertToRuntimeConfig(ctx, idp)
		}
	}

	// Fallback: if no exact issuer match, try matching by authority
	// This handles cases where Spec.Issuer is not set or doesn't match JWT iss claim exactly
	// Many OIDC providers (including Keycloak) use the realm URL as both authority and issuer
	l.logger.Debugw("No exact issuer match found, trying authority fallback", "issuer", issuer)
	for i := range idpList.Items {
		idp := &idpList.Items[i]
		// Normalize both URLs for comparison (trim trailing slashes)
		authority := strings.TrimRight(idp.Spec.OIDC.Authority, "/")
		issuerNorm := strings.TrimRight(issuer, "/")

		if !idp.Spec.Disabled && authority == issuerNorm {
			l.logger.Debugw("Found IdentityProvider by authority fallback", "name", idp.Name, "authority", authority, "issuer", issuer)
			return l.convertToRuntimeConfig(ctx, idp)
		}
	}

	l.logger.Warnw("No IdentityProvider found for issuer", "issuer", issuer)
	return nil, fmt.Errorf("no enabled IdentityProvider found for issuer %s", issuer)
}

// ValidateIdentityProviderRefs checks that all named IdentityProviders exist and are enabled
// Used for validating ClusterConfig.IdentityProviderRefs and BreakglassEscalation.AllowedIdentityProviders
// If refs is empty, this is considered valid (means accept all enabled providers)
func (l *IdentityProviderLoader) ValidateIdentityProviderRefs(ctx context.Context, refs []string) error {
	if len(refs) == 0 {
		l.logger.Debug("Empty IdentityProviderRefs - will accept all enabled providers")
		return nil
	}

	l.logger.Debugw("Validating IdentityProviderRefs", "count", len(refs), "refs", refs)

	idpList := &breakglassv1alpha1.IdentityProviderList{}
	err := l.kubeClient.List(ctx, idpList)
	if err != nil {
		l.logger.Errorw("Failed to list IdentityProvider resources", "error", err)
		return fmt.Errorf("failed to validate IdentityProviderRefs: %w", err)
	}

	// Build map of available providers
	enabledProviders := make(map[string]bool)
	for i := range idpList.Items {
		idp := &idpList.Items[i]
		if !idp.Spec.Disabled {
			enabledProviders[idp.Name] = true
		}
	}

	// Check that all refs point to valid, enabled providers
	var missingRefs []string
	for _, ref := range refs {
		if !enabledProviders[ref] {
			missingRefs = append(missingRefs, ref)
		}
	}

	if len(missingRefs) > 0 {
		l.logger.Errorw("IdentityProviderRefs validation failed - providers not found or disabled", "missing", missingRefs)
		return fmt.Errorf("invalid IdentityProviderRefs: providers not found or disabled: %v", missingRefs)
	}

	l.logger.Debug("IdentityProviderRefs validation passed")
	return nil
}

// GetIDPNameByIssuer returns the name of the IdentityProvider that matches the given issuer
// Used to convert from JWT issuer claim to IDP name for storage in sessions
func (l *IdentityProviderLoader) GetIDPNameByIssuer(ctx context.Context, issuer string) (string, error) {
	config, err := l.LoadIdentityProviderByIssuer(ctx, issuer)
	if err != nil {
		return "", err
	}
	return config.Name, nil
}

// MarshalIdentityProviderToJSON marshals an IdentityProviderConfig to JSON
// for API responses
func MarshalIdentityProviderToJSON(config *IdentityProviderConfig) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal IdentityProvider config: %w", err)
	}
	return string(data), nil
}

// updateConversionFailureStatus updates the IdentityProvider CR status to mark a conversion failure
// This makes the error visible in kubectl describe and enables monitoring of failed configurations
func (l *IdentityProviderLoader) updateConversionFailureStatus(ctx context.Context, idp *breakglassv1alpha1.IdentityProvider, err error) {
	if idp == nil || err == nil {
		return
	}

	// Categorize the error for metrics
	failureReason := categorizeConversionError(err)

	// Create a new condition for the conversion failure
	condition := metav1.Condition{
		Type:               string(breakglassv1alpha1.IdentityProviderConditionConversionFailed),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: idp.Generation,
		Reason:             "ConversionError",
		Message:            fmt.Sprintf("Failed to convert IdentityProvider configuration: %v", err),
		LastTransitionTime: metav1.Now(),
	}

	// Update the condition on the status
	apimeta.SetStatusCondition(&idp.Status.Conditions, condition)

	// Try to update the status in Kubernetes
	if updateErr := l.kubeClient.Status().Update(ctx, idp); updateErr != nil {
		l.logger.Warnw("Failed to update IdentityProvider status on conversion failure",
			"name", idp.Name,
			"conversionError", err,
			"updateError", updateErr)
	} else {
		l.logger.Debugw("Updated IdentityProvider status to mark conversion failure",
			"name", idp.Name,
			"error", err)
	}

	// Emit metric to track conversion failures
	// This enables alerting and monitoring of repeated conversion failures
	l.recordConversionFailureMetric(idp.Name, failureReason)
}

// categorizeConversionError classifies the error type for metrics
// Returns a metric-friendly label describing the failure category
func categorizeConversionError(err error) string {
	if err == nil {
		return "unknown"
	}

	errMsg := err.Error()

	// Check for common error patterns and categorize them
	switch {
	case strings.Contains(errMsg, "required"):
		return "missing_field"
	case strings.Contains(errMsg, "invalid"):
		return "invalid_config"
	case strings.Contains(errMsg, "parse"):
		return "parse_error"
	case strings.Contains(errMsg, "secret"):
		return "secret_error"
	case strings.Contains(errMsg, "connection"):
		return "connection_error"
	case strings.Contains(errMsg, "timeout"):
		return "timeout_error"
	case strings.Contains(errMsg, "unauthorized"):
		return "auth_error"
	default:
		return "other_error"
	}
}

// recordConversionFailureMetric calls the metrics recorder callback
func (l *IdentityProviderLoader) recordConversionFailureMetric(idpName, failureReason string) {
	if l.metricsRecorder != nil {
		l.metricsRecorder(idpName, failureReason)
	}
}

func DefaultIdentityProviderLoader(ctx context.Context, kubeClient client.Client, scheme *runtime.Scheme, log *zap.SugaredLogger) (*IdentityProviderLoader, error) {
	// Load IdentityProvider configuration for group sync
	idpLoader := NewIdentityProviderLoader(kubeClient)
	idpLoader.WithLogger(log)

	// Set up metrics recorder for conversion failures
	idpLoader.WithMetricsRecorder(func(idpName, failureReason string) {
		metrics.IdentityProviderConversionErrors.WithLabelValues(idpName, failureReason).Inc()
	})

	// Check if IdentityProvider exists (warn if missing, don't fail)
	// This allows the controller to start and serve webhooks even without IdentityProvider
	if err := idpLoader.ValidateIdentityProviderExists(ctx); err != nil {
		metrics.IdentityProviderValidationFailed.WithLabelValues("not_found").Inc()
		log.Warnw("IdentityProvider not found - controller will start with limited functionality",
			"error", err,
			"note", "Webhooks will be served, but session/escalation processing requires IdentityProvider")
		// Return the loader anyway - it can be used once IdentityProvider is created
	}

	return idpLoader, nil
}
