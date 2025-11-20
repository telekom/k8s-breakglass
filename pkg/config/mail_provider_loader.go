package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// MailProviderConfig represents runtime mail provider configuration
type MailProviderConfig struct {
	// Name is the name of the MailProvider CRD resource (metadata.name)
	Name string

	// DisplayName is a human-readable name
	DisplayName string

	// Default indicates if this is the default provider
	Default bool

	// Disabled indicates if this provider is disabled
	Disabled bool

	// SMTP configuration
	Host                 string
	Port                 int
	Username             string
	Password             string
	InsecureSkipVerify   bool
	CertificateAuthority string

	// Sender configuration
	SenderAddress string
	SenderName    string

	// Retry configuration
	RetryCount     int
	RetryBackoffMs int
	QueueSize      int
}

// MailProviderLoader loads and caches MailProvider configurations from Kubernetes
type MailProviderLoader struct {
	client          client.Client
	logger          *zap.SugaredLogger
	mu              sync.RWMutex
	cache           map[string]*MailProviderConfig // name -> config
	defaultProvider string
	metricsRecorder func(providerName, failureReason string)
}

// NewMailProviderLoader creates a new MailProviderLoader
func NewMailProviderLoader(kubeClient client.Client) *MailProviderLoader {
	return &MailProviderLoader{
		client: kubeClient,
		cache:  make(map[string]*MailProviderConfig),
		logger: zap.NewNop().Sugar(),
	}
}

// WithLogger sets the logger for this loader
func (l *MailProviderLoader) WithLogger(logger *zap.SugaredLogger) *MailProviderLoader {
	l.logger = logger
	return l
}

// WithMetricsRecorder sets the metrics recorder callback
func (l *MailProviderLoader) WithMetricsRecorder(recorder func(providerName, failureReason string)) *MailProviderLoader {
	l.metricsRecorder = recorder
	return l
}

// LoadAllMailProviders loads all MailProvider CRDs and returns them as a map
func (l *MailProviderLoader) LoadAllMailProviders(ctx context.Context) (map[string]*MailProviderConfig, error) {
	var mailProviderList breakglassv1alpha1.MailProviderList
	if err := l.client.List(ctx, &mailProviderList); err != nil {
		l.logger.Errorw("Failed to list MailProvider resources", "error", err)
		return nil, fmt.Errorf("failed to list MailProvider resources: %w", err)
	}

	result := make(map[string]*MailProviderConfig)
	var defaultProviderName string
	defaultCount := 0

	for i := range mailProviderList.Items {
		mp := &mailProviderList.Items[i]

		if mp.Spec.Disabled {
			l.logger.Debugw("Skipping disabled MailProvider", "name", mp.Name)
			continue
		}

		config, err := l.convertToRuntimeConfig(ctx, mp)
		if err != nil {
			l.logger.Errorw("Failed to convert MailProvider to runtime config", "name", mp.Name, "error", err)
			if l.metricsRecorder != nil {
				l.metricsRecorder(mp.Name, "conversion_error")
			}
			continue
		}

		result[mp.Name] = config

		if mp.Spec.Default {
			defaultCount++
			defaultProviderName = mp.Name
		}
	}

	// Validate default provider configuration
	if defaultCount == 0 {
		l.logger.Warn("No default MailProvider found")
		return result, fmt.Errorf("no default MailProvider configured")
	}
	if defaultCount > 1 {
		l.logger.Warnw("Multiple default MailProviders found", "count", defaultCount)
		return result, fmt.Errorf("multiple default MailProviders found (%d)", defaultCount)
	}

	l.logger.Infow("Loaded MailProviders", "count", len(result), "default", defaultProviderName)

	// Update cache
	l.mu.Lock()
	l.cache = result
	l.defaultProvider = defaultProviderName
	l.mu.Unlock()

	return result, nil
}

// LoadMailProvider loads a specific MailProvider by name
func (l *MailProviderLoader) LoadMailProvider(ctx context.Context, name string) (*MailProviderConfig, error) {
	// Check cache first
	l.mu.RLock()
	cached, exists := l.cache[name]
	l.mu.RUnlock()

	if exists {
		return cached, nil
	}

	// Load from Kubernetes
	var mp breakglassv1alpha1.MailProvider
	if err := l.client.Get(ctx, client.ObjectKey{Name: name}, &mp); err != nil {
		l.logger.Errorw("Failed to get MailProvider", "name", name, "error", err)
		return nil, fmt.Errorf("failed to get MailProvider %s: %w", name, err)
	}

	if mp.Spec.Disabled {
		return nil, fmt.Errorf("MailProvider %s is disabled", name)
	}

	config, err := l.convertToRuntimeConfig(ctx, &mp)
	if err != nil {
		l.logger.Errorw("Failed to convert MailProvider", "name", name, "error", err)
		return nil, err
	}

	// Update cache
	l.mu.Lock()
	l.cache[name] = config
	l.mu.Unlock()

	return config, nil
}

// GetDefaultMailProvider returns the default MailProvider
func (l *MailProviderLoader) GetDefaultMailProvider(ctx context.Context) (*MailProviderConfig, error) {
	l.mu.RLock()
	defaultName := l.defaultProvider
	l.mu.RUnlock()

	if defaultName == "" {
		// Try to find default by loading all
		_, err := l.LoadAllMailProviders(ctx)
		if err != nil {
			return nil, err
		}

		l.mu.RLock()
		defaultName = l.defaultProvider
		l.mu.RUnlock()

		if defaultName == "" {
			return nil, fmt.Errorf("no default MailProvider found")
		}
	}

	return l.LoadMailProvider(ctx, defaultName)
}

// GetMailProviderByPriority returns the appropriate MailProvider based on priority:
// 1. Escalation-specific provider (if set)
// 2. Cluster-specific provider (if set)
// 3. Default provider
func (l *MailProviderLoader) GetMailProviderByPriority(ctx context.Context, escalationProvider, clusterProvider string) (*MailProviderConfig, error) {
	// Priority 1: Escalation-specific
	if escalationProvider != "" {
		config, err := l.LoadMailProvider(ctx, escalationProvider)
		if err != nil {
			l.logger.Warnw("Failed to load escalation-specific MailProvider, falling back",
				"provider", escalationProvider, "error", err)
		} else {
			l.logger.Debugw("Using escalation-specific MailProvider", "provider", escalationProvider)
			return config, nil
		}
	}

	// Priority 2: Cluster-specific
	if clusterProvider != "" {
		config, err := l.LoadMailProvider(ctx, clusterProvider)
		if err != nil {
			l.logger.Warnw("Failed to load cluster-specific MailProvider, falling back to default",
				"provider", clusterProvider, "error", err)
		} else {
			l.logger.Debugw("Using cluster-specific MailProvider", "provider", clusterProvider)
			return config, nil
		}
	}

	// Priority 3: Default
	l.logger.Debug("Using default MailProvider")
	return l.GetDefaultMailProvider(ctx)
}

// convertToRuntimeConfig converts a MailProvider CRD to runtime configuration
func (l *MailProviderLoader) convertToRuntimeConfig(ctx context.Context, mp *breakglassv1alpha1.MailProvider) (*MailProviderConfig, error) {
	config := &MailProviderConfig{
		Name:                 mp.Name,
		DisplayName:          mp.Spec.DisplayName,
		Default:              mp.Spec.Default,
		Disabled:             mp.Spec.Disabled,
		Host:                 mp.Spec.SMTP.Host,
		Port:                 mp.Spec.SMTP.Port,
		Username:             mp.Spec.SMTP.Username,
		InsecureSkipVerify:   mp.Spec.SMTP.InsecureSkipVerify,
		CertificateAuthority: mp.Spec.SMTP.CertificateAuthority,
		SenderAddress:        mp.Spec.Sender.Address,
		SenderName:           mp.Spec.Sender.Name,
		RetryCount:           mp.Spec.Retry.Count,
		RetryBackoffMs:       mp.Spec.Retry.InitialBackoffMs,
		QueueSize:            mp.Spec.Retry.QueueSize,
	}

	// Apply defaults
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.RetryBackoffMs == 0 {
		config.RetryBackoffMs = 100
	}
	if config.QueueSize == 0 {
		config.QueueSize = 1000
	}
	if config.DisplayName == "" {
		config.DisplayName = mp.Name
	}

	// Load password from secret if referenced
	if mp.Spec.SMTP.PasswordRef != nil {
		password, err := l.getSecretValue(ctx, mp.Spec.SMTP.PasswordRef)
		if err != nil {
			l.logger.Errorw("Failed to load SMTP password from secret", "name", mp.Name, "error", err)
			return nil, fmt.Errorf("failed to load SMTP password: %w", err)
		}
		config.Password = password
	}

	l.logger.Debugw("Converted MailProvider to runtime config",
		"name", mp.Name,
		"host", config.Host,
		"port", config.Port,
		"default", config.Default)

	return config, nil
}

// getSecretValue retrieves a value from a Kubernetes Secret
func (l *MailProviderLoader) getSecretValue(ctx context.Context, ref *breakglassv1alpha1.SecretKeyReference) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("secret reference is nil")
	}

	var secret corev1.Secret
	secretKey := client.ObjectKey{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}

	if err := l.client.Get(ctx, secretKey, &secret); err != nil {
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

// InvalidateCache clears the cache, forcing a reload on next access
func (l *MailProviderLoader) InvalidateCache(providerName string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if providerName == "" {
		// Clear all
		l.cache = make(map[string]*MailProviderConfig)
		l.defaultProvider = ""
		l.logger.Info("Cleared entire MailProvider cache")
	} else {
		// Clear specific
		delete(l.cache, providerName)
		if l.defaultProvider == providerName {
			l.defaultProvider = ""
		}
		l.logger.Infow("Cleared MailProvider from cache", "provider", providerName)
	}
}

// GetTLSConfig returns TLS configuration for the mail provider
func (c *MailProviderConfig) GetTLSConfig() *tls.Config {
	tlsConfig := &tls.Config{
		ServerName:         c.Host,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	// Add custom CA certificate if provided
	if c.CertificateAuthority != "" {
		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM([]byte(c.CertificateAuthority)); ok {
			tlsConfig.RootCAs = certPool
		}
		// If parsing fails, we'll fall back to system certificates
	}

	return tlsConfig
}
