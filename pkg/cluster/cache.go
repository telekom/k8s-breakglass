package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientProvider resolves ClusterConfig objects and caches lightweight metadata.
var ErrClusterConfigNotFound = errors.New("clusterconfig not found")

// Cache TTL defaults (can be overridden via environment variables)
var (
	// RESTConfigCacheTTL is how long cached rest.Config entries remain valid.
	// OIDC configs use WrapTransport for dynamic token refresh, but we still
	// expire the cache to pick up TLS/CA changes.
	// Override with BREAKGLASS_REST_CONFIG_CACHE_TTL (e.g., "10m", "300s")
	RESTConfigCacheTTL = getEnvDuration("BREAKGLASS_REST_CONFIG_CACHE_TTL", 5*time.Minute)

	// KubeconfigCacheTTL is longer since kubeconfigs change less frequently.
	// Override with BREAKGLASS_KUBECONFIG_CACHE_TTL (e.g., "30m", "900s")
	KubeconfigCacheTTL = getEnvDuration("BREAKGLASS_KUBECONFIG_CACHE_TTL", 15*time.Minute)
)

// getEnvDuration reads a duration from an environment variable, falling back to defaultVal.
// If the environment variable is set but contains an invalid duration string,
// a warning is printed to stderr and the default value is used.
func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		d, err := time.ParseDuration(val)
		if err == nil {
			return d
		}
		// Log warning about invalid value - using fmt.Fprintf since logger may not
		// be initialized yet during package init
		fmt.Fprintf(os.Stderr, "WARNING: invalid duration for %s=%q, using default %v: %v\n", key, val, defaultVal, err)
	}
	return defaultVal
}

// cachedRESTConfig wraps a rest.Config with expiry time for TTL-based eviction.
type cachedRESTConfig struct {
	config    *rest.Config
	expiresAt time.Time
	authType  telekomv1alpha1.ClusterAuthType
}

type ClientProvider struct {
	k8s  ctrlclient.Client
	log  *zap.SugaredLogger
	mu   sync.RWMutex
	data map[string]*telekomv1alpha1.ClusterConfig
	rest map[string]*cachedRESTConfig
	// clusterToSecret tracks which kubeconfig secret each ClusterConfig uses (keyed by namespace/name)
	clusterToSecret map[string]string
	// secretToClusters tracks all clusters backed by a given secret (keyed by namespace/name)
	secretToClusters map[string]map[string]struct{}
	// oidcProvider handles OIDC token acquisition for clusters using OIDC auth
	oidcProvider *OIDCTokenProvider
}

func NewClientProvider(c ctrlclient.Client, log *zap.SugaredLogger) *ClientProvider {
	return &ClientProvider{
		k8s:              c,
		log:              log,
		data:             map[string]*telekomv1alpha1.ClusterConfig{},
		rest:             map[string]*cachedRESTConfig{},
		clusterToSecret:  map[string]string{},
		secretToClusters: map[string]map[string]struct{}{},
		oidcProvider:     NewOIDCTokenProvider(c, log),
	}
}

// cacheKey generates a namespaced cache key for ClusterConfig or Secret lookups.
// Both namespace and name are required to avoid cache collisions between resources
// with the same name in different namespaces.
func cacheKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func splitNamespacedName(value string) (string, string, bool) {
	if strings.Contains(value, "/") {
		parts := strings.SplitN(value, "/", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return parts[0], parts[1], true
		}
	}
	return "", "", false
}

// GetAcrossAllNamespaces returns a ClusterConfig by name, searching across all namespaces.
// This method first checks the cache for an exact name match, then falls back to listing
// all ClusterConfigs if not found. For better performance when the namespace is known,
// callers should use GetInNamespace instead.
//
// Note: This method performs an O(n) scan of cached entries. For high-throughput scenarios
// with many cached ClusterConfigs, consider using GetInNamespace with a known namespace.
func (p *ClientProvider) GetAcrossAllNamespaces(ctx context.Context, name string) (*telekomv1alpha1.ClusterConfig, error) {
	// Try exact namespace/name lookup first if we have cached entries
	p.mu.RLock()
	// First, try to find a cached entry by scanning for any namespace with this name
	// We match by the ClusterConfig's Name field to ensure exact match (avoids
	// issues with similar cluster names like "prod" vs "my-prod").
	for _, cfg := range p.data {
		if cfg != nil && cfg.Name == name {
			p.mu.RUnlock()
			metrics.ClusterCacheHits.WithLabelValues(name).Inc()
			return cfg, nil
		}
	}
	p.mu.RUnlock()
	metrics.ClusterCacheMisses.WithLabelValues(name).Inc()

	// Namespace not provided: preserve legacy behavior and list across namespaces
	list := telekomv1alpha1.ClusterConfigList{}
	if err := p.k8s.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list clusterconfigs: %w", err)
	}
	for _, item := range list.Items {
		if item.Name == name {
			// copy loop variable before taking address
			cp := item
			p.mu.Lock()
			p.data[cacheKey(cp.Namespace, cp.Name)] = &cp
			p.mu.Unlock()
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrClusterConfigNotFound, name)
}

// GetInNamespace fetches a ClusterConfig by metadata.name within the provided namespace.
// This avoids any implicit namespace assumptions; callers that know the namespace
// should use this method. It caches the result keyed by the logical cluster name.
func (p *ClientProvider) GetInNamespace(ctx context.Context, namespace, name string) (*telekomv1alpha1.ClusterConfig, error) {
	key := cacheKey(namespace, name)
	p.mu.RLock()
	cfg, ok := p.data[key]
	p.mu.RUnlock()
	if ok {
		metrics.ClusterCacheHits.WithLabelValues(name).Inc()
		return cfg, nil
	}
	metrics.ClusterCacheMisses.WithLabelValues(name).Inc()

	got := telekomv1alpha1.ClusterConfig{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &got); err != nil {
		return nil, fmt.Errorf("get clusterconfig %s/%s: %w", namespace, name, err)
	}
	cp := got
	p.mu.Lock()
	p.data[key] = &cp
	p.mu.Unlock()
	return &cp, nil
}

// getAcrossAllNamespacesLocked is the lock-held variant of GetAcrossAllNamespaces.
// Caller MUST hold p.mu as a write lock (Lock, not RLock) before calling this method,
// as this function may modify p.data when caching results.
func (p *ClientProvider) getAcrossAllNamespacesLocked(ctx context.Context, name string) (*telekomv1alpha1.ClusterConfig, error) {
	// First, try to find a cached entry by scanning for any namespace with this name
	for _, cfg := range p.data {
		if cfg != nil && cfg.Name == name {
			return cfg, nil
		}
	}

	// Namespace not provided: preserve legacy behavior and list across namespaces
	list := telekomv1alpha1.ClusterConfigList{}
	if err := p.k8s.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list clusterconfigs: %w", err)
	}
	for _, item := range list.Items {
		if item.Name == name {
			// copy loop variable before taking address
			cp := item
			p.data[cacheKey(cp.Namespace, cp.Name)] = &cp
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrClusterConfigNotFound, name)
}

// getInNamespaceLocked is the lock-held variant of GetInNamespace.
// Caller MUST hold p.mu as a write lock (Lock, not RLock) before calling this method,
// as this function may modify p.data when caching results.
func (p *ClientProvider) getInNamespaceLocked(ctx context.Context, namespace, name string) (*telekomv1alpha1.ClusterConfig, error) {
	key := cacheKey(namespace, name)
	if cfg, ok := p.data[key]; ok {
		return cfg, nil
	}

	got := telekomv1alpha1.ClusterConfig{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &got); err != nil {
		return nil, fmt.Errorf("get clusterconfig %s/%s: %w", namespace, name, err)
	}
	cp := got
	p.data[key] = &cp
	return &cp, nil
}

// GetRESTConfig returns a rest.Config for the cluster, supporting both kubeconfig and OIDC authentication.
// The auth method is determined by the ClusterConfig's authType field.
// For OIDC clusters, the config uses WrapTransport for dynamic token injection, allowing caching
// while still refreshing tokens as needed. TTL-based expiry ensures TLS/CA changes are picked up.
func (p *ClientProvider) GetRESTConfig(ctx context.Context, name string) (*rest.Config, error) {
	now := time.Now()

	// If caller provided namespace/name, use it for exact cache lookup
	var cacheLookupKey string
	var parsedNamespace, parsedName string
	if ns, n, ok := splitNamespacedName(name); ok {
		parsedNamespace = ns
		parsedName = n
		cacheLookupKey = cacheKey(ns, n)
	}

	// Check cache with TTL validation (read lock for fast path)
	p.mu.RLock()
	cached, ok := p.rest[cacheLookupKey]
	if cacheLookupKey != "" && ok && now.Before(cached.expiresAt) {
		p.mu.RUnlock()
		metrics.ClusterCacheHits.WithLabelValues(name).Inc()
		return cached.config, nil
	}
	p.mu.RUnlock()

	// Cache miss or expired - this request takes the slow path
	// Note: We count this as a miss immediately, even if another thread populates the cache
	// while we wait for the write lock. This prevents double-counting if we later find
	// the cache populated by another thread (the double-checked locking optimization).
	metrics.ClusterCacheMisses.WithLabelValues(name).Inc()

	// Acquire write lock for the slow path
	// Use double-checked locking to prevent redundant REST config creation
	p.mu.Lock()
	defer p.mu.Unlock()

	// Recapture timestamp after acquiring write lock to avoid using stale value.
	// If we used the pre-lock `now`, we might incorrectly consider a fresh cache entry
	// (populated by another goroutine while we waited for the lock) as expired.
	now = time.Now()

	// Re-check cache after acquiring write lock (another thread may have populated it)
	// No metric increment here - we already counted this as a miss above.
	cached, ok = p.rest[cacheLookupKey]
	if cacheLookupKey != "" && ok && now.Before(cached.expiresAt) {
		return cached.config, nil
	}

	// Log expiry if we had a stale entry
	if cacheLookupKey != "" && ok {
		p.log.Debugw("REST config cache expired", "cluster", name, "expiredAt", cached.expiresAt)
	}

	// Use GetInNamespaceLocked if namespace is known, otherwise fall back to GetAcrossAllNamespacesLocked
	// Note: Using *Locked variants since we already hold the lock
	var cc *telekomv1alpha1.ClusterConfig
	var err error
	if parsedNamespace != "" && parsedName != "" {
		cc, err = p.getInNamespaceLocked(ctx, parsedNamespace, parsedName)
	} else {
		cc, err = p.getAcrossAllNamespacesLocked(ctx, name)
	}
	if err != nil {
		metrics.ClusterRESTConfigErrors.WithLabelValues(name, "clusterconfig_not_found").Inc()
		return nil, err
	}

	// Determine auth type - check explicit authType or infer from configuration
	authType := cc.Spec.AuthType
	if authType == "" {
		// Infer from configuration
		if cc.Spec.OIDCAuth != nil {
			authType = telekomv1alpha1.ClusterAuthTypeOIDC
		} else if cc.Spec.KubeconfigSecretRef != nil {
			authType = telekomv1alpha1.ClusterAuthTypeKubeconfig
		} else {
			return nil, fmt.Errorf("no authentication method configured for cluster %s", name)
		}
	}

	var cfg *rest.Config
	var ttl time.Duration

	switch authType {
	case telekomv1alpha1.ClusterAuthTypeOIDC:
		// OIDC clusters use WrapTransport for dynamic token refresh
		cfg, err = p.getRESTConfigFromOIDC(ctx, cc)
		ttl = RESTConfigCacheTTL
	case telekomv1alpha1.ClusterAuthTypeKubeconfig:
		cfg, err = p.getRESTConfigFromKubeconfig(ctx, cc)
		ttl = KubeconfigCacheTTL
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", authType)
	}

	if err != nil {
		return nil, err
	}

	// Cache with TTL (keyed by namespace/name)
	// Note: We already hold the write lock from above
	finalCacheKey := cacheKey(cc.Namespace, cc.Name)
	p.rest[finalCacheKey] = &cachedRESTConfig{
		config:    cfg,
		expiresAt: now.Add(ttl),
		authType:  authType,
	}

	p.log.Debugw("Cached REST config", "cluster", finalCacheKey, "authType", authType, "ttl", ttl)
	return cfg, nil
}

// getRESTConfigFromKubeconfig builds a rest.Config from a kubeconfig stored in a secret.
// Caller MUST hold p.mu as a write lock (Lock, not RLock) before calling this method,
// as this function may modify p.clusterToSecret and p.secretToClusters when tracking secret references.
func (p *ClientProvider) getRESTConfigFromKubeconfig(ctx context.Context, cc *telekomv1alpha1.ClusterConfig) (*rest.Config, error) {
	if cc.Spec.KubeconfigSecretRef == nil {
		return nil, fmt.Errorf("kubeconfigSecretRef is required for kubeconfig auth")
	}

	secretDataKey := cc.Spec.KubeconfigSecretRef.Key
	if secretDataKey == "" {
		// default to 'value' for Cluster API compatibility
		secretDataKey = "value"
	}
	secret := corev1.Secret{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Name: cc.Spec.KubeconfigSecretRef.Name, Namespace: cc.Spec.KubeconfigSecretRef.Namespace}, &secret); err != nil {
		metrics.ClusterRESTConfigErrors.WithLabelValues(cc.Name, "secret_fetch_failed").Inc()
		return nil, fmt.Errorf("fetch kubeconfig secret: %w", err)
	}
	raw, ok := secret.Data[secretDataKey]
	if !ok {
		metrics.ClusterRESTConfigErrors.WithLabelValues(cc.Name, "secret_key_missing").Inc()
		return nil, fmt.Errorf("secret %s/%s missing key %s", cc.Spec.KubeconfigSecretRef.Namespace, cc.Spec.KubeconfigSecretRef.Name, secretDataKey)
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		metrics.ClusterRESTConfigErrors.WithLabelValues(cc.Name, "kubeconfig_parse_failed").Inc()
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	// If the kubeconfig references a loopback endpoint (kind default), rewrite to in-cluster service DNS
	if strings.Contains(cfg.Host, "127.0.0.1") || strings.Contains(cfg.Host, "localhost") {
		if disableRewrite, _ := strconv.ParseBool(os.Getenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE")); disableRewrite {
			p.log.Debugw("Skipping loopback kubeconfig host rewrite due to BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "host", cfg.Host)
		} else {
			p.log.Infow("Rewriting loopback kubeconfig host to in-cluster DNS", "original", cfg.Host, "replacement", "https://kubernetes.default.svc")
			cfg.Host = "https://kubernetes.default.svc"
		}
	}
	if cc.Spec.QPS != nil {
		cfg.QPS = float32(*cc.Spec.QPS)
	}
	if cc.Spec.Burst != nil {
		cfg.Burst = int(*cc.Spec.Burst)
	}

	// Track secret reference for cache invalidation
	// Note: Caller (GetRESTConfig) already holds p.mu write lock
	secretRefKey := cacheKey(cc.Spec.KubeconfigSecretRef.Namespace, cc.Spec.KubeconfigSecretRef.Name)
	clusterKey := cacheKey(cc.Namespace, cc.Name)

	p.clusterToSecret[clusterKey] = secretRefKey
	if _, ok := p.secretToClusters[secretRefKey]; !ok {
		p.secretToClusters[secretRefKey] = map[string]struct{}{}
	}
	p.secretToClusters[secretRefKey][clusterKey] = struct{}{}

	metrics.ClusterRESTConfigLoaded.WithLabelValues(cc.Name).Inc()
	return cfg, nil
}

// getRESTConfigFromOIDC builds a rest.Config using OIDC token authentication.
// Caller MUST hold p.mu as a write lock (Lock, not RLock) before calling this method.
func (p *ClientProvider) getRESTConfigFromOIDC(ctx context.Context, cc *telekomv1alpha1.ClusterConfig) (*rest.Config, error) {
	if p.oidcProvider == nil {
		return nil, fmt.Errorf("OIDC provider not initialized")
	}
	return p.oidcProvider.GetRESTConfig(ctx, cc)
}

// Invalidate removes an entry (called by informer/controller update hooks later).
func (p *ClientProvider) Invalidate(namespace, name string) {
	metrics.ClusterCacheInvalidations.WithLabelValues("cluster_update").Inc()
	p.mu.Lock()
	p.evictClusterLocked(cacheKey(namespace, name))
	p.mu.Unlock()
}

// InvalidateSecret removes all cached entries (ClusterConfig + rest.Config) that rely on a specific secret.
func (p *ClientProvider) InvalidateSecret(namespace, name string) {
	key := cacheKey(namespace, name)
	p.mu.Lock()
	defer p.mu.Unlock()
	clusters, ok := p.secretToClusters[key]
	if !ok {
		return
	}
	metrics.ClusterCacheInvalidations.WithLabelValues("secret_update").Inc()
	for cluster := range clusters {
		p.evictClusterLocked(cluster)
	}
	delete(p.secretToClusters, key)
}

// IsSecretTracked reports whether the provider currently caches any cluster configs referencing the secret.
func (p *ClientProvider) IsSecretTracked(namespace, name string) bool {
	key := cacheKey(namespace, name)
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.secretToClusters[key]
	return ok
}

func (p *ClientProvider) evictClusterLocked(clusterKey string) {
	delete(p.data, clusterKey)
	delete(p.rest, clusterKey)
	if p.oidcProvider != nil {
		if ns, name, ok := splitNamespacedName(clusterKey); ok {
			p.oidcProvider.Invalidate(ns, name)
		}
	}
	if secretKey, ok := p.clusterToSecret[clusterKey]; ok {
		if clusters, found := p.secretToClusters[secretKey]; found {
			delete(clusters, clusterKey)
			if len(clusters) == 0 {
				delete(p.secretToClusters, secretKey)
			}
		}
		delete(p.clusterToSecret, clusterKey)
	}
}
