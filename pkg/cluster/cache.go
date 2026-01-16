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

// Cache TTL constants
const (
	// RESTConfigCacheTTL is how long cached rest.Config entries remain valid.
	// OIDC configs use WrapTransport for dynamic token refresh, but we still
	// expire the cache to pick up TLS/CA changes.
	RESTConfigCacheTTL = 5 * time.Minute

	// KubeconfigCacheTTL is longer since kubeconfigs change less frequently.
	KubeconfigCacheTTL = 15 * time.Minute
)

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
	// clusterToSecret tracks which kubeconfig secret each ClusterConfig uses (keyed by cluster name)
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

// Get returns cached ClusterConfig or fetches it (metadata only usage for now).
func cacheKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func secretCacheKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

// Get returns a ClusterConfig. If namespace is the empty string the method
// will list across all namespaces and match by metadata.name (backwards
// compatible behavior). Callers that know the namespace should pass it to
// avoid the cross-namespace list.
func (p *ClientProvider) GetAcrossAllNamespaces(ctx context.Context, name string) (*telekomv1alpha1.ClusterConfig, error) {
	key := cacheKey("", name)
	p.mu.RLock()
	cfg, ok := p.data[key]
	p.mu.RUnlock()
	if ok {
		metrics.ClusterCacheHits.WithLabelValues(name).Inc()
		return cfg, nil
	}
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

// GetRESTConfig returns a rest.Config for the cluster, supporting both kubeconfig and OIDC authentication.
// The auth method is determined by the ClusterConfig's authType field.
// For OIDC clusters, the config uses WrapTransport for dynamic token injection, allowing caching
// while still refreshing tokens as needed. TTL-based expiry ensures TLS/CA changes are picked up.
func (p *ClientProvider) GetRESTConfig(ctx context.Context, name string) (*rest.Config, error) {
	now := time.Now()

	// Check cache with TTL validation
	p.mu.RLock()
	cached, ok := p.rest[name]
	p.mu.RUnlock()

	if ok && now.Before(cached.expiresAt) {
		metrics.ClusterCacheHits.WithLabelValues(name).Inc()
		return cached.config, nil
	}

	// Cache miss or expired
	if ok {
		p.log.Debugw("REST config cache expired", "cluster", name, "expiredAt", cached.expiresAt)
	}
	metrics.ClusterCacheMisses.WithLabelValues(name).Inc()

	// Legacy Get behavior lists across namespaces when namespace is empty.
	cc, err := p.GetAcrossAllNamespaces(ctx, name)
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

	// Cache with TTL
	p.mu.Lock()
	p.rest[name] = &cachedRESTConfig{
		config:    cfg,
		expiresAt: now.Add(ttl),
		authType:  authType,
	}
	p.mu.Unlock()

	p.log.Debugw("Cached REST config", "cluster", name, "authType", authType, "ttl", ttl)
	return cfg, nil
}

// getRESTConfigFromKubeconfig builds a rest.Config from a kubeconfig stored in a secret.
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
	secretRefKey := secretCacheKey(cc.Spec.KubeconfigSecretRef.Namespace, cc.Spec.KubeconfigSecretRef.Name)

	p.mu.Lock()
	p.clusterToSecret[cc.Name] = secretRefKey
	if _, ok := p.secretToClusters[secretRefKey]; !ok {
		p.secretToClusters[secretRefKey] = map[string]struct{}{}
	}
	p.secretToClusters[secretRefKey][cc.Name] = struct{}{}
	p.mu.Unlock()

	metrics.ClusterRESTConfigLoaded.WithLabelValues(cc.Name).Inc()
	return cfg, nil
}

// getRESTConfigFromOIDC builds a rest.Config using OIDC token authentication.
func (p *ClientProvider) getRESTConfigFromOIDC(ctx context.Context, cc *telekomv1alpha1.ClusterConfig) (*rest.Config, error) {
	if p.oidcProvider == nil {
		return nil, fmt.Errorf("OIDC provider not initialized")
	}
	return p.oidcProvider.GetRESTConfig(ctx, cc)
}

// Invalidate removes an entry (called by informer/controller update hooks later).
func (p *ClientProvider) Invalidate(name string) {
	metrics.ClusterCacheInvalidations.WithLabelValues("cluster_update").Inc()
	p.mu.Lock()
	p.evictClusterLocked(name)
	p.mu.Unlock()
}

// InvalidateSecret removes all cached entries (ClusterConfig + rest.Config) that rely on a specific secret.
func (p *ClientProvider) InvalidateSecret(namespace, name string) {
	key := secretCacheKey(namespace, name)
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
	key := secretCacheKey(namespace, name)
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.secretToClusters[key]
	return ok
}

func (p *ClientProvider) evictClusterLocked(name string) {
	for k := range p.data {
		if strings.HasSuffix(k, "/"+name) || k == name {
			delete(p.data, k)
		}
	}
	delete(p.rest, name)
	if secretKey, ok := p.clusterToSecret[name]; ok {
		if clusters, found := p.secretToClusters[secretKey]; found {
			delete(clusters, name)
			if len(clusters) == 0 {
				delete(p.secretToClusters, secretKey)
			}
		}
		delete(p.clusterToSecret, name)
	}
}
