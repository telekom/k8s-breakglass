package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientProvider resolves ClusterConfig objects and caches lightweight metadata.
var ErrClusterConfigNotFound = errors.New("clusterconfig not found")

type ClientProvider struct {
	k8s  ctrlclient.Client
	log  *zap.SugaredLogger
	mu   sync.RWMutex
	data map[string]*telekomv1alpha1.ClusterConfig
	rest map[string]*rest.Config
	// clusterToSecret tracks which kubeconfig secret each ClusterConfig uses (keyed by cluster name)
	clusterToSecret map[string]string
	// secretToClusters tracks all clusters backed by a given secret (keyed by namespace/name)
	secretToClusters map[string]map[string]struct{}
}

func NewClientProvider(c ctrlclient.Client, log *zap.SugaredLogger) *ClientProvider {
	return &ClientProvider{
		k8s:              c,
		log:              log,
		data:             map[string]*telekomv1alpha1.ClusterConfig{},
		rest:             map[string]*rest.Config{},
		clusterToSecret:  map[string]string{},
		secretToClusters: map[string]map[string]struct{}{},
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
		return cfg, nil
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
		return cfg, nil
	}

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

// GetRESTConfig returns a rest.Config built from the referenced kubeconfig secret, caching it.
func (p *ClientProvider) GetRESTConfig(ctx context.Context, name string) (*rest.Config, error) {
	p.mu.RLock()
	rc, ok := p.rest[name]
	p.mu.RUnlock()
	if ok {
		return rc, nil
	}
	// Legacy Get behavior lists across namespaces when namespace is empty.
	cc, err := p.GetAcrossAllNamespaces(ctx, name)
	if err != nil {
		return nil, err
	}
	secretDataKey := cc.Spec.KubeconfigSecretRef.Key
	if secretDataKey == "" {
		// default to 'value' for Cluster API compatibility
		secretDataKey = "value"
	}
	secret := corev1.Secret{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Name: cc.Spec.KubeconfigSecretRef.Name, Namespace: cc.Spec.KubeconfigSecretRef.Namespace}, &secret); err != nil {
		return nil, fmt.Errorf("fetch kubeconfig secret: %w", err)
	}
	raw, ok := secret.Data[secretDataKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing key %s", cc.Spec.KubeconfigSecretRef.Namespace, cc.Spec.KubeconfigSecretRef.Name, secretDataKey)
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
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
	p.mu.Lock()
	p.rest[name] = cfg
	secretRefKey := secretCacheKey(cc.Spec.KubeconfigSecretRef.Namespace, cc.Spec.KubeconfigSecretRef.Name)
	p.clusterToSecret[name] = secretRefKey
	if _, ok := p.secretToClusters[secretRefKey]; !ok {
		p.secretToClusters[secretRefKey] = map[string]struct{}{}
	}
	p.secretToClusters[secretRefKey][name] = struct{}{}
	p.mu.Unlock()
	return cfg, nil
}

// Invalidate removes an entry (called by informer/controller update hooks later).
func (p *ClientProvider) Invalidate(name string) {
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
