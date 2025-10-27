package cluster

import (
	"context"
	"fmt"
	"strings"
	"sync"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientProvider resolves ClusterConfig objects and caches lightweight metadata.
type ClientProvider struct {
	k8s  ctrlclient.Client
	log  *zap.SugaredLogger
	mu   sync.RWMutex
	data map[string]*telekomv1alpha1.ClusterConfig
	rest map[string]*rest.Config
}

func NewClientProvider(c ctrlclient.Client, log *zap.SugaredLogger) *ClientProvider {
	return &ClientProvider{k8s: c, log: log, data: map[string]*telekomv1alpha1.ClusterConfig{}, rest: map[string]*rest.Config{}}
}

// Get returns cached ClusterConfig or fetches it (metadata only usage for now).
func (p *ClientProvider) Get(ctx context.Context, name string) (*telekomv1alpha1.ClusterConfig, error) {
	p.mu.RLock()
	cfg, ok := p.data[name]
	p.mu.RUnlock()
	if ok {
		return cfg, nil
	}

	cc := telekomv1alpha1.ClusterConfig{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Name: name}, &cc); err != nil {
		return nil, fmt.Errorf("fetch clusterconfig %s: %w", name, err)
	}
	p.mu.Lock()
	p.data[name] = &cc
	p.mu.Unlock()
	return &cc, nil
}

// GetRESTConfig returns a rest.Config built from the referenced kubeconfig secret, caching it.
func (p *ClientProvider) GetRESTConfig(ctx context.Context, name string) (*rest.Config, error) {
	p.mu.RLock()
	rc, ok := p.rest[name]
	p.mu.RUnlock()
	if ok {
		return rc, nil
	}
	cc, err := p.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	secretKey := cc.Spec.KubeconfigSecretRef.Key
	if secretKey == "" {
		secretKey = "kubeconfig"
	}
	secret := corev1.Secret{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Name: cc.Spec.KubeconfigSecretRef.Name, Namespace: cc.Spec.KubeconfigSecretRef.Namespace}, &secret); err != nil {
		return nil, fmt.Errorf("fetch kubeconfig secret: %w", err)
	}
	raw, ok := secret.Data[secretKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing key %s", cc.Spec.KubeconfigSecretRef.Namespace, cc.Spec.KubeconfigSecretRef.Name, secretKey)
	}
	cfg, err := clientcmd.RESTConfigFromKubeConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	// If the kubeconfig references a loopback endpoint (kind default), rewrite to in-cluster service DNS
	if strings.Contains(cfg.Host, "127.0.0.1") || strings.Contains(cfg.Host, "localhost") {
		p.log.Infow("Rewriting loopback kubeconfig host to in-cluster DNS", "original", cfg.Host, "replacement", "https://kubernetes.default.svc")
		cfg.Host = "https://kubernetes.default.svc"
	}
	if cc.Spec.QPS != nil {
		cfg.QPS = float32(*cc.Spec.QPS)
	}
	if cc.Spec.Burst != nil {
		cfg.Burst = int(*cc.Spec.Burst)
	}
	p.mu.Lock()
	p.rest[name] = cfg
	p.mu.Unlock()
	return cfg, nil
}

// Invalidate removes an entry (called by informer/controller update hooks later).
func (p *ClientProvider) Invalidate(name string) {
	p.mu.Lock()
	delete(p.data, name)
	delete(p.rest, name)
	p.mu.Unlock()
}
