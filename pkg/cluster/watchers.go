package cluster

import (
	"context"
	"fmt"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	clientcache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
)

// RegisterInvalidationHandlers wires controller-runtime cache event handlers to keep the ClientProvider caches fresh.
// It watches ClusterConfig and Secret events to invalidate cached ClusterConfigs and REST configs whenever
// a relevant object changes or is deleted.
func RegisterInvalidationHandlers(ctx context.Context, mgr ctrl.Manager, provider *ClientProvider, log *zap.SugaredLogger) error {
	if provider == nil {
		return fmt.Errorf("client provider is nil")
	}
	if mgr == nil {
		return fmt.Errorf("manager is nil")
	}
	cache := mgr.GetCache()
	if cache == nil {
		return fmt.Errorf("manager cache is nil")
	}

	ccInformer, err := cache.GetInformer(ctx, &telekomv1alpha1.ClusterConfig{})
	if err != nil {
		return fmt.Errorf("get ClusterConfig informer: %w", err)
	}
	if _, err := ccInformer.AddEventHandler(clientcache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldCfg := extractClusterConfig(oldObj)
			newCfg := extractClusterConfig(newObj)
			if newCfg == nil {
				return
			}
			if oldCfg != nil && oldCfg.ResourceVersion == newCfg.ResourceVersion {
				return
			}
			provider.Invalidate(newCfg.Name)
			if log != nil {
				log.Debugw("ClusterConfig cache invalidated", "cluster", newCfg.Name)
			}
		},
		DeleteFunc: func(obj interface{}) {
			cfg := extractClusterConfig(obj)
			if cfg == nil {
				return
			}
			provider.Invalidate(cfg.Name)
			if log != nil {
				log.Debugw("ClusterConfig cache invalidated due to delete", "cluster", cfg.Name)
			}
		},
	}); err != nil {
		return fmt.Errorf("register ClusterConfig invalidation handler: %w", err)
	}

	secretInformer, err := cache.GetInformer(ctx, &corev1.Secret{})
	if err != nil {
		return fmt.Errorf("get Secret informer: %w", err)
	}
	if _, err := secretInformer.AddEventHandler(clientcache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			sec := extractSecret(newObj)
			if sec == nil {
				return
			}
			if !provider.IsSecretTracked(sec.Namespace, sec.Name) {
				return
			}
			provider.InvalidateSecret(sec.Namespace, sec.Name)
			if log != nil {
				log.Debugw("ClusterConfig caches invalidated due to Secret update", "secret", fmt.Sprintf("%s/%s", sec.Namespace, sec.Name))
			}
		},
		DeleteFunc: func(obj interface{}) {
			sec := extractSecret(obj)
			if sec == nil {
				return
			}
			if !provider.IsSecretTracked(sec.Namespace, sec.Name) {
				return
			}
			provider.InvalidateSecret(sec.Namespace, sec.Name)
			if log != nil {
				log.Debugw("ClusterConfig caches invalidated due to Secret delete", "secret", fmt.Sprintf("%s/%s", sec.Namespace, sec.Name))
			}
		},
	}); err != nil {
		return fmt.Errorf("register Secret invalidation handler: %w", err)
	}

	if log != nil {
		log.Infow("Registered ClusterConfig/Secret invalidation handlers")
	}
	return nil
}

func extractClusterConfig(obj interface{}) *telekomv1alpha1.ClusterConfig {
	switch t := obj.(type) {
	case *telekomv1alpha1.ClusterConfig:
		return t
	case clientcache.DeletedFinalStateUnknown:
		if cfg, ok := t.Obj.(*telekomv1alpha1.ClusterConfig); ok {
			return cfg
		}
	}
	return nil
}

func extractSecret(obj interface{}) *corev1.Secret {
	switch t := obj.(type) {
	case *corev1.Secret:
		return t
	case clientcache.DeletedFinalStateUnknown:
		if sec, ok := t.Obj.(*corev1.Secret); ok {
			return sec
		}
	}
	return nil
}
