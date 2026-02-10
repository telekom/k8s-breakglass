package breakglass

import (
	"context"
	"fmt"
	"strings"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterConfigManager provides access to ClusterConfig CRs by name.
type ClusterConfigManager struct {
	client client.Client
	log    *zap.SugaredLogger
}

func NewClusterConfigManager(c client.Client, log ...*zap.SugaredLogger) *ClusterConfigManager {
	return &ClusterConfigManager{client: c, log: getLoggerOrDefault(log...)}
}

// getLog returns the configured logger or falls back to the cached no-op logger
// to prevent nil-pointer panics when the log field was not set via the constructor.
func (ccm *ClusterConfigManager) getLog() *zap.SugaredLogger {
	if ccm.log != nil {
		return ccm.log
	}
	return nopLogger
}

// GetClusterConfigByName fetches the ClusterConfig CR by metadata.name (which is usually the cluster name/ID)
func (ccm *ClusterConfigManager) GetClusterConfigByName(ctx context.Context, name string) (*telekomv1alpha1.ClusterConfig, error) {
	// Try to use a field index (metadata.name) if available via the client's cache.
	list := telekomv1alpha1.ClusterConfigList{}
	// Try to use a field index (metadata.name) via MatchingFields if available.
	if err := ccm.client.List(ctx, &list, client.MatchingFields{"metadata.name": name}); err == nil {
		matching := make([]*telekomv1alpha1.ClusterConfig, 0, len(list.Items))
		for i := range list.Items {
			if list.Items[i].Name == name {
				matching = append(matching, &list.Items[i])
			}
		}
		switch len(matching) {
		case 0:
			// continue to fallback for legacy behavior
		case 1:
			return matching[0], nil
		default:
			namespaces := make([]string, 0, len(matching))
			for _, cfg := range matching {
				namespaces = append(namespaces, cfg.Namespace)
			}
			return nil, fmt.Errorf("clusterconfig name %q is not unique; found in namespaces: %s", name, strings.Join(namespaces, ","))
		}
	}

	// Fallback: do a full list scan (should be rare) - maintain original behavior for safety.
	list2 := telekomv1alpha1.ClusterConfigList{}
	if err := ccm.client.List(ctx, &list2); err != nil {
		ccm.getLog().Errorw("Failed to list ClusterConfig resources", "error", err.Error())
		return nil, fmt.Errorf("failed to list ClusterConfig resources: %w", err)
	}
	matching := make([]*telekomv1alpha1.ClusterConfig, 0, len(list2.Items))
	for i := range list2.Items {
		if list2.Items[i].Name == name {
			matching = append(matching, &list2.Items[i])
		}
	}
	switch len(matching) {
	case 0:
		return nil, fmt.Errorf("failed to get ClusterConfig by name %q: not found", name)
	case 1:
		return matching[0], nil
	default:
		namespaces := make([]string, 0, len(matching))
		for _, cfg := range matching {
			namespaces = append(namespaces, cfg.Namespace)
		}
		return nil, fmt.Errorf("clusterconfig name %q is not unique; found in namespaces: %s", name, strings.Join(namespaces, ","))
	}
}

// GetClusterConfigInNamespace fetches the ClusterConfig resource by name within the provided namespace.
// This avoids cross-namespace listing when the caller knows the escalation or resource namespace.
func (ccm *ClusterConfigManager) GetClusterConfigInNamespace(ctx context.Context, namespace, name string) (*telekomv1alpha1.ClusterConfig, error) {
	got := &telekomv1alpha1.ClusterConfig{}
	if err := ccm.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, got); err != nil {
		return nil, err
	}
	return got, nil
}
