package breakglass

import (
	"context"
	"fmt"
	"strings"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterConfigManager provides access to ClusterConfig CRs by name.
type ClusterConfigManager struct {
	client client.Client
	log    *zap.SugaredLogger
}

// ClusterConfigManagerOption configures a ClusterConfigManager during construction.
type ClusterConfigManagerOption func(*ClusterConfigManager)

// WithClusterConfigLogger sets a custom logger for the ClusterConfigManager.
// If not provided, the global zap.S() logger is used as fallback.
// Passing nil is a no-op (the existing logger is retained).
func WithClusterConfigLogger(log *zap.SugaredLogger) ClusterConfigManagerOption {
	return func(ccm *ClusterConfigManager) {
		if log != nil {
			ccm.log = log
		}
	}
}

// getLogger returns the injected logger or falls back to the global logger.
func (ccm *ClusterConfigManager) getLogger() *zap.SugaredLogger {
	if ccm.log != nil {
		return ccm.log
	}
	return zap.S()
}

// NewClusterConfigManager creates a ClusterConfigManager backed by the provided client.
// Configuration is applied via functional options (WithClusterConfigLogger).
func NewClusterConfigManager(c client.Client, opts ...ClusterConfigManagerOption) *ClusterConfigManager {
	ccm := &ClusterConfigManager{client: c}
	for _, opt := range opts {
		if opt != nil {
			opt(ccm)
		}
	}
	return ccm
}

// GetClusterConfigByName fetches the ClusterConfig CR by metadata.name (which is usually the cluster name/ID)
func (ccm *ClusterConfigManager) GetClusterConfigByName(ctx context.Context, name string) (*breakglassv1alpha1.ClusterConfig, error) {
	// Try to use a field index (metadata.name) if available via the client's cache.
	list := breakglassv1alpha1.ClusterConfigList{}
	// Try to use a field index (metadata.name) via MatchingFields if available.
	if err := ccm.client.List(ctx, &list, client.MatchingFields{"metadata.name": name}); err == nil {
		matching := make([]*breakglassv1alpha1.ClusterConfig, 0, len(list.Items))
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
	list2 := breakglassv1alpha1.ClusterConfigList{}
	if err := ccm.client.List(ctx, &list2); err != nil {
		ccm.getLogger().Errorw("Failed to list ClusterConfig resources", "error", err)
		return nil, fmt.Errorf("failed to list ClusterConfig resources: %w", err)
	}
	matching := make([]*breakglassv1alpha1.ClusterConfig, 0, len(list2.Items))
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
func (ccm *ClusterConfigManager) GetClusterConfigInNamespace(ctx context.Context, namespace, name string) (*breakglassv1alpha1.ClusterConfig, error) {
	got := &breakglassv1alpha1.ClusterConfig{}
	if err := ccm.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, got); err != nil {
		return nil, err
	}
	return got, nil
}
