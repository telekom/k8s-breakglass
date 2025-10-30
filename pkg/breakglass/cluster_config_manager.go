package breakglass

import (
	"context"
	"fmt"

	telekomv1alpha1 "gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/api/v1alpha1"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterConfigManager provides access to ClusterConfig CRs by name.
type ClusterConfigManager struct {
	client client.Client
}

func NewClusterConfigManager(c client.Client) *ClusterConfigManager {
	return &ClusterConfigManager{client: c}
}

// GetClusterConfigByName fetches the ClusterConfig CR by metadata.name (which is usually the cluster name/ID)
func (ccm *ClusterConfigManager) GetClusterConfigByName(ctx context.Context, name string) (*telekomv1alpha1.ClusterConfig, error) {
	// Try to use a field index (metadata.name) if available via the client's cache.
	list := telekomv1alpha1.ClusterConfigList{}
	// Try to use a field index (metadata.name) via MatchingFields if available.
	if err := ccm.client.List(ctx, &list, client.MatchingFields{"metadata.name": name}); err == nil {
		for i := range list.Items {
			if list.Items[i].Name == name {
				return &list.Items[i], nil
			}
		}
	}

	// Fallback: do a full list scan (should be rare) - maintain original behavior for safety.
	list2 := telekomv1alpha1.ClusterConfigList{}
	if err := ccm.client.List(ctx, &list2); err != nil {
		zap.S().Errorw("Failed to list ClusterConfig resources", "error", err.Error())
		return nil, fmt.Errorf("failed to list ClusterConfig resources: %w", err)
	}
	for i := range list2.Items {
		if list2.Items[i].Name == name {
			return &list2.Items[i], nil
		}
	}
	return nil, fmt.Errorf("failed to get ClusterConfig by name %q: not found", name)
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
