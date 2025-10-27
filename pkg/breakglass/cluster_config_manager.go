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
	var cc telekomv1alpha1.ClusterConfig
	err := ccm.client.Get(ctx, client.ObjectKey{Name: name}, &cc)
	if err != nil {
		zap.S().Errorw("Failed to get ClusterConfig by name", "name", name, "error", err.Error())
		return nil, fmt.Errorf("failed to get ClusterConfig by name %q: %w", name, err)
	}
	return &cc, nil
}
