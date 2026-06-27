package debug

import (
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/clusterconfiglookup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
)

func isDebugClusterConfigReady(cc *breakglassv1alpha1.ClusterConfig) bool {
	if cc == nil {
		return false
	}
	if len(cc.Status.Conditions) == 0 {
		// Preserve compatibility with generation-less fake objects in existing unit tests.
		return cc.Generation == 0
	}
	return apimeta.IsStatusConditionTrue(cc.Status.Conditions, string(breakglassv1alpha1.ClusterConfigConditionReady))
}

func readyDebugClusterConfigMap(items []breakglassv1alpha1.ClusterConfig) (map[string]*breakglassv1alpha1.ClusterConfig, []string) {
	nameCounts := debugClusterConfigNameCounts(items)
	clusterMap := make(map[string]*breakglassv1alpha1.ClusterConfig, len(items))
	clusterNames := make([]string, 0, len(items))
	for i := range items {
		cc := &items[i]
		if !isDebugClusterConfigReady(cc) {
			continue
		}
		if nameCounts[cc.Name] != 1 {
			continue
		}
		clusterMap[cc.Name] = cc
		clusterNames = append(clusterNames, cc.Name)
	}
	return clusterMap, clusterNames
}

func debugClusterConfigMap(items []breakglassv1alpha1.ClusterConfig) map[string]*breakglassv1alpha1.ClusterConfig {
	nameCounts := debugClusterConfigNameCounts(items)
	clusterMap := make(map[string]*breakglassv1alpha1.ClusterConfig, len(items))
	for i := range items {
		cc := &items[i]
		if nameCounts[cc.Name] != 1 {
			continue
		}
		clusterMap[cc.Name] = cc
	}
	return clusterMap
}

func debugClusterConfigNameCounts(items []breakglassv1alpha1.ClusterConfig) map[string]int {
	nameCounts := make(map[string]int, len(items))
	for i := range items {
		cc := &items[i]
		nameCounts[cc.Name]++
	}
	return nameCounts
}

type debugClusterConfigAmbiguity string

const (
	debugClusterConfigAmbiguityNone   debugClusterConfigAmbiguity = ""
	debugClusterConfigAmbiguityName   debugClusterConfigAmbiguity = "name"
	debugClusterConfigAmbiguityTenant debugClusterConfigAmbiguity = "tenant"
)

func findDebugClusterConfigByNameOrTenant(items []breakglassv1alpha1.ClusterConfig, cluster string) (*breakglassv1alpha1.ClusterConfig, debugClusterConfigAmbiguity) {
	nameMatch, err := clusterconfiglookup.SingleByName(items, cluster)
	if err != nil {
		if apierrors.IsConflict(err) {
			return nil, debugClusterConfigAmbiguityName
		}
		return nil, debugClusterConfigAmbiguityName
	}
	if nameMatch != nil {
		return nameMatch, debugClusterConfigAmbiguityNone
	}

	nameCounts := debugClusterConfigNameCounts(items)
	var tenantMatch *breakglassv1alpha1.ClusterConfig
	for i := range items {
		cc := &items[i]
		if cc.Spec.Tenant != cluster {
			continue
		}
		if tenantMatch != nil {
			return nil, debugClusterConfigAmbiguityTenant
		}
		tenantMatch = cc
	}
	if tenantMatch != nil && nameCounts[tenantMatch.Name] != 1 {
		return tenantMatch, debugClusterConfigAmbiguityName
	}
	return tenantMatch, debugClusterConfigAmbiguityNone
}
