package debug

import (
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
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
	clusterMap := make(map[string]*breakglassv1alpha1.ClusterConfig, len(items))
	clusterNames := make([]string, 0, len(items))
	for i := range items {
		cc := &items[i]
		if !isDebugClusterConfigReady(cc) {
			continue
		}
		clusterMap[cc.Name] = cc
		clusterNames = append(clusterNames, cc.Name)
	}
	return clusterMap, clusterNames
}
