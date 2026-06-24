package breakglass

import (
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
)

// IsClusterConfigReady reports whether a ClusterConfig is usable for new sessions.
func IsClusterConfigReady(cc *breakglassv1alpha1.ClusterConfig) bool {
	if cc == nil {
		return false
	}
	if len(cc.Status.Conditions) == 0 {
		// Preserve unit-test and initial-object compatibility, matching
		// BreakglassEscalation.IsReady behavior for generation-less fake objects.
		return cc.Generation == 0
	}
	return apimeta.IsStatusConditionTrue(cc.Status.Conditions, string(breakglassv1alpha1.ClusterConfigConditionReady))
}
