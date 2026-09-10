// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// directTemplateAllowsCluster applies the documented OR between names and labels.
// Selector matching requires a uniquely resolved ClusterConfig from the caller.
func directTemplateAllowsCluster(template *breakglassv1alpha1.DebugSessionTemplate, name string, cluster *breakglassv1alpha1.ClusterConfig) bool {
	if template.Spec.Allowed == nil {
		return false
	}
	for _, pattern := range template.Spec.Allowed.Clusters {
		if matchPattern(pattern, name) {
			return true
		}
	}
	if template.Spec.Allowed.ClusterSelector == nil || cluster == nil {
		return false
	}
	selector, err := metav1.LabelSelectorAsSelector(template.Spec.Allowed.ClusterSelector)
	return err == nil && selector.Matches(labels.Set(cluster.Labels))
}
