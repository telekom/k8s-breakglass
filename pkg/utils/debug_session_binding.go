// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"fmt"
	"slices"
	"sort"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// FindDebugSessionBinding uses the same deterministic selection for activation and retention.
func FindDebugSessionBinding(ctx context.Context, reader ctrlclient.Reader, template *breakglassv1alpha1.DebugSessionTemplate, clusterName string) (*breakglassv1alpha1.DebugSessionClusterBinding, error) {
	bindingList := &breakglassv1alpha1.DebugSessionClusterBindingList{}
	if err := reader.List(ctx, bindingList); err != nil {
		return nil, fmt.Errorf("failed to list cluster bindings: %w", err)
	}

	// Get cluster config for label-based matching
	var clusterConfig *breakglassv1alpha1.ClusterConfig
	clusterConfigList := &breakglassv1alpha1.ClusterConfigList{}
	if err := reader.List(ctx, clusterConfigList); err != nil {
		return nil, fmt.Errorf("list cluster configs for binding quota resolution: %w", err)
	}
	for i := range clusterConfigList.Items {
		if clusterConfigList.Items[i].Name == clusterName {
			if clusterConfig != nil {
				return nil, fmt.Errorf("ambiguous cluster config for binding quota resolution")
			}
			clusterConfig = &clusterConfigList.Items[i]
		}
	}

	sort.Slice(bindingList.Items, func(i, j int) bool {
		a, b := bindingList.Items[i], bindingList.Items[j]
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	for i := range bindingList.Items {
		binding := &bindingList.Items[i]
		if !IsDebugSessionBindingActive(binding) {
			continue
		}

		// Check if binding references this template
		if !DebugBindingMatchesTemplate(binding, template) {
			continue
		}

		if binding.Spec.ClusterSelector != nil && clusterConfig == nil && !slices.Contains(binding.Spec.Clusters, clusterName) {
			return nil, fmt.Errorf("cluster config required to resolve binding selector")
		}

		// Check if binding matches this cluster
		if !DebugBindingMatchesCluster(binding, clusterName, clusterConfig) {
			continue
		}

		// Found a matching binding
		return binding, nil
	}

	return nil, nil // No matching binding found (not an error)
}

// DebugBindingMatchesTemplate matches an explicit reference or label selector.
func DebugBindingMatchesTemplate(binding *breakglassv1alpha1.DebugSessionClusterBinding, template *breakglassv1alpha1.DebugSessionTemplate) bool {
	// Check templateRef
	if binding.Spec.TemplateRef != nil && binding.Spec.TemplateRef.Name == template.Name {
		return true
	}
	// Check templateSelector
	if binding.Spec.TemplateSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.TemplateSelector)
		if err == nil {
			templateLabels := labels.Set(template.Labels)
			if selector.Matches(templateLabels) {
				return true
			}
		}
	}
	return false
}

// DebugBindingMatchesCluster matches an explicit cluster or label selector.
func DebugBindingMatchesCluster(binding *breakglassv1alpha1.DebugSessionClusterBinding, clusterName string, clusterConfig *breakglassv1alpha1.ClusterConfig) bool {
	// Check explicit cluster list
	for _, cluster := range binding.Spec.Clusters {
		if cluster == clusterName {
			return true
		}
	}

	// Check clusterSelector
	if binding.Spec.ClusterSelector != nil && clusterConfig != nil {
		selector, err := metav1.LabelSelectorAsSelector(binding.Spec.ClusterSelector)
		if err == nil {
			clusterLabels := labels.Set(clusterConfig.Labels)
			if selector.Matches(clusterLabels) {
				return true
			}
		}
	}

	return false
}

// IsDebugSessionBindingActive preserves the binding effective and expiry boundaries.
func IsDebugSessionBindingActive(binding *breakglassv1alpha1.DebugSessionClusterBinding) bool {
	if binding.Spec.Disabled {
		return false
	}

	now := metav1.Now()

	// Check if binding has expired
	if binding.Spec.ExpiresAt != nil && binding.Spec.ExpiresAt.Before(&now) {
		return false
	}

	// Check if binding is not yet effective
	if binding.Spec.EffectiveFrom != nil && now.Before(binding.Spec.EffectiveFrom) {
		return false
	}

	return true
}
