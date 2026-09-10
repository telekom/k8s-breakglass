// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"

// Exempt only the exact observed auxiliary identity selected for retention.
// Unknown create outcomes and name-reused resources still require cleanup review.
func DebugSessionResourceIntentionallyRetained(ds *breakglassv1alpha1.DebugSession, ref breakglassv1alpha1.DeployedResourceRef) bool {
	if ref.UID == "" || ds.Status.ResolvedTemplate == nil {
		return false
	}
	for _, configured := range ds.Status.ResolvedTemplate.AuxiliaryResources {
		if configured.DeleteAfter || ref.Source != "auxiliary:"+configured.Name {
			continue
		}
		for _, status := range ds.Status.AuxiliaryResourceStatuses {
			if status.Name != configured.Name {
				continue
			}
			if status.UID == ref.UID && status.Kind == ref.Kind && status.APIVersion == ref.APIVersion && status.ResourceName == ref.Name && status.Namespace == ref.Namespace {
				return true
			}
			for _, child := range status.AdditionalResources {
				if child.UID == ref.UID && child.Kind == ref.Kind && child.APIVersion == ref.APIVersion && child.ResourceName == ref.Name && child.Namespace == ref.Namespace {
					return true
				}
			}
		}
	}
	return false
}
