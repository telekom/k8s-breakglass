// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package utils

import breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"

// Exempt only the exact observed auxiliary identity selected for retention.
// Unknown create outcomes and name-reused resources still require cleanup review.
func DebugSessionResourceIntentionallyRetained(ds *breakglassv1alpha1.DebugSession, ref breakglassv1alpha1.DeployedResourceRef) bool {
	if !completeDebugResourceIdentity(ref.UID, ref.APIVersion, ref.Kind, ref.Name) || ds.Status.ResolvedTemplate == nil {
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

// DebugSessionHasActionableDeployedResources excludes only confirmed policy-retained identities.
func DebugSessionHasActionableDeployedResources(ds *breakglassv1alpha1.DebugSession) bool {
	for _, ref := range ds.Status.DeployedResources {
		if !DebugSessionResourceIntentionallyRetained(ds, ref) {
			return true
		}
	}
	return false
}

// DebugSessionDeletesAuxiliaryResource returns the resolved cleanup policy.
func DebugSessionDeletesAuxiliaryResource(session *breakglassv1alpha1.DebugSession, name string) bool {
	if session.Status.ResolvedTemplate != nil {
		for _, resource := range session.Status.ResolvedTemplate.AuxiliaryResources {
			if resource.Name == name {
				return resource.DeleteAfter
			}
		}
	}
	return true
}

// DebugSessionAuxiliaryStatusHasCleanupResidual preserves unknown outcomes even for retained resources.
func DebugSessionAuxiliaryStatusHasCleanupResidual(session *breakglassv1alpha1.DebugSession, status breakglassv1alpha1.AuxiliaryResourceStatus) bool {
	return !status.Deleted && (status.Created || status.CreateOperationID != "" || status.UID != "" || status.ResourceName != "" || status.APIVersion != "" || status.Kind != "") && (!completeDebugResourceIdentity(status.UID, status.APIVersion, status.Kind, status.ResourceName) || DebugSessionDeletesAuxiliaryResource(session, status.Name))
}

// DebugSessionAuxiliaryChildHasCleanupResidual preserves unknown child outcomes independently of its parent.
func DebugSessionAuxiliaryChildHasCleanupResidual(session *breakglassv1alpha1.DebugSession, parent string, child breakglassv1alpha1.AdditionalResourceRef) bool {
	return !child.Deleted && (!completeDebugResourceIdentity(child.UID, child.APIVersion, child.Kind, child.ResourceName) || DebugSessionDeletesAuxiliaryResource(session, parent))
}

// DebugSessionPodTemplateStatusHasCleanupResidual treats every unconfirmed
// deletion as outstanding, including partially populated creation evidence.
func DebugSessionPodTemplateStatusHasCleanupResidual(status breakglassv1alpha1.PodTemplateResourceStatus) bool {
	return !status.Deleted
}

// Namespace is optional because auxiliary resources may be cluster-scoped.
func completeDebugResourceIdentity(uid, apiVersion, kind, name string) bool {
	return uid != "" && apiVersion != "" && kind != "" && name != ""
}
