// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"fmt"
	"testing"

	kptr "k8s.io/utils/ptr"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestDebugSessionResourceIntentionallyRetainedRequiresExactIdentity(t *testing.T) {
	ref := breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "evidence", UID: "uid", Source: "auxiliary:kept"}
	ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "kept", DeleteAfter: kptr.To(false)}}}, AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "kept", APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, ResourceName: ref.Name, UID: ref.UID}}}}
	require.True(t, DebugSessionResourceIntentionallyRetained(ds, ref))
	for _, field := range []string{"uid", "source", "kind", "version", "namespace", "name"} {
		t.Run(field, func(t *testing.T) {
			candidate := ref
			switch field {
			case "uid":
				candidate.UID = ""
			case "source":
				candidate.Source = "debug-pod"
			case "kind":
				candidate.Kind = "Secret"
			case "version":
				candidate.APIVersion = "v2"
			case "namespace":
				candidate.Namespace = "elsewhere"
			case "name":
				candidate.Name = "replacement"
			}
			require.False(t, DebugSessionResourceIntentionallyRetained(ds, candidate))
		})
	}
	ds.Status.ResolvedTemplate.AuxiliaryResources[0].DeleteAfter = kptr.To(true)
	require.False(t, DebugSessionResourceIntentionallyRetained(ds, ref))
	ds.Status.ResolvedTemplate.AuxiliaryResources[0].DeleteAfter = kptr.To(false)
	ds.Status.AuxiliaryResourceStatuses[0].UID = "primary"
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, ResourceName: ref.Name, UID: ref.UID}}
	require.True(t, DebugSessionResourceIntentionallyRetained(ds, ref))
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].UID = ""
	require.False(t, DebugSessionResourceIntentionallyRetained(ds, ref))
}

func TestDeletedAuxiliaryInventoryRequiresExactIdentity(t *testing.T) {
	for _, child := range []bool{false, true} {
		for _, mismatch := range []string{"", "uid", "source", "version", "kind", "name", "namespace", "incomplete", "not deleted"} {
			t.Run(fmt.Sprintf("child=%t/%s", child, mismatch), func(t *testing.T) {
				ref := breakglassv1alpha1.DeployedResourceRef{UID: "uid", APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "object", Source: "auxiliary:removed"}
				status := breakglassv1alpha1.AuxiliaryResourceStatus{Name: "removed", UID: ref.UID, APIVersion: ref.APIVersion, Kind: ref.Kind, ResourceName: ref.Name, Namespace: ref.Namespace, Deleted: mismatch != "not deleted"}
				if child {
					status.ResourceName = "parent"
					status.AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{UID: ref.UID, APIVersion: ref.APIVersion, Kind: ref.Kind, ResourceName: ref.Name, Namespace: ref.Namespace, Deleted: status.Deleted}}
				}
				switch mismatch {
				case "uid":
					ref.UID = "replacement"
				case "source":
					ref.Source = "auxiliary:other"
				case "version":
					ref.APIVersion = "v2"
				case "kind":
					ref.Kind = "Secret"
				case "name":
					ref.Name = "other"
				case "namespace":
					ref.Namespace = "other"
				case "incomplete":
					ref.UID = ""
				}
				session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
					DeployedResources:         []breakglassv1alpha1.DeployedResourceRef{ref},
					AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{status},
				}}
				require.Equal(t, mismatch == "", DebugSessionAuxiliaryResourceDeleted(session, ref))
				require.Equal(t, mismatch != "", DebugSessionHasActionableDeployedResources(session))
			})
		}
	}
	legacyRef := breakglassv1alpha1.DeployedResourceRef{UID: "uid", APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "object"}
	legacyStatus := breakglassv1alpha1.AuxiliaryResourceStatus{Name: "removed", UID: legacyRef.UID, APIVersion: legacyRef.APIVersion, Kind: legacyRef.Kind, ResourceName: legacyRef.Name, Namespace: legacyRef.Namespace}
	session := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{
		DeployedResources:         []breakglassv1alpha1.DeployedResourceRef{legacyRef},
		AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{legacyStatus},
	}}
	require.False(t, DebugSessionAuxiliaryResourceDeleted(session, legacyRef))
	legacyStatus.Deleted = true
	session.Status.AuxiliaryResourceStatuses[0] = legacyStatus
	require.True(t, DebugSessionAuxiliaryResourceDeleted(session, legacyRef))
}

func TestRetainedAuxiliaryRequiresCompleteIdentity(t *testing.T) {
	for _, child := range []bool{false, true} {
		for _, missing := range []string{"", "uid", "version", "kind", "name"} {
			t.Run(fmt.Sprintf("child=%t/missing=%s", child, missing), func(t *testing.T) {
				ref := breakglassv1alpha1.DeployedResourceRef{UID: "uid", APIVersion: "v1", Kind: "Namespace", Name: "evidence", Source: "auxiliary:keep"}
				switch missing {
				case "uid":
					ref.UID = ""
				case "version":
					ref.APIVersion = ""
				case "kind":
					ref.Kind = ""
				case "name":
					ref.Name = ""
				}

				ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "keep", DeleteAfter: kptr.To(false)}}}}}
				status := breakglassv1alpha1.AuxiliaryResourceStatus{Name: "keep", Created: true, UID: ref.UID, APIVersion: ref.APIVersion, Kind: ref.Kind, ResourceName: ref.Name}
				if child {
					item := breakglassv1alpha1.AdditionalResourceRef{UID: ref.UID, APIVersion: ref.APIVersion, Kind: ref.Kind, ResourceName: ref.Name}
					status = breakglassv1alpha1.AuxiliaryResourceStatus{Name: "keep", Deleted: true, AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{item}}
					require.Equal(t, missing != "", DebugSessionAuxiliaryChildHasCleanupResidual(ds, "keep", item))
				} else {
					require.Equal(t, missing != "", DebugSessionAuxiliaryStatusHasCleanupResidual(ds, status))
				}
				ds.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{status}
				require.Equal(t, missing == "", DebugSessionResourceIntentionallyRetained(ds, ref))
			})
		}
	}
}
