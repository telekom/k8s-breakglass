// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestDebugSessionResourceIntentionallyRetainedRequiresExactIdentity(t *testing.T) {
	ref := breakglassv1alpha1.DeployedResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "evidence", UID: "uid", Source: "auxiliary:kept"}
	ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "kept", DeleteAfter: false}}}, AuxiliaryResourceStatuses: []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "kept", APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, ResourceName: ref.Name, UID: ref.UID}}}}
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
	ds.Status.ResolvedTemplate.AuxiliaryResources[0].DeleteAfter = true
	require.False(t, DebugSessionResourceIntentionallyRetained(ds, ref))
	ds.Status.ResolvedTemplate.AuxiliaryResources[0].DeleteAfter = false
	ds.Status.AuxiliaryResourceStatuses[0].UID = "primary"
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, ResourceName: ref.Name, UID: ref.UID}}
	require.True(t, DebugSessionResourceIntentionallyRetained(ds, ref))
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].UID = ""
	require.False(t, DebugSessionResourceIntentionallyRetained(ds, ref))
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
				ds := &breakglassv1alpha1.DebugSession{Status: breakglassv1alpha1.DebugSessionStatus{ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{AuxiliaryResources: []breakglassv1alpha1.AuxiliaryResource{{Name: "keep"}}}}}
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
