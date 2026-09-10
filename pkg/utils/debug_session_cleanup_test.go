// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"github.com/stretchr/testify/require"
	v1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"testing"
)

func TestDebugSessionResourceIntentionallyRetainedRequiresExactIdentity(t *testing.T) {
	ref := v1.DeployedResourceRef{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "evidence", UID: "uid", Source: "auxiliary:kept"}
	ds := &v1.DebugSession{Status: v1.DebugSessionStatus{ResolvedTemplate: &v1.DebugSessionTemplateSpec{AuxiliaryResources: []v1.AuxiliaryResource{{Name: "kept", DeleteAfter: false}}}, AuxiliaryResourceStatuses: []v1.AuxiliaryResourceStatus{{Name: "kept", APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, ResourceName: ref.Name, UID: ref.UID}}}}
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
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources = []v1.AdditionalResourceRef{{APIVersion: ref.APIVersion, Kind: ref.Kind, Namespace: ref.Namespace, ResourceName: ref.Name, UID: ref.UID}}
	require.True(t, DebugSessionResourceIntentionallyRetained(ds, ref))
	ds.Status.AuxiliaryResourceStatuses[0].AdditionalResources[0].UID = ""
	require.False(t, DebugSessionResourceIntentionallyRetained(ds, ref))
}
