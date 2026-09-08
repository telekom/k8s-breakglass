// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"testing"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestDebugSessionCleanupPreservesConcurrentAuxiliaryDocument(t *testing.T) {
	baseline := []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "bundle", APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", ResourceName: "first", UID: "first-uid"}}
	desired := []breakglassv1alpha1.AuxiliaryResourceStatus{baseline[0]}
	current := []breakglassv1alpha1.AuxiliaryResourceStatus{baseline[0]}
	current[0].AdditionalResources = []breakglassv1alpha1.AdditionalResourceRef{{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", ResourceName: "late-document", UID: "late-uid"}}
	merged := mergeAuxiliaryResourceStatuses(baseline, desired, current)
	if len(merged) != 1 || len(merged[0].AdditionalResources) != 1 || merged[0].AdditionalResources[0].UID != "late-uid" {
		t.Fatal("cleanup merge erased concurrently persisted additional-document inventory")
	}
}
