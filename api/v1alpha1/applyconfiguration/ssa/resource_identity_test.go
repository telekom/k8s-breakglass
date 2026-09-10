// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestDebugSessionStatusPreservesResourceIdentities(t *testing.T) {
	status := breakglassv1alpha1.DebugSessionStatus{
		Approval:                    &breakglassv1alpha1.DebugSessionApproval{ApprovedBy: "approver", ApprovedByIdentityProvider: "idp-a"},
		Participants:                []breakglassv1alpha1.DebugSessionParticipant{{User: "owner", IdentityProviderName: "idp-a", IdentityProviderIssuer: "https://a.example"}},
		DeployedResources:           []breakglassv1alpha1.DeployedResourceRef{{APIVersion: "v1", Kind: "Pod", Name: "pod", Namespace: "ns", UID: "deployed", Source: "debug-pod", CreateOperationID: "deployed-op"}},
		AllowedPods:                 []breakglassv1alpha1.AllowedPodRef{{Name: "pod", Namespace: "ns", UID: "allowed"}},
		AuxiliaryResourceStatuses:   []breakglassv1alpha1.AuxiliaryResourceStatus{{UID: "auxiliary", CreateOperationID: "auxiliary-op", AdditionalResources: []breakglassv1alpha1.AdditionalResourceRef{{UID: "additional", CreateOperationID: "additional-op"}}}},
		PodTemplateResourceStatuses: []breakglassv1alpha1.PodTemplateResourceStatus{{UID: "pod-template", CreateOperationID: "pod-template-op"}},
		KubectlDebugStatus:          &breakglassv1alpha1.KubectlDebugStatus{EphemeralContainersInjected: []breakglassv1alpha1.EphemeralContainerRef{{PodUID: "ephemeral"}}, CopiedPods: []breakglassv1alpha1.CopiedPodRef{{CopyUID: "copy"}}},
	}
	encoded, err := json.Marshal(DebugSessionStatusFrom(&status))
	require.NoError(t, err)
	var roundtrip breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(encoded, &roundtrip))
	require.Equal(t, status.Approval, roundtrip.Approval)
	require.Equal(t, status.Participants, roundtrip.Participants)
	require.Equal(t, status.DeployedResources, roundtrip.DeployedResources)
	require.Equal(t, "deployed-op", roundtrip.DeployedResources[0].CreateOperationID)
	require.Equal(t, "allowed", roundtrip.AllowedPods[0].UID)
	require.Equal(t, "auxiliary", roundtrip.AuxiliaryResourceStatuses[0].UID)
	require.Equal(t, "auxiliary-op", roundtrip.AuxiliaryResourceStatuses[0].CreateOperationID)
	require.Equal(t, "additional", roundtrip.AuxiliaryResourceStatuses[0].AdditionalResources[0].UID)
	require.Equal(t, "additional-op", roundtrip.AuxiliaryResourceStatuses[0].AdditionalResources[0].CreateOperationID)
	require.Equal(t, "pod-template", roundtrip.PodTemplateResourceStatuses[0].UID)
	require.Equal(t, "pod-template-op", roundtrip.PodTemplateResourceStatuses[0].CreateOperationID)
	require.Equal(t, "ephemeral", roundtrip.KubectlDebugStatus.EphemeralContainersInjected[0].PodUID)
	require.Equal(t, "copy", roundtrip.KubectlDebugStatus.CopiedPods[0].CopyUID)
}
