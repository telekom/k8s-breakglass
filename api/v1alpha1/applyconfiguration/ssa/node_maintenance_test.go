// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestNodeMaintenanceSnapshotRoundTrip(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
			NodeMaintenance: &breakglassv1alpha1.DebugSessionNodeMaintenance{
				Action: "bridge-fdb-replace", Image: "registry.example/helper@sha256:" + strings.Repeat("a", 64), DryRun: true,
				AllowedTargets: []breakglassv1alpha1.NodeMaintenanceTarget{{TargetNode: "node-a", TargetNodeUID: "node-uid",
					Interface: "port0", Bridge: "br0", EntryMAC: "02:00:00:00:00:02", VLAN: ptr.To(int32(100)), VRF: "vrf-blue"}},
			},
		},
		NodeMaintenance: &breakglassv1alpha1.NodeMaintenanceStatus{OperationID: "operation", NamespaceUID: "ns-uid",
			ActiveDeadlineSeconds: 30, LeaseUID: "lease-uid", JobUID: "job-uid", JobCreateAttempted: true, PodUID: "pod-uid", CreateAttempted: true,
			Result: "succeeded", ResultAudited: true, Released: true},
	}
	raw, err := json.Marshal(DebugSessionStatusFrom(status))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, status.NodeMaintenance, restored.NodeMaintenance)
	require.Equal(t, status.ResolvedTemplate.NodeMaintenance, restored.ResolvedTemplate.NodeMaintenance)
}

func TestKexecRecoverySnapshotRoundTrip(t *testing.T) {
	digest := strings.Repeat("b", 64)
	status := &breakglassv1alpha1.DebugSessionStatus{
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
			NodeMaintenance: &breakglassv1alpha1.DebugSessionNodeMaintenance{
				Action: "kexec-recovery", Image: "registry.example/helper@sha256:" + strings.Repeat("a", 64),
				AllowedTargets: []breakglassv1alpha1.NodeMaintenanceTarget{{TargetNode: "node-a", TargetNodeUID: "node-uid"}},
				Kexec: &breakglassv1alpha1.NodeMaintenanceKexec{Profile: "recovery-6-8", HostPath: "/var/lib/recovery/6.8",
					KernelSHA256: digest, InitrdSHA256: digest, CmdlineSHA256: digest, DrainTimeoutSeconds: 600},
			},
		},
		NodeMaintenance: &breakglassv1alpha1.NodeMaintenanceStatus{OperationID: "operation", NamespaceUID: "ns-uid",
			ActiveDeadlineSeconds: 900, BootID: "0f0e0d0c-0b0a-0908-0706-050403020100",
			CordonedAt: ptr.To(metav1.Unix(1700000000, 0)), CreateAttempted: true},
	}
	raw, err := json.Marshal(DebugSessionStatusFrom(status))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, status.NodeMaintenance, restored.NodeMaintenance)
	require.Equal(t, status.ResolvedTemplate.NodeMaintenance, restored.ResolvedTemplate.NodeMaintenance)
}
