// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestTrafficMirrorSnapshotRoundTrip(t *testing.T) {
	status := &breakglassv1alpha1.DebugSessionStatus{
		ResolvedTemplate: &breakglassv1alpha1.DebugSessionTemplateSpec{
			TrafficMirror: &breakglassv1alpha1.DebugSessionTrafficMirror{
				Image: "registry.example/mirror@sha256:" + strings.Repeat("a", 64), Direction: "ingress", Filter: "tcp port 8080",
				SnapLength: 128, MaxPackets: 1000, CapturePayload: true, MaxBandwidthMbps: 20,
				AllowedSources: []breakglassv1alpha1.TrafficMirrorSource{
					{Pod: &breakglassv1alpha1.TrafficMirrorPodSource{Namespace: "shop", MatchLabels: map[string]string{"app": "cart"}}, Interfaces: []string{"eth0", "net1"}},
					{Node: &breakglassv1alpha1.TrafficMirrorNodeSource{MatchLabels: map[string]string{"role": "edge"}}, Interfaces: []string{"bond0"}},
				},
			},
		},
		TrafficMirror: &breakglassv1alpha1.TrafficMirrorStatus{OperationID: "traffic-mirror-op", State: "mirroring", CreateAttempted: true,
			PodUID: "agent-uid", CapturePodUID: "capture-uid", TeardownResult: "teardown failed on Node node-a: teardown-unverifiable",
			ClusterConfigUID: "cc-uid", NamespaceUID: "ns-uid", SourcePodIP: "10.244.0.7", TeardownVerified: true, StopAudited: true, Released: true, Message: "attached"},
	}
	raw, err := json.Marshal(DebugSessionStatusFrom(status))
	require.NoError(t, err)
	var restored breakglassv1alpha1.DebugSessionStatus
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, status.TrafficMirror, restored.TrafficMirror)
	require.Equal(t, status.ResolvedTemplate.TrafficMirror, restored.ResolvedTemplate.TrafficMirror)
}
