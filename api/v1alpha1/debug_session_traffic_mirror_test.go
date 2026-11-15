// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func trafficMirrorTemplateSpec() *DebugSessionTemplateSpec {
	return &DebugSessionTemplateSpec{
		TargetNamespace: NodeMaintenanceNamespace,
		Approvers:       &DebugSessionApprovers{Users: []string{"approver@example.com"}},
		Constraints:     &DebugSessionConstraints{MaxDuration: "30m"},
		TrafficMirror: &DebugSessionTrafficMirror{
			Image: "ghcr.io/example/network-debug@sha256:" + strings.Repeat("a", 64),
			AllowedSources: []TrafficMirrorSource{
				{Pod: &TrafficMirrorPodSource{Namespace: "shop", MatchLabels: map[string]string{"app": "cart"}}, Interfaces: []string{"eth0", "net1"}},
				{Node: &TrafficMirrorNodeSource{MatchLabels: map[string]string{"pool": "edge"}}, Interfaces: []string{"bond0"}},
			},
			Filter: "tcp port 8080 and not (host 10.0.0.1)",
		},
	}
}

func TestValidateTrafficMirrorTemplate(t *testing.T) {
	require.NoError(t, ValidateTrafficMirrorTemplate(trafficMirrorTemplateSpec()))
	for name, mutate := range map[string]func(*DebugSessionTemplateSpec){
		"mutable image":        func(s *DebugSessionTemplateSpec) { s.TrafficMirror.Image = "ghcr.io/example/network-debug:latest" },
		"no sources":           func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources = nil },
		"pod and node":         func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources[0].Node = &TrafficMirrorNodeSource{} },
		"neither pod nor node": func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources[0].Pod = nil },
		"pod without labels":   func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources[0].Pod.MatchLabels = nil },
		"executor namespace pods": func(s *DebugSessionTemplateSpec) {
			s.TrafficMirror.AllowedSources[0].Pod.Namespace = NodeMaintenanceNamespace
		},
		"wildcard namespace": func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources[0].Pod.Namespace = "*" },
		"invalid label": func(s *DebugSessionTemplateSpec) {
			s.TrafficMirror.AllowedSources[1].Node.MatchLabels = map[string]string{"bad key!": "x"}
		},
		"no interfaces": func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources[0].Interfaces = nil },
		"duplicate interface": func(s *DebugSessionTemplateSpec) {
			s.TrafficMirror.AllowedSources[0].Interfaces = []string{"eth0", "eth0"}
		},
		"interface traversal": func(s *DebugSessionTemplateSpec) { s.TrafficMirror.AllowedSources[0].Interfaces = []string{".."} },
		"long interface": func(s *DebugSessionTemplateSpec) {
			s.TrafficMirror.AllowedSources[0].Interfaces = []string{"interface-name-16"}
		},
		"shell filter":       func(s *DebugSessionTemplateSpec) { s.TrafficMirror.Filter = "tcp; rm -rf /" },
		"option filter":      func(s *DebugSessionTemplateSpec) { s.TrafficMirror.Filter = "-w /tmp/x" },
		"direction":          func(s *DebugSessionTemplateSpec) { s.TrafficMirror.Direction = "sideways" },
		"snap length":        func(s *DebugSessionTemplateSpec) { s.TrafficMirror.SnapLength = 10 },
		"bandwidth":          func(s *DebugSessionTemplateSpec) { s.TrafficMirror.MaxBandwidthMbps = 5000 },
		"too long":           func(s *DebugSessionTemplateSpec) { s.Constraints.MaxDuration = "2h" },
		"renewal":            func(s *DebugSessionTemplateSpec) { s.Constraints.AllowRenewal = ptr(true) },
		"auto approval":      func(s *DebugSessionTemplateSpec) { s.Approvers.AutoApproveFor = &AutoApproveConfig{} },
		"self approval":      func(s *DebugSessionTemplateSpec) { s.BlockSelfApproval = ptr(false) },
		"no approvers":       func(s *DebugSessionTemplateSpec) { s.Approvers = nil },
		"other namespace":    func(s *DebugSessionTemplateSpec) { s.TargetNamespace = "default" },
		"pod template":       func(s *DebugSessionTemplateSpec) { s.PodTemplateString = "kind: Pod" },
		"terminal recording": func(s *DebugSessionTemplateSpec) { s.Audit = &DebugSessionAuditConfig{EnableTerminalRecording: true} },
		"node maintenance": func(s *DebugSessionTemplateSpec) {
			s.NodeMaintenance = &DebugSessionNodeMaintenance{Action: "link-cycle"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := trafficMirrorTemplateSpec()
			mutate(spec)
			require.Error(t, ValidateTrafficMirrorTemplate(spec))
		})
	}
}

func TestTrafficMirrorTemplateValidatedThroughWebhookPath(t *testing.T) {
	template := &DebugSessionTemplate{Spec: *trafficMirrorTemplateSpec()}
	require.Empty(t, ValidateDebugSessionTemplate(template).Errors, "a mirror template needs no Pod template")
	template.Spec.TrafficMirror.Filter = "tcp && `id`"
	errs := ValidateDebugSessionTemplate(template).Errors
	require.NotEmpty(t, errs)
	require.Equal(t, "spec.trafficMirror", errs[0].Field)
}

func TestTrafficMirrorSourceAllows(t *testing.T) {
	mirror := trafficMirrorTemplateSpec().TrafficMirror
	require.True(t, TrafficMirrorSourceAllows(mirror, "shop", map[string]string{"app": "cart", "extra": "x"}, "net1"))
	require.False(t, TrafficMirrorSourceAllows(mirror, "shop", map[string]string{"app": "cart"}, "bond0"), "interface of another source")
	require.False(t, TrafficMirrorSourceAllows(mirror, "shop", map[string]string{"app": "payments"}, "eth0"), "label mismatch")
	require.False(t, TrafficMirrorSourceAllows(mirror, "other", map[string]string{"app": "cart"}, "eth0"), "namespace mismatch")
	require.True(t, TrafficMirrorSourceAllows(mirror, "", map[string]string{"pool": "edge"}, "bond0"))
	require.False(t, TrafficMirrorSourceAllows(mirror, "", map[string]string{"pool": "core"}, "bond0"))
	require.False(t, TrafficMirrorSourceAllows(mirror, "", map[string]string{"app": "cart"}, "eth0"), "a Pod source never allows a Node")
}

func TestValidateTrafficMirrorSession(t *testing.T) {
	spec := trafficMirrorTemplateSpec()
	pod := &TrafficMirrorRequest{PodNamespace: "shop", PodName: "cart-0", Interface: "eth0"}
	require.NoError(t, ValidateTrafficMirrorSession(spec, &DebugSessionSpec{TrafficMirror: pod}))
	require.NoError(t, ValidateTrafficMirrorSession(spec, &DebugSessionSpec{TrafficMirror: &TrafficMirrorRequest{NodeName: "edge-1", Interface: "bond0"}}))
	for name, request := range map[string]*DebugSessionSpec{
		"missing":          {},
		"no source":        {TrafficMirror: &TrafficMirrorRequest{Interface: "eth0"}},
		"half pod":         {TrafficMirror: &TrafficMirrorRequest{PodName: "cart-0", Interface: "eth0"}},
		"bad interface":    {TrafficMirror: &TrafficMirrorRequest{NodeName: "edge-1", Interface: "eth0;reboot"}},
		"bad uid":          {TrafficMirror: &TrafficMirrorRequest{NodeName: "edge-1", NodeUID: "../x", Interface: "eth0"}},
		"generic override": {TrafficMirror: pod, NodeSelector: map[string]string{"a": "b"}},
		"invited":          {TrafficMirror: pod, InvitedParticipants: []string{"x"}},
		"other executor":   {TrafficMirror: pod, AdmissionRecipe: &AdmissionRecipeRequest{}},
		"other namespace":  {TrafficMirror: pod, TargetNamespace: "default"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, ValidateTrafficMirrorSession(spec, request))
		})
	}
	require.Error(t, ValidateTrafficMirrorSession(&DebugSessionTemplateSpec{}, &DebugSessionSpec{TrafficMirror: pod}), "template without trafficMirror")
}

func TestTrafficMirrorDefaultsAndOperationID(t *testing.T) {
	mirror := &DebugSessionTrafficMirror{}
	require.Equal(t, TrafficMirrorDirectionBoth, mirror.EffectiveDirection())
	require.Equal(t, int32(256), mirror.EffectiveSnapLength())
	require.Equal(t, int32(10000), mirror.EffectiveMaxPackets())
	require.Equal(t, int32(10), mirror.EffectiveMaxBandwidthMbps())
	id := TrafficMirrorOperationID("uid-1")
	require.Regexp(t, `^traffic-mirror-[a-f0-9]{32}$`, id)
	require.Equal(t, id, TrafficMirrorOperationID("uid-1"))
	require.NotEqual(t, id, TrafficMirrorOperationID("uid-2"))
}
