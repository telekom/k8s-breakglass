// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	kptr "k8s.io/utils/ptr"
)

func TestNodeMaintenanceExactAllowlist(t *testing.T) {
	neighbor := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", EntryMAC: "02:00:00:00:00:02", NeighborAddress: "192.0.2.2"}
	fdb := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "port0", Bridge: "br0", EntryMAC: neighbor.EntryMAC, VLAN: kptr.To(int32(100))}
	for _, tc := range []struct {
		action string
		target NodeMaintenanceTarget
	}{
		{"neighbor-replace", neighbor}, {"bridge-fdb-replace", fdb},
	} {
		t.Run(tc.action, func(t *testing.T) {
			profile := &DebugSessionNodeMaintenance{Action: tc.action, Image: "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64), AllowedTargets: []NodeMaintenanceTarget{tc.target}}
			require.NoError(t, ValidateNodeMaintenanceRequest(profile, &tc.target))
			for _, change := range []struct {
				name   string
				mutate func(*NodeMaintenanceTarget)
			}{
				{"node", func(v *NodeMaintenanceTarget) { v.TargetNode = "other-node" }},
				{"uid", func(v *NodeMaintenanceTarget) { v.TargetNodeUID = "replacement" }},
				{"interface", func(v *NodeMaintenanceTarget) { v.Interface = "eth9" }},
				{"mac", func(v *NodeMaintenanceTarget) { v.EntryMAC = "02:00:00:00:00:09" }},
				{"zero MAC", func(v *NodeMaintenanceTarget) { v.EntryMAC = "00:00:00:00:00:00" }},
				{"multicast MAC", func(v *NodeMaintenanceTarget) { v.EntryMAC = "01:00:5e:00:00:01" }},
				{"broadcast MAC", func(v *NodeMaintenanceTarget) { v.EntryMAC = "ff:ff:ff:ff:ff:ff" }},
				{"address", func(v *NodeMaintenanceTarget) { v.NeighborAddress = "192.0.2.9" }},
				{"bridge", func(v *NodeMaintenanceTarget) { v.Bridge = "other" }},
				{"vlan", func(v *NodeMaintenanceTarget) { v.VLAN = kptr.To(int32(101)) }},
				{"wildcard", func(v *NodeMaintenanceTarget) { v.Interface = "*" }},
				{"free text", func(v *NodeMaintenanceTarget) { v.Interface = "eth0;reboot" }},
				{"broad prefix", func(v *NodeMaintenanceTarget) { v.NeighborAddress = "192.0.2.0/24" }},
				{"added vrf", func(v *NodeMaintenanceTarget) { v.VRF = "vrf-red" }},
			} {
				t.Run(change.name, func(t *testing.T) {
					request := *tc.target.DeepCopy()
					change.mutate(&request)
					require.Error(t, ValidateNodeMaintenanceRequest(profile, &request))
				})
			}
			require.Error(t, ValidateNodeMaintenanceRequest(profile, nil))
			for _, mac := range []string{"00:00:00:00:00:00", "01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff"} {
				target := *tc.target.DeepCopy()
				target.EntryMAC = mac
				invalidProfile := profile.DeepCopy()
				invalidProfile.AllowedTargets = []NodeMaintenanceTarget{target}
				require.Error(t, ValidateNodeMaintenanceRequest(invalidProfile, &target), "even allowlisted invalid MACs must fail")
			}
			profile.Image = "registry.example/node-maintenance:latest"
			require.Error(t, ValidateNodeMaintenanceRequest(profile, &tc.target))
		})
	}
	require.Error(t, ValidateNodeMaintenanceRequest(nil, &neighbor))
	require.NoError(t, ValidateNodeMaintenanceRequest(nil, nil))
	require.Error(t, ValidateNodeMaintenanceTarget("flush-neighbors", &neighbor))
	require.Error(t, ValidateNodeMaintenanceTarget("neighbor-flush", &neighbor))
	require.Error(t, ValidateNodeMaintenanceTarget("bridge-fdb-flush", &fdb))
}

func TestNodeMaintenanceLinkActionsAreInterfaceOnly(t *testing.T) {
	link := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0"}
	image := "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64)
	for _, action := range []string{"link-cycle", "restart-autonegotiation"} {
		t.Run(action, func(t *testing.T) {
			profile := &DebugSessionNodeMaintenance{Action: action, Image: image, AllowedTargets: []NodeMaintenanceTarget{link}}
			require.NoError(t, ValidateNodeMaintenanceRequest(profile, &link))
			for _, change := range []struct {
				name   string
				mutate func(*NodeMaintenanceTarget)
			}{
				{"interface", func(v *NodeMaintenanceTarget) { v.Interface = "eth9" }},
				{"no interface", func(v *NodeMaintenanceTarget) { v.Interface = "" }},
				{"entryMAC", func(v *NodeMaintenanceTarget) { v.EntryMAC = "02:00:00:00:00:02" }},
				{"neighbour", func(v *NodeMaintenanceTarget) { v.NeighborAddress = "192.0.2.2" }},
				{"bridge", func(v *NodeMaintenanceTarget) { v.Bridge = "br0" }},
				{"vlan", func(v *NodeMaintenanceTarget) { v.VLAN = kptr.To(int32(100)) }},
				{"vrf", func(v *NodeMaintenanceTarget) { v.VRF = "vrf-red" }},
			} {
				t.Run("request "+change.name, func(t *testing.T) {
					request := *link.DeepCopy()
					change.mutate(&request)
					require.Error(t, ValidateNodeMaintenanceRequest(profile, &request))
				})
				if change.name == "interface" {
					continue // another exact interface is a valid allowlist entry
				}
				t.Run("allowlist "+change.name, func(t *testing.T) {
					allowed := *link.DeepCopy()
					change.mutate(&allowed)
					broad := profile.DeepCopy()
					broad.AllowedTargets = []NodeMaintenanceTarget{allowed}
					require.Error(t, ValidateNodeMaintenanceRequest(broad, &allowed))
				})
			}
			preview := profile.DeepCopy()
			preview.DryRun = true
			require.ErrorContains(t, ValidateNodeMaintenanceRequest(preview, &link), "no preview")
		})
	}
	// The replace actions still need the MAC.
	for _, target := range []NodeMaintenanceTarget{
		{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", NeighborAddress: "192.0.2.2"},
		{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "port0", Bridge: "br0", VLAN: kptr.To(int32(100))},
	} {
		action := "neighbor-replace"
		if target.Bridge != "" {
			action = "bridge-fdb-replace"
		}
		profile := &DebugSessionNodeMaintenance{Action: action, Image: image, AllowedTargets: []NodeMaintenanceTarget{target}}
		require.ErrorContains(t, ValidateNodeMaintenanceRequest(profile, &target), "entryMAC", action)
	}
}

func TestNodeMaintenanceVRFTupleIsExact(t *testing.T) {
	inVRF := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", EntryMAC: "02:00:00:00:00:02", NeighborAddress: "192.0.2.2", VRF: "vrf-red"}
	profile := &DebugSessionNodeMaintenance{Action: "neighbor-replace", Image: "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64), AllowedTargets: []NodeMaintenanceTarget{inVRF}}
	require.NoError(t, ValidateNodeMaintenanceRequest(profile, &inVRF))
	for name, vrf := range map[string]string{"omitted": "", "other": "vrf-blue", "same as interface": "eth0", "free text": "vrf;ip", "wildcard": "*"} {
		t.Run(name, func(t *testing.T) {
			request := *inVRF.DeepCopy()
			request.VRF = vrf
			require.Error(t, ValidateNodeMaintenanceRequest(profile, &request))
		})
	}
	fdb := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "port0", Bridge: "br0", EntryMAC: inVRF.EntryMAC, VLAN: kptr.To(int32(100)), VRF: "vrf-red"}
	require.ErrorContains(t, ValidateNodeMaintenanceTarget("bridge-fdb-replace", &fdb), "VRF")
}

// The fixed executor helper accepts only plain IPv4 or IPv6 literals, so
// admission must reject IPv4-mapped IPv6 instead of approving an executor that
// is guaranteed to fail before mutation.
func TestNodeMaintenanceNeighborAddressMatchesExecutorContract(t *testing.T) {
	for address, valid := range map[string]bool{
		"192.0.2.2":        true,
		"2001:db8::2":      true,
		"::ffff:192.0.2.2": false,
		"::ffff:c000:202":  false,
		"::":               false,
		"ff02::1":          false,
	} {
		t.Run(address, func(t *testing.T) {
			target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", EntryMAC: "02:00:00:00:00:02", NeighborAddress: address}
			err := ValidateNodeMaintenanceTarget("neighbor-replace", &target)
			if valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestNodeMaintenanceTemplateAndRequestIsolation(t *testing.T) {
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", EntryMAC: "02:00:00:00:00:02", NeighborAddress: "192.0.2.2"}
	spec := DebugSessionTemplateSpec{
		TargetNamespace: NodeMaintenanceNamespace, Approvers: &DebugSessionApprovers{Users: []string{"approver"}},
		Constraints:     &DebugSessionConstraints{MaxDuration: "5m"},
		NodeMaintenance: &DebugSessionNodeMaintenance{Action: "neighbor-replace", Image: "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64), AllowedTargets: []NodeMaintenanceTarget{target}},
	}
	require.NoError(t, ValidateNodeMaintenanceTemplate(&spec))
	require.Empty(t, ValidateDebugSessionTemplate(&DebugSessionTemplate{Spec: spec}).Errors)
	blocked := spec.DeepCopy()
	blocked.BlockSelfApproval = kptr.To(true)
	require.NoError(t, ValidateNodeMaintenanceTemplate(blocked))
	spec.AuxiliaryResources = []AuxiliaryResource{{
		Name: "policy-exception", Category: "policy-exceptions", CreateBefore: kptr.To(true), DeleteAfter: kptr.To(true),
		FailurePolicy: AuxiliaryResourceFailurePolicyFail, TemplateString: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: debug-{{ .session.uid }}\n",
	}}
	spec.RequiredAuxiliaryResourceCategories = []string{"policy-exceptions"}
	require.NoError(t, ValidateNodeMaintenanceTemplate(&spec), "a required createBefore exception is allowed")
	for _, tc := range []struct {
		name   string
		mutate func(*DebugSessionTemplateSpec)
	}{
		{"no approvers", func(s *DebugSessionTemplateSpec) { s.Approvers = nil }},
		{"auto approve", func(s *DebugSessionTemplateSpec) {
			s.Approvers.AutoApproveFor = &AutoApproveConfig{Groups: []string{"*"}}
		}},
		{"generic rendering", func(s *DebugSessionTemplateSpec) { s.PodTemplateString = "unsafe" }},
		{"job retry", func(s *DebugSessionTemplateSpec) { s.WorkloadType = DebugWorkloadJob }},
		{"other namespace", func(s *DebugSessionTemplateSpec) { s.TargetNamespace = "other" }},
		{"open", func(s *DebugSessionTemplateSpec) { s.FailMode = "open" }},
		{"hybrid", func(s *DebugSessionTemplateSpec) { s.Mode = DebugSessionModeHybrid }},
		{"empty allowlist", func(s *DebugSessionTemplateSpec) { s.NodeMaintenance.AllowedTargets = nil }},
		{"idle timeout", func(s *DebugSessionTemplateSpec) { s.Constraints.IdleTimeout = "1m" }},
		{"self approval allowed", func(s *DebugSessionTemplateSpec) { s.BlockSelfApproval = kptr.To(false) }},
		{"auxiliary after workload", func(s *DebugSessionTemplateSpec) { s.AuxiliaryResources[0].CreateBefore = kptr.To(false) }},
		{"auxiliary retained", func(s *DebugSessionTemplateSpec) { s.AuxiliaryResources[0].DeleteAfter = kptr.To(false) }},
		{"auxiliary optional", func(s *DebugSessionTemplateSpec) { s.AuxiliaryResources[0].Optional = true }},
		{"auxiliary ignore failure", func(s *DebugSessionTemplateSpec) {
			s.AuxiliaryResources[0].FailurePolicy = AuxiliaryResourceFailurePolicyIgnore
		}},
		{"auxiliary not required", func(s *DebugSessionTemplateSpec) { s.RequiredAuxiliaryResourceCategories = nil }},
		{"auxiliary user default", func(s *DebugSessionTemplateSpec) {
			s.AuxiliaryResourceDefaults = map[string]bool{"policy-exceptions": true}
		}},
		{"required category without resources", func(s *DebugSessionTemplateSpec) {
			s.RequiredAuxiliaryResourceCategories = append(s.RequiredAuxiliaryResourceCategories, "network-policies")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := spec.DeepCopy()
			tc.mutate(changed)
			require.Error(t, ValidateNodeMaintenanceTemplate(changed))
		})
	}
	request := DebugSessionSpec{NodeMaintenance: &target}
	require.NoError(t, ValidateNodeMaintenanceSession(&spec, &request))
	request.SelectedAuxiliaryResources = []string{"policy-exception"}
	require.Error(t, ValidateNodeMaintenanceSession(&spec, &request))
	request.SelectedAuxiliaryResources = nil
	request.NodeSelector = map[string]string{"node": "other"}
	require.Error(t, ValidateNodeMaintenanceSession(&spec, &request))
	// A binding-merged idle timeout in the resolved snapshot is rejected as well.
	request.NodeSelector = nil
	resolved := spec.DeepCopy()
	resolved.Constraints.IdleTimeout = "1m"
	require.ErrorContains(t, ValidateNodeMaintenanceSession(resolved, &request), "idleTimeout")
}

func kexecTestProfile() *DebugSessionNodeMaintenance {
	return &DebugSessionNodeMaintenance{
		Action: NodeMaintenanceActionKexecRecovery, Image: "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64),
		AllowedTargets: []NodeMaintenanceTarget{{TargetNode: "node-a", TargetNodeUID: "node-uid"}},
		Kexec: &NodeMaintenanceKexec{Profile: "provider-recovery", HostPath: "/var/lib/provider/recovery",
			KernelSHA256: strings.Repeat("1", 64), InitrdSHA256: strings.Repeat("2", 64), CmdlineSHA256: strings.Repeat("3", 64),
			DrainTimeoutSeconds: 300},
	}
}

func TestNodeMaintenanceKexecTargetsOnlyAnExactNode(t *testing.T) {
	profile := kexecTestProfile()
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid"}
	require.NoError(t, ValidateNodeMaintenanceRequest(profile, &target))
	for name, mutate := range map[string]func(*NodeMaintenanceTarget){
		"other node":   func(v *NodeMaintenanceTarget) { v.TargetNode = "node-b" },
		"replaced uid": func(v *NodeMaintenanceTarget) { v.TargetNodeUID = "replacement" },
		"interface":    func(v *NodeMaintenanceTarget) { v.Interface = "eth0" },
		"mac":          func(v *NodeMaintenanceTarget) { v.EntryMAC = "02:00:00:00:00:02" },
		"address":      func(v *NodeMaintenanceTarget) { v.NeighborAddress = "192.0.2.2" },
		"bridge":       func(v *NodeMaintenanceTarget) { v.Bridge = "br0" },
		"vlan":         func(v *NodeMaintenanceTarget) { v.VLAN = kptr.To(int32(100)) },
		"vrf":          func(v *NodeMaintenanceTarget) { v.VRF = "vrf-red" },
	} {
		t.Run(name, func(t *testing.T) {
			request := target
			mutate(&request)
			require.Error(t, ValidateNodeMaintenanceRequest(profile, &request))
		})
	}
}

func TestNodeMaintenanceKexecProfileIsPinned(t *testing.T) {
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid"}
	for name, mutate := range map[string]func(*DebugSessionNodeMaintenance){
		"missing bundle":     func(p *DebugSessionNodeMaintenance) { p.Kexec = nil },
		"relative path":      func(p *DebugSessionNodeMaintenance) { p.Kexec.HostPath = "var/lib/recovery" },
		"root path":          func(p *DebugSessionNodeMaintenance) { p.Kexec.HostPath = "/" },
		"parent traversal":   func(p *DebugSessionNodeMaintenance) { p.Kexec.HostPath = "/var/lib/../../etc" },
		"unclean path":       func(p *DebugSessionNodeMaintenance) { p.Kexec.HostPath = "/var/lib//recovery/" },
		"uppercase digest":   func(p *DebugSessionNodeMaintenance) { p.Kexec.KernelSHA256 = strings.Repeat("A", 64) },
		"short digest":       func(p *DebugSessionNodeMaintenance) { p.Kexec.InitrdSHA256 = "abc" },
		"missing digest":     func(p *DebugSessionNodeMaintenance) { p.Kexec.CmdlineSHA256 = "" },
		"bad profile":        func(p *DebugSessionNodeMaintenance) { p.Kexec.Profile = "Provider Recovery" },
		"short drain":        func(p *DebugSessionNodeMaintenance) { p.Kexec.DrainTimeoutSeconds = 5 },
		"unbounded drain":    func(p *DebugSessionNodeMaintenance) { p.Kexec.DrainTimeoutSeconds = 7200 },
		"bundle on repair":   func(p *DebugSessionNodeMaintenance) { p.Action = "neighbor-replace" },
		"unsupported action": func(p *DebugSessionNodeMaintenance) { p.Action = "reboot" },
	} {
		t.Run(name, func(t *testing.T) {
			profile := kexecTestProfile()
			mutate(profile)
			require.Error(t, ValidateNodeMaintenanceRequest(profile, &target))
		})
	}
}

func TestNodeMaintenanceKexecDurationCoversDrainAndReturn(t *testing.T) {
	spec := DebugSessionTemplateSpec{
		TargetNamespace: NodeMaintenanceNamespace, Approvers: &DebugSessionApprovers{Groups: []string{"platform-emergency"}},
		Constraints: &DebugSessionConstraints{MaxDuration: "10m"}, NodeMaintenance: kexecTestProfile(),
	}
	require.NoError(t, ValidateNodeMaintenanceTemplate(&spec))
	spec.Constraints.MaxDuration = "9m"
	require.ErrorContains(t, ValidateNodeMaintenanceTemplate(&spec), "maxDuration must cover")
	spec.NodeMaintenance.DryRun = true
	require.NoError(t, ValidateNodeMaintenanceTemplate(&spec), "a validate-only profile never drains or reboots")
}

func TestNodeMaintenanceServiceRestartIsUnitOnly(t *testing.T) {
	image := "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64)
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Unit: "cra.service"}
	service := &NodeMaintenanceService{DrainTimeoutSeconds: 60,
		RestartPods: []NodeMaintenancePodSelector{{Namespace: "kube-system", MatchLabels: map[string]string{"app.kubernetes.io/name": "network-operator-agent-cra-vsr"}}}}
	profile := func() *DebugSessionNodeMaintenance {
		return &DebugSessionNodeMaintenance{Action: NodeMaintenanceActionServiceRestart, Image: image,
			AllowedTargets: []NodeMaintenanceTarget{target}, Service: service.DeepCopy()}
	}
	require.NoError(t, ValidateNodeMaintenanceRequest(profile(), &target))
	for _, change := range []struct {
		name   string
		mutate func(*NodeMaintenanceTarget)
	}{
		{"other unit", func(v *NodeMaintenanceTarget) { v.Unit = "kubelet.service" }},
		{"unit outside allowlist", func(v *NodeMaintenanceTarget) { v.Unit = "sshd.service" }},
		{"no unit", func(v *NodeMaintenanceTarget) { v.Unit = "" }},
		{"interface", func(v *NodeMaintenanceTarget) { v.Interface = "eth0" }},
		{"mac", func(v *NodeMaintenanceTarget) { v.EntryMAC = "02:00:00:00:00:02" }},
		{"replaced node", func(v *NodeMaintenanceTarget) { v.TargetNodeUID = "replacement" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			request := *target.DeepCopy()
			change.mutate(&request)
			require.Error(t, ValidateNodeMaintenanceRequest(profile(), &request))
		})
	}
	for _, change := range []struct {
		name   string
		mutate func(*DebugSessionNodeMaintenance)
	}{
		{"missing service", func(p *DebugSessionNodeMaintenance) { p.Service = nil }},
		{"preview", func(p *DebugSessionNodeMaintenance) { p.DryRun = true }},
		{"short drain", func(p *DebugSessionNodeMaintenance) { p.Service.DrainTimeoutSeconds = 10 }},
		{"long drain", func(p *DebugSessionNodeMaintenance) { p.Service.DrainTimeoutSeconds = 3601 }},
		{"bad namespace", func(p *DebugSessionNodeMaintenance) { p.Service.RestartPods[0].Namespace = "Kube System" }},
		{"executor namespace", func(p *DebugSessionNodeMaintenance) { p.Service.RestartPods[0].Namespace = NodeMaintenanceNamespace }},
		{"empty selector", func(p *DebugSessionNodeMaintenance) { p.Service.RestartPods[0].MatchLabels = map[string]string{} }},
		{"empty label value", func(p *DebugSessionNodeMaintenance) {
			p.Service.RestartPods[0].MatchLabels = map[string]string{"app": ""}
		}},
		{"too many selectors", func(p *DebugSessionNodeMaintenance) {
			p.Service.RestartPods = append(p.Service.RestartPods, p.Service.RestartPods[0], p.Service.RestartPods[0], p.Service.RestartPods[0], p.Service.RestartPods[0])
		}},
		{"kexec bundle", func(p *DebugSessionNodeMaintenance) { p.Kexec = &NodeMaintenanceKexec{} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			p := profile()
			change.mutate(p)
			require.Error(t, ValidateNodeMaintenanceRequest(p, &target))
		})
	}
	// Service settings and units belong to service-restart only.
	neighbor := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "eth0", EntryMAC: "02:00:00:00:00:02", NeighborAddress: "192.0.2.2"}
	other := &DebugSessionNodeMaintenance{Action: "neighbor-replace", Image: image, AllowedTargets: []NodeMaintenanceTarget{neighbor}, Service: service.DeepCopy()}
	require.Error(t, ValidateNodeMaintenanceRequest(other, &neighbor))
	other.Service = nil
	withUnit := neighbor
	withUnit.Unit = "containerd.service"
	require.Error(t, ValidateNodeMaintenanceTarget("neighbor-replace", &withUnit))
	require.Error(t, ValidateNodeMaintenanceTarget(NodeMaintenanceActionKexecRecovery, &NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Unit: "kubelet.service"}))
}

func TestNodeMaintenanceServiceRestartMaxDurationCoversDrainAndChecks(t *testing.T) {
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Unit: "kubelet.service"}
	spec := &DebugSessionTemplateSpec{
		TargetNamespace: NodeMaintenanceNamespace,
		Approvers:       &DebugSessionApprovers{Users: []string{"approver"}},
		Constraints:     &DebugSessionConstraints{MaxDuration: "10m"},
		NodeMaintenance: &DebugSessionNodeMaintenance{Action: NodeMaintenanceActionServiceRestart,
			Image:          "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64),
			AllowedTargets: []NodeMaintenanceTarget{target}, Service: &NodeMaintenanceService{DrainTimeoutSeconds: 60}},
	}
	require.ErrorContains(t, ValidateNodeMaintenanceTemplate(spec), "maxDuration must cover drainTimeoutSeconds plus 600s")
	spec.Constraints.MaxDuration = "11m"
	require.NoError(t, ValidateNodeMaintenanceTemplate(spec))
}

func TestNodeMaintenanceModuleLoadIsModuleOnly(t *testing.T) {
	image := "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64)
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Module: "ip6_gre"}
	profile := &DebugSessionNodeMaintenance{Action: NodeMaintenanceActionModuleLoad, Image: image, AllowedTargets: []NodeMaintenanceTarget{target}}
	require.NoError(t, ValidateNodeMaintenanceRequest(profile, &target))
	for _, change := range []struct {
		name   string
		mutate func(*NodeMaintenanceTarget)
	}{
		{"other module", func(v *NodeMaintenanceTarget) { v.Module = "gre" }},
		{"path", func(v *NodeMaintenanceTarget) { v.Module = "../ip6_gre" }},
		{"parameters", func(v *NodeMaintenanceTarget) { v.Module = "ip6_gre debug=1" }},
		{"dash form", func(v *NodeMaintenanceTarget) { v.Module = "ip6-gre" }},
		{"no module", func(v *NodeMaintenanceTarget) { v.Module = "" }},
		{"unit", func(v *NodeMaintenanceTarget) { v.Unit = "kubelet.service" }},
		{"interface", func(v *NodeMaintenanceTarget) { v.Interface = "eth0" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			request := *target.DeepCopy()
			change.mutate(&request)
			require.Error(t, ValidateNodeMaintenanceRequest(profile, &request))
		})
	}
	preview := profile.DeepCopy()
	preview.DryRun = true
	require.ErrorContains(t, ValidateNodeMaintenanceRequest(preview, &target), "no preview")
	withModule := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Unit: "kubelet.service", Module: "gre"}
	require.Error(t, ValidateNodeMaintenanceTarget(NodeMaintenanceActionServiceRestart, &withModule))
}

func TestNodeMaintenanceSRIOVReprovisionIsPFAndCountOnly(t *testing.T) {
	image := "registry.example/node-maintenance@sha256:" + strings.Repeat("a", 64)
	target := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Interface: "ens1f0", VirtualFunctions: kptr.To(int32(8))}
	profile := &DebugSessionNodeMaintenance{Action: NodeMaintenanceActionSRIOVReprovision, Image: image,
		AllowedTargets: []NodeMaintenanceTarget{target}, Service: &NodeMaintenanceService{DrainTimeoutSeconds: 60}}
	require.NoError(t, ValidateNodeMaintenanceRequest(profile, &target))
	for _, change := range []struct {
		name   string
		mutate func(*NodeMaintenanceTarget)
	}{
		{"other PF", func(v *NodeMaintenanceTarget) { v.Interface = "ens1f1" }},
		{"other count", func(v *NodeMaintenanceTarget) { v.VirtualFunctions = kptr.To(int32(4)) }},
		{"no count", func(v *NodeMaintenanceTarget) { v.VirtualFunctions = nil }},
		{"zero count", func(v *NodeMaintenanceTarget) { v.VirtualFunctions = kptr.To(int32(0)) }},
		{"count over 256", func(v *NodeMaintenanceTarget) { v.VirtualFunctions = kptr.To(int32(257)) }},
		{"no PF", func(v *NodeMaintenanceTarget) { v.Interface = "" }},
		{"dot PF", func(v *NodeMaintenanceTarget) { v.Interface = ".." }},
		{"option-like PF", func(v *NodeMaintenanceTarget) { v.Interface = "-h" }},
		{"PF with space", func(v *NodeMaintenanceTarget) { v.Interface = "ens1f0 x" }},
		{"unit", func(v *NodeMaintenanceTarget) { v.Unit = "kubelet.service" }},
		{"module", func(v *NodeMaintenanceTarget) { v.Module = "igb" }},
		{"MAC", func(v *NodeMaintenanceTarget) { v.EntryMAC = "02:00:00:00:00:02" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			request := *target.DeepCopy()
			change.mutate(&request)
			require.Error(t, ValidateNodeMaintenanceRequest(profile, &request))
		})
	}
	preview := profile.DeepCopy()
	preview.DryRun = true
	require.ErrorContains(t, ValidateNodeMaintenanceRequest(preview, &target), "no preview")
	noBounds := profile.DeepCopy()
	noBounds.Service = nil
	require.ErrorContains(t, ValidateNodeMaintenanceRequest(noBounds, &target), "drainTimeoutSeconds")
	// The count belongs only to sriov-reprovision.
	withCount := NodeMaintenanceTarget{TargetNode: "node-a", TargetNodeUID: "node-uid", Unit: "kubelet.service", VirtualFunctions: kptr.To(int32(8))}
	require.ErrorContains(t, ValidateNodeMaintenanceTarget(NodeMaintenanceActionServiceRestart, &withCount), "virtualFunctions")
	// The service bounds belong only to the systemd actions.
	module := &DebugSessionNodeMaintenance{Action: NodeMaintenanceActionModuleLoad, Image: image, Service: &NodeMaintenanceService{DrainTimeoutSeconds: 60},
		AllowedTargets: []NodeMaintenanceTarget{{TargetNode: "node-a", TargetNodeUID: "node-uid", Module: "igb"}}}
	require.ErrorContains(t, ValidateNodeMaintenanceRequest(module, &module.AllowedTargets[0]), "service-restart and sriov-reprovision")
}
