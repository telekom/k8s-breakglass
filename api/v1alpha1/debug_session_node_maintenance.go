// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// DebugSessionNodeMaintenance defines a fixed, operator-approved repair profile.
// It deliberately has no command, environment, capability or shell overrides.
type DebugSessionNodeMaintenance struct {
	// action is the one executor operation enabled by this profile.
	// +kubebuilder:validation:Enum=neighbor-replace;bridge-fdb-replace;kexec-recovery;service-restart
	Action string `json:"action"`
	// image must be an immutable node-maintenance helper image.
	// +kubebuilder:validation:Pattern=`^.+@sha256:[a-f0-9]{64}$`
	Image string `json:"image"`
	// allowedTargets is an exact allowlist, not a selector or wildcard.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	// +listType=atomic
	AllowedTargets []NodeMaintenanceTarget `json:"allowedTargets"`
	// dryRun makes every session of this profile a preview: the executor runs
	// the same exact tuple preflight and records the entry it would replace,
	// but has no NET_ADMIN capability and never mutates the kernel table.
	// +optional
	DryRun bool `json:"dryRun,omitempty"`
	// kexec pins the provider recovery bundle for a kexec-recovery profile.
	// It is required for kexec-recovery and forbidden for every other action.
	// +optional
	Kexec *NodeMaintenanceKexec `json:"kexec,omitempty"`
	// service bounds a service-restart profile. It is required for
	// service-restart and forbidden for every other action.
	// +optional
	Service *NodeMaintenanceService `json:"service,omitempty"`
}

// NodeMaintenanceService restarts one allowlisted host systemd unit on a
// cordoned and drained Node through systemd's private socket. After the helper
// verified the unit, the controller recreates the listed Pods on that Node
// (for example a network agent that must re-apply its configuration to a
// restarted router container) and requires the Node and each replacement to
// be Ready before it reports success and uncordons the Node.
type NodeMaintenanceService struct {
	// drainTimeoutSeconds bounds cordon and eviction before execution. On
	// timeout the controller uncordons the Node and fails without executing.
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:validation:Maximum=3600
	DrainTimeoutSeconds int32 `json:"drainTimeoutSeconds"`
	// restartPods selects Pods on the target Node that the controller deletes
	// once after a verified restart; each selector must then have a new Ready
	// Pod on the Node. Typically DaemonSet Pods.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +listType=atomic
	RestartPods []NodeMaintenancePodSelector `json:"restartPods,omitempty"`
}

// NodeMaintenancePodSelector selects Pods by exact labels in one namespace.
type NodeMaintenancePodSelector struct {
	// namespace is the exact namespace of the Pods.
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// matchLabels must all match; at least one and at most eight labels.
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:MaxProperties=8
	MatchLabels map[string]string `json:"matchLabels"`
}

// NodeMaintenanceKexec pins one provider-owned recovery kernel bundle. A dryRun
// profile only validates the bundle; an execute profile cordons and drains the
// Node, loads the verified kernel with kexec_file_load and reboots into it.
type NodeMaintenanceKexec struct {
	// profile is the provider recovery profile name recorded in evidence.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`
	Profile string `json:"profile"`
	// hostPath is the absolute provider-owned node directory holding exactly
	// kernel, initrd and cmdline. It is mounted read-only at /recovery.
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^/[A-Za-z0-9._/-]+$`
	HostPath string `json:"hostPath"`
	// kernelSHA256 is the exact lowercase SHA-256 of the kernel image.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	KernelSHA256 string `json:"kernelSHA256"`
	// initrdSHA256 is the exact lowercase SHA-256 of the initrd.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	InitrdSHA256 string `json:"initrdSHA256"`
	// cmdlineSHA256 is the exact lowercase SHA-256 of the cmdline file.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	CmdlineSHA256 string `json:"cmdlineSHA256"`
	// drainTimeoutSeconds bounds cordon and eviction before execution. On
	// timeout the controller uncordons the Node and fails without executing.
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:validation:Maximum=3600
	DrainTimeoutSeconds int32 `json:"drainTimeoutSeconds"`
}

// NodeMaintenanceTarget identifies exactly one kernel table entry on one Node incarnation.
type NodeMaintenanceTarget struct {
	// targetNode is the exact Kubernetes Node name.
	// +kubebuilder:validation:MaxLength=253
	TargetNode string `json:"targetNode"`
	// targetNodeUID prevents execution against a replaced Node.
	// +kubebuilder:validation:MaxLength=128
	TargetNodeUID string `json:"targetNodeUID"`
	// interface is the neighbour interface or bridge FDB port. It is required
	// for network repair and forbidden for kexec-recovery.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	Interface string `json:"interface,omitempty"`
	// entryMAC is the canonical lowercase colon-delimited six-byte MAC. It is
	// required for network repair and forbidden for kexec-recovery.
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`
	EntryMAC string `json:"entryMAC,omitempty"`
	// neighborAddress is a canonical individual IP, never a prefix.
	// +optional
	// +kubebuilder:validation:MaxLength=45
	NeighborAddress string `json:"neighborAddress,omitempty"`
	// bridge is the exact master bridge for an FDB operation.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	Bridge string `json:"bridge,omitempty"`
	// vlan is required only for an FDB operation.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4094
	VLAN *int32 `json:"vlan,omitempty"`
	// vrf optionally binds a neighbour operation to the exact VRF device that
	// must be the interface master. It is never valid for an FDB operation.
	// +optional
	// +kubebuilder:validation:MaxLength=15
	VRF string `json:"vrf,omitempty"`
	// unit is the host systemd unit for service-restart and forbidden for
	// every other action. On a CRA node a containerd.service restart also
	// restarts cra.service (systemd Requires=).
	// +optional
	// +kubebuilder:validation:Enum=containerd.service;kubelet.service;cra.service
	Unit string `json:"unit,omitempty"`
}

var maintenanceInterfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var maintenanceUIDPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,128}$`)
var maintenanceImagePattern = regexp.MustCompile(`^.+@sha256:[a-f0-9]{64}$`)
var maintenanceProfilePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
var maintenanceHostPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,254}$`)
var maintenanceSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// NodeMaintenanceActionKexecRecovery reboots one drained Node into a pinned recovery kernel.
const NodeMaintenanceActionKexecRecovery = "kexec-recovery"

// NodeMaintenanceActionServiceRestart restarts one allowlisted host systemd unit on a drained Node.
const NodeMaintenanceActionServiceRestart = "service-restart"

// serviceRestartMarginSeconds is the minimum session time left after a full
// drain for the helper (at most 240s), a Ready Node and recreated Pods.
const serviceRestartMarginSeconds = 600

// nodeMaintenanceServiceUnits is the complete service-restart unit allowlist.
var nodeMaintenanceServiceUnits = []string{"containerd.service", "kubelet.service", "cra.service"}

// kexecReturnMarginSeconds is the minimum session time left after a full
// drain for the kexec, the reboot and the Node returning Ready.
const kexecReturnMarginSeconds = 300

// NodeMaintenanceNamespace is a single lock domain shared by all profiles and requesters.
const NodeMaintenanceNamespace = "breakglass-node-maintenance"

// ValidateNodeMaintenanceTemplate excludes generic rendering and approval bypasses.
func ValidateNodeMaintenanceTemplate(spec *DebugSessionTemplateSpec) error {
	if spec.NodeMaintenance == nil {
		return nil
	}
	if (spec.Mode != "" && spec.Mode != DebugSessionModeWorkload) || spec.WorkloadType != "" ||
		spec.TargetNamespace != NodeMaintenanceNamespace || (spec.FailMode != "" && spec.FailMode != "closed") ||
		(spec.ExpirationBehavior != "" && spec.ExpirationBehavior != "terminate") {
		return fmt.Errorf("nodeMaintenance requires workload mode, no generic workloadType, fixed maintenance namespace and closed termination")
	}
	if spec.PodTemplateRef != nil || spec.PodTemplateString != "" || spec.PodOverridesTemplate != "" ||
		spec.PodOverrides != nil || len(spec.ExtraDeployVariables) != 0 || spec.AffinityOverrides != nil ||
		len(spec.AdditionalTolerations) != 0 || spec.SchedulingConstraints != nil || spec.SchedulingOptions != nil ||
		spec.KubectlDebug != nil || spec.NamespaceConstraints != nil || spec.Impersonation != nil ||
		spec.TerminalSharing != nil || spec.ArtifactCollection != nil ||
		len(spec.AuxiliaryResourceDefaults) != 0 || spec.PodDisruptionBudget != nil || spec.ResourceQuota != nil ||
		(spec.Audit != nil && spec.Audit.EnableTerminalRecording) {
		return fmt.Errorf("nodeMaintenance cannot use generic workload, scheduling, interactive or auxiliary overrides")
	}
	if err := validateNodeMaintenanceAuxiliaryResources(spec); err != nil {
		return err
	}
	if spec.Approvers == nil || len(spec.Approvers.Users)+len(spec.Approvers.Groups) == 0 || spec.Approvers.AutoApproveFor != nil {
		return fmt.Errorf("nodeMaintenance requires explicit independent approvers without auto-approval")
	}
	if spec.BlockSelfApproval != nil && !*spec.BlockSelfApproval {
		return fmt.Errorf("nodeMaintenance requires blocked self-approval")
	}
	if spec.Constraints == nil || spec.Constraints.MaxDuration == "" {
		return fmt.Errorf("nodeMaintenance requires an explicit bounded maxDuration")
	}
	if errs := validatePositiveDurationFormat(spec.Constraints.MaxDuration, field.NewPath("constraints", "maxDuration")); len(errs) > 0 {
		return fmt.Errorf("nodeMaintenance requires a valid positive maxDuration: %w", errs[0])
	}
	// The executor receives only the hard expiry. No debug operation advances
	// activity, so an idle deadline would expire the session while the helper
	// could still mutate until the later hard deadline.
	if spec.Constraints.IdleTimeout != "" {
		return fmt.Errorf("nodeMaintenance does not support idleTimeout; bound the session with maxDuration")
	}
	if len(spec.NodeMaintenance.AllowedTargets) == 0 {
		return fmt.Errorf("nodeMaintenance requires a nonempty exact allowlist")
	}
	if kexec := spec.NodeMaintenance.Kexec; kexec != nil && !spec.NodeMaintenance.DryRun {
		maxDuration, err := ParseDuration(spec.Constraints.MaxDuration)
		if err != nil || maxDuration < time.Duration(int64(kexec.DrainTimeoutSeconds)+kexecReturnMarginSeconds)*time.Second {
			return fmt.Errorf("kexec-recovery maxDuration must cover drainTimeoutSeconds plus %ds for the Node to return", kexecReturnMarginSeconds)
		}
	}
	if service := spec.NodeMaintenance.Service; service != nil {
		maxDuration, err := ParseDuration(spec.Constraints.MaxDuration)
		if err != nil || maxDuration < time.Duration(int64(service.DrainTimeoutSeconds)+serviceRestartMarginSeconds)*time.Second {
			return fmt.Errorf("service-restart maxDuration must cover drainTimeoutSeconds plus %ds for the restart and post-checks", serviceRestartMarginSeconds)
		}
	}
	return ValidateNodeMaintenanceRequest(spec.NodeMaintenance, &spec.NodeMaintenance.AllowedTargets[0])
}

// validateNodeMaintenanceAuxiliaryResources admits only resources that are
// always deployed before the executor and deleted with it, such as a
// per-session admission PolicyException. Requesters and bindings cannot
// select, add or retain them.
func validateNodeMaintenanceAuxiliaryResources(spec *DebugSessionTemplateSpec) error {
	required := map[string]bool{}
	for _, category := range spec.RequiredAuxiliaryResourceCategories {
		required[category] = true
	}
	used := map[string]bool{}
	for _, resource := range spec.AuxiliaryResources {
		if resource.CreateBefore == nil || !*resource.CreateBefore || (resource.DeleteAfter != nil && !*resource.DeleteAfter) ||
			resource.Optional || (resource.FailurePolicy != "" && resource.FailurePolicy != AuxiliaryResourceFailurePolicyFail) ||
			resource.Category == "" || !required[resource.Category] {
			return fmt.Errorf("nodeMaintenance auxiliary resources must be required, createBefore, deleteAfter and fail closed")
		}
		used[resource.Category] = true
	}
	for category := range required {
		if !used[category] {
			return fmt.Errorf("nodeMaintenance required auxiliary category %q has no resources", category)
		}
	}
	return nil
}

// ValidateNodeMaintenanceSession forbids request-side alternate executor inputs.
func ValidateNodeMaintenanceSession(spec *DebugSessionTemplateSpec, request *DebugSessionSpec) error {
	if err := ValidateNodeMaintenanceRequest(spec.NodeMaintenance, request.NodeMaintenance); err != nil {
		return err
	}
	if spec.NodeMaintenance == nil {
		return nil
	}
	if err := ValidateNodeMaintenanceTemplate(spec); err != nil {
		return err
	}
	if len(request.ExtraDeployValues) != 0 || len(request.NodeSelector) != 0 || request.SelectedSchedulingOption != "" ||
		request.ResolvedSchedulingConstraints != nil || len(request.SelectedAuxiliaryResources) != 0 ||
		len(request.InvitedParticipants) != 0 ||
		(request.TargetNamespace != "" && request.TargetNamespace != NodeMaintenanceNamespace) {
		return fmt.Errorf("nodeMaintenance accepts only typed tuple parameters, not generic workload overrides")
	}
	return nil
}

// ValidateNodeMaintenanceTarget rejects ambiguous, broad and noncanonical tuples.
func ValidateNodeMaintenanceTarget(action string, target *NodeMaintenanceTarget) error {
	if target == nil {
		return fmt.Errorf("nodeMaintenance target is required")
	}
	if len(validation.IsDNS1123Subdomain(target.TargetNode)) != 0 ||
		!maintenanceUIDPattern.MatchString(target.TargetNodeUID) {
		return fmt.Errorf("an exact Node name and UID are required")
	}
	if action == NodeMaintenanceActionServiceRestart {
		if !slices.Contains(nodeMaintenanceServiceUnits, target.Unit) {
			return fmt.Errorf("service-restart requires a unit from %v", nodeMaintenanceServiceUnits)
		}
		if target.Interface != "" || target.EntryMAC != "" || target.NeighborAddress != "" ||
			target.Bridge != "" || target.VLAN != nil || target.VRF != "" {
			return fmt.Errorf("service-restart targets only an exact Node name, UID and unit")
		}
		return nil
	}
	if target.Unit != "" {
		return fmt.Errorf("unit is valid only for service-restart")
	}
	if action == NodeMaintenanceActionKexecRecovery {
		if target.Interface != "" || target.EntryMAC != "" || target.NeighborAddress != "" ||
			target.Bridge != "" || target.VLAN != nil || target.VRF != "" {
			return fmt.Errorf("kexec-recovery targets only an exact Node name and UID")
		}
		return nil
	}
	if !maintenanceInterfacePattern.MatchString(target.Interface) || target.Interface == "." || target.Interface == ".." {
		return fmt.Errorf("an exact interface is required")
	}
	mac, err := net.ParseMAC(target.EntryMAC)
	if err != nil || len(mac) != 6 || mac.String() != target.EntryMAC ||
		mac[0]&1 != 0 || target.EntryMAC == "00:00:00:00:00:00" {
		return fmt.Errorf("entryMAC must be a canonical nonzero unicast six-byte MAC")
	}
	switch action {
	case "neighbor-replace":
		address, err := netip.ParseAddr(target.NeighborAddress)
		if err != nil || address.String() != target.NeighborAddress || address.Zone() != "" ||
			address.IsMulticast() || address.IsUnspecified() || address.Is4In6() || target.Bridge != "" || target.VLAN != nil {
			return fmt.Errorf("neighbor-replace requires an exact canonical IP/MAC/interface and no bridge or VLAN")
		}
		if target.VRF != "" && (!maintenanceInterfacePattern.MatchString(target.VRF) || target.VRF == "." ||
			target.VRF == ".." || target.VRF == target.Interface) {
			return fmt.Errorf("neighbor-replace vrf must be the exact VRF device of the interface")
		}
	case "bridge-fdb-replace":
		if !maintenanceInterfacePattern.MatchString(target.Bridge) || target.Bridge == "." || target.Bridge == ".." ||
			target.Bridge == target.Interface || target.NeighborAddress != "" || target.VRF != "" ||
			target.VLAN == nil || *target.VLAN < 1 || *target.VLAN > 4094 {
			return fmt.Errorf("bridge-fdb-replace requires exact bridge/port/MAC/VLAN and no neighbour IP or VRF")
		}
	default:
		return fmt.Errorf("unsupported node-maintenance action %q", action)
	}
	return nil
}

// ValidateNodeMaintenanceRequest matches every field against the approved template.
func ValidateNodeMaintenanceRequest(profile *DebugSessionNodeMaintenance, target *NodeMaintenanceTarget) error {
	if profile == nil {
		if target != nil {
			return fmt.Errorf("template does not enable nodeMaintenance")
		}
		return nil
	}
	if !maintenanceImagePattern.MatchString(profile.Image) || strings.ContainsAny(profile.Image, " \t\r\n") ||
		len(profile.AllowedTargets) == 0 || len(profile.AllowedTargets) > 128 {
		return fmt.Errorf("nodeMaintenance requires an immutable image and nonempty bounded allowlist")
	}
	if err := validateNodeMaintenanceKexec(profile); err != nil {
		return err
	}
	if err := validateNodeMaintenanceService(profile); err != nil {
		return err
	}
	if err := ValidateNodeMaintenanceTarget(profile.Action, target); err != nil {
		return err
	}
	for i := range profile.AllowedTargets {
		allowed := &profile.AllowedTargets[i]
		if err := ValidateNodeMaintenanceTarget(profile.Action, allowed); err != nil {
			return fmt.Errorf("invalid nodeMaintenance allowlist: %w", err)
		}
	}
	for _, allowed := range profile.AllowedTargets {
		vlanMatches := target.VLAN == nil && allowed.VLAN == nil ||
			target.VLAN != nil && allowed.VLAN != nil && *target.VLAN == *allowed.VLAN
		if target.TargetNode == allowed.TargetNode && target.TargetNodeUID == allowed.TargetNodeUID &&
			target.Interface == allowed.Interface && target.EntryMAC == allowed.EntryMAC &&
			target.NeighborAddress == allowed.NeighborAddress && target.Bridge == allowed.Bridge &&
			target.VRF == allowed.VRF && target.Unit == allowed.Unit && vlanMatches {
			return nil
		}
	}
	return fmt.Errorf("nodeMaintenance tuple is not in the template allowlist")
}

func validateNodeMaintenanceService(profile *DebugSessionNodeMaintenance) error {
	service := profile.Service
	if profile.Action != NodeMaintenanceActionServiceRestart {
		if service != nil {
			return fmt.Errorf("nodeMaintenance service is valid only for service-restart")
		}
		return nil
	}
	if profile.DryRun {
		return fmt.Errorf("service-restart has no preview; dryRun is not supported")
	}
	if service == nil || service.DrainTimeoutSeconds < 30 || service.DrainTimeoutSeconds > 3600 || len(service.RestartPods) > 4 {
		return fmt.Errorf("service-restart requires a drainTimeoutSeconds from 30 through 3600 and at most four restartPods")
	}
	for _, selector := range service.RestartPods {
		if len(validation.IsDNS1123Label(selector.Namespace)) != 0 || len(selector.MatchLabels) == 0 || len(selector.MatchLabels) > 8 {
			return fmt.Errorf("service-restart restartPods need an exact namespace and one to eight matchLabels")
		}
		for key, value := range selector.MatchLabels {
			if len(validation.IsQualifiedName(key)) != 0 || len(validation.IsValidLabelValue(value)) != 0 || value == "" {
				return fmt.Errorf("service-restart restartPods matchLabels must be exact non-empty label pairs")
			}
		}
	}
	return nil
}

func validateNodeMaintenanceKexec(profile *DebugSessionNodeMaintenance) error {
	kexec := profile.Kexec
	if profile.Action != NodeMaintenanceActionKexecRecovery {
		if kexec != nil {
			return fmt.Errorf("nodeMaintenance kexec is valid only for kexec-recovery")
		}
		return nil
	}
	if kexec == nil || !maintenanceProfilePattern.MatchString(kexec.Profile) ||
		!maintenanceHostPathPattern.MatchString(kexec.HostPath) || path.Clean(kexec.HostPath) != kexec.HostPath ||
		kexec.HostPath == "/" || slices.Contains(strings.Split(kexec.HostPath, "/"), "..") ||
		!maintenanceSHA256Pattern.MatchString(kexec.KernelSHA256) || !maintenanceSHA256Pattern.MatchString(kexec.InitrdSHA256) ||
		!maintenanceSHA256Pattern.MatchString(kexec.CmdlineSHA256) ||
		kexec.DrainTimeoutSeconds < 30 || kexec.DrainTimeoutSeconds > 3600 {
		return fmt.Errorf("kexec-recovery requires a profile, a clean absolute hostPath, three exact SHA-256 digests and a drainTimeoutSeconds from 30 through 3600")
	}
	return nil
}

// NodeMaintenanceStatus is the durable, single-attempt executor inventory.
type NodeMaintenanceStatus struct {
	// operationID correlates the approval, helper and audit events.
	OperationID string `json:"operationID"`
	// namespaceUID fences the operator-provisioned common lock/workload namespace.
	NamespaceUID string `json:"namespaceUID"`
	// activeDeadlineSeconds is fixed before creation, never extended on recovery.
	// +kubebuilder:validation:Minimum=1
	ActiveDeadlineSeconds int64 `json:"activeDeadlineSeconds"`
	// leaseUID is the exact per-node Lease incarnation acquired by this session.
	// +optional
	LeaseUID string `json:"leaseUID,omitempty"`
	// jobUID is the exact externally managed Job envelope for the single Pod.
	// +optional
	JobUID string `json:"jobUID,omitempty"`
	// jobCreateAttempted is persisted before Job creation; missing unknown Jobs are never recreated.
	// +optional
	JobCreateAttempted bool `json:"jobCreateAttempted,omitempty"`
	// podUID is recovered only from an exact matching single-attempt Pod.
	// +optional
	PodUID string `json:"podUID,omitempty"`
	// createAttempted is persisted before calling Create. Never retry a missing Pod.
	// +optional
	CreateAttempted bool `json:"createAttempted,omitempty"`
	// result is the observed terminal Pod outcome, not a claim of kernel verification.
	// +optional
	// +kubebuilder:validation:Enum=succeeded;failed;interrupted;unknown
	Result string `json:"result,omitempty"`
	// resultAudited records a durable audit receipt for the observed result.
	// +optional
	ResultAudited bool `json:"resultAudited,omitempty"`
	// bootID is the Node boot ID observed before a kexec-recovery executor
	// was created. A different boot ID on a Ready Node proves the reboot.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	BootID string `json:"bootID,omitempty"`
	// cordonedAt is when this operation cordoned the Node for kexec-recovery or service-restart.
	// It bounds the drain and marks the cordon as owned by this operation.
	// +optional
	CordonedAt *metav1.Time `json:"cordonedAt,omitempty"`
	// restartedPodUIDs are the Pods a service-restart deleted after its
	// verified restart; their replacements must be Ready before success.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	RestartedPodUIDs []string `json:"restartedPodUIDs,omitempty"`
	// podRestartIssued is set once the restartPods deletions were sent, so they
	// are never repeated.
	// +optional
	PodRestartIssued bool `json:"podRestartIssued,omitempty"`
	// released is set only after Pod absence and UID-fenced Lease deletion.
	// +optional
	Released bool `json:"released,omitempty"`
}
