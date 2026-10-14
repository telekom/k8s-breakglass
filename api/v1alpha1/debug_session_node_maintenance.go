// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// DebugSessionNodeMaintenance defines a fixed, operator-approved repair profile.
// It deliberately has no command, environment, capability or shell overrides.
type DebugSessionNodeMaintenance struct {
	// action is the one executor operation enabled by this profile.
	// +kubebuilder:validation:Enum=neighbor-replace;bridge-fdb-replace
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
}

// NodeMaintenanceTarget identifies exactly one kernel table entry on one Node incarnation.
type NodeMaintenanceTarget struct {
	// targetNode is the exact Kubernetes Node name.
	// +kubebuilder:validation:MaxLength=253
	TargetNode string `json:"targetNode"`
	// targetNodeUID prevents execution against a replaced Node.
	// +kubebuilder:validation:MaxLength=128
	TargetNodeUID string `json:"targetNodeUID"`
	// interface is the neighbour interface or bridge FDB port.
	// +kubebuilder:validation:MaxLength=15
	Interface string `json:"interface"`
	// entryMAC is the canonical lowercase colon-delimited six-byte MAC.
	// +kubebuilder:validation:Pattern=`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`
	EntryMAC string `json:"entryMAC"`
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
}

var maintenanceInterfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
var maintenanceUIDPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,128}$`)
var maintenanceImagePattern = regexp.MustCompile(`^.+@sha256:[a-f0-9]{64}$`)

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
			target.VRF == allowed.VRF && vlanMatches {
			return nil
		}
	}
	return fmt.Errorf("nodeMaintenance tuple is not in the template allowlist")
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
	// released is set only after Pod absence and UID-fenced Lease deletion.
	// +optional
	Released bool `json:"released,omitempty"`
}
