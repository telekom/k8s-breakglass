// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// TrafficMirrorMaxDuration is the hard upper bound for one mirroring session.
const TrafficMirrorMaxDuration = time.Hour

// Traffic mirror directions.
const (
	TrafficMirrorDirectionIngress = "ingress"
	TrafficMirrorDirectionEgress  = "egress"
	TrafficMirrorDirectionBoth    = "both"
)

// Traffic mirror states recorded in DebugSession status.
const (
	// TrafficMirrorStatePending means the mirror Pod is created but not attached yet.
	TrafficMirrorStatePending = "pending"
	// TrafficMirrorStateMirroring means the tc mirror is attached and the capture runs.
	TrafficMirrorStateMirroring = "mirroring"
	// TrafficMirrorStateFailed means the mirror agent failed; cleanup still runs.
	TrafficMirrorStateFailed = "failed"
	// TrafficMirrorStateStopped means the mirror state was removed and verified.
	TrafficMirrorStateStopped = "stopped"
)

// Defaults applied when the template leaves a bound unset.
const (
	defaultTrafficMirrorSnapLength       = 256
	defaultTrafficMirrorMaxPackets       = 10000
	defaultTrafficMirrorMaxBandwidthMbps = 10
)

// DebugSessionTrafficMirror is a controller-executed, session-scoped traffic
// mirror. The controller attaches a tc clsact match-all basic filter with a mirred
// mirror action to one allowlisted interface of one Pod or Node and copies the
// traffic over a veth pair into a capture container of the session. Requesters
// select only the source; image, filter and bounds are fixed by the template.
type DebugSessionTrafficMirror struct {
	// image must be an immutable image that provides iproute2 (ip, tc),
	// util-linux nsenter and tcpdump, for example the network-debug utility.
	// +kubebuilder:validation:Pattern=`^.+@sha256:[a-f0-9]{64}$`
	Image string `json:"image"`
	// allowedSources is the allowlist of mirrorable Pods and Node interfaces.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	AllowedSources []TrafficMirrorSource `json:"allowedSources"`
	// direction selects the mirrored traffic of the interface (default both).
	// +optional
	// +kubebuilder:validation:Enum=ingress;egress;both
	Direction string `json:"direction,omitempty"`
	// filter is a tcpdump/BPF expression applied by the capture container.
	// It is passed as one argument, never through a shell.
	// +optional
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9 .:/()!&|=<>\[\]-]*$`
	Filter string `json:"filter,omitempty"`
	// snapLength bounds the captured bytes per packet (default 256).
	// +optional
	// +kubebuilder:validation:Minimum=64
	// +kubebuilder:validation:Maximum=65535
	SnapLength int32 `json:"snapLength,omitempty"`
	// maxPackets stops the capture after this many packets (default 10000).
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000000
	MaxPackets int32 `json:"maxPackets,omitempty"`
	// maxBandwidthMbps limits the mirrored copies with a token bucket on the
	// mirror device (default 10). Excess copies are dropped; the original
	// traffic is never shaped.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	MaxBandwidthMbps int32 `json:"maxBandwidthMbps,omitempty"`
}

// TrafficMirrorSource allows one kind of source: exactly one of pod or node.
type TrafficMirrorSource struct {
	// pod allows Pods in one exact namespace whose labels match.
	// +optional
	Pod *TrafficMirrorPodSource `json:"pod,omitempty"`
	// node allows the host interfaces of Nodes whose labels match.
	// +optional
	Node *TrafficMirrorNodeSource `json:"node,omitempty"`
	// interfaces are the exact interface names that may be mirrored, for
	// example eth0 or a Multus/SR-IOV net1 inside the Pod network namespace.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=8
	// +listType=set
	Interfaces []string `json:"interfaces"`
}

// TrafficMirrorPodSource selects Pods by exact namespace and labels.
type TrafficMirrorPodSource struct {
	// namespace is the exact Pod namespace.
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`
	// matchLabels must all match; at least one and at most eight labels.
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:MaxProperties=8
	MatchLabels map[string]string `json:"matchLabels"`
}

// TrafficMirrorNodeSource selects Nodes by labels.
type TrafficMirrorNodeSource struct {
	// matchLabels must all match; empty allows every Node.
	// +optional
	// +kubebuilder:validation:MaxProperties=8
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// TrafficMirrorRequest is the requester's source selection. The API resolves
// and records the Pod and Node UIDs before approval; execution requires the
// same live incarnations.
type TrafficMirrorRequest struct {
	// podNamespace and podName select a Pod source; empty selects a Node source.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	PodNamespace string `json:"podNamespace,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxLength=253
	PodName string `json:"podName,omitempty"`
	// podUID is the expected Pod UID; the API fills it when empty.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	PodUID string `json:"podUID,omitempty"`
	// nodeName is the Node source, or the Node of the Pod (filled by the API).
	// +optional
	// +kubebuilder:validation:MaxLength=253
	NodeName string `json:"nodeName,omitempty"`
	// nodeUID is the expected Node UID; the API fills it when empty.
	// +optional
	// +kubebuilder:validation:MaxLength=128
	NodeUID string `json:"nodeUID,omitempty"`
	// interface is the exact interface to mirror.
	// +kubebuilder:validation:MaxLength=15
	Interface string `json:"interface"`
}

// TrafficMirrorStatus is the durable executor inventory of one session.
type TrafficMirrorStatus struct {
	// operationID names the mirror Pod and correlates audit events.
	OperationID string `json:"operationID"`
	// state is the last observed mirror state.
	// +optional
	// +kubebuilder:validation:Enum=pending;mirroring;failed;stopped
	State string `json:"state,omitempty"`
	// createAttempted is persisted before the mirror Pod is created; once set,
	// cleanup always runs and verifies the teardown on the Node.
	// +optional
	CreateAttempted bool `json:"createAttempted,omitempty"`
	// podUID is the mirror Pod incarnation.
	// +optional
	PodUID string `json:"podUID,omitempty"`
	// teardownVerified is set after a teardown Pod proved that no tc filter
	// with this operation's cookie and no mirror device remain.
	// +optional
	TeardownVerified bool `json:"teardownVerified,omitempty"`
	// stopAudited records the durable stop receipt.
	// +optional
	StopAudited bool `json:"stopAudited,omitempty"`
	// released is set once every target resource of the mirror is gone.
	// +optional
	Released bool `json:"released,omitempty"`
	// message explains failures.
	// +optional
	Message string `json:"message,omitempty"`
}

var trafficMirrorFilterPattern = regexp.MustCompile(`^[a-zA-Z0-9 .:/()!&|=<>\[\]-]*$`)

// TrafficMirrorOperationID is the deterministic operation identity of a session UID.
func TrafficMirrorOperationID(sessionUID string) string {
	digest := sha256.Sum256([]byte("traffic-mirror/" + sessionUID))
	return "traffic-mirror-" + hex.EncodeToString(digest[:16])
}

// EffectiveDirection returns the direction with its default.
func (m *DebugSessionTrafficMirror) EffectiveDirection() string {
	if m.Direction == "" {
		return TrafficMirrorDirectionBoth
	}
	return m.Direction
}

// EffectiveSnapLength returns the snap length with its default.
func (m *DebugSessionTrafficMirror) EffectiveSnapLength() int32 {
	if m.SnapLength == 0 {
		return defaultTrafficMirrorSnapLength
	}
	return m.SnapLength
}

// EffectiveMaxPackets returns the packet limit with its default.
func (m *DebugSessionTrafficMirror) EffectiveMaxPackets() int32 {
	if m.MaxPackets == 0 {
		return defaultTrafficMirrorMaxPackets
	}
	return m.MaxPackets
}

// EffectiveMaxBandwidthMbps returns the mirror bandwidth with its default.
func (m *DebugSessionTrafficMirror) EffectiveMaxBandwidthMbps() int32 {
	if m.MaxBandwidthMbps == 0 {
		return defaultTrafficMirrorMaxBandwidthMbps
	}
	return m.MaxBandwidthMbps
}

func validTrafficMirrorInterface(name string) bool {
	return maintenanceInterfacePattern.MatchString(name) && name != "." && name != ".."
}

func validTrafficMirrorLabels(selector map[string]string) error {
	for key, value := range selector {
		if errs := validation.IsQualifiedName(key); len(errs) != 0 {
			return fmt.Errorf("invalid label key %q", key)
		}
		if errs := validation.IsValidLabelValue(value); len(errs) != 0 {
			return fmt.Errorf("invalid label value %q", value)
		}
	}
	return nil
}

func validateTrafficMirrorProfile(mirror *DebugSessionTrafficMirror) error {
	if !maintenanceImagePattern.MatchString(mirror.Image) {
		return fmt.Errorf("trafficMirror image must be pinned by digest")
	}
	if len(mirror.AllowedSources) == 0 || len(mirror.AllowedSources) > 32 {
		return fmt.Errorf("trafficMirror requires between 1 and 32 allowedSources")
	}
	for i, source := range mirror.AllowedSources {
		if (source.Pod == nil) == (source.Node == nil) {
			return fmt.Errorf("trafficMirror allowedSources[%d] must set exactly one of pod or node", i)
		}
		if source.Pod != nil {
			if len(validation.IsDNS1123Label(source.Pod.Namespace)) != 0 || source.Pod.Namespace == NodeMaintenanceNamespace {
				return fmt.Errorf("trafficMirror allowedSources[%d] needs an exact workload namespace", i)
			}
			if len(source.Pod.MatchLabels) == 0 || len(source.Pod.MatchLabels) > 8 {
				return fmt.Errorf("trafficMirror allowedSources[%d] pod needs between 1 and 8 matchLabels", i)
			}
			if err := validTrafficMirrorLabels(source.Pod.MatchLabels); err != nil {
				return fmt.Errorf("trafficMirror allowedSources[%d]: %w", i, err)
			}
		} else {
			if len(source.Node.MatchLabels) > 8 {
				return fmt.Errorf("trafficMirror allowedSources[%d] node allows at most 8 matchLabels", i)
			}
			if err := validTrafficMirrorLabels(source.Node.MatchLabels); err != nil {
				return fmt.Errorf("trafficMirror allowedSources[%d]: %w", i, err)
			}
		}
		if len(source.Interfaces) == 0 || len(source.Interfaces) > 8 {
			return fmt.Errorf("trafficMirror allowedSources[%d] needs between 1 and 8 interfaces", i)
		}
		for j, name := range source.Interfaces {
			if !validTrafficMirrorInterface(name) || slices.Contains(source.Interfaces[:j], name) {
				return fmt.Errorf("trafficMirror allowedSources[%d] has an invalid or duplicate interface %q", i, name)
			}
		}
	}
	if !slices.Contains([]string{"", TrafficMirrorDirectionIngress, TrafficMirrorDirectionEgress, TrafficMirrorDirectionBoth}, mirror.Direction) {
		return fmt.Errorf("trafficMirror direction must be ingress, egress or both")
	}
	if len(mirror.Filter) > 256 || !trafficMirrorFilterPattern.MatchString(mirror.Filter) || (mirror.Filter != "" && mirror.Filter[0] == '-') {
		return fmt.Errorf("trafficMirror filter must be a plain tcpdump expression of at most 256 characters")
	}
	if mirror.SnapLength != 0 && (mirror.SnapLength < 64 || mirror.SnapLength > 65535) {
		return fmt.Errorf("trafficMirror snapLength must be between 64 and 65535")
	}
	if mirror.MaxPackets < 0 || mirror.MaxPackets > 1000000 {
		return fmt.Errorf("trafficMirror maxPackets must be between 1 and 1000000")
	}
	if mirror.MaxBandwidthMbps < 0 || mirror.MaxBandwidthMbps > 1000 {
		return fmt.Errorf("trafficMirror maxBandwidthMbps must be between 1 and 1000")
	}
	return nil
}

// ValidateTrafficMirrorTemplate applies the fixed-executor contract to a mirror profile.
func ValidateTrafficMirrorTemplate(spec *DebugSessionTemplateSpec) error {
	if spec.TrafficMirror == nil {
		return nil
	}
	if spec.NodeMaintenance != nil || spec.AdmissionRecipe != nil || spec.Hotfix != nil {
		return fmt.Errorf("trafficMirror is mutually exclusive with nodeMaintenance, admissionRecipe and hotfix")
	}
	if spec.Toolbox != nil {
		return fmt.Errorf("trafficMirror does not support toolbox; the mirror Pod is fixed")
	}
	if err := validateFixedExecutorTemplate(spec, "trafficMirror"); err != nil {
		return err
	}
	if spec.Constraints.AllowRenewal != nil && *spec.Constraints.AllowRenewal {
		return fmt.Errorf("trafficMirror does not support renewal; bound the session with maxDuration")
	}
	if duration, err := ParseDuration(spec.Constraints.MaxDuration); err != nil || duration > TrafficMirrorMaxDuration {
		return fmt.Errorf("trafficMirror maxDuration must be at most %s", TrafficMirrorMaxDuration)
	}
	return validateTrafficMirrorProfile(spec.TrafficMirror)
}

// ValidateTrafficMirrorRequestShape rejects malformed source selections.
func ValidateTrafficMirrorRequestShape(request *TrafficMirrorRequest) error {
	if request == nil {
		return fmt.Errorf("trafficMirror request is required")
	}
	if !validTrafficMirrorInterface(request.Interface) {
		return fmt.Errorf("trafficMirror requires an exact interface")
	}
	if request.PodName != "" || request.PodNamespace != "" || request.PodUID != "" {
		if len(validation.IsDNS1123Label(request.PodNamespace)) != 0 || len(validation.IsDNS1123Subdomain(request.PodName)) != 0 {
			return fmt.Errorf("trafficMirror pod source needs an exact podNamespace and podName")
		}
	} else if len(validation.IsDNS1123Subdomain(request.NodeName)) != 0 {
		return fmt.Errorf("trafficMirror needs either an exact pod or an exact nodeName")
	}
	for _, uid := range []string{request.PodUID, request.NodeUID} {
		if uid != "" && !maintenanceUIDPattern.MatchString(uid) {
			return fmt.Errorf("trafficMirror UIDs must be canonical")
		}
	}
	if request.NodeName != "" && len(validation.IsDNS1123Subdomain(request.NodeName)) != 0 {
		return fmt.Errorf("trafficMirror nodeName must be an exact Node name")
	}
	return nil
}

// TrafficMirrorSourceAllows reports whether a live source with these labels and
// interface is allowlisted. podNamespace is empty for a Node source.
func TrafficMirrorSourceAllows(mirror *DebugSessionTrafficMirror, podNamespace string, sourceLabels map[string]string, iface string) bool {
	for _, source := range mirror.AllowedSources {
		if !slices.Contains(source.Interfaces, iface) {
			continue
		}
		switch {
		case podNamespace != "" && source.Pod != nil && source.Pod.Namespace == podNamespace &&
			labels.SelectorFromSet(source.Pod.MatchLabels).Matches(labels.Set(sourceLabels)):
			return true
		case podNamespace == "" && source.Node != nil &&
			labels.SelectorFromSet(source.Node.MatchLabels).Matches(labels.Set(sourceLabels)):
			return true
		}
	}
	return false
}

// ValidateTrafficMirrorSession matches the request against the template and
// forbids generic workload inputs.
func ValidateTrafficMirrorSession(spec *DebugSessionTemplateSpec, request *DebugSessionSpec) error {
	if spec.TrafficMirror == nil {
		if request.TrafficMirror != nil {
			return fmt.Errorf("template does not enable trafficMirror")
		}
		return nil
	}
	if err := ValidateTrafficMirrorTemplate(spec); err != nil {
		return err
	}
	if err := ValidateTrafficMirrorRequestShape(request.TrafficMirror); err != nil {
		return err
	}
	if request.NodeMaintenance != nil || request.AdmissionRecipe != nil || request.Hotfix != nil ||
		len(request.ExtraDeployValues) != 0 || len(request.NodeSelector) != 0 ||
		request.SelectedSchedulingOption != "" || request.ResolvedSchedulingConstraints != nil ||
		len(request.SelectedAuxiliaryResources) != 0 || len(request.InvitedParticipants) != 0 ||
		(request.TargetNamespace != "" && request.TargetNamespace != NodeMaintenanceNamespace) {
		return fmt.Errorf("trafficMirror accepts only a typed source selection, not generic workload overrides")
	}
	return nil
}
