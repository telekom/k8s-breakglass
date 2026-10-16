// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HotfixRecordConditionType is a condition of a HotfixRecord.
type HotfixRecordConditionType string

const (
	// HotfixRecordConditionActive is true while the hotfix is applied on at least one node.
	HotfixRecordConditionActive HotfixRecordConditionType = "Active"
	// HotfixRecordConditionReverted is true when a node lost the hotfix without a rollback session.
	HotfixRecordConditionReverted HotfixRecordConditionType = "Reverted"
	// HotfixRecordConditionUncovered is true when a selected node does not carry the hotfix.
	HotfixRecordConditionUncovered HotfixRecordConditionType = "Uncovered"
	// HotfixRecordConditionExpiring is true within three days of expiresAt.
	HotfixRecordConditionExpiring HotfixRecordConditionType = "Expiring"
	// HotfixRecordConditionExpired is true after expiresAt until reconfirm, rollback or close.
	HotfixRecordConditionExpired HotfixRecordConditionType = "Expired"
	// HotfixRecordConditionClosed is true after a four-eyes close or a complete rollback.
	HotfixRecordConditionClosed HotfixRecordConditionType = "Closed"
)

// HotfixNodeState is the tracked state of a hotfix on one node.
// +kubebuilder:validation:Enum=applied;skipped;failed;rolledBack;uncovered;reverted
type HotfixNodeState string

const (
	HotfixNodeApplied    HotfixNodeState = "applied"
	HotfixNodeSkipped    HotfixNodeState = "skipped"
	HotfixNodeFailed     HotfixNodeState = "failed"
	HotfixNodeRolledBack HotfixNodeState = "rolledBack"
	HotfixNodeUncovered  HotfixNodeState = "uncovered"
	HotfixNodeReverted   HotfixNodeState = "reverted"
)

// HotfixRecordSession links a four-eyes session to the record.
type HotfixRecordSession struct {
	// stage is the session stage.
	Stage HotfixStage `json:"stage"`
	// name is the DebugSession name.
	Name string `json:"name"`
	// uid is the DebugSession UID.
	UID string `json:"uid"`
	// requestedBy is the requester.
	RequestedBy string `json:"requestedBy"`
	// approvedBy is the independent approver.
	ApprovedBy string `json:"approvedBy"`
	// at is when the stage started.
	At metav1.Time `json:"at"`
}

// HotfixRecordSpec is the durable drift record of one applied hotfix. Only the
// controller writes it.
type HotfixRecordSpec struct {
	// cluster is the target cluster.
	Cluster string `json:"cluster"`
	// templateRef is the DebugSessionTemplate of the hotfix.
	TemplateRef string `json:"templateRef"`
	// payload is the applied change, including sources and digests.
	Payload HotfixPayload `json:"payload"`
	// planHash is the reviewed plan hash of the apply session.
	PlanHash string `json:"planHash"`
	// rollout is the effective rollout of the apply stage; rollback reuses it.
	Rollout HotfixRollout `json:"rollout"`
	// nodeSelection is the original selection, used to detect uncovered nodes.
	NodeSelection HotfixNodeSelection `json:"nodeSelection"`
	// fixedIn names the regular release that will contain the fix.
	FixedIn string `json:"fixedIn"`
	// expiresAt is when the hotfix must be reconfirmed, rolled back or closed.
	// Expiry raises a critical alert; it never rolls back on its own.
	ExpiresAt metav1.Time `json:"expiresAt"`
	// sessions are the four-eyes sessions of this hotfix, in order.
	// +listType=atomic
	Sessions []HotfixRecordSession `json:"sessions"`
}

// HotfixRecordNode is the tracked state of one node.
type HotfixRecordNode struct {
	// name is the Node name.
	Name string `json:"name"`
	// uid is the Node UID.
	UID string `json:"uid"`
	// state is the tracked state.
	State HotfixNodeState `json:"state"`
	// controlPlane marks control-plane nodes, which change one at a time.
	// +optional
	ControlPlane bool `json:"controlPlane,omitempty"`
	// beforeSHA256 is the pre-image hash on this node; rollback restores it.
	// +optional
	BeforeSHA256 string `json:"beforeSHA256,omitempty"`
	// afterSHA256 is the verified result hash on this node.
	// +optional
	AfterSHA256 string `json:"afterSHA256,omitempty"`
	// newPackages are Debian packages the hotfix added; rollback purges them.
	// +optional
	// +listType=atomic
	NewPackages []string `json:"newPackages,omitempty"`
	// at is the last state change.
	At metav1.Time `json:"at"`
	// message explains failed, reverted and uncovered states.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
}

// HotfixRecordStatus is the observed drift state.
type HotfixRecordStatus struct {
	// nodes is the per-node state.
	// +optional
	// +listType=map
	// +listMapKey=name
	Nodes []HotfixRecordNode `json:"nodes,omitempty"`
	// conditions are Active, Reverted, Uncovered, Expiring, Expired and Closed.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// observedAt is the last drift check.
	// +optional
	ObservedAt *metav1.Time `json:"observedAt,omitempty"`
}

// HotfixRecord tracks one platform hotfix as drift until it is closed.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=hfr
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=".spec.cluster"
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=".spec.payload.type"
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=".spec.expiresAt"
// +kubebuilder:printcolumn:name="Active",type=string,JSONPath=`.status.conditions[?(@.type=="Active")].status`
// +kubebuilder:printcolumn:name="Closed",type=string,JSONPath=`.status.conditions[?(@.type=="Closed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
type HotfixRecord struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HotfixRecordSpec   `json:"spec,omitempty"`
	Status HotfixRecordStatus `json:"status,omitempty"`
}

// HotfixRecordList contains a list of HotfixRecord.
// +kubebuilder:object:root=true
type HotfixRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HotfixRecord `json:"items"`
}

func init() { SchemeBuilder.Register(&HotfixRecord{}, &HotfixRecordList{}) }
