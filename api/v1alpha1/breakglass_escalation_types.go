/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BreakglassEscalationSpec defines the desired state of BreakglassEscalation.
type BreakglassEscalationSpec struct {
	// allowed specifies who is allowed to use this escalation.
	Allowed BreakglassEscalationAllowed `json:"allowed"`
	// approvers specifies who is allowed to approve this escalation.
	Approvers BreakglassEscalationApprovers `json:"approvers,omitempty"`
	// escalatedGroup is the group to be granted by this escalation.
	EscalatedGroup string `json:"escalatedGroup,omitempty"`

	// maxValidFor is the maximum amount of time a session for this escalation will be active for after it is approved.
	// +default="1h"
	MaxValidFor string `json:"MaxValidFor,omitempty"`
	// retainFor is the amount of time to wait before removing a session for this escalation after it expired
	// +optional
	RetainFor string `json:"retainFor,omitempty"`
	// idleTimeout is the maximum amount of time a session for this escalation can sit idle without being used.
	// +default="1h"
	IdleTimeout string `json:"idleTimeout,omitempty"`
}

// BreakglassEscalationAllowed defines who is allowed to use an escalation.
// todo: consider how to handle both users and groups being specified - should probably be logical 'or'
type BreakglassEscalationAllowed struct {
	// clusters is a list of clusters this escalation can be used for.
	// todo: implement globbing (or regex?) support
	Clusters []string `json:"clusters,omitempty"`
	// users is a list of users this escalation can be used by.
	// todo: implement globbing (or regex?) support
	Users []string `json:"users,omitempty"`
	// groups is a list of groups this escalation can be used by.
	// todo: implement globbing (or regex?) support
	Groups []string `json:"groups,omitempty"`
}

// BreakglassEscalationApprovers
type BreakglassEscalationApprovers struct {
	// users that are allowed to approve a session for this escalation
	Users []string `json:"users,omitempty"`
	// groups that are allowed to approve a session for this escalation
	Groups []string `json:"groups,omitempty"`
}

// BreakglassEscalationStatus defines the observed state of BreakglassEscalation.
type BreakglassEscalationStatus struct{}

// +kubebuilder:resource:scope=Cluster
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=`.spec.cluster`
// +kubebuilder:selectablefield:JSONPath=`.spec.username`
// +kubebuilder:selectablefield:JSONPath=`.spec.escalatedGroup`

type BreakglassEscalation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   BreakglassEscalationSpec   `json:"spec"`
	Status BreakglassEscalationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BreakglassEscalationList contains a list of BreakglassEscalation.
type BreakglassEscalationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BreakglassEscalation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BreakglassEscalation{}, &BreakglassEscalationList{})
}
