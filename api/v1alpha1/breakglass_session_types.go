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

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BreakglassSessionSpec defines the desired state of BreakglassSession.
// todo: make all of this immutable (probably using CEL)
type BreakglassSessionSpec struct {
	// cluster is the name of the cluster the session is valid for.
	// +required
	Cluster string `json:"cluster,omitempty"`

	// username is the name of the user the session is valid for.
	// +required
	User string `json:"user,omitempty"`

	// grantedGroup is the group granted by the session.
	// +required
	GrantedGroup string `json:"grantedGroup,omitempty"`

	// Max time a session can sit idle without being used by user after approved.
	// +default="1h"
	IdleTimeout string `json:"idleTimeout,omitempty"`

	// maxValidFor is the maximum amount of time the session will be active for after it is approved.
	// +default="1h"
	MaxValidFor string `json:"MaxValidFor,omitempty"`

	// retainFor is the amount of time to wait before removing the session object after it was expired.
	// +default="1m"
	RetainFor string `json:"retainFor,omitempty"`
}

// BreakglassSessionStatus defines the observed state of BreakglassSessionStatus.
type BreakglassSessionStatus struct {
	// Important: Run "make" to regenerate code after modifying this file

	// conditions is an array of current observed BreakglassSession conditions.
	// todo: implement 'Active' and 'Expired' conditions.
	Conditions []metav1.Condition `json:"conditions"`

	// approvedAt is the time when the session was approved.
	// todo: make immutable
	// +omitempty
	ApprovedAt metav1.Time `json:"approvedAt,omitempty"`

	// expiresAt is the time when the session will expire.
	// This value is set based on spec.expiresAfter when the session is approved.
	// todo: make immutable
	// +omitempty
	ExpiredAfter metav1.Time `json:"expiresAt,omitempty"`

	// retainedUntil is the time when the session object will be removed from the cluster.
	// This value is set based on spec.retainFor when the session is approved.
	// todo: make immutable
	// +omitempty
	RetainedUntil metav1.Time `json:"retainedUntil,omitempty"`

	// NOT IMPLEMENTED https://github.com/telekom/das-schiff-breakglass/issues/8
	// Time until session is revoked due to user not actively using it.
	IdleUntil metav1.Time `json:"idleUntil,omitempty"`

	// NOT IMPLEMENTED https://github.com/telekom/das-schiff-breakglass/issues/8
	// Last time session was used for breakglass session based authorization.
	LastUsed metav1.Time `json:"lastUsed,omitempty"`
}

// +kubebuilder:resource:scope=Cluster
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=`.spec.cluster`
// +kubebuilder:selectablefield:JSONPath=`.spec.username`
// +kubebuilder:selectablefield:JSONPath=`.spec.grantedGroup`
// +kubebuilder:selectablefield:JSONPath=`.status.expiredAfter`
// +kubebuilder:selectablefield:JSONPath=`.status.approvedAt`

// BreakglassSession is the Schema for the breakglasssessions API.
// Session unique identifier is a triple - cluster name, username, RBAC group.
type BreakglassSession struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   BreakglassSessionSpec   `json:"spec"`
	Status BreakglassSessionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// BreakglassSessionList contains a list of BreakglassSession.
type BreakglassSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BreakglassSession `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BreakglassSession{}, &BreakglassSessionList{})
}
