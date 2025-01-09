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
type BreakglassSessionSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// The cluster for which a breakglass session is managed.
	// +required
	Cluster string `json:"cluster,omitempty"`

	// The name user of a user that requested for breakglass group session.
	// +required
	Username string `json:"username,omitempty"`

	// The requested RBAC group.
	// +required
	Group string `json:"group,omitempty"`

	// A list of usernames (or emails) of users that can grant requested session.
	// +required
	Approvers []string `json:"approvers,omitempty"`

	// Max time a session can sit idle without being used by user after approved.
	// +default="1h"
	IdleTimeout string `json:"idleTimeout,omitempty"`

	// Max time until session becomes expired.
	// +default="1h"
	ExpirationTimeout string `json:"expirationTimeout,omitempty"`

	// Timeout value after which sesssion should be removed and no longer kept for logs / audit.
	// +default="1m"
	HistoryTimeout string `json:"historyTimeout,omitempty"`
}

// BreakglassSessionStatus defines the observed state of BreakglassSessionStatus.
type BreakglassSessionStatus struct {
	// Important: Run "make" to regenerate code after modifying this file

	// Defines if session is expired by either being denied by approvers or reached expiration timeout.
	Expired bool `json:"expired"`

	// Defines if session is approved by one of the approvers.
	Approved bool `json:"approved"`

	// Not implemented
	// Defines if session reached idle timeout.
	IdleTimeoutReached bool `json:"idleTimeoutReached"`

	// Creation time.
	CreatedAt metav1.Time `json:"createdAt,omitempty"`

	// Last approval time.
	ApprovedAt metav1.Time `json:"approvedAt,omitempty"`

	// Time until approval is expired, rbac group can no longer be used by user.
	ValidUntil metav1.Time `json:"validUntil,omitempty"`

	// Time until session object should be removed.
	StoreUntil metav1.Time `json:"storeUntil,omitempty"`

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
// +kubebuilder:selectablefield:JSONPath=`.spec.group`
// +kubebuilder:selectablefield:JSONPath=`.status.expired`
// +kubebuilder:selectablefield:JSONPath=`.status.approved`
// +kubebuilder:selectablefield:JSONPath=`.status.idleTimeoutReached`

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

// BreakglassSessionList contains a list of ClusterGroup.
type BreakglassSessionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BreakglassSession `json:"items"`
}

type ClusterGroupRequest struct{}

func init() {
	SchemeBuilder.Register(&BreakglassSession{}, &BreakglassSessionList{})
}

func NewBreakglassSession(cluster, username, group string, approvers []string) BreakglassSession {
	return BreakglassSession{
		Spec: BreakglassSessionSpec{
			Cluster:   cluster,
			Username:  username,
			Group:     group,
			Approvers: approvers,
		},
		Status: BreakglassSessionStatus{},
	}
}
