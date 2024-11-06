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

// ClusterAccessReviewSpec defines the desired state of ClusterAccessReview.
type ClusterAccessReviewSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	ID      uint   `json:"id,omitempty"`
	Cluster string `json:"cluster,omitempty"`

	Subject  ClusterAccessReviewSubject    `json:"subject,omitempty"`
	Status   AccessReviewApplicationStatus `json:"application_status,omitempty"`
	Until    metav1.Time                   `json:"until,omitempty"`
	Duration metav1.Duration               `json:"duration,omitempty"`
}

type (
	ClusterAccessReviewSubject struct {
		Namespace string `json:"namespace,omitempty"`
		Verb      string `json:"verb,omitempty"`
		Resource  string `json:"resource,omitempty"`
		Username  string `json:"username,omitempty"`
	}
	AccessReviewApplicationStatus string
)

const (
	StatusPending  AccessReviewApplicationStatus = "Pending"
	StatusAccepted AccessReviewApplicationStatus = "Accepted"
	StatusRejected AccessReviewApplicationStatus = "Rejected"
)

// ClusterAccessReviewStatus defines the observed state of ClusterAccessReview.
type ClusterAccessReviewStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:selectablefield:JSONPath=`.spec.id`
// +kubebuilder:selectablefield:JSONPath=`.spec.cluster`
// +kubebuilder:selectablefield:JSONPath=`.spec.application_status`
// +kubebuilder:selectablefield:JSONPath=`.spec.until`
// +kubebuilder:selectablefield:JSONPath=`.spec.subject.namespace`
// +kubebuilder:selectablefield:JSONPath=`.spec.subject.verb`
// +kubebuilder:selectablefield:JSONPath=`.spec.subject.resource`
// +kubebuilder:selectablefield:JSONPath=`.spec.subject.username`

// ClusterAccessReview is the Schema for the clusteraccessreviews API.
type ClusterAccessReview struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterAccessReviewSpec   `json:"spec,omitempty"`
	Status ClusterAccessReviewStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterAccessReviewList contains a list of ClusterAccessReview.
type ClusterAccessReviewList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterAccessReview `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterAccessReview{}, &ClusterAccessReviewList{})
}
