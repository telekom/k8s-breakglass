// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ArtifactRecordingMetadata binds terminal evidence to its original target and capability.
type ArtifactRecordingMetadata struct {
	// formatVersion is controller-supplied recording metadata.
	// +kubebuilder:validation:Enum=1
	// +required
	FormatVersion int32 `json:"formatVersion,omitempty"`
	// startedAt is controller-supplied recording metadata.
	// +optional
	StartedAt metav1.Time `json:"startedAt,omitempty"`
	// finishedAt is controller-supplied recording metadata.
	// +optional
	FinishedAt *metav1.Time `json:"finishedAt,omitempty"`
	// streamExpiresAt is controller-supplied recording metadata.
	// +optional
	StreamExpiresAt metav1.Time `json:"streamExpiresAt,omitempty"`
	// complete is controller-supplied recording metadata.
	// +optional
	Complete bool `json:"complete,omitempty"`
	// frames is controller-supplied recording metadata.
	// +optional
	Frames int64 `json:"frames,omitempty"`
	// podNamespace is controller-supplied recording metadata.
	// +optional
	PodNamespace string `json:"podNamespace,omitempty"`
	// podName is controller-supplied recording metadata.
	// +optional
	PodName string `json:"podName,omitempty"`
	// podUID is controller-supplied recording metadata.
	// +optional
	PodUID string `json:"podUID,omitempty"`
	// containerName is controller-supplied recording metadata.
	// +optional
	ContainerName string `json:"containerName,omitempty"`
	// operation is controller-supplied recording metadata.
	// +kubebuilder:validation:Enum=exec;attach
	// +required
	Operation string `json:"operation,omitempty"`
	// leaseUID is controller-supplied recording metadata.
	// +optional
	LeaseUID string `json:"leaseUID,omitempty"`
	// leaseEpoch is controller-supplied recording metadata.
	// +optional
	LeaseEpoch string `json:"leaseEpoch,omitempty"`
	// generation is controller-supplied recording metadata.
	// +optional
	Generation string `json:"generation,omitempty"`
}
