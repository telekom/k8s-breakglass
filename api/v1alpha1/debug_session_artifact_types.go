/*
Copyright 2026.

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

// ArtifactLifecycleState is the monotonic lifecycle state of one diagnostic
// artifact. Unknown is intentionally terminal until an operator reconciles the
// provider result; it is never treated as available.
// +kubebuilder:validation:Enum=Pending;Uploading;Available;Deleting;Deleted;Expired;Revoked;Unknown
type ArtifactLifecycleState string

const (
	ArtifactStatePending   ArtifactLifecycleState = "Pending"
	ArtifactStateUploading ArtifactLifecycleState = "Uploading"
	ArtifactStateAvailable ArtifactLifecycleState = "Available"
	ArtifactStateDeleting  ArtifactLifecycleState = "Deleting"
	ArtifactStateDeleted   ArtifactLifecycleState = "Deleted"
	ArtifactStateExpired   ArtifactLifecycleState = "Expired"
	ArtifactStateRevoked   ArtifactLifecycleState = "Revoked"
	ArtifactStateUnknown   ArtifactLifecycleState = "Unknown"
)

// ArtifactOperationKind identifies one durable provider operation.
// +kubebuilder:validation:Enum=Upload;Delete
type ArtifactOperationKind string

const (
	ArtifactOperationUpload ArtifactOperationKind = "Upload"
	ArtifactOperationDelete ArtifactOperationKind = "Delete"
)

// ArtifactSessionReference binds an artifact to the exact live session UID.
// Name and namespace alone are insufficient because Kubernetes permits name
// reuse after deletion.
type ArtifactSessionReference struct {
	// namespace is the session namespace.
	// +kubebuilder:validation:MinLength=1
	// +required
	Namespace string `json:"namespace"`
	// name is the session name.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
	// uid is the immutable session UID.
	// +kubebuilder:validation:MinLength=1
	// +required
	UID string `json:"uid"`
}

// ArtifactInputs is the closed, typed input set accepted by the allowlisted
// collector recipes. It deliberately has no command, path, image, or output
// fields.
type ArtifactInputs struct {
	// maxArchiveBytes is the server-selected compressed archive limit.
	// +kubebuilder:validation:Minimum=1
	// +required
	MaxArchiveBytes int64 `json:"maxArchiveBytes"`
	// maxAgeMinutes bounds crashdump collection age.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10080
	// +optional
	MaxAgeMinutes *int64 `json:"maxAgeMinutes,omitempty"`
	// detailLevel is the system-summary detail level.
	// +kubebuilder:validation:Enum=basic;extended
	// +optional
	DetailLevel *string `json:"detailLevel,omitempty"`
}

// DebugSessionArtifactSpec is immutable after creation. Provider credentials,
// endpoints, bucket names, object keys, and arbitrary execution controls are
// intentionally absent.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact specification is immutable"
type DebugSessionArtifactSpec struct {
	// artifactID is the public opaque artifact identifier.
	// +kubebuilder:validation:Pattern="^dsa-[0-9a-f]{24}$"
	// +required
	ArtifactID string `json:"artifactID"`
	// sessionRef identifies the exact session that owns this artifact.
	// +required
	SessionRef ArtifactSessionReference `json:"sessionRef"`
	// targetClusterUID binds collection and access to one target identity.
	// +kubebuilder:validation:MinLength=1
	// +required
	TargetClusterUID string `json:"targetClusterUID"`
	// recipe is an immutable allowlisted recipe identifier.
	// +kubebuilder:validation:Enum=system-summary.v1;crashdump-collection.v1
	// +required
	Recipe string `json:"recipe"`
	// recipeVersion is the immutable recipe schema version.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=9999
	// +required
	RecipeVersion int32 `json:"recipeVersion"`
	// planDigest binds the rendered Job and uploader contract.
	// +kubebuilder:validation:Pattern="^[0-9a-f]{64}$"
	// +required
	PlanDigest string `json:"planDigest"`
	// runtimeBindingDigest binds the target runtime identity and operation.
	// +kubebuilder:validation:Pattern="^[0-9a-f]{64}$"
	// +required
	RuntimeBindingDigest string `json:"runtimeBindingDigest"`
	// targetIdentityDigest binds immutable target identity details.
	// +kubebuilder:validation:Pattern="^[0-9a-f]{64}$"
	// +required
	TargetIdentityDigest string `json:"targetIdentityDigest"`
	// operationEpoch fences tokens issued before a session identity change.
	// +kubebuilder:validation:Minimum=1
	// +required
	OperationEpoch uint64 `json:"operationEpoch"`
	// uploadJTIHash binds the one-time upload lease without persisting the token identifier.
	// +kubebuilder:validation:Pattern="^[0-9a-f]{64}$"
	// +required
	UploadJTIHash string `json:"uploadJTIHash"`
	// redactionProfile selects the server-owned metadata redaction policy.
	// +kubebuilder:validation:Pattern="^[a-z][a-z0-9.-]{0,63}$"
	// +required
	RedactionProfile string `json:"redactionProfile"`
	// redactionVersion is the policy version used by the collector.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=9999
	// +required
	RedactionVersion int32 `json:"redactionVersion"`
	// node pins crashdump collection to the selected node.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Node *string `json:"node,omitempty"`
	// inputs contains only recipe-specific bounded values.
	// +required
	Inputs ArtifactInputs `json:"inputs"`
	// maxBytes is the immutable artifact reservation.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=536870912
	// +required
	MaxBytes int64 `json:"maxBytes"`
	// timeoutSeconds is the immutable collector Job deadline.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=3600
	// +required
	TimeoutSeconds int32 `json:"timeoutSeconds"`
	// expiresAt is the retention deadline after which access is denied.
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// ArtifactOutboxStatus records bounded retry and lease evidence without
// exposing provider details.
type ArtifactOutboxStatus struct {
	// kind is the current durable provider operation.
	// +required
	Kind ArtifactOperationKind `json:"kind"`
	// attempt is bounded by the controller's retry policy.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=3
	Attempt int32 `json:"attempt"`
	// leaseOwner identifies the controller worker holding the operation lease.
	// +kubebuilder:validation:MaxLength=128
	// +optional
	LeaseOwner string `json:"leaseOwner,omitempty"`
	// leaseExpiresAt bounds abandoned work recovery.
	// +optional
	LeaseExpiresAt *metav1.Time `json:"leaseExpiresAt,omitempty"`
	// lastError is a bounded redacted classification, never a provider URL or credential.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	LastError string `json:"lastError,omitempty"`
}

// ArtifactResourceReference identifies one spoke resource created for this
// artifact. UID and resourceVersion make restart cleanup safe against name
// reuse and replacement; this is intentionally not an owner reference because
// the artifact and resource live in different clusters.
type ArtifactResourceReference struct {
	// kind is the Kubernetes resource kind.
	// +required
	Kind string `json:"kind"`
	// namespace is the spoke namespace.
	// +required
	Namespace string `json:"namespace"`
	// name is the spoke resource name.
	// +required
	Name string `json:"name"`
	// uid is the exact UID observed after creation.
	// +required
	UID string `json:"uid"`
	// resourceVersion is the version observed after creation.
	// +required
	ResourceVersion string `json:"resourceVersion"`
	// operationID is the persisted create intent marker used for recovery.
	// +required
	OperationID string `json:"operationID"`
}

// DebugSessionArtifactStatus is safe to expose to API readers. Provider
// object keys, URLs, version IDs, credentials, and secret references are not
// persisted here.
type DebugSessionArtifactStatus struct {
	// targetCluster is the immutable ClusterConfig name used for spoke cleanup.
	// +optional
	TargetCluster string `json:"targetCluster,omitempty"`
	// targetNamespace is the approved spoke namespace used for collection.
	// +optional
	TargetNamespace string `json:"targetNamespace,omitempty"`
	// state is the monotonic lifecycle state.
	// +optional
	State ArtifactLifecycleState `json:"state,omitempty"`
	// lifecycleRevision is the CAS revision for durable state transitions.
	// +kubebuilder:validation:Minimum=0
	// +optional
	LifecycleRevision int64 `json:"lifecycleRevision,omitempty"`
	// observedGeneration is the last processed object generation.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// size is the validated compressed archive size.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Size int64 `json:"size,omitempty"`
	// sha256 is the validated compressed archive digest.
	// +kubebuilder:validation:Pattern="^[0-9a-f]{64}$"
	// +optional
	SHA256 string `json:"sha256,omitempty"`
	// createdAt records artifact admission.
	// +optional
	CreatedAt *metav1.Time `json:"createdAt,omitempty"`
	// availableAt records successful validated upload.
	// +optional
	AvailableAt *metav1.Time `json:"availableAt,omitempty"`
	// deletedAt records successful exact-version cleanup.
	// +optional
	DeletedAt *metav1.Time `json:"deletedAt,omitempty"`
	// outbox is the bounded provider operation state.
	// +optional
	Outbox *ArtifactOutboxStatus `json:"outbox,omitempty"`
	// resources records the exact spoke Secret and Job inventory for restart
	// cleanup. It is bounded to the controller's fixed resource set.
	// +kubebuilder:validation:MaxItems=2
	// +optional
	Resources []ArtifactResourceReference `json:"resources,omitempty"`
	// cleanupAmbiguous requires operator/reconciler evidence before finalization.
	// +optional
	CleanupAmbiguous bool `json:"cleanupAmbiguous,omitempty"`
	// conditions contain bounded lifecycle evidence.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=dsa
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Session, type=string, JSONPath=`.spec.sessionRef.name`
// +kubebuilder:printcolumn:name=Recipe, type=string, JSONPath=`.spec.recipe`
// +kubebuilder:printcolumn:name=State, type=string, JSONPath=`.status.state`
type DebugSessionArtifact struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DebugSessionArtifactSpec   `json:"spec"`
	Status DebugSessionArtifactStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type DebugSessionArtifactList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DebugSessionArtifact `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DebugSessionArtifact{}, &DebugSessionArtifactList{})
}
