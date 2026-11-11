// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// CleanupAcknowledgedIdentity names one DebugSession cleanup residual by its
// full recorded identity. UID is empty only for an unresolved create intent.
type CleanupAcknowledgedIdentity struct {
	// apiVersion of the residual resource.
	// +kubebuilder:validation:MinLength=1
	APIVersion string `json:"apiVersion"`
	// kind of the residual resource.
	// +kubebuilder:validation:MinLength=1
	Kind string `json:"kind"`
	// namespace of the residual resource; empty for cluster-scoped resources.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// name of the residual resource.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// uid is the recorded UID; omit it only for an unresolved create intent.
	// +optional
	UID string `json:"uid,omitempty"`
}

func (i CleanupAcknowledgedIdentity) String() string {
	s := i.APIVersion + "/" + i.Kind + "/" + i.Namespace + "/" + i.Name
	if i.UID != "" {
		s += " (uid=" + i.UID + ")"
	}
	return s
}

// DebugSessionCleanupAcknowledgementSpec lists cleanup residuals of one
// DebugSession that an operator verified are gone.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
type DebugSessionCleanupAcknowledgementSpec struct {
	// sessionName is the DebugSession in the same namespace.
	// +kubebuilder:validation:MinLength=1
	SessionName string `json:"sessionName"`
	// sessionUID binds the acknowledgement to one DebugSession instance.
	// +kubebuilder:validation:MinLength=1
	SessionUID string `json:"sessionUID"`
	// identities are the exact residuals to retire. Every entry must match an
	// outstanding residual, otherwise nothing is retired.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +listType=atomic
	Identities []CleanupAcknowledgedIdentity `json:"identities"`
	// acknowledgedBy is the creating user; the admission webhook requires it to
	// equal the requesting user.
	// +kubebuilder:validation:MinLength=1
	AcknowledgedBy string `json:"acknowledgedBy"`
	// reason is an optional reason or ticket reference for the audit trail.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Reason string `json:"reason,omitempty"`
}

// DebugSessionCleanupAcknowledgement retires DebugSession cleanup residuals
// that the controller cannot prove gone, for example objects of an
// uninstalled CRD. Creating one requires RBAC create on this resource, which
// the API server enforces; grant it only to independent operators.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=dsca
// +kubebuilder:printcolumn:name="Session",type=string,JSONPath=".spec.sessionName"
// +kubebuilder:printcolumn:name="By",type=string,JSONPath=".spec.acknowledgedBy"
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
type DebugSessionCleanupAcknowledgement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec DebugSessionCleanupAcknowledgementSpec `json:"spec"`
	// status is written only by the controller.
	// +optional
	Status DebugSessionCleanupAcknowledgementObjectStatus `json:"status,omitempty"`
}

// CleanupAcknowledgementPhase is the processing phase of an acknowledgement.
// +kubebuilder:validation:Enum=Processing;Applied;Rejected
type CleanupAcknowledgementPhase string

const (
	// CleanupAcknowledgementProcessing means a controller replica claimed it.
	CleanupAcknowledgementProcessing CleanupAcknowledgementPhase = "Processing"
	// CleanupAcknowledgementApplied means the listed residuals were retired.
	CleanupAcknowledgementApplied CleanupAcknowledgementPhase = "Applied"
	// CleanupAcknowledgementRejected means nothing was retired; see message.
	CleanupAcknowledgementRejected CleanupAcknowledgementPhase = "Rejected"
)

// DebugSessionCleanupAcknowledgementObjectStatus is the durable processing
// outcome of one acknowledgement. It is the processing evidence: a final
// phase is never processed again.
type DebugSessionCleanupAcknowledgementObjectStatus struct {
	// phase is the processing phase.
	// +optional
	Phase CleanupAcknowledgementPhase `json:"phase,omitempty"`
	// claimedAt is when a controller replica claimed the acknowledgement. A
	// stale claim is taken over by another replica.
	// +optional
	ClaimedAt *metav1.Time `json:"claimedAt,omitempty"`
	// processedAt is when the final phase was recorded.
	// +optional
	ProcessedAt *metav1.Time `json:"processedAt,omitempty"`
	// retired lists the identities retired by an applied acknowledgement.
	// +optional
	Retired []string `json:"retired,omitempty"`
	// message explains a rejection.
	// +optional
	Message string `json:"message,omitempty"`
}

// DebugSessionCleanupAcknowledgementList contains a list of acknowledgements.
// +kubebuilder:object:root=true
type DebugSessionCleanupAcknowledgementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DebugSessionCleanupAcknowledgement `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DebugSessionCleanupAcknowledgement{}, &DebugSessionCleanupAcknowledgementList{})
}

// DebugSessionCleanupAcknowledgementStatus records one applied
// DebugSessionCleanupAcknowledgement in the DebugSession status.
type DebugSessionCleanupAcknowledgementStatus struct {
	// name of the processed acknowledgement.
	Name string `json:"name"`
	// uid of the processed acknowledgement; each is processed once.
	UID string `json:"uid"`
	// acknowledgedBy is the user recorded in the acknowledgement.
	AcknowledgedBy string `json:"acknowledgedBy"`
	// reason is the optional reason or ticket reference.
	// +optional
	Reason string `json:"reason,omitempty"`
	// applied is true when every listed identity matched an outstanding
	// residual and was retired.
	Applied bool `json:"applied"`
	// retired lists the identities retired by this acknowledgement.
	// +optional
	Retired []string `json:"retired,omitempty"`
	// message explains a rejected acknowledgement.
	// +optional
	Message string `json:"message,omitempty"`
	// processedAt is when the controller processed the acknowledgement.
	ProcessedAt metav1.Time `json:"processedAt"`
}

// +kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-debugsessioncleanupacknowledgement,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=debugsessioncleanupacknowledgements,verbs=create;update,versions=v1alpha1,name=debugsessioncleanupacknowledgement.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// ValidateCreate requires acknowledgedBy to equal the requesting user.
func (a *DebugSessionCleanupAcknowledgement) ValidateCreate(ctx context.Context, obj *DebugSessionCleanupAcknowledgement) (admission.Warnings, error) {
	path := field.NewPath("spec").Child("acknowledgedBy")
	req, err := admission.RequestFromContext(ctx)
	var errs field.ErrorList
	switch {
	case err != nil || req.UserInfo.Username == "":
		errs = append(errs, field.Forbidden(path, "an authenticated admission request is required"))
	case obj.Spec.AcknowledgedBy != req.UserInfo.Username:
		errs = append(errs, field.Invalid(path, obj.Spec.AcknowledgedBy, fmt.Sprintf("must equal the requesting user %q", req.UserInfo.Username)))
	}
	if len(errs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: GroupVersion.Group, Kind: "DebugSessionCleanupAcknowledgement"}, obj.Name, errs)
}

// ValidateUpdate leaves spec immutability to the CRD schema.
func (a *DebugSessionCleanupAcknowledgement) ValidateUpdate(context.Context, *DebugSessionCleanupAcknowledgement, *DebugSessionCleanupAcknowledgement) (admission.Warnings, error) {
	return nil, nil
}

// ValidateDelete allows deletion; processed outcomes stay in session status.
func (a *DebugSessionCleanupAcknowledgement) ValidateDelete(context.Context, *DebugSessionCleanupAcknowledgement) (admission.Warnings, error) {
	return nil, nil
}

// SetupWebhookWithManager registers the acknowledgement webhook.
func (a *DebugSessionCleanupAcknowledgement) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &DebugSessionCleanupAcknowledgement{}).WithValidator(a).Complete()
}
