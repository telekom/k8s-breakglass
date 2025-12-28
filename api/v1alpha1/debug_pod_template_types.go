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
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// DebugPodTemplateConditionType defines condition types for DebugPodTemplate.
type DebugPodTemplateConditionType string

const (
	// DebugPodTemplateConditionReady indicates the template is ready for use.
	DebugPodTemplateConditionReady DebugPodTemplateConditionType = "Ready"
	// DebugPodTemplateConditionValid indicates the template configuration is valid.
	DebugPodTemplateConditionValid DebugPodTemplateConditionType = "Valid"
)

// DebugPodTemplateSpec defines the desired state of DebugPodTemplate.
// It contains a reusable pod specification for debug sessions.
type DebugPodTemplateSpec struct {
	// displayName is a human-readable name for this template.
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// description provides detailed information about what this template does.
	// +optional
	Description string `json:"description,omitempty"`

	// template defines the pod specification that will be used to create debug pods.
	// This spec is rendered into DaemonSet/Deployment by DebugSessionTemplate.
	// +required
	Template DebugPodSpec `json:"template"`
}

// DebugPodSpec defines the pod specification for debug containers.
// This is a subset of corev1.PodSpec with fields relevant to debugging.
type DebugPodSpec struct {
	// metadata contains labels and annotations for the pod.
	// +optional
	Metadata *DebugPodMetadata `json:"metadata,omitempty"`

	// spec contains the pod specification.
	// +required
	Spec DebugPodSpecInner `json:"spec"`
}

// DebugPodMetadata contains metadata for debug pods.
type DebugPodMetadata struct {
	// labels are key/value pairs attached to the pod.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations are key/value pairs attached to the pod.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// DebugPodSpecInner defines the inner pod specification.
type DebugPodSpecInner struct {
	// securityContext holds pod-level security attributes.
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// containers is the list of containers in the debug pod.
	// +required
	// +kubebuilder:validation:MinItems=1
	Containers []corev1.Container `json:"containers"`

	// initContainers is the list of init containers in the debug pod.
	// +optional
	InitContainers []corev1.Container `json:"initContainers,omitempty"`

	// volumes defines the volumes that can be mounted by containers.
	// +optional
	Volumes []corev1.Volume `json:"volumes,omitempty"`

	// automountServiceAccountToken indicates whether a service account token should be mounted.
	// Defaults to false for security - debug pods should be isolated from cluster.
	// +optional
	// +kubebuilder:default=false
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`

	// tolerations allow the pod to schedule on tainted nodes.
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// affinity specifies scheduling constraints.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// nodeSelector selects nodes for scheduling.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// serviceAccountName is the name of the ServiceAccount to use.
	// Defaults to "default" if not specified.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// hostNetwork indicates whether the pod should use the host's network namespace.
	// +optional
	// +kubebuilder:default=false
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// hostPID indicates whether the pod should use the host's PID namespace.
	// +optional
	// +kubebuilder:default=false
	HostPID bool `json:"hostPID,omitempty"`

	// hostIPC indicates whether the pod should use the host's IPC namespace.
	// +optional
	// +kubebuilder:default=false
	HostIPC bool `json:"hostIPC,omitempty"`

	// dnsPolicy specifies the DNS policy for the pod.
	// +optional
	DNSPolicy corev1.DNSPolicy `json:"dnsPolicy,omitempty"`

	// restartPolicy specifies the restart policy for containers.
	// +optional
	// +kubebuilder:default="Never"
	RestartPolicy corev1.RestartPolicy `json:"restartPolicy,omitempty"`

	// terminationGracePeriodSeconds specifies the duration in seconds for graceful termination.
	// +optional
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
}

// DebugPodTemplateStatus defines the observed state of DebugPodTemplate.
type DebugPodTemplateStatus struct {
	// conditions represent the latest available observations of the template's state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// usedBy lists DebugSessionTemplates that reference this pod template.
	// +optional
	UsedBy []string `json:"usedBy,omitempty"`
}

// +kubebuilder:resource:scope=Cluster,shortName=dpt
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Display Name",type=string,JSONPath=".spec.displayName",description="Human-readable name"
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=".spec.description",description="Template description"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status

// DebugPodTemplate defines a reusable pod specification for debug sessions.
// These templates can be referenced by multiple DebugSessionTemplates.
type DebugPodTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec   DebugPodTemplateSpec   `json:"spec"`
	Status DebugPodTemplateStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-debugpodtemplate,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=debugpodtemplates,verbs=create;update,versions=v1alpha1,name=debugpodtemplate.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// SetCondition updates or adds a condition in the DebugPodTemplate status
func (dpt *DebugPodTemplate) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&dpt.Status.Conditions, condition)
}

// GetCondition retrieves a condition by type from the DebugPodTemplate status
func (dpt *DebugPodTemplate) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(dpt.Status.Conditions, condType)
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (dpt *DebugPodTemplate) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	template, ok := obj.(*DebugPodTemplate)
	if !ok {
		return nil, fmt.Errorf("expected a DebugPodTemplate object but got %T", obj)
	}

	var allErrs field.ErrorList
	allErrs = append(allErrs, validateDebugPodTemplateSpec(template)...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugPodTemplate"}, template.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (dpt *DebugPodTemplate) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	template, ok := newObj.(*DebugPodTemplate)
	if !ok {
		return nil, fmt.Errorf("expected a DebugPodTemplate object but got %T", newObj)
	}

	var allErrs field.ErrorList
	allErrs = append(allErrs, validateDebugPodTemplateSpec(template)...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugPodTemplate"}, template.Name, allErrs)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (dpt *DebugPodTemplate) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// SetupWebhookWithManager registers webhooks for DebugPodTemplate
func (dpt *DebugPodTemplate) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(dpt).
		WithValidator(dpt).
		Complete()
}

func validateDebugPodTemplateSpec(template *DebugPodTemplate) field.ErrorList {
	if template == nil {
		return nil
	}

	specPath := field.NewPath("spec")
	var allErrs field.ErrorList

	// Validate containers are specified
	if len(template.Spec.Template.Spec.Containers) == 0 {
		allErrs = append(allErrs, field.Required(specPath.Child("template").Child("spec").Child("containers"), "at least one container is required"))
	}

	// Validate container names are unique
	containerNames := make(map[string]bool)
	for i, c := range template.Spec.Template.Spec.Containers {
		if c.Name == "" {
			allErrs = append(allErrs, field.Required(specPath.Child("template").Child("spec").Child("containers").Index(i).Child("name"), "container name is required"))
		} else if containerNames[c.Name] {
			allErrs = append(allErrs, field.Duplicate(specPath.Child("template").Child("spec").Child("containers").Index(i).Child("name"), c.Name))
		} else {
			containerNames[c.Name] = true
		}
	}

	return allErrs
}

// +kubebuilder:object:root=true

// DebugPodTemplateList contains a list of DebugPodTemplate.
type DebugPodTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DebugPodTemplate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DebugPodTemplate{}, &DebugPodTemplateList{})
}
