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
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// priorityClassName is the name of the PriorityClass for this pod.
	// Use this to control scheduling priority of debug pods.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// runtimeClassName refers to a RuntimeClass for running this pod.
	// Useful for running debug pods with specific container runtimes (e.g., gVisor, Kata).
	// +optional
	RuntimeClassName *string `json:"runtimeClassName,omitempty"`

	// preemptionPolicy controls whether this pod can preempt lower-priority pods.
	// Valid values: "PreemptLowerPriority" (default) or "Never".
	// +optional
	// +kubebuilder:validation:Enum=PreemptLowerPriority;Never
	PreemptionPolicy *corev1.PreemptionPolicy `json:"preemptionPolicy,omitempty"`

	// topologySpreadConstraints describe how debug pods should be spread across topology domains.
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// dnsConfig specifies additional DNS configuration for the pod.
	// +optional
	DNSConfig *corev1.PodDNSConfig `json:"dnsConfig,omitempty"`

	// shareProcessNamespace enables sharing the process namespace between containers.
	// Useful for debugging when you need to see processes in other containers.
	// +optional
	// +kubebuilder:default=false
	ShareProcessNamespace *bool `json:"shareProcessNamespace,omitempty"`

	// hostAliases adds entries to the pod's /etc/hosts file.
	// +optional
	HostAliases []corev1.HostAlias `json:"hostAliases,omitempty"`

	// imagePullSecrets references secrets for pulling container images.
	// +optional
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty"`

	// enableServiceLinks specifies whether to inject service environment variables.
	// Defaults to false for security - debug pods should be isolated.
	// +optional
	// +kubebuilder:default=false
	EnableServiceLinks *bool `json:"enableServiceLinks,omitempty"`

	// schedulerName specifies the scheduler to use for this pod.
	// +optional
	SchedulerName string `json:"schedulerName,omitempty"`

	// overhead represents the resource overhead associated with the pod.
	// Used for RuntimeClass overhead accounting.
	// +optional
	Overhead corev1.ResourceList `json:"overhead,omitempty"`
}

// DebugPodTemplateStatus defines the observed state of DebugPodTemplate.
type DebugPodTemplateStatus struct {
	// conditions represent the latest available observations of the template's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// observedGeneration is the generation last observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// usedBy lists DebugSessionTemplates that reference this pod template.
	// +optional
	UsedBy []string `json:"usedBy,omitempty"`

	// usageCount tracks how many active debug sessions use this template.
	// +optional
	UsageCount int32 `json:"usageCount,omitempty"`

	// lastUsedAt records when this template was last used to create a debug session.
	// +optional
	LastUsedAt *metav1.Time `json:"lastUsedAt,omitempty"`
}

// +kubebuilder:resource:scope=Cluster,shortName=dpt
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Display Name",type=string,JSONPath=".spec.displayName",description="Human-readable name"
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=".spec.description",description="Template description"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Ready status"
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
func (dpt *DebugPodTemplate) ValidateCreate(ctx context.Context, obj *DebugPodTemplate) (admission.Warnings, error) {
	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateDebugPodTemplate(obj)
	if result.IsValid() {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugPodTemplate"}, obj.Name, result.Errors)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (dpt *DebugPodTemplate) ValidateUpdate(ctx context.Context, oldObj, newObj *DebugPodTemplate) (admission.Warnings, error) {
	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateDebugPodTemplate(newObj)
	if result.IsValid() {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "DebugPodTemplate"}, newObj.Name, result.Errors)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (dpt *DebugPodTemplate) ValidateDelete(ctx context.Context, obj *DebugPodTemplate) (admission.Warnings, error) {
	return nil, nil
}

// SetupWebhookWithManager registers webhooks for DebugPodTemplate
func (dpt *DebugPodTemplate) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr, &DebugPodTemplate{}).
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
