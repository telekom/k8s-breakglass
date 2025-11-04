// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterConfigSpec defines metadata and secret reference for a managed tenant cluster.
// This enables the hub (breakglass) instance to perform authorization checks (SAR) on the target cluster.
type ClusterConfigSpec struct {
	// clusterID is the canonical identifier of the cluster. Defaults to metadata.name if empty.
	// +optional
	ClusterID string `json:"clusterID,omitempty"`

	// tenant override; if omitted tenant can be parsed from the clusterID.
	// +optional
	Tenant string `json:"tenant,omitempty"`

	// environment (e.g. dev, staging, prod) override.
	// +optional
	Environment string `json:"environment,omitempty"`

	// site override.
	// +optional
	Site string `json:"site,omitempty"`

	// location / region override.
	// +optional
	Location string `json:"location,omitempty"`

	// kubeconfigSecretRef references a secret containing an admin-level kubeconfig for the target cluster.
	// The referenced Secret MUST exist in the specified namespace and contain the key (default: kubeconfig).
	KubeconfigSecretRef SecretKeyReference `json:"kubeconfigSecretRef"`

	// qps configures the client QPS against the target cluster.
	// +optional
	QPS *int32 `json:"qps,omitempty"`

	// burst configures the client burst against the target cluster.
	// +optional
	Burst *int32 `json:"burst,omitempty"`
	// blockSelfApproval, if true, prevents users from self-approving their own breakglass sessions for this cluster.
	// +optional
	BlockSelfApproval bool `json:"blockSelfApproval,omitempty"`

	// allowedApproverDomains restricts approvers to users whose email matches one of the listed domains (e.g. ["telekom.de", "t-systems.com"])
	// If set, an approver must have an email address ending with one of these domains.
	// +optional
	AllowedApproverDomains []string `json:"allowedApproverDomains,omitempty"`
}

// SecretKeyReference is a namespaced secret key reference.
type SecretKeyReference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// +optional
	Key string `json:"key,omitempty"`
}

// ClusterConfigStatus captures readiness of the cluster configuration.
type ClusterConfigStatus struct {
	// phase indicates readiness.
	// +optional
	Phase string `json:"phase,omitempty"`
	// message provides details in case of failure.
	// +optional
	Message string `json:"message,omitempty"`
	// lastCheckTime is when connectivity / secret was last verified.
	// +optional
	LastCheckTime metav1.Time `json:"lastCheckTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ccfg
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenant`
// +kubebuilder:printcolumn:name="ClusterID",type=string,JSONPath=`.spec.clusterID`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
type ClusterConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterConfigSpec   `json:"spec"`
	Status ClusterConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-clusterconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=create;update,versions=v1alpha1,name=vclusterconfig.kb.io,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateCreate() error {
	var allErrs field.ErrorList
	if cc.Spec.KubeconfigSecretRef.Name == "" || cc.Spec.KubeconfigSecretRef.Namespace == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("kubeconfigSecretRef"), "kubeconfigSecretRef name and namespace are required"))
	}
	// global name uniqueness across namespaces - prefer cache-backed listing
	if webhookCache != nil {
		var list ClusterConfigList
		if err := webhookCache.List(context.Background(), &list); err == nil {
			for _, item := range list.Items {
				if item.Name == cc.Name && item.Namespace != cc.Namespace {
					msg := fmt.Sprintf("name must be unique cluster-wide; conflicting namespace=%s", item.Namespace)
					allErrs = append(allErrs, field.Duplicate(field.NewPath("metadata").Child("name"), msg))
					break
				}
			}
		}
	} else if webhookClient != nil {
		var list ClusterConfigList
		if err := webhookClient.List(context.Background(), &list, &client.ListOptions{}); err == nil {
			for _, item := range list.Items {
				if item.Name == cc.Name && item.Namespace != cc.Namespace {
					msg := fmt.Sprintf("name must be unique cluster-wide; conflicting namespace=%s", item.Namespace)
					allErrs = append(allErrs, field.Duplicate(field.NewPath("metadata").Child("name"), msg))
					break
				}
			}
		}
	}
	if len(allErrs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "ClusterConfig"}, cc.Name, allErrs)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateUpdate(old runtime.Object) error {
	var allErrs field.ErrorList
	// no immutability enforcement for ClusterConfig
	// still ensure the name is unique across the cluster
	if webhookCache != nil {
		var list ClusterConfigList
		if err := webhookCache.List(context.Background(), &list); err == nil {
			for _, item := range list.Items {
				if item.Name == cc.Name && item.Namespace != cc.Namespace {
					msg := fmt.Sprintf("name must be unique cluster-wide; conflicting namespace=%s", item.Namespace)
					allErrs = append(allErrs, field.Duplicate(field.NewPath("metadata").Child("name"), msg))
					break
				}
			}
		}
	} else if webhookClient != nil {
		var list ClusterConfigList
		if err := webhookClient.List(context.Background(), &list, &client.ListOptions{}); err == nil {
			for _, item := range list.Items {
				if item.Name == cc.Name && item.Namespace != cc.Namespace {
					msg := fmt.Sprintf("name must be unique cluster-wide; conflicting namespace=%s", item.Namespace)
					allErrs = append(allErrs, field.Duplicate(field.NewPath("metadata").Child("name"), msg))
					break
				}
			}
		}
	}
	if len(allErrs) == 0 {
		return nil
	}
	return apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "ClusterConfig"}, cc.Name, allErrs)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateDelete() error {
	// allow deletes
	return nil
}

// SetupWebhookWithManager registers webhooks for ClusterConfig
func (cc *ClusterConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(cc).
		Complete()
}

// +kubebuilder:object:root=true
type ClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterConfig `json:"items"`
}

func init() { SchemeBuilder.Register(&ClusterConfig{}, &ClusterConfigList{}) }
