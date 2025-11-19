package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// ClusterConfigConditionType defines condition types for ClusterConfig resources.
type ClusterConfigConditionType string

const (
	// ClusterConfigConditionReady indicates the ClusterConfig is ready for use.
	// Condition fails when kubeconfig is invalid, cluster is unreachable, or other checks fail.
	ClusterConfigConditionReady ClusterConfigConditionType = "Ready"
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

	// identityProviderRefs specifies which IdentityProvider CRs are allowed to authenticate for this cluster.
	// If empty or unset, all enabled IdentityProviders are accepted (backward compatible default).
	// If set, users must authenticate via one of the named providers.
	// Names should match the metadata.name of IdentityProvider resources.
	// +optional
	IdentityProviderRefs []string `json:"identityProviderRefs,omitempty"`

	// blockSelfApproval, if true, prevents users from self-approving their own breakglass sessions for this cluster.
	// +optional
	BlockSelfApproval bool `json:"blockSelfApproval,omitempty"`

	// allowedApproverDomains restricts approvers to users whose email matches one of the listed domains (e.g. ["telekom.de", "t-systems.com"])
	// If set, an approver must have an email address ending with one of these domains.
	// +optional
	AllowedApproverDomains []string `json:"allowedApproverDomains,omitempty"`
}

// SecretKeyReference is a namespaced secret key reference supporting cross-namespace references.
// This allows cluster-scoped resources (like IdentityProvider) to reference Secrets in any namespace.
type SecretKeyReference struct {
	// Name is the name of the secret
	Name string `json:"name"`

	// Namespace is the namespace containing the secret (supports cross-namespace references)
	Namespace string `json:"namespace"`

	// Key is the data key in the secret (defaults to "value" if not specified)
	// +optional
	Key string `json:"key,omitempty"`
}

// ClusterConfigStatus captures readiness of the cluster configuration.
type ClusterConfigStatus struct {
	// ObservedGeneration reflects the generation of the most recently observed ClusterConfig
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions track ClusterConfig state (kubeconfig validation, connection status, etc.)
	// All status information is conveyed through conditions.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ccfg
// +kubebuilder:printcolumn:name="Tenant",type=string,JSONPath=`.spec.tenant`
// +kubebuilder:printcolumn:name="ClusterID",type=string,JSONPath=`.spec.clusterID`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type ClusterConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterConfigSpec   `json:"spec"`
	Status ClusterConfigStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-clusterconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=create;update,versions=v1alpha1,name=clusterconfig.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	clusterConfig, ok := obj.(*ClusterConfig)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterConfig object but got %T", obj)
	}

	var allErrs field.ErrorList
	if clusterConfig.Spec.KubeconfigSecretRef.Name == "" || clusterConfig.Spec.KubeconfigSecretRef.Namespace == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("kubeconfigSecretRef"), "kubeconfigSecretRef name and namespace are required"))
	}
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &ClusterConfigList{}, clusterConfig.Namespace, clusterConfig.Name, field.NewPath("metadata").Child("name"))...)

	// Multi-IDP: Validate IdentityProviderRefs (empty refs is valid - means accept all enabled IDPs)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, clusterConfig.Spec.IdentityProviderRefs, field.NewPath("spec").Child("identityProviderRefs"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "ClusterConfig"}, clusterConfig.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	clusterConfig, ok := newObj.(*ClusterConfig)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterConfig object but got %T", newObj)
	}

	var allErrs field.ErrorList
	// no immutability enforcement for ClusterConfig
	// still ensure the name is unique across the cluster
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &ClusterConfigList{}, clusterConfig.Namespace, clusterConfig.Name, field.NewPath("metadata").Child("name"))...)

	// Multi-IDP: Validate IdentityProviderRefs (empty refs is valid - means accept all enabled IDPs)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, clusterConfig.Spec.IdentityProviderRefs, field.NewPath("spec").Child("identityProviderRefs"))...)

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "ClusterConfig"}, clusterConfig.Name, allErrs)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	// allow deletes
	return nil, nil
}

// SetCondition updates or adds a condition in the ClusterConfig status
func (cc *ClusterConfig) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&cc.Status.Conditions, condition)
}

// GetCondition retrieves a condition from the ClusterConfig status by type
func (cc *ClusterConfig) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(cc.Status.Conditions, condType)
}

// SetupWebhookWithManager registers webhooks for ClusterConfig
func (cc *ClusterConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(cc).
		WithValidator(cc).
		Complete()
}

// +kubebuilder:object:root=true
type ClusterConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterConfig `json:"items"`
}

func init() { SchemeBuilder.Register(&ClusterConfig{}, &ClusterConfigList{}) }
