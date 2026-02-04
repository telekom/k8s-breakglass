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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// GroupSyncProvider defines which provider to use for group synchronization
// +kubebuilder:validation:Enum=Keycloak
type GroupSyncProvider string

const (
	// GroupSyncProviderKeycloak uses Keycloak for group/user synchronization
	GroupSyncProviderKeycloak GroupSyncProvider = "Keycloak"
)

// IdentityProviderConditionType defines the type of condition for IdentityProvider status
type IdentityProviderConditionType string

const (
	// IdentityProviderConditionReady indicates the IdentityProvider configuration is valid and ready
	IdentityProviderConditionReady IdentityProviderConditionType = "Ready"
	// IdentityProviderConditionConversionFailed indicates the IdentityProvider configuration failed to convert
	IdentityProviderConditionConversionFailed IdentityProviderConditionType = "ConversionFailed"
	// IdentityProviderConditionValidationFailed indicates the IdentityProvider configuration failed validation
	IdentityProviderConditionValidationFailed IdentityProviderConditionType = "ValidationFailed"
	// IdentityProviderConditionGroupSyncHealthy indicates the GroupSync provider is healthy and reachable
	IdentityProviderConditionGroupSyncHealthy IdentityProviderConditionType = "GroupSyncHealthy"
	// IdentityProviderConditionCacheUpdated indicates the provider cache has been successfully updated
	IdentityProviderConditionCacheUpdated IdentityProviderConditionType = "CacheUpdated"
)

// OIDCConfig holds mandatory OIDC configuration for identity provider
// All IdentityProviders require OIDC for user authentication
type OIDCConfig struct {
	// Authority is the OIDC provider authority endpoint
	// Example: https://auth.example.com
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^https://.+`
	Authority string `json:"authority"`

	// JWKSEndpoint is the endpoint for fetching JSON Web Key Sets
	// If empty, defaults to Authority/.well-known/openid-configuration
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^https://.+`
	JWKSEndpoint string `json:"jwksEndpoint,omitempty"`

	// ClientID is the OIDC client ID for user authentication (frontend/UI)
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^\S+$`
	ClientID string `json:"clientID"`

	// InsecureSkipVerify allows skipping TLS verification (NOT for production!)
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// CertificateAuthority contains a PEM encoded CA certificate for TLS validation
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`
}

// KeycloakGroupSync holds Keycloak-specific group synchronization configuration
type KeycloakGroupSync struct {
	// BaseURL is the Keycloak server URL
	// Example: https://keycloak.example.com
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^https://.+`
	BaseURL string `json:"baseURL"`

	// Realm is the Keycloak realm name
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Realm string `json:"realm"`

	// ClientID is the service account client ID for group/user queries (should have view-users/view-groups only)
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^\S+$`
	ClientID string `json:"clientID"`

	// ClientSecretRef references a Secret containing the client secret
	ClientSecretRef SecretKeyReference `json:"clientSecretRef"`

	// CacheTTL is the duration to cache user/group memberships (default: 10m)
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9]+(ns|us|µs|ms|s|m|h))+$`
	CacheTTL string `json:"cacheTTL,omitempty"`

	// RequestTimeout is the timeout for Keycloak API requests (default: 10s)
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-9]+(ns|us|µs|ms|s|m|h))+$`
	RequestTimeout string `json:"requestTimeout,omitempty"`

	// InsecureSkipVerify allows skipping TLS verification (NOT for production!)
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// CertificateAuthority contains a PEM encoded CA certificate for TLS validation
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`
}

// IdentityProviderSpec defines the desired state of an IdentityProvider
type IdentityProviderSpec struct {
	// OIDC holds mandatory OIDC configuration for user authentication
	// This is the base authentication mechanism for all identity providers
	OIDC OIDCConfig `json:"oidc"`

	// GroupSyncProvider specifies which provider to use for group synchronization (optional)
	// If not set, group synchronization is disabled
	// +optional
	GroupSyncProvider GroupSyncProvider `json:"groupSyncProvider,omitempty"`

	// Keycloak holds Keycloak-specific configuration for group synchronization
	// Required when groupSyncProvider is "Keycloak"
	// +optional
	Keycloak *KeycloakGroupSync `json:"keycloak,omitempty"`

	// Issuer is the OIDC issuer URL, which must match the 'iss' claim in JWT tokens
	// This uniquely identifies the identity provider and is used to determine which provider
	// authenticated a user based on their JWT token.
	// Example: https://auth.example.com
	// +optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^https://.+`
	Issuer string `json:"issuer,omitempty"`

	// Primary indicates if this is the primary identity provider (used by default)
	// Deprecated: Primary is kept for backward compatibility. In multi-IDP mode, use ClusterConfig.IdentityProviderRefs instead.
	// +optional
	Primary bool `json:"primary,omitempty"`

	// DisplayName is a human-readable name for this provider (shown in UI/logs)
	// +optional
	// +kubebuilder:validation:MaxLength=100
	DisplayName string `json:"displayName,omitempty"`

	// Disabled can be set to true to temporarily disable this provider without deleting it
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// IdentityProviderStatus defines the observed state of an IdentityProvider
type IdentityProviderStatus struct {
	// ObservedGeneration reflects the generation of the most recently observed IdentityProvider
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions represent the latest available observations of the IdentityProvider's state.
	// All status information is conveyed through conditions:
	// - Ready: Configuration is valid and provider is operational
	// - ConversionFailed: Configuration conversion failed
	// - ValidationFailed: Configuration validation failed
	// - GroupSyncHealthy: Group sync provider is healthy and reachable
	// - CacheUpdated: Provider cache has been successfully updated
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuer`
// +kubebuilder:printcolumn:name="GroupSync",type=string,JSONPath=`.spec.groupSyncProvider`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// IdentityProvider represents a configured identity provider with OIDC authentication and optional group synchronization
// IdentityProvider is cluster-scoped, allowing global identity provider configuration.
// All identity providers use OIDC for user authentication. Group synchronization can be optionally
// configured using providers like Keycloak. Multiple IdentityProviders can be configured per cluster.
// The Issuer field must be set to the OIDC issuer URL (matching the 'iss' claim in JWT tokens) to enable
// multi-IDP support. ClusterConfig and BreakglassEscalation can restrict access to specific IDPs by name.
type IdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IdentityProviderSpec   `json:"spec,omitempty"`
	Status IdentityProviderStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-identityprovider,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=identityproviders,verbs=create;update,versions=v1alpha1,name=identityprovider.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (idp *IdentityProvider) ValidateCreate(ctx context.Context, obj *IdentityProvider) (admission.Warnings, error) {
	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateIdentityProvider(obj)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Multi-IDP: Validate Issuer field for multi-IDP mode (must be unique - requires k8s client)
	allErrs = append(allErrs, ensureClusterWideUniqueIssuer(ctx, obj.Spec.Issuer, obj.Name, field.NewPath("spec").Child("issuer"))...)

	// Collect warnings for insecure settings
	var warnings admission.Warnings
	if obj.Spec.OIDC.InsecureSkipVerify {
		warnings = append(warnings, "OIDC insecureSkipVerify is enabled - TLS certificate validation is disabled. This should only be used for testing and MUST NOT be used in production!")
	}
	if obj.Spec.Keycloak != nil && obj.Spec.Keycloak.InsecureSkipVerify {
		warnings = append(warnings, "Keycloak insecureSkipVerify is enabled - TLS certificate validation is disabled. This should only be used for testing and MUST NOT be used in production!")
	}

	if len(allErrs) == 0 {
		return warnings, nil
	}
	return warnings, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "IdentityProvider"}, obj.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (idp *IdentityProvider) ValidateUpdate(ctx context.Context, oldObj, newObj *IdentityProvider) (admission.Warnings, error) {
	// For updates, perform same validations as create
	return idp.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (idp *IdentityProvider) ValidateDelete(ctx context.Context, obj *IdentityProvider) (admission.Warnings, error) {
	// allow deletes
	return nil, nil
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// IdentityProviderList contains a list of IdentityProvider resources
type IdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IdentityProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IdentityProvider{}, &IdentityProviderList{})
}

// SetCondition adds or updates a condition on the IdentityProvider status
func (idp *IdentityProvider) SetCondition(condition metav1.Condition) {
	apimeta.SetStatusCondition(&idp.Status.Conditions, condition)
}

// GetCondition retrieves a condition by type from the IdentityProvider status
func (idp *IdentityProvider) GetCondition(condType string) *metav1.Condition {
	return apimeta.FindStatusCondition(idp.Status.Conditions, condType)
}

// SetupWebhookWithManager registers webhooks for IdentityProvider
func (idp *IdentityProvider) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr, &IdentityProvider{}).
		WithValidator(idp).
		Complete()
}
