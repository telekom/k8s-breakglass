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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

// OIDCConfig holds mandatory OIDC configuration for identity provider
// All IdentityProviders require OIDC for user authentication
type OIDCConfig struct {
	// Authority is the OIDC provider authority endpoint
	// Example: https://auth.example.com
	Authority string `json:"authority"`

	// JWKSEndpoint is the endpoint for fetching JSON Web Key Sets
	// If empty, defaults to Authority/.well-known/openid-configuration
	// +optional
	JWKSEndpoint string `json:"jwksEndpoint,omitempty"`

	// ClientID is the OIDC client ID for user authentication (frontend/UI)
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
	BaseURL string `json:"baseURL"`

	// Realm is the Keycloak realm name
	Realm string `json:"realm"`

	// ClientID is the service account client ID for group/user queries (should have view-users/view-groups only)
	ClientID string `json:"clientID"`

	// ClientSecretRef references a Secret containing the client secret
	ClientSecretRef SecretKeyReference `json:"clientSecretRef"`

	// CacheTTL is the duration to cache user/group memberships (default: 10m)
	// +optional
	CacheTTL string `json:"cacheTTL,omitempty"`

	// RequestTimeout is the timeout for Keycloak API requests (default: 10s)
	// +optional
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

	// Primary indicates if this is the primary identity provider (used by default)
	// Only one IdentityProvider should have primary: true per cluster
	// +optional
	Primary bool `json:"primary,omitempty"`

	// DisplayName is a human-readable name for this provider (shown in UI/logs)
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Disabled can be set to true to temporarily disable this provider without deleting it
	// +optional
	Disabled bool `json:"disabled,omitempty"`
}

// IdentityProviderStatus defines the observed state of an IdentityProvider
type IdentityProviderStatus struct {
	// Phase indicates the current phase: Ready, Validating, Error
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides details about the current phase
	// +optional
	Message string `json:"message,omitempty"`

	// LastValidation is when the provider was last validated
	// +optional
	LastValidation metav1.Time `json:"lastValidation,omitempty"`

	// Connected indicates if the provider is currently reachable
	// +optional
	Connected bool `json:"connected,omitempty"`

	// ConfigHash is a hash of the current configuration for change detection
	// +optional
	ConfigHash string `json:"configHash,omitempty"`

	// Conditions represent the latest available observations of the IdentityProvider's state
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Primary",type=boolean,JSONPath=`.spec.primary`
// +kubebuilder:printcolumn:name="GroupSync",type=string,JSONPath=`.spec.groupSyncProvider`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Connected",type=boolean,JSONPath=`.status.connected`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// IdentityProvider represents a configured identity provider with OIDC authentication and optional group synchronization
// IdentityProvider is cluster-scoped, allowing global identity provider configuration.
// All identity providers use OIDC for user authentication. Group synchronization can be optionally
// configured using providers like Keycloak. Multiple IdentityProviders can be configured, but only
// one should be marked as Primary for use as the default.
type IdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IdentityProviderSpec   `json:"spec,omitempty"`
	Status IdentityProviderStatus `json:"status,omitempty"`
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-identityprovider,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=identityproviders,verbs=create;update,versions=v1alpha1,name=videntityprovider.kb.io,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type
func (idp *IdentityProvider) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	identityProvider, ok := obj.(*IdentityProvider)
	if !ok {
		return nil, fmt.Errorf("expected an IdentityProvider object but got %T", obj)
	}

	var allErrs field.ErrorList

	// Validate mandatory OIDC configuration
	if identityProvider.Spec.OIDC.Authority == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("oidc").Child("authority"), "authority is required"))
	}
	if identityProvider.Spec.OIDC.ClientID == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("oidc").Child("clientID"), "clientID is required"))
	}

	// Validate Keycloak configuration if group sync is enabled
	if identityProvider.Spec.GroupSyncProvider == GroupSyncProviderKeycloak {
		if identityProvider.Spec.Keycloak == nil {
			allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("keycloak"), "keycloak configuration is required when groupSyncProvider is Keycloak"))
		} else {
			if identityProvider.Spec.Keycloak.BaseURL == "" {
				allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("keycloak").Child("baseURL"), "baseURL is required"))
			}
			if identityProvider.Spec.Keycloak.Realm == "" {
				allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("keycloak").Child("realm"), "realm is required"))
			}
			if identityProvider.Spec.Keycloak.ClientID == "" {
				allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("keycloak").Child("clientID"), "clientID is required"))
			}
			if identityProvider.Spec.Keycloak.ClientSecretRef.Name == "" || identityProvider.Spec.Keycloak.ClientSecretRef.Namespace == "" {
				allErrs = append(allErrs, field.Required(field.NewPath("spec").Child("keycloak").Child("clientSecretRef"), "clientSecretRef name and namespace are required"))
			}
		}
	}

	if len(allErrs) == 0 {
		return nil, nil
	}
	return nil, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "IdentityProvider"}, identityProvider.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (idp *IdentityProvider) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	// For updates, perform same validations as create
	return idp.ValidateCreate(ctx, newObj)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type
func (idp *IdentityProvider) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
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
	if idp.Status.Conditions == nil {
		idp.Status.Conditions = []metav1.Condition{}
	}

	// Find and update existing condition, or append new one
	found := false
	for i, c := range idp.Status.Conditions {
		if c.Type == condition.Type {
			idp.Status.Conditions[i] = condition
			found = true
			break
		}
	}

	if !found {
		idp.Status.Conditions = append(idp.Status.Conditions, condition)
	}
}

// GetCondition retrieves a condition by type from the IdentityProvider status
func (idp *IdentityProvider) GetCondition(condType string) *metav1.Condition {
	for i := range idp.Status.Conditions {
		if idp.Status.Conditions[i].Type == condType {
			return &idp.Status.Conditions[i]
		}
	}
	return nil
}

// SetupWebhookWithManager registers webhooks for IdentityProvider
func (idp *IdentityProvider) SetupWebhookWithManager(mgr ctrl.Manager) error {
	webhookClient = mgr.GetClient()
	if c := mgr.GetCache(); c != nil {
		webhookCache = c
	}
	return ctrl.NewWebhookManagedBy(mgr).
		For(idp).
		WithValidator(idp).
		Complete()
}
