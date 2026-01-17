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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// MailProviderSpec defines the desired state of MailProvider
type MailProviderSpec struct {
	// DisplayName is a human-readable name for this mail provider
	// +optional
	DisplayName string `json:"displayName,omitempty"`

	// Default indicates this is the default mail provider when no specific provider is selected
	// Only one MailProvider should have Default=true
	// +optional
	Default bool `json:"default,omitempty"`

	// Disabled allows temporarily disabling a mail provider without deleting it
	// When disabled, emails will not be sent through this provider
	// +optional
	Disabled bool `json:"disabled,omitempty"`

	// SMTP contains SMTP server configuration
	SMTP SMTPConfig `json:"smtp"`

	// Sender contains email sender configuration
	Sender SenderConfig `json:"sender"`

	// Retry contains retry and queue configuration
	// +optional
	Retry RetryConfig `json:"retry,omitempty"`
}

// SMTPConfig defines SMTP server connection settings
type SMTPConfig struct {
	// Host is the SMTP server hostname
	// Example: smtp.gmail.com, smtp.example.com
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Host string `json:"host"`

	// Port is the SMTP server port
	// Common values: 587 (STARTTLS), 465 (TLS), 25 (plain)
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int `json:"port"`

	// Username for SMTP authentication
	// +optional
	Username string `json:"username,omitempty"`

	// PasswordRef references a Secret containing the SMTP password
	// +optional
	PasswordRef *SecretKeyReference `json:"passwordRef,omitempty"`

	// InsecureSkipVerify allows skipping TLS certificate verification
	// WARNING: Only use for testing/development!
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	// CertificateAuthority contains a PEM encoded CA certificate for TLS validation
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`

	// DisableTLS disables TLS/STARTTLS encryption for the SMTP connection.
	// Use this when connecting to plain SMTP servers like MailHog that don't support TLS.
	// WARNING: Only use for testing/development environments!
	// +optional
	DisableTLS bool `json:"disableTLS,omitempty"`
}

// SenderConfig defines email sender information
type SenderConfig struct {
	// Address is the email address used in the From header
	// Example: noreply@example.com
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=254
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	Address string `json:"address"`

	// Name is the display name used in the From header
	// Example: "Platform Breakglass", "Das SCHIFF Breakglass"
	// +optional
	// +kubebuilder:validation:MaxLength=100
	Name string `json:"name,omitempty"`
}

// RetryConfig defines retry and queue behavior
type RetryConfig struct {
	// Count is the number of retry attempts after initial send fails
	// Default: 3
	// +optional
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=10
	Count int `json:"count,omitempty"`

	// InitialBackoffMs is the initial backoff duration in milliseconds for exponential backoff
	// Subsequent retries double the backoff time
	// Default: 100ms
	// +optional
	// +kubebuilder:default=100
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=60000
	InitialBackoffMs int `json:"initialBackoffMs,omitempty"`

	// QueueSize is the maximum number of pending emails in the queue
	// Default: 1000
	// +optional
	// +kubebuilder:default=1000
	// +kubebuilder:validation:Minimum=10
	// +kubebuilder:validation:Maximum=10000
	QueueSize int `json:"queueSize,omitempty"`
}

// MailProviderStatus defines the observed state of MailProvider
type MailProviderStatus struct {
	// Conditions represent the latest available observations of the MailProvider's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastHealthCheck is the timestamp of the last successful health check
	// +optional
	LastHealthCheck *metav1.Time `json:"lastHealthCheck,omitempty"`

	// LastSendAttempt is the timestamp of the last email send attempt
	// +optional
	LastSendAttempt *metav1.Time `json:"lastSendAttempt,omitempty"`

	// LastSendError contains the error message from the last failed send attempt
	// +optional
	LastSendError string `json:"lastSendError,omitempty"`
}

// MailProviderConditionType defines the type of condition for MailProvider status
type MailProviderConditionType string

const (
	// MailProviderConditionReady indicates the MailProvider is configured and ready
	MailProviderConditionReady MailProviderConditionType = "Ready"
	// MailProviderConditionHealthy indicates the MailProvider passed health checks
	MailProviderConditionHealthy MailProviderConditionType = "Healthy"
	// MailProviderConditionPasswordLoaded indicates the password was successfully loaded from secret
	MailProviderConditionPasswordLoaded MailProviderConditionType = "PasswordLoaded"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Host",type=string,JSONPath=`.spec.smtp.host`
// +kubebuilder:printcolumn:name="Port",type=integer,JSONPath=`.spec.smtp.port`
// +kubebuilder:printcolumn:name="Default",type=boolean,JSONPath=`.spec.default`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// MailProvider is the Schema for the mailproviders API
type MailProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MailProviderSpec   `json:"spec,omitempty"`
	Status MailProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MailProviderList contains a list of MailProvider
type MailProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MailProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MailProvider{}, &MailProviderList{})
}

// SetupWebhookWithManager registers webhooks for MailProvider
func (mp *MailProvider) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
	return ctrl.NewWebhookManagedBy(mgr).
		For(mp).
		WithValidator(mp).
		Complete()
}

//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-mailprovider,mutating=false,failurePolicy=fail,sideEffects=None,groups=breakglass.t-caas.telekom.com,resources=mailproviders,verbs=create;update,versions=v1alpha1,name=mailprovider.validation.breakglass.t-caas.telekom.com,admissionReviewVersions={v1,v1beta1}

// ValidateCreate implements webhook.CustomValidator
func (mp *MailProvider) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	mailProvider, ok := obj.(*MailProvider)
	if !ok {
		return nil, fmt.Errorf("expected a MailProvider object but got %T", obj)
	}

	// Check for multiple default providers
	if mailProvider.Spec.Default {
		if err := mp.validateDefaultUniqueness(ctx, ""); err != nil {
			return nil, err
		}
	}

	return mailProvider.validate()
}

// ValidateUpdate implements webhook.CustomValidator
func (mp *MailProvider) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	mailProvider, ok := newObj.(*MailProvider)
	if !ok {
		return nil, fmt.Errorf("expected a MailProvider object but got %T", newObj)
	}

	oldMailProvider, ok := oldObj.(*MailProvider)
	if !ok {
		return nil, fmt.Errorf("expected old object to be a MailProvider but got %T", oldObj)
	}

	// Check for multiple default providers (excluding self if updating)
	if mailProvider.Spec.Default && (!oldMailProvider.Spec.Default || mailProvider.Name != oldMailProvider.Name) {
		if err := mp.validateDefaultUniqueness(ctx, mailProvider.Name); err != nil {
			return nil, err
		}
	}

	return mailProvider.validate()
}

// ValidateDelete implements webhook.CustomValidator
func (mp *MailProvider) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

// validate performs validation on MailProvider
func (mp *MailProvider) validate() (admission.Warnings, error) {
	warnings := admission.Warnings{}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateMailProvider(mp)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Additional webhook-specific validations (SMTP auth consistency)
	smtpPath := field.NewPath("spec", "smtp")

	// Validate username/password consistency
	if mp.Spec.SMTP.Username != "" && mp.Spec.SMTP.PasswordRef == nil {
		allErrs = append(allErrs, field.Invalid(smtpPath.Child("passwordRef"), nil, "passwordRef must be specified when username is provided"))
	}
	if mp.Spec.SMTP.PasswordRef != nil && mp.Spec.SMTP.Username == "" {
		allErrs = append(allErrs, field.Invalid(smtpPath.Child("username"), "", "username must be specified when passwordRef is provided"))
	}

	// Validate passwordRef structure if present
	if mp.Spec.SMTP.PasswordRef != nil {
		if mp.Spec.SMTP.PasswordRef.Name == "" {
			allErrs = append(allErrs, field.Required(smtpPath.Child("passwordRef", "name"), "secret name is required"))
		}
		if mp.Spec.SMTP.PasswordRef.Namespace == "" {
			allErrs = append(allErrs, field.Required(smtpPath.Child("passwordRef", "namespace"), "secret namespace is required"))
		}
		if mp.Spec.SMTP.PasswordRef.Key == "" {
			allErrs = append(allErrs, field.Required(smtpPath.Child("passwordRef", "key"), "secret key is required"))
		}
	}

	// Warn if insecureSkipVerify is enabled
	if mp.Spec.SMTP.InsecureSkipVerify {
		warnings = append(warnings, "insecureSkipVerify is enabled - TLS certificate validation is disabled. This should only be used for testing!")
	}

	// Warn if authentication is not configured
	if mp.Spec.SMTP.Username == "" && mp.Spec.SMTP.PasswordRef == nil {
		warnings = append(warnings, "No SMTP authentication configured - ensure your SMTP server allows unauthenticated connections")
	}

	if len(allErrs) > 0 {
		return warnings, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "MailProvider"},
			mp.Name,
			allErrs,
		)
	}

	return warnings, nil
}

// validateDefaultUniqueness ensures only one MailProvider is marked as default
func (mp *MailProvider) validateDefaultUniqueness(ctx context.Context, excludeName string) error {
	reader := getWebhookReader()
	if reader == nil {
		// No reader available, skip validation (will be caught in reconciler)
		return nil
	}

	var providerList MailProviderList
	if err := reader.List(ctx, &providerList); err != nil {
		// Unable to list providers, skip validation
		return nil
	}

	var defaultProviders []string
	for _, provider := range providerList.Items {
		if provider.Spec.Default && provider.Name != excludeName {
			defaultProviders = append(defaultProviders, provider.Name)
		}
	}

	if len(defaultProviders) > 0 {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "MailProvider"},
			mp.Name,
			field.ErrorList{
				field.Forbidden(
					field.NewPath("spec", "default"),
					fmt.Sprintf("only one MailProvider can be marked as default, but the following providers are already marked as default: %v", defaultProviders),
				),
			},
		)
	}

	return nil
}
