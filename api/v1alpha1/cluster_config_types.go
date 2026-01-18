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

// ClusterConfigConditionReason provides machine-readable reasons for ClusterConfig conditions.
type ClusterConfigConditionReason string

const (
	// Kubeconfig auth reasons
	ClusterConfigReasonKubeconfigValidated ClusterConfigConditionReason = "KubeconfigValidated"
	ClusterConfigReasonSecretMissing       ClusterConfigConditionReason = "SecretMissing"
	ClusterConfigReasonSecretKeyMissing    ClusterConfigConditionReason = "SecretKeyMissing"
	ClusterConfigReasonKubeconfigInvalid   ClusterConfigConditionReason = "KubeconfigParseFailed"

	// OIDC auth reasons
	ClusterConfigReasonOIDCValidated       ClusterConfigConditionReason = "OIDCValidated"
	ClusterConfigReasonOIDCConfigMissing   ClusterConfigConditionReason = "OIDCConfigMissing"
	ClusterConfigReasonOIDCDiscoveryFailed ClusterConfigConditionReason = "OIDCDiscoveryFailed"
	ClusterConfigReasonOIDCTokenFailed     ClusterConfigConditionReason = "OIDCTokenFetchFailed"
	ClusterConfigReasonOIDCRefreshFailed   ClusterConfigConditionReason = "OIDCRefreshFailed"
	ClusterConfigReasonOIDCCAMissing       ClusterConfigConditionReason = "OIDCCASecretMissing"

	// Common reasons
	ClusterConfigReasonClusterUnreachable ClusterConfigConditionReason = "ClusterUnreachable"
	ClusterConfigReasonTOFUFailed         ClusterConfigConditionReason = "TOFUFailed"
	ClusterConfigReasonValidationFailed   ClusterConfigConditionReason = "ValidationFailed"
)

// UserIdentifierClaimType specifies which OIDC claim to use for identifying users.
// This must match the cluster's apiserver OIDC configuration (claimMappings.username.claim).
// +kubebuilder:validation:Enum=email;preferred_username;sub
type UserIdentifierClaimType string

const (
	// UserIdentifierClaimEmail uses the email claim (recommended for production).
	// Most human-readable and typically unique across identity providers.
	UserIdentifierClaimEmail UserIdentifierClaimType = "email"
	// UserIdentifierClaimPreferredUsername uses the preferred_username claim.
	// Shorter but may not be unique across identity providers.
	UserIdentifierClaimPreferredUsername UserIdentifierClaimType = "preferred_username"
	// UserIdentifierClaimSub uses the sub (subject) claim.
	// Guaranteed unique within an IDP but not human-readable.
	UserIdentifierClaimSub UserIdentifierClaimType = "sub"
)

// ClusterAuthType specifies the authentication method for connecting to the target cluster.
// +kubebuilder:validation:Enum=Kubeconfig;OIDC
type ClusterAuthType string

const (
	// ClusterAuthTypeKubeconfig uses a kubeconfig file stored in a secret.
	ClusterAuthTypeKubeconfig ClusterAuthType = "Kubeconfig"
	// ClusterAuthTypeOIDC uses OIDC tokens for authentication (e.g., Keycloak, AWS IAM).
	ClusterAuthTypeOIDC ClusterAuthType = "OIDC"
)

// OIDCAuthConfig configures OIDC-based authentication for the target cluster.
// Supports client credentials flow and token exchange for obtaining cluster access tokens.
type OIDCAuthConfig struct {
	// ========================================
	// OIDC Provider Configuration
	// ========================================

	// issuerURL is the OIDC issuer URL (e.g., https://keycloak.example.com/realms/myrealm).
	// Must match the issuer configured on the target cluster's API server.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://.+`
	IssuerURL string `json:"issuerURL"`

	// clientID is the OIDC client ID for authenticating the breakglass controller.
	// +kubebuilder:validation:MinLength=1
	ClientID string `json:"clientID"`

	// clientSecretRef references a secret containing the OIDC client secret.
	// Required for client credentials flow.
	// +optional
	ClientSecretRef *SecretKeyReference `json:"clientSecretRef,omitempty"`

	// audience specifies the intended audience for the token (typically the cluster's API server).
	// If empty, defaults to the target server URL.
	// +optional
	Audience string `json:"audience,omitempty"`

	// scopes specifies additional OIDC scopes to request.
	// Default scopes (openid, email, groups) are always included.
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// certificateAuthority contains a PEM-encoded CA certificate for validating the OIDC issuer's TLS cert.
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`

	// ========================================
	// Target Cluster Configuration
	// ========================================

	// server is the URL of the target cluster's Kubernetes API server.
	// Required when using OIDC auth to know where to send authenticated requests.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://.+`
	Server string `json:"server"`

	// caSecretRef references a secret containing the CA certificate for the target cluster.
	// The CA is used to verify the target server's TLS certificate.
	// +optional
	CASecretRef *SecretKeyReference `json:"caSecretRef,omitempty"`

	// insecureSkipTLSVerify skips TLS verification for the target cluster (NOT recommended for production).
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// ========================================
	// Token Exchange Configuration (Optional)
	// ========================================

	// tokenExchange enables token exchange flow instead of client credentials.
	// When enabled, the controller exchanges the user's token for a cluster-scoped token.
	// +optional
	TokenExchange *TokenExchangeConfig `json:"tokenExchange,omitempty"`
}

// TokenExchangeConfig configures OAuth 2.0 token exchange (RFC 8693).
// Token exchange allows the controller to exchange a subject token (stored in a secret)
// for a cluster-scoped access token. This is useful for scenarios where:
// - A service account token needs to be exchanged for a cluster-specific token
// - Cross-realm authentication is required
// - The OIDC provider supports token exchange for delegation
type TokenExchangeConfig struct {
	// enabled activates token exchange flow.
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// subjectTokenSecretRef references a secret containing the subject token to exchange.
	// This is required when enabled=true. The controller reads this token and exchanges
	// it for a cluster-scoped token using RFC 8693 token exchange.
	// +optional
	SubjectTokenSecretRef *SecretKeyReference `json:"subjectTokenSecretRef,omitempty"`

	// subjectTokenType specifies the type of the subject token being exchanged.
	// Default: urn:ietf:params:oauth:token-type:access_token
	// +optional
	SubjectTokenType string `json:"subjectTokenType,omitempty"`

	// requestedTokenType specifies the type of token to request.
	// Default: urn:ietf:params:oauth:token-type:access_token
	// +optional
	RequestedTokenType string `json:"requestedTokenType,omitempty"`

	// resource specifies the target resource for the exchanged token.
	// This typically identifies the target API server or service.
	// +optional
	Resource string `json:"resource,omitempty"`

	// actorTokenSecretRef optionally references a secret containing an actor token.
	// This is used in delegation scenarios where the actor (controller) is acting
	// on behalf of the subject (user/service).
	// +optional
	ActorTokenSecretRef *SecretKeyReference `json:"actorTokenSecretRef,omitempty"`

	// actorTokenType specifies the type of the actor token.
	// Default: urn:ietf:params:oauth:token-type:access_token
	// +optional
	ActorTokenType string `json:"actorTokenType,omitempty"`
}

// OIDCFromIdentityProviderConfig allows ClusterConfig to inherit OIDC settings from an IdentityProvider.
// This reduces duplication when the same OIDC provider is used for both user authentication
// and cluster authentication.
type OIDCFromIdentityProviderConfig struct {
	// ========================================
	// IdentityProvider Reference
	// ========================================

	// name is the name of the IdentityProvider resource to inherit OIDC settings from.
	// The IdentityProvider must exist and be enabled.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// clientID overrides the client ID from the IdentityProvider.
	// Use this when the controller needs a different client (service account) than the UI.
	// If empty, uses the IdentityProvider's clientID.
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// clientSecretRef references a secret containing the client secret for the controller.
	// Required for client credentials flow when using a service account client.
	// +optional
	ClientSecretRef *SecretKeyReference `json:"clientSecretRef,omitempty"`

	// ========================================
	// Target Cluster Configuration
	// ========================================

	// server is the URL of the target cluster's Kubernetes API server.
	// Required - this is cluster-specific and cannot be inherited from IdentityProvider.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://.+`
	Server string `json:"server"`

	// caSecretRef references a secret containing the CA certificate for the target cluster.
	// +optional
	CASecretRef *SecretKeyReference `json:"caSecretRef,omitempty"`

	// insecureSkipTLSVerify skips TLS verification for the target cluster (NOT recommended for production).
	// +optional
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`
}

// ClusterConfigSpec defines metadata and secret reference for a managed tenant cluster.
// This enables the hub (breakglass) instance to perform authorization checks (SAR) on the target cluster.
type ClusterConfigSpec struct {
	// clusterID is the canonical identifier of the cluster. Defaults to metadata.name if empty.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	ClusterID string `json:"clusterID,omitempty"`

	// tenant override; if omitted tenant can be parsed from the clusterID.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Tenant string `json:"tenant,omitempty"`

	// environment (e.g. dev, staging, prod) override.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Environment string `json:"environment,omitempty"`

	// site override.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Site string `json:"site,omitempty"`

	// location / region override.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Location string `json:"location,omitempty"`

	// authType specifies the authentication method for connecting to the target cluster.
	// Defaults to "Kubeconfig" if kubeconfigSecretRef is specified, "OIDC" if oidcAuth is specified.
	// +optional
	// +kubebuilder:validation:Enum=Kubeconfig;OIDC
	// +kubebuilder:default=Kubeconfig
	AuthType ClusterAuthType `json:"authType,omitempty"`

	// kubeconfigSecretRef references a secret containing an admin-level kubeconfig for the target cluster.
	// Required when authType is "Kubeconfig". The referenced Secret MUST exist in the specified namespace and contain the key (default: "value", compatible with cluster-api).
	// +optional
	KubeconfigSecretRef *SecretKeyReference `json:"kubeconfigSecretRef,omitempty"`

	// oidcAuth configures OIDC-based authentication for the target cluster.
	// Required when authType is "OIDC" (unless oidcFromIdentityProvider is set).
	// Supports client credentials and token exchange flows.
	// +optional
	OIDCAuth *OIDCAuthConfig `json:"oidcAuth,omitempty"`

	// oidcFromIdentityProvider references an IdentityProvider to inherit OIDC configuration from.
	// When set, the cluster uses the referenced IdentityProvider's OIDC issuer URL and settings.
	// You must still provide clusterAPIServer and optionally clientSecretRef for controller authentication.
	// This is useful when the same OIDC provider is used for both user auth and cluster auth.
	// Mutually exclusive with oidcAuth.issuerURL - if both are set, oidcAuth.issuerURL takes precedence.
	// +optional
	OIDCFromIdentityProvider *OIDCFromIdentityProviderConfig `json:"oidcFromIdentityProvider,omitempty"`

	// qps configures the client QPS against the target cluster.
	// +optional
	// +kubebuilder:validation:Minimum=1
	QPS *int32 `json:"qps,omitempty"`

	// burst configures the client burst against the target cluster.
	// +optional
	// +kubebuilder:validation:Minimum=1
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

	// mailProvider specifies which MailProvider to use for email notifications for this cluster.
	// If empty, falls back to the default MailProvider.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	MailProvider string `json:"mailProvider,omitempty"`

	// userIdentifierClaim specifies which OIDC claim is used to identify users on this cluster.
	// This MUST match the `claimMappings.username.claim` configured on the target cluster's
	// Kubernetes API server OIDC configuration.
	// Common values: "email" (recommended), "preferred_username", "sub"
	// If not set, falls back to global config kubernetes.userIdentifierClaim.
	// +optional
	// +kubebuilder:validation:Enum=email;preferred_username;sub
	UserIdentifierClaim UserIdentifierClaimType `json:"userIdentifierClaim,omitempty"`
}

// SecretKeyReference is a namespaced secret key reference supporting cross-namespace references.
// This allows cluster-scoped resources (like IdentityProvider) to reference Secrets in any namespace.
type SecretKeyReference struct {
	// Name is the name of the secret
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace is the namespace containing the secret (supports cross-namespace references)
	// +kubebuilder:validation:MinLength=1
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

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateClusterConfig(clusterConfig)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Additional webhook-only validations (require k8s client)
	specPath := field.NewPath("spec")

	// Validate auth configuration - either kubeconfigSecretRef OR oidcAuth is required
	allErrs = append(allErrs, validateClusterAuthConfig(clusterConfig.Spec, specPath)...)
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &ClusterConfigList{}, clusterConfig.Namespace, clusterConfig.Name, field.NewPath("metadata").Child("name"))...)

	// Multi-IDP: Validate IdentityProviderRefs existence (requires k8s client)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, clusterConfig.Spec.IdentityProviderRefs, specPath.Child("identityProviderRefs"))...)

	// Validate mail provider reference exists (requires k8s client)
	allErrs = append(allErrs, validateMailProviderReference(ctx, clusterConfig.Spec.MailProvider, specPath.Child("mailProvider"))...)

	// Collect warnings for insecure settings
	var warnings admission.Warnings
	if clusterConfig.Spec.OIDCAuth != nil && clusterConfig.Spec.OIDCAuth.InsecureSkipTLSVerify {
		warnings = append(warnings, "OIDCAuth insecureSkipTLSVerify is enabled - TLS certificate validation is disabled. This should only be used for testing and MUST NOT be used in production!")
	}
	if clusterConfig.Spec.OIDCFromIdentityProvider != nil && clusterConfig.Spec.OIDCFromIdentityProvider.InsecureSkipTLSVerify {
		warnings = append(warnings, "OIDCFromIdentityProvider insecureSkipTLSVerify is enabled - TLS certificate validation is disabled. This should only be used for testing and MUST NOT be used in production!")
	}

	if len(allErrs) == 0 {
		return warnings, nil
	}
	return warnings, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "ClusterConfig"}, clusterConfig.Name, allErrs)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type
func (cc *ClusterConfig) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	clusterConfig, ok := newObj.(*ClusterConfig)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterConfig object but got %T", newObj)
	}

	// Use shared validation function for consistent validation between webhooks and reconcilers
	result := ValidateClusterConfig(clusterConfig)
	var allErrs field.ErrorList
	allErrs = append(allErrs, result.Errors...)

	// Additional webhook-only validations (require k8s client)
	specPath := field.NewPath("spec")

	// Validate auth configuration - either kubeconfigSecretRef OR oidcAuth is required
	allErrs = append(allErrs, validateClusterAuthConfig(clusterConfig.Spec, specPath)...)

	// no immutability enforcement for ClusterConfig
	// still ensure the name is unique across the cluster
	allErrs = append(allErrs, ensureClusterWideUniqueName(ctx, &ClusterConfigList{}, clusterConfig.Namespace, clusterConfig.Name, field.NewPath("metadata").Child("name"))...)

	// Multi-IDP: Validate IdentityProviderRefs existence (requires k8s client)
	allErrs = append(allErrs, validateIdentityProviderRefs(ctx, clusterConfig.Spec.IdentityProviderRefs, specPath.Child("identityProviderRefs"))...)

	// Validate mail provider reference exists (requires k8s client)
	allErrs = append(allErrs, validateMailProviderReference(ctx, clusterConfig.Spec.MailProvider, specPath.Child("mailProvider"))...)

	// Collect warnings for insecure settings
	var warnings admission.Warnings
	if clusterConfig.Spec.OIDCAuth != nil && clusterConfig.Spec.OIDCAuth.InsecureSkipTLSVerify {
		warnings = append(warnings, "OIDCAuth insecureSkipTLSVerify is enabled - TLS certificate validation is disabled. This should only be used for testing and MUST NOT be used in production!")
	}
	if clusterConfig.Spec.OIDCFromIdentityProvider != nil && clusterConfig.Spec.OIDCFromIdentityProvider.InsecureSkipTLSVerify {
		warnings = append(warnings, "OIDCFromIdentityProvider insecureSkipTLSVerify is enabled - TLS certificate validation is disabled. This should only be used for testing and MUST NOT be used in production!")
	}

	if len(allErrs) == 0 {
		return warnings, nil
	}
	return warnings, apierrors.NewInvalid(schema.GroupKind{Group: "breakglass.t-caas.telekom.com", Kind: "ClusterConfig"}, clusterConfig.Name, allErrs)
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

// GetUserIdentifierClaim returns the user identifier claim configured for this cluster.
// Returns empty string if not configured - callers should use global config as fallback.
func (cc *ClusterConfig) GetUserIdentifierClaim() UserIdentifierClaimType {
	return cc.Spec.UserIdentifierClaim
}

// SetupWebhookWithManager registers webhooks for ClusterConfig
func (cc *ClusterConfig) SetupWebhookWithManager(mgr ctrl.Manager) error {
	InitWebhookClient(mgr.GetClient(), mgr.GetCache())
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
