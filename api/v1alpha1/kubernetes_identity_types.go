// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

// KubernetesIdentityConfig contains the structured JWT identity mapping
// understood by kube-apiserver's structured authentication configuration.
// The types are intentionally the upstream API types so new Kubernetes OIDC
// capabilities can be adopted without maintaining a second CEL model here.
type KubernetesIdentityConfig struct {
	// claimMappings maps token claims to Kubernetes user attributes.
	// +kubebuilder:validation:Required
	ClaimMappings apiserverv1.ClaimMappings `json:"claimMappings"`

	// claimValidationRules validate claims before the identity is constructed.
	// +optional
	ClaimValidationRules []apiserverv1.ClaimValidationRule `json:"claimValidationRules,omitempty"`

	// userValidationRules validate the final Kubernetes user info.
	// +optional
	UserValidationRules []apiserverv1.UserValidationRule `json:"userValidationRules,omitempty"`
}

// ToJWTAuthenticator converts the Kubernetes API representation to the
// internal apiserver representation. Issuer and audiences are supplied by the
// owning OIDC configuration because this block only describes identity policy.
func (c *KubernetesIdentityConfig) ToJWTAuthenticator(issuer string, audiences []string) (apiserver.JWTAuthenticator, error) {
	if c == nil {
		return apiserver.JWTAuthenticator{}, fmt.Errorf("kubernetes identity configuration is nil")
	}

	input := apiserverv1.JWTAuthenticator{
		Issuer: apiserverv1.Issuer{
			URL:                 issuer,
			Audiences:           append([]string(nil), audiences...),
			AudienceMatchPolicy: apiserverv1.AudienceMatchPolicyMatchAny,
		},
		ClaimMappings:        c.ClaimMappings,
		ClaimValidationRules: c.ClaimValidationRules,
		UserValidationRules:  c.UserValidationRules,
	}
	var output apiserver.JWTAuthenticator
	if err := apiserverv1.Convert_v1_JWTAuthenticator_To_apiserver_JWTAuthenticator(input.DeepCopy(), &output, nil); err != nil {
		return apiserver.JWTAuthenticator{}, fmt.Errorf("convert Kubernetes identity configuration: %w", err)
	}
	return output, nil
}

// Validate validates this policy with the same compiler and validation rules
// used by kube-apiserver. The issuer and audiences are supplied by the caller.
func (c *KubernetesIdentityConfig) Validate(issuer string, audiences []string) field.ErrorList {
	return c.ValidateWithDiscoveryURL(issuer, audiences, "")
}

// ValidateWithDiscoveryURL validates the policy and issuer settings using the
// same kube-apiserver validator used for structured authentication.
func (c *KubernetesIdentityConfig) ValidateWithDiscoveryURL(issuer string, audiences []string, discoveryURL string) field.ErrorList {
	if c == nil {
		return nil
	}
	authenticator, err := c.ToJWTAuthenticator(issuer, audiences)
	if err != nil {
		return field.ErrorList{field.Invalid(field.NewPath(""), nil, err.Error())}
	}
	authenticator.Issuer.DiscoveryURL = discoveryURL
	_, errs := apiservervalidation.CompileAndValidateJWTAuthenticator(authenticationcel.NewDefaultCompiler(), authenticator, nil)
	return errs
}
