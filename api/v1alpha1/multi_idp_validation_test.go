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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestIdentityProviderIssuerValidationUnique tests that Issuer field is validated for uniqueness
func TestIdentityProviderIssuerValidationUnique(t *testing.T) {
	// Setup fake client with existing IDP
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp1 := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-1"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client1",
			},
			Issuer: "https://auth.example.com",
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp1).Build()
	webhookClient = client

	// Try to create a new IDP with same issuer - should fail
	idp2 := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-2"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "client2",
			},
			Issuer: "https://auth.example.com", // Same issuer as idp1
		},
	}

	_, err := idp2.ValidateCreate(context.Background(), idp2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unique")
}

// TestIdentityProviderIssuerValidationURL tests that Issuer field must be a valid URL (or at least parse as one)
// Note: url.Parse is lenient and accepts paths like "not a valid url", so we only test obviously broken URLs
func TestIdentityProviderIssuerValidationURL(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	webhookClient = client

	// IDP with obviously invalid issuer (colon-only string causes parse error)
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-invalid"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Issuer: ":", // Will fail url.Parse
		},
	}

	_, err := idp.ValidateCreate(context.Background(), idp)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "URL")
}

// TestClusterConfigIdentityProviderRefsValidation tests that referenced IDPs exist
func TestClusterConfigIdentityProviderRefsValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	enabledIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "enabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledIDP).Build()
	webhookClient = client

	// ClusterConfig with reference to non-existent IDP
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{
				Name:      "kubeconfig",
				Namespace: "default",
			},
			IdentityProviderRefs: []string{"non-existent-idp"},
		},
	}

	_, err := clusterConfig.ValidateCreate(context.Background(), clusterConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not found") // Field error message
}

// TestClusterConfigIdentityProviderRefsValidationDisabled tests that disabled IDPs are rejected
func TestClusterConfigIdentityProviderRefsValidationDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	disabledIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Disabled: true,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabledIDP).Build()
	webhookClient = client

	// ClusterConfig referencing disabled IDP should fail
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{
				Name:      "kubeconfig",
				Namespace: "default",
			},
			IdentityProviderRefs: []string{"disabled-idp"},
		},
	}

	_, err := clusterConfig.ValidateCreate(context.Background(), clusterConfig)
	assert.Error(t, err)
}

// TestClusterConfigEmptyIdentityProviderRefsAllowed tests backward compatibility
func TestClusterConfigEmptyIdentityProviderRefsAllowed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	webhookClient = client

	// ClusterConfig with empty IdentityProviderRefs (backward compatible)
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "test-cluster"},
		Spec: ClusterConfigSpec{
			KubeconfigSecretRef: SecretKeyReference{
				Name:      "kubeconfig",
				Namespace: "default",
			},
			// Empty IdentityProviderRefs - should be valid
		},
	}

	err := validateIdentityProviderRefs(context.Background(), clusterConfig.Spec.IdentityProviderRefs, field.NewPath("spec").Child("identityProviderRefs"))
	// Should not error due to IDP refs (empty refs is always valid)
	// The important part is we're testing that empty refs is valid
	assert.Empty(t, err)
}

// TestBreakglassEscalationAllowedIdentityProvidersValidation verifies that IDP lookups are deferred to runtime.
// The webhook should accept references to IdentityProviders that do not exist yet so reconcilers can surface
// the missing objects via conditions and events instead of blocking the CR creation.
func TestBreakglassEscalationAllowedIdentityProvidersValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	enabledIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledIDP).Build()
	webhookClient = client

	// BreakglassEscalation with reference to non-existent IDP
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "escalation-group",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-1"},
			},
			Approvers:                BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			AllowedIdentityProviders: []string{"non-existent-idp"},
		},
	}

	_, err := escalation.ValidateCreate(context.Background(), escalation)
	assert.NoError(t, err)
}

// TestBreakglassEscalationAllowedIdentityProvidersFormatting ensures duplicates/empty entries are still rejected.
func TestBreakglassEscalationAllowedIdentityProvidersFormatting(t *testing.T) {
	path := field.NewPath("spec").Child("allowedIdentityProviders")

	err := validateIdentityProviderRefsFormat([]string{"", "idp-a"}, path)
	assert.Len(t, err, 1)

	err = validateIdentityProviderRefsFormat([]string{"idp-a", "idp-a"}, path)
	assert.Len(t, err, 1)

	err = validateIdentityProviderRefsFormat([]string{"idp-a", "idp-b"}, path)
	assert.Empty(t, err)
}

// TestBreakglassEscalationEmptyAllowedIdentityProvidersAllowed tests backward compatibility
func TestBreakglassEscalationEmptyAllowedIdentityProvidersAllowed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	webhookClient = client

	// BreakglassEscalation with empty AllowedIdentityProviders (inherits from cluster)
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: BreakglassEscalationSpec{
			EscalatedGroup: "escalation-group",
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-1"},
			},
			// Empty AllowedIdentityProviders - valid, inherits from cluster
		},
	}

	err := validateIdentityProviderRefsFormat(escalation.Spec.AllowedIdentityProviders, field.NewPath("spec").Child("allowedIdentityProviders"))
	// May error due to unique name check, but not due to empty IDP list
	assert.Empty(t, err)
}

// TestBreakglassSessionIdentityProviderFieldsValidation tests session IDP field validation
func TestBreakglassSessionIdentityProviderFieldsValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Issuer:   "https://auth.example.com",
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()
	webhookClient = client

	// Session with reference to non-existent IDP
	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: BreakglassSessionSpec{
			Cluster:                "test-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "granted-group",
			IdentityProviderName:   "non-existent-idp",
			IdentityProviderIssuer: "https://auth.example.com",
		},
	}

	_, err := session.ValidateCreate(context.Background(), session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not found")
}

// TestBreakglassSessionIdentityProviderIssuerMismatch tests issuer consistency validation
func TestBreakglassSessionIdentityProviderIssuerMismatch(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Issuer:   "https://auth.example.com",
			Disabled: false,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp).Build()
	webhookClient = client

	// Session with mismatched issuer
	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: BreakglassSessionSpec{
			Cluster:                "test-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "granted-group",
			IdentityProviderName:   "tenant-idp",
			IdentityProviderIssuer: "https://different.example.com", // Mismatch!
		},
	}

	_, err := session.ValidateCreate(context.Background(), session)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

// TestBreakglassSessionEmptyIdentityProviderFieldsAllowed tests optional IDP fields
func TestBreakglassSessionEmptyIdentityProviderFieldsAllowed(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	webhookClient = client

	// Session with empty IDP fields (valid during manual creation)
	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "user@example.com",
			GrantedGroup: "granted-group",
			// Empty IDP fields - valid, will be filled during authentication
		},
	}

	err := validateIdentityProviderFields(context.Background(), session.Spec.IdentityProviderName, session.Spec.IdentityProviderIssuer, field.NewPath("spec").Child("identityProviderName"), field.NewPath("spec").Child("identityProviderIssuer"))
	// May error due to unique name check, but not due to empty IDP fields
	assert.Empty(t, err)
	assert.Empty(t, session.Spec.IdentityProviderIssuer)
}

// TestValidateIdentityProviderRefsHelper tests the helper function directly
func TestValidateIdentityProviderRefsHelper(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	enabledIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "enabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Disabled: false,
		},
	}

	disabledIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "client2",
			},
			Disabled: true,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledIDP, disabledIDP).Build()
	webhookClient = client

	tests := []struct {
		name        string
		refs        []string
		expectError bool
		expectCount int
	}{
		{
			name:        "empty refs is valid",
			refs:        []string{},
			expectError: false,
			expectCount: 0,
		},
		{
			name:        "valid enabled ref",
			refs:        []string{"enabled-idp"},
			expectError: false,
			expectCount: 0,
		},
		{
			name:        "reference to non-existent IDP",
			refs:        []string{"non-existent"},
			expectError: true,
			expectCount: 1,
		},
		{
			name:        "reference to disabled IDP",
			refs:        []string{"disabled-idp"},
			expectError: true,
			expectCount: 1,
		},
		{
			name:        "mixed valid and invalid refs",
			refs:        []string{"enabled-idp", "non-existent"},
			expectError: true,
			expectCount: 1,
		},
		{
			name:        "duplicate refs rejected",
			refs:        []string{"enabled-idp", "enabled-idp"},
			expectError: true,
			expectCount: 1,
		},
		{
			name:        "empty ref entries rejected",
			refs:        []string{"enabled-idp", ""},
			expectError: true,
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateIdentityProviderRefs(context.Background(), tt.refs, field.NewPath("spec").Child("identityProviderRefs"))
			if tt.expectError {
				require.NotEmpty(t, errs, "expected errors but got none")
				require.Equal(t, tt.expectCount, len(errs), "expected %d error(s) but got %d", tt.expectCount, len(errs))
			} else {
				require.Empty(t, errs, "expected no errors but got %v", errs)
			}
		})
	}
}

// TestValidateIdentityProviderFieldsHelper tests the session IDP fields helper
func TestValidateIdentityProviderFieldsHelper(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Issuer:   "https://auth.example.com",
			Disabled: false,
		},
	}

	disabledIdp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "client2",
			},
			Issuer:   "https://auth2.example.com",
			Disabled: true,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(idp, disabledIdp).Build()
	webhookClient = client

	tests := []struct {
		name        string
		idpName     string
		idpIssuer   string
		expectError bool
	}{
		{
			name:        "empty fields are valid",
			idpName:     "",
			idpIssuer:   "",
			expectError: false,
		},
		{
			name:        "valid IDP name only",
			idpName:     "tenant-idp",
			idpIssuer:   "",
			expectError: false,
		},
		{
			name:        "valid IDP name and matching issuer",
			idpName:     "tenant-idp",
			idpIssuer:   "https://auth.example.com",
			expectError: false,
		},
		{
			name:        "non-existent IDP name",
			idpName:     "non-existent",
			idpIssuer:   "",
			expectError: true,
		},
		{
			name:        "disabled IDP name",
			idpName:     "disabled-idp",
			idpIssuer:   "",
			expectError: true,
		},
		{
			name:        "mismatched issuer",
			idpName:     "tenant-idp",
			idpIssuer:   "https://different.example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateIdentityProviderFields(context.Background(), tt.idpName, tt.idpIssuer, field.NewPath("spec").Child("identityProviderName"), field.NewPath("spec").Child("identityProviderIssuer"))
			if tt.expectError {
				require.NotEmpty(t, errs, "expected errors but got none")
			} else {
				require.Empty(t, errs, "expected no errors but got %v", errs)
			}
		})
	}
}

func TestValidateMailProviderReference(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = AddToScheme(scheme)

	enabledMail := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-enabled"},
		Spec: MailProviderSpec{
			SMTP:   SMTPConfig{Host: "smtp.example.com", Port: 587},
			Sender: SenderConfig{Address: "noreply@example.com"},
		},
	}

	disabledMail := &MailProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "mail-disabled"},
		Spec: MailProviderSpec{
			Disabled: true,
			SMTP:     SMTPConfig{Host: "smtp.disabled.example.com", Port: 587},
			Sender:   SenderConfig{Address: "noreply-disabled@example.com"},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledMail, disabledMail).Build()
	webhookClient = client

	tests := []struct {
		name         string
		mailProvider string
		expectError  bool
	}{
		{name: "empty value allowed", mailProvider: "", expectError: false},
		{name: "enabled provider", mailProvider: "mail-enabled", expectError: false},
		{name: "missing provider", mailProvider: "missing", expectError: true},
		{name: "disabled provider", mailProvider: "mail-disabled", expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateMailProviderReference(context.Background(), tt.mailProvider, field.NewPath("spec").Child("mailProvider"))
			if tt.expectError {
				require.NotEmpty(t, errs, "expected errors but got none")
			} else {
				require.Empty(t, errs, "expected no errors but got %v", errs)
			}
		})
	}
}
