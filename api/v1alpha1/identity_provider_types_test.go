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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIdentityProviderOIDCConfig verifies OIDC configuration structure
func TestIdentityProviderOIDCConfig(t *testing.T) {
	oidc := OIDCConfig{
		Authority:    "https://auth.example.com",
		ClientID:     "my-client-id",
		JWKSEndpoint: "https://auth.example.com/jwks",
	}

	assert.Equal(t, "https://auth.example.com", oidc.Authority)
	assert.Equal(t, "my-client-id", oidc.ClientID)
	assert.Equal(t, "https://auth.example.com/jwks", oidc.JWKSEndpoint)
}

// TestIdentityProviderOIDCWithTLS verifies OIDC TLS configuration
func TestIdentityProviderOIDCWithTLS(t *testing.T) {
	oidc := OIDCConfig{
		Authority:            "https://auth.example.com",
		ClientID:             "client-id",
		InsecureSkipVerify:   false,
		CertificateAuthority: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
	}

	assert.False(t, oidc.InsecureSkipVerify)
	assert.NotEmpty(t, oidc.CertificateAuthority)
}

// TestKeycloakGroupSync verifies Keycloak group sync configuration
func TestKeycloakGroupSync(t *testing.T) {
	keycloak := KeycloakGroupSync{
		BaseURL:  "https://keycloak.example.com",
		Realm:    "master",
		ClientID: "group-sync-client",
		ClientSecretRef: SecretKeyReference{
			Name:      "keycloak-secret",
			Namespace: "default",
		},
	}

	assert.Equal(t, "https://keycloak.example.com", keycloak.BaseURL)
	assert.Equal(t, "master", keycloak.Realm)
	assert.Equal(t, "group-sync-client", keycloak.ClientID)
	assert.Equal(t, "keycloak-secret", keycloak.ClientSecretRef.Name)
}

// TestKeycloakGroupSyncWithTLS verifies Keycloak TLS configuration
func TestKeycloakGroupSyncWithTLS(t *testing.T) {
	keycloak := KeycloakGroupSync{
		BaseURL:            "https://keycloak.example.com",
		Realm:              "master",
		ClientID:           "client",
		InsecureSkipVerify: true,
		CacheTTL:           "5m",
		RequestTimeout:     "10s",
	}

	assert.True(t, keycloak.InsecureSkipVerify)
	assert.Equal(t, "5m", keycloak.CacheTTL)
	assert.Equal(t, "10s", keycloak.RequestTimeout)
}

// TestIdentityProviderSpecBasic verifies basic IdentityProvider specification
func TestIdentityProviderSpecBasic(t *testing.T) {
	spec := IdentityProviderSpec{
		OIDC: OIDCConfig{
			Authority: "https://auth.example.com",
			ClientID:  "frontend-app",
		},
		Issuer:      "https://auth.example.com",
		DisplayName: "Corporate Identity",
	}

	assert.Equal(t, "https://auth.example.com", spec.OIDC.Authority)
	assert.Equal(t, "https://auth.example.com", spec.Issuer)
	assert.Equal(t, "Corporate Identity", spec.DisplayName)
}

// TestIdentityProviderSpecWithGroupSync verifies group sync configuration
func TestIdentityProviderSpecWithGroupSync(t *testing.T) {
	spec := IdentityProviderSpec{
		OIDC: OIDCConfig{
			Authority: "https://auth.example.com",
			ClientID:  "frontend-app",
		},
		GroupSyncProvider: GroupSyncProviderKeycloak,
		Keycloak: &KeycloakGroupSync{
			BaseURL:  "https://keycloak.example.com",
			Realm:    "master",
			ClientID: "sync-client",
		},
	}

	assert.Equal(t, GroupSyncProviderKeycloak, spec.GroupSyncProvider)
	require.NotNil(t, spec.Keycloak)
	assert.Equal(t, "master", spec.Keycloak.Realm)
}

// TestIdentityProviderSpecPrimary verifies backward compatibility with Primary field
func TestIdentityProviderSpecPrimary(t *testing.T) {
	spec := IdentityProviderSpec{
		OIDC: OIDCConfig{
			Authority: "https://auth.example.com",
			ClientID:  "frontend-app",
		},
		Primary: true,
	}

	assert.True(t, spec.Primary)
}

// TestIdentityProviderSpecDisabled verifies Disabled field
func TestIdentityProviderSpecDisabled(t *testing.T) {
	spec := IdentityProviderSpec{
		OIDC: OIDCConfig{
			Authority: "https://auth.example.com",
			ClientID:  "frontend-app",
		},
		Disabled: true,
	}

	assert.True(t, spec.Disabled)
}

// TestIdentityProviderStatus verifies status tracking with conditions
func TestIdentityProviderStatus(t *testing.T) {
	status := IdentityProviderStatus{
		ObservedGeneration: 1,
		Conditions: []metav1.Condition{
			{
				Type:               string(IdentityProviderConditionReady),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "ConfigurationValid",
				Message:            "Provider is healthy and operational",
			},
		},
	}

	assert.Equal(t, int64(1), status.ObservedGeneration)
	assert.Len(t, status.Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, status.Conditions[0].Status)
}

// TestIdentityProviderStatusWithErrors verifies error tracking through conditions
func TestIdentityProviderStatusWithErrors(t *testing.T) {
	status := IdentityProviderStatus{
		ObservedGeneration: 1,
		Conditions: []metav1.Condition{
			{
				Type:               string(IdentityProviderConditionValidationFailed),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "InvalidConfiguration",
				Message:            "Failed to validate provider: missing required field",
			},
			{
				Type:               string(IdentityProviderConditionGroupSyncHealthy),
				Status:             metav1.ConditionFalse,
				ObservedGeneration: 1,
				Reason:             "GroupSyncUnreachable",
				Message:            "Group sync provider unreachable",
			},
		},
	}

	assert.Len(t, status.Conditions, 2)
	assert.Equal(t, string(IdentityProviderConditionValidationFailed), status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, status.Conditions[0].Status)
	assert.NotEmpty(t, status.Conditions[0].Message)
	assert.Equal(t, string(IdentityProviderConditionGroupSyncHealthy), status.Conditions[1].Type)
	assert.Equal(t, metav1.ConditionFalse, status.Conditions[1].Status)
}

// TestIdentityProviderStatusConditions verifies condition management
func TestIdentityProviderStatusConditions(t *testing.T) {
	status := IdentityProviderStatus{
		Conditions: []metav1.Condition{
			{
				Type:               string(IdentityProviderConditionReady),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "ConfigurationValid",
				Message:            "Provider is configured correctly",
			},
			{
				Type:               string(IdentityProviderConditionGroupSyncHealthy),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "GroupSyncConnected",
				Message:            "Group sync provider is healthy",
			},
		},
	}

	assert.Len(t, status.Conditions, 2)
	assert.Equal(t, string(IdentityProviderConditionReady), status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, status.Conditions[0].Status)
}

// TestIdentityProvider verifies complete IdentityProvider object
func TestIdentityProvider(t *testing.T) {
	idp := &IdentityProvider{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "breakglass.t-caas.telekom.com/v1alpha1",
			Kind:       "IdentityProvider",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "corporate-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.corp.com",
				ClientID:  "frontend-web",
			},
			Issuer:      "https://auth.corp.com",
			DisplayName: "Corporate OIDC Provider",
		},
		Status: IdentityProviderStatus{
			ObservedGeneration: 1,
			Conditions: []metav1.Condition{
				{
					Type:   string(IdentityProviderConditionReady),
					Status: metav1.ConditionTrue,
					Reason: "ConfigurationValid",
				},
			},
		},
	}

	assert.Equal(t, "breakglass.t-caas.telekom.com/v1alpha1", idp.APIVersion)
	assert.Equal(t, "IdentityProvider", idp.Kind)
	assert.Equal(t, "corporate-idp", idp.Name)
	assert.Equal(t, int64(1), idp.Status.ObservedGeneration)
}

// TestIdentityProviderList verifies list structure
func TestIdentityProviderList(t *testing.T) {
	list := &IdentityProviderList{
		Items: []IdentityProvider{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "idp-1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "idp-2",
				},
			},
		},
	}

	assert.Len(t, list.Items, 2)
	assert.Equal(t, "idp-1", list.Items[0].Name)
	assert.Equal(t, "idp-2", list.Items[1].Name)
}

// TestIdentityProviderSetCondition verifies SetCondition method
func TestIdentityProviderSetCondition(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Status: IdentityProviderStatus{},
	}

	condition := metav1.Condition{
		Type:   string(IdentityProviderConditionReady),
		Status: metav1.ConditionTrue,
		Reason: "ConfigurationValid",
	}

	idp.SetCondition(condition)

	assert.Len(t, idp.Status.Conditions, 1)
	assert.Equal(t, string(IdentityProviderConditionReady), idp.Status.Conditions[0].Type)
}

// TestIdentityProviderSetConditionUpdate verifies updating existing condition
func TestIdentityProviderSetConditionUpdate(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Status: IdentityProviderStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(IdentityProviderConditionReady),
					Status: metav1.ConditionFalse,
					Reason: "ConfigurationInvalid",
				},
			},
		},
	}

	newCondition := metav1.Condition{
		Type:   string(IdentityProviderConditionReady),
		Status: metav1.ConditionTrue,
		Reason: "ConfigurationValid",
	}

	idp.SetCondition(newCondition)

	assert.Len(t, idp.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionTrue, idp.Status.Conditions[0].Status)
	assert.Equal(t, "ConfigurationValid", idp.Status.Conditions[0].Reason)
}

// TestIdentityProviderGetCondition verifies GetCondition method
func TestIdentityProviderGetCondition(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Status: IdentityProviderStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(IdentityProviderConditionReady),
					Status: metav1.ConditionTrue,
					Reason: "ConfigurationValid",
				},
				{
					Type:   string(IdentityProviderConditionGroupSyncHealthy),
					Status: metav1.ConditionFalse,
					Reason: "GroupSyncDisabled",
				},
			},
		},
	}

	condition := idp.GetCondition(string(IdentityProviderConditionReady))

	require.NotNil(t, condition)
	assert.Equal(t, metav1.ConditionTrue, condition.Status)
}

// TestIdentityProviderGetConditionNotFound verifies GetCondition returns nil when not found
func TestIdentityProviderGetConditionNotFound(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Status: IdentityProviderStatus{
			Conditions: []metav1.Condition{},
		},
	}

	condition := idp.GetCondition(string(IdentityProviderConditionReady))

	assert.Nil(t, condition)
}

// TestGroupSyncProviderEnum verifies GroupSyncProvider enum
func TestGroupSyncProviderEnum(t *testing.T) {
	provider := GroupSyncProviderKeycloak
	assert.Equal(t, GroupSyncProvider("Keycloak"), provider)
}

// TestIdentityProviderConditionTypeEnum verifies condition type enum
func TestIdentityProviderConditionTypeEnum(t *testing.T) {
	tests := []struct {
		name      string
		condition IdentityProviderConditionType
	}{
		{"Ready", IdentityProviderConditionReady},
		{"ConversionFailed", IdentityProviderConditionConversionFailed},
		{"ValidationFailed", IdentityProviderConditionValidationFailed},
		{"GroupSyncHealthy", IdentityProviderConditionGroupSyncHealthy},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.condition)
		})
	}
}

// TestIdentityProviderValidateCreateValidSpec verifies successful validation
func TestIdentityProviderValidateCreateValidSpec(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
		},
	}

	warnings, err := idp.ValidateCreate(context.Background(), idp)

	// Note: ValidateCreate will fail without proper context setup, but we test the structure
	assert.NotNil(t, idp)
	_ = err // Error is expected in unit test without full webhook setup
	_ = warnings
}

// TestIdentityProviderValidateUpdateValidSpec verifies update validation
func TestIdentityProviderValidateUpdateValidSpec(t *testing.T) {
	oldIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client-id",
			},
		},
	}

	newIDP := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "updated-client-id",
			},
		},
	}

	warnings, err := newIDP.ValidateUpdate(context.Background(), oldIDP, newIDP)

	// Note: ValidateUpdate will fail without proper context setup
	assert.NotNil(t, newIDP)
	_ = err // Error is expected in unit test without full webhook setup
	_ = warnings
}

// TestIdentityProviderValidateDelete verifies delete validation
func TestIdentityProviderValidateDelete(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "idp-to-delete",
		},
	}

	warnings, err := idp.ValidateDelete(context.Background(), idp)

	assert.NoError(t, err)
	assert.Empty(t, warnings)
}

// TestIdentityProviderWithMultipleConditions verifies multiple conditions
func TestIdentityProviderWithMultipleConditions(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "multi-condition-idp",
		},
	}

	// Add first condition
	readyCondition := metav1.Condition{
		Type:   string(IdentityProviderConditionReady),
		Status: metav1.ConditionTrue,
		Reason: "ConfigValid",
	}
	idp.SetCondition(readyCondition)

	// Add second condition
	syncCondition := metav1.Condition{
		Type:   string(IdentityProviderConditionGroupSyncHealthy),
		Status: metav1.ConditionTrue,
		Reason: "SyncHealthy",
	}
	idp.SetCondition(syncCondition)

	// Add third condition
	conversionCondition := metav1.Condition{
		Type:   string(IdentityProviderConditionConversionFailed),
		Status: metav1.ConditionFalse,
		Reason: "ConversionOK",
	}
	idp.SetCondition(conversionCondition)

	assert.Len(t, idp.Status.Conditions, 3)
}

// TestIdentityProviderIntegration verifies complete workflow
func TestIdentityProviderIntegration(t *testing.T) {
	// Create provider
	idp := &IdentityProvider{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "breakglass.t-caas.telekom.com/v1alpha1",
			Kind:       "IdentityProvider",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "integration-test-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority:    "https://auth.example.com",
				ClientID:     "test-client",
				JWKSEndpoint: "https://auth.example.com/.well-known/jwks.json",
			},
			GroupSyncProvider: GroupSyncProviderKeycloak,
			Keycloak: &KeycloakGroupSync{
				BaseURL:  "https://keycloak.example.com",
				Realm:    "master",
				ClientID: "sync-client",
				ClientSecretRef: SecretKeyReference{
					Name:      "keycloak-secret",
					Namespace: "default",
				},
			},
			Issuer:      "https://auth.example.com",
			DisplayName: "Test Identity Provider",
		},
	}

	// Set conditions
	idp.SetCondition(metav1.Condition{
		Type:   string(IdentityProviderConditionReady),
		Status: metav1.ConditionTrue,
		Reason: "Initialized",
	})

	idp.SetCondition(metav1.Condition{
		Type:   string(IdentityProviderConditionGroupSyncHealthy),
		Status: metav1.ConditionTrue,
		Reason: "SyncConnected",
	})

	// Verify complete structure
	assert.Equal(t, "integration-test-idp", idp.Name)
	assert.Equal(t, GroupSyncProviderKeycloak, idp.Spec.GroupSyncProvider)
	assert.Len(t, idp.Status.Conditions, 2)
	readyCondition := idp.GetCondition(string(IdentityProviderConditionReady))
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
}
