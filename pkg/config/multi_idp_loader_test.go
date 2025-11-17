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

package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

// TestLoadAllIdentityProviders verifies loading all enabled IDPs
func TestLoadAllIdentityProviders(t *testing.T) {
	scheme := setupScheme(t)
	idp1 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-1"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth1.example.com",
				ClientID:  "client-1",
			},
			Issuer:   "https://auth1.example.com",
			Disabled: false,
		},
	}

	idp2 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-2"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "client-2",
			},
			Issuer:   "https://auth2.example.com",
			Disabled: false,
		},
	}

	idp3Disabled := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-3-disabled"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth3.example.com",
				ClientID:  "client-3",
			},
			Issuer:   "https://auth3.example.com",
			Disabled: true, // Disabled, should not be included
		},
	}

	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp1, idp2, idp3Disabled).
		Build()

	loader := NewIdentityProviderLoader(kubeClient)
	idps, err := loader.LoadAllIdentityProviders(context.Background())

	require.NoError(t, err)
	assert.Len(t, idps, 2) // Only 2 enabled IDPs
	assert.Contains(t, idps, "idp-1")
	assert.Contains(t, idps, "idp-2")
	assert.NotContains(t, idps, "idp-3-disabled")

	// Verify content
	assert.Equal(t, "https://auth1.example.com", idps["idp-1"].Issuer)
	assert.Equal(t, "idp-1", idps["idp-1"].Name)
}

// TestLoadIdentityProviderByIssuer verifies finding IDP by issuer URL
func TestLoadIdentityProviderByIssuer(t *testing.T) {
	scheme := setupScheme(t)
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.tenant.com",
				ClientID:  "tenant-client",
			},
			Issuer:   "https://auth.tenant.com",
			Disabled: false,
		},
	}

	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()

	loader := NewIdentityProviderLoader(kubeClient)

	// Test loading by matching issuer
	config, err := loader.LoadIdentityProviderByIssuer(context.Background(), "https://auth.tenant.com")
	require.NoError(t, err)
	assert.Equal(t, "tenant-idp", config.Name)
	assert.Equal(t, "https://auth.tenant.com", config.Issuer)

	// Test loading by non-matching issuer returns error
	_, err = loader.LoadIdentityProviderByIssuer(context.Background(), "https://nonexistent.example.com")
	assert.Error(t, err)
}

// TestValidateIdentityProviderRefs verifies validation of IDP references
func TestValidateIdentityProviderRefs(t *testing.T) {
	scheme := setupScheme(t)
	idp1 := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-1"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth1.example.com",
				ClientID:  "client-1",
			},
			Issuer:   "https://auth1.example.com",
			Disabled: false,
		},
	}

	idp2Disabled := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-2-disabled"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth2.example.com",
				ClientID:  "client-2",
			},
			Issuer:   "https://auth2.example.com",
			Disabled: true,
		},
	}

	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp1, idp2Disabled).
		Build()

	loader := NewIdentityProviderLoader(kubeClient)

	// Empty refs should be valid
	err := loader.ValidateIdentityProviderRefs(context.Background(), []string{})
	assert.NoError(t, err)

	// Valid enabled ref should pass
	err = loader.ValidateIdentityProviderRefs(context.Background(), []string{"idp-1"})
	assert.NoError(t, err)

	// Disabled ref should fail
	err = loader.ValidateIdentityProviderRefs(context.Background(), []string{"idp-2-disabled"})
	assert.Error(t, err)

	// Non-existent ref should fail
	err = loader.ValidateIdentityProviderRefs(context.Background(), []string{"non-existent"})
	assert.Error(t, err)

	// Mixed valid and invalid should fail
	err = loader.ValidateIdentityProviderRefs(context.Background(), []string{"idp-1", "non-existent"})
	assert.Error(t, err)
}

// TestGetIDPNameByIssuer verifies getting IDP name from issuer
func TestGetIDPNameByIssuer(t *testing.T) {
	scheme := setupScheme(t)
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "my-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "client",
			},
			Issuer:   "https://auth.example.com",
			Disabled: false,
		},
	}

	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()

	loader := NewIdentityProviderLoader(kubeClient)

	// Test conversion from issuer to name
	name, err := loader.GetIDPNameByIssuer(context.Background(), "https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, "my-idp", name)
}

// TestIdentityProviderConfigIncludesIssuerAndName verifies Name and Issuer are populated
func TestIdentityProviderConfigIncludesIssuerAndName(t *testing.T) {
	scheme := setupScheme(t)
	idp := &breakglassv1alpha1.IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "test-idp"},
		Spec: breakglassv1alpha1.IdentityProviderSpec{
			OIDC: breakglassv1alpha1.OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Issuer:      "https://auth.example.com",
			DisplayName: "Test IDP",
			Disabled:    false,
		},
	}

	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(idp).
		Build()

	loader := NewIdentityProviderLoader(kubeClient)
	config, err := loader.LoadIdentityProviderByName(context.Background(), "test-idp")

	require.NoError(t, err)
	assert.Equal(t, "test-idp", config.Name)
	assert.Equal(t, "https://auth.example.com", config.Issuer)
	assert.Equal(t, "https://auth.example.com", config.Authority)
	assert.Equal(t, "test-client", config.ClientID)
}

// setupScheme creates a scheme with necessary types for testing
func setupScheme(t *testing.T) *runtime.Scheme {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)
	return scheme
}
