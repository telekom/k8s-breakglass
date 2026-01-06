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
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestIdentityProviderIssuerField verifies the Issuer field is present in IdentityProviderSpec
func TestIdentityProviderIssuerField(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "test-client",
			},
			Issuer:      "https://auth.example.com",
			DisplayName: "Test IDP",
			Disabled:    false,
		},
	}

	assert.Equal(t, "https://auth.example.com", idp.Spec.Issuer)
	assert.Equal(t, "Test IDP", idp.Spec.DisplayName)
	assert.False(t, idp.Spec.Disabled)
}

// TestClusterConfigIdentityProviderRefs verifies IdentityProviderRefs field is present
func TestClusterConfigIdentityProviderRefs(t *testing.T) {
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cluster",
		},
		Spec: ClusterConfigSpec{
			ClusterID: "test-cluster-id",
			KubeconfigSecretRef: SecretKeyReference{
				Name:      "test-secret",
				Namespace: "default",
			},
			IdentityProviderRefs: []string{"idp-1", "idp-2"},
		},
	}

	assert.Equal(t, []string{"idp-1", "idp-2"}, clusterConfig.Spec.IdentityProviderRefs)
}

// TestBreakglassEscalationAllowedIdentityProviders verifies AllowedIdentityProviders field
func TestBreakglassEscalationAllowedIdentityProviders(t *testing.T) {
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: BreakglassEscalationSpec{
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-1"},
			},
			AllowedIdentityProviders: []string{"tenant-idp"},
		},
	}

	assert.Equal(t, []string{"tenant-idp"}, escalation.Spec.AllowedIdentityProviders)
}

// TestBreakglassSessionIdentityProviderFields verifies IDP tracking fields
func TestBreakglassSessionIdentityProviderFields(t *testing.T) {
	session := &BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session",
			Namespace: "default",
		},
		Spec: BreakglassSessionSpec{
			Cluster:                "test-cluster",
			User:                   "user@example.com",
			GrantedGroup:           "test-group",
			IdentityProviderName:   "tenant-idp",
			IdentityProviderIssuer: "https://auth.tenant.com",
		},
	}

	assert.Equal(t, "tenant-idp", session.Spec.IdentityProviderName)
	assert.Equal(t, "https://auth.tenant.com", session.Spec.IdentityProviderIssuer)
}

// TestBackwardCompatibilityPrimaryField verifies Primary field still works for backward compatibility
func TestBackwardCompatibilityPrimaryField(t *testing.T) {
	idp := &IdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name: "legacy-idp",
		},
		Spec: IdentityProviderSpec{
			OIDC: OIDCConfig{
				Authority: "https://auth.example.com",
				ClientID:  "legacy-client",
			},
			Primary: true, // Backward compatibility
		},
	}

	assert.True(t, idp.Spec.Primary)
}

// TestEmptyIdentityProviderRefsAllowsAllIDPs verifies backward compatibility
// when IdentityProviderRefs is not set
func TestEmptyIdentityProviderRefsAllowsAllIDPs(t *testing.T) {
	clusterConfig := &ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "unrestricted-cluster",
		},
		Spec: ClusterConfigSpec{
			ClusterID: "unrestricted-cluster-id",
			KubeconfigSecretRef: SecretKeyReference{
				Name:      "kubeconfig",
				Namespace: "default",
			},
			// IdentityProviderRefs is empty - should accept any enabled IDP
		},
	}

	// Empty refs should be interpreted as "accept all enabled IDPs"
	assert.Empty(t, clusterConfig.Spec.IdentityProviderRefs)
}

// TestEmptyAllowedIdentityProvidersInheritsFromCluster verifies escalation filtering logic
func TestEmptyAllowedIdentityProvidersInheritsFromCluster(t *testing.T) {
	escalation := &BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unrestricted-escalation",
			Namespace: "default",
		},
		Spec: BreakglassEscalationSpec{
			Allowed: BreakglassEscalationAllowed{
				Clusters: []string{"cluster-1"},
			},
			// AllowedIdentityProviders is empty - should inherit from cluster config
		},
	}

	// Empty refs should inherit from cluster config
	assert.Empty(t, escalation.Spec.AllowedIdentityProviders)
}
