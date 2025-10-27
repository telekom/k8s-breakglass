package breakglass

import (
	"reflect"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	authenticationv1alpha1 "k8s.io/api/authentication/v1alpha1"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestStripOIDCPrefixes(t *testing.T) {
	tests := []struct {
		name           string
		groups         []string
		oidcPrefixes   []string
		expectedGroups []string
	}{
		{
			name:           "No prefixes configured",
			groups:         []string{"admin", "user", "guest"},
			oidcPrefixes:   []string{},
			expectedGroups: []string{"admin", "user", "guest"},
		},
		{
			name:           "Nil prefixes",
			groups:         []string{"admin", "user", "guest"},
			oidcPrefixes:   nil,
			expectedGroups: []string{"admin", "user", "guest"},
		},
		{
			name:           "Single prefix matching",
			groups:         []string{"keycloak:admin", "keycloak:user", "guest"},
			oidcPrefixes:   []string{"keycloak:"},
			expectedGroups: []string{"admin", "user", "guest"},
		},
		{
			name:           "Multiple prefixes",
			groups:         []string{"keycloak:admin", "oidc:user", "ldap:guest", "system:authenticated"},
			oidcPrefixes:   []string{"keycloak:", "oidc:", "ldap:"},
			expectedGroups: []string{"admin", "user", "guest", "system:authenticated"},
		},
		{
			name:           "No matching prefixes",
			groups:         []string{"admin", "user", "guest"},
			oidcPrefixes:   []string{"keycloak:", "oidc:"},
			expectedGroups: []string{"admin", "user", "guest"},
		},
		{
			name:           "Partial matching prefixes",
			groups:         []string{"keycloak:admin", "user", "oidc:guest"},
			oidcPrefixes:   []string{"keycloak:", "ldap:"},
			expectedGroups: []string{"admin", "user", "oidc:guest"},
		},
		{
			name:           "Empty groups",
			groups:         []string{},
			oidcPrefixes:   []string{"keycloak:", "oidc:"},
			expectedGroups: []string{},
		},
		{
			name:           "Groups with multiple prefixes - first match wins",
			groups:         []string{"keycloak:oidc:admin"},
			oidcPrefixes:   []string{"keycloak:", "oidc:"},
			expectedGroups: []string{"oidc:admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripOIDCPrefixes(tt.groups, tt.oidcPrefixes)
			if !reflect.DeepEqual(result, tt.expectedGroups) {
				t.Errorf("stripOIDCPrefixes() = %v, want %v", result, tt.expectedGroups)
			}
		})
	}
}

func TestGetUserInfo(t *testing.T) {
	tests := []struct {
		name           string
		input          runtime.Object
		expectedGroups []string
		expectedUser   string
		expectError    bool
	}{
		{
			name: "v1 SelfSubjectReview",
			input: &authenticationv1.SelfSubjectReview{
				Status: authenticationv1.SelfSubjectReviewStatus{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user",
						Groups:   []string{"admin", "users"},
					},
				},
			},
			expectedGroups: []string{"admin", "users"},
			expectedUser:   "test-user",
			expectError:    false,
		},
		{
			name: "v1beta1 SelfSubjectReview",
			input: &authenticationv1beta1.SelfSubjectReview{
				Status: authenticationv1beta1.SelfSubjectReviewStatus{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user-beta",
						Groups:   []string{"beta-admin", "beta-users"},
					},
				},
			},
			expectedGroups: []string{"beta-admin", "beta-users"},
			expectedUser:   "test-user-beta",
			expectError:    false,
		},
		{
			name: "v1alpha1 SelfSubjectReview",
			input: &authenticationv1alpha1.SelfSubjectReview{
				Status: authenticationv1alpha1.SelfSubjectReviewStatus{
					UserInfo: authenticationv1.UserInfo{
						Username: "test-user-alpha",
						Groups:   []string{"alpha-admin", "alpha-users"},
					},
				},
			},
			expectedGroups: []string{"alpha-admin", "alpha-users"},
			expectedUser:   "test-user-alpha",
			expectError:    false,
		},
		{
			name:        "unsupported type",
			input:       &metav1.Status{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getUserInfo(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("getUserInfo() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("getUserInfo() unexpected error: %v", err)
				return
			}

			if result.Username != tt.expectedUser {
				t.Errorf("getUserInfo() username = %v, want %v", result.Username, tt.expectedUser)
			}

			if !reflect.DeepEqual(result.Groups, tt.expectedGroups) {
				t.Errorf("getUserInfo() groups = %v, want %v", result.Groups, tt.expectedGroups)
			}
		})
	}
}
