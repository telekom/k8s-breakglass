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

package helpers

import (
	"context"
	"os"
	"testing"
)

// IsMultiClusterEnabled returns true if multi-cluster E2E tests should run
func IsMultiClusterEnabled() bool {
	return os.Getenv("E2E_MULTI_CLUSTER") == "true"
}

// GetHubKubeconfig returns the kubeconfig path for the hub cluster
func GetHubKubeconfig() string {
	return getEnvOrDefault("E2E_HUB_KUBECONFIG", "")
}

// GetSpokeAKubeconfig returns the kubeconfig path for spoke-cluster-a
func GetSpokeAKubeconfig() string {
	return getEnvOrDefault("E2E_SPOKE_A_KUBECONFIG", "")
}

// GetSpokeBKubeconfig returns the kubeconfig path for spoke-cluster-b
func GetSpokeBKubeconfig() string {
	return getEnvOrDefault("E2E_SPOKE_B_KUBECONFIG", "")
}

// GetSpokeAOIDCKubeconfig returns the OIDC-only kubeconfig path for spoke-cluster-a
// This kubeconfig has no client certificates, forcing token-based authentication
func GetSpokeAOIDCKubeconfig() string {
	return getEnvOrDefault("E2E_SPOKE_A_OIDC_KUBECONFIG", "")
}

// GetSpokeBOIDCKubeconfig returns the OIDC-only kubeconfig path for spoke-cluster-b
// This kubeconfig has no client certificates, forcing token-based authentication
func GetSpokeBOIDCKubeconfig() string {
	return getEnvOrDefault("E2E_SPOKE_B_OIDC_KUBECONFIG", "")
}

// GetHubClusterName returns the hub cluster name
func GetHubClusterName() string {
	return getEnvOrDefault("E2E_HUB_CLUSTER_NAME", "breakglass-hub")
}

// GetSpokeAClusterName returns the spoke-cluster-a name
func GetSpokeAClusterName() string {
	return getEnvOrDefault("E2E_SPOKE_A_CLUSTER_NAME", "spoke-cluster-a")
}

// GetSpokeBClusterName returns the spoke-cluster-b name
func GetSpokeBClusterName() string {
	return getEnvOrDefault("E2E_SPOKE_B_CLUSTER_NAME", "spoke-cluster-b")
}

// GetKeycloakMainRealm returns the main Keycloak realm name (for employees)
func GetKeycloakMainRealm() string {
	return getEnvOrDefault("KEYCLOAK_MAIN_REALM", "breakglass-e2e")
}

// GetKeycloakContractorsRealm returns the contractors Keycloak realm name
func GetKeycloakContractorsRealm() string {
	return getEnvOrDefault("KEYCLOAK_CONTRACTORS_REALM", "breakglass-e2e-contractors")
}

// GetContractorsClientID returns the client ID for the contractors realm
func GetContractorsClientID() string {
	return getEnvOrDefault("KEYCLOAK_CONTRACTORS_CLIENT_ID", "breakglass-contractors")
}

// GetHubExternalIP returns the external IP of the hub cluster (for cross-cluster access)
func GetHubExternalIP() string {
	return getEnvOrDefault("E2E_HUB_EXTERNAL_IP", "")
}

// GetHubWebhookURL returns the external webhook URL of the hub cluster
func GetHubWebhookURL() string {
	return getEnvOrDefault("E2E_HUB_WEBHOOK_URL", "")
}

// GetHubAPIURL returns the external API URL of the hub cluster
func GetHubAPIURL() string {
	return getEnvOrDefault("E2E_HUB_API_URL", "")
}

// MultiClusterConfig holds configuration for multi-cluster test environment
type MultiClusterConfig struct {
	HubKubeconfig    string
	SpokeAKubeconfig string
	SpokeBKubeconfig string
	// OIDC-only kubeconfigs have no client certificates, forcing token-based auth
	SpokeAOIDCKubeconfig string
	SpokeBOIDCKubeconfig string
	HubClusterName       string
	SpokeAClusterName    string
	SpokeBClusterName    string
	MainRealm            string
	ContractorsRealm     string
	MainClientID         string
	ContractorsClientID  string
	// Hub external access for spoke clusters
	HubExternalIP string
	HubWebhookURL string
	HubAPIURL     string
}

// GetMultiClusterConfig returns the full multi-cluster configuration
func GetMultiClusterConfig() MultiClusterConfig {
	return MultiClusterConfig{
		HubKubeconfig:        GetHubKubeconfig(),
		SpokeAKubeconfig:     GetSpokeAKubeconfig(),
		SpokeBKubeconfig:     GetSpokeBKubeconfig(),
		SpokeAOIDCKubeconfig: GetSpokeAOIDCKubeconfig(),
		SpokeBOIDCKubeconfig: GetSpokeBOIDCKubeconfig(),
		HubClusterName:       GetHubClusterName(),
		SpokeAClusterName:    GetSpokeAClusterName(),
		SpokeBClusterName:    GetSpokeBClusterName(),
		MainRealm:            GetKeycloakMainRealm(),
		ContractorsRealm:     GetKeycloakContractorsRealm(),
		MainClientID:         GetKeycloakClientID(),
		ContractorsClientID:  GetContractorsClientID(),
		HubExternalIP:        GetHubExternalIP(),
		HubWebhookURL:        GetHubWebhookURL(),
		HubAPIURL:            GetHubAPIURL(),
	}
}

// MultiClusterTestUsers contains test user configurations for multi-cluster testing
var MultiClusterTestUsers = struct {
	// MainRealmUsers - users from the main realm (employees)
	Employee struct {
		Email    string
		Password string
		Groups   []string
	}
	Approver struct {
		Email    string
		Password string
		Groups   []string
	}
	// ContractorRealmUsers - users from the contractors realm
	Contractor1 struct {
		Email    string
		Password string
		Groups   []string
	}
	Contractor2 struct {
		Email    string
		Password string
		Groups   []string
	}
}{
	Employee: struct {
		Email    string
		Password string
		Groups   []string
	}{
		// Must match users created by configure_keycloak_realm() in e2e/lib/common.sh
		Email:    "requester@example.com",
		Password: "password",
		Groups:   []string{"breakglass-users"},
	},
	Approver: struct {
		Email    string
		Password string
		Groups   []string
	}{
		// Must match users created by configure_keycloak_realm() in e2e/lib/common.sh
		Email:    "approver@example.com",
		Password: "password",
		Groups:   []string{"breakglass-approvers"},
	},
	Contractor1: struct {
		Email    string
		Password string
		Groups   []string
	}{
		Email:    "contractor1@vendor.com",
		Password: "password",
		Groups:   []string{"contractors"},
	},
	Contractor2: struct {
		Email    string
		Password string
		Groups   []string
	}{
		Email:    "contractor2@vendor.com",
		Password: "password",
		Groups:   []string{"contractors", "vendor-team"},
	},
}

// MultiClusterTestContext provides helpers for multi-cluster authorization testing.
// This context manages clients and tokens for testing spoke→hub authorization flows.
type MultiClusterTestContext struct {
	Config     MultiClusterConfig
	HubOIDC    *OIDCTokenProvider
	ContOIDC   *OIDCTokenProvider // Contractors realm OIDC provider
	tokenCache map[string]string
}

// NewMultiClusterTestContext creates a test context for multi-cluster testing
func NewMultiClusterTestContext() *MultiClusterTestContext {
	config := GetMultiClusterConfig()
	return &MultiClusterTestContext{
		Config: config,
		HubOIDC: &OIDCTokenProvider{
			KeycloakHost: GetKeycloakHost(),
			Realm:        config.MainRealm,
			ClientID:     config.MainClientID,
			IssuerHost:   GetKeycloakIssuerHost(),
		},
		ContOIDC: &OIDCTokenProvider{
			KeycloakHost: GetKeycloakHost(),
			Realm:        config.ContractorsRealm,
			ClientID:     config.ContractorsClientID,
			IssuerHost:   GetKeycloakIssuerHost(),
		},
		tokenCache: make(map[string]string),
	}
}

// GetOIDCTokenForRealm retrieves an OIDC token for a user in a specific realm.
// realm should be "main" for employees or "contractors" for contractors.
func (mc *MultiClusterTestContext) GetOIDCTokenForRealm(t testing.TB, ctx context.Context, username, password, realm string) string {
	cacheKey := realm + ":" + username
	if token, ok := mc.tokenCache[cacheKey]; ok {
		return token
	}

	var provider *OIDCTokenProvider
	if realm == "contractors" {
		provider = mc.ContOIDC
	} else {
		provider = mc.HubOIDC
	}

	token, err := provider.getTokenViaHTTP(ctx, username, password)
	if err != nil {
		t.Fatalf("Failed to get OIDC token for %s in realm %s: %v", username, realm, err)
	}
	mc.tokenCache[cacheKey] = token
	return token
}

// GetEmployeeToken returns a token for the test employee user
func (mc *MultiClusterTestContext) GetEmployeeToken(t testing.TB, ctx context.Context) string {
	return mc.GetOIDCTokenForRealm(t, ctx,
		MultiClusterTestUsers.Employee.Email,
		MultiClusterTestUsers.Employee.Password,
		"main")
}

// GetApproverToken returns a token for the test approver user
func (mc *MultiClusterTestContext) GetApproverToken(t testing.TB, ctx context.Context) string {
	return mc.GetOIDCTokenForRealm(t, ctx,
		MultiClusterTestUsers.Approver.Email,
		MultiClusterTestUsers.Approver.Password,
		"main")
}

// GetContractorToken returns a token for the test contractor user
func (mc *MultiClusterTestContext) GetContractorToken(t testing.TB, ctx context.Context) string {
	return mc.GetOIDCTokenForRealm(t, ctx,
		MultiClusterTestUsers.Contractor1.Email,
		MultiClusterTestUsers.Contractor1.Password,
		"contractors")
}

// GetTokenForTestUser returns a token for any TestUser from the main realm.
// This allows tests to use the full set of users defined in users.go.
func (mc *MultiClusterTestContext) GetTokenForTestUser(t testing.TB, ctx context.Context, user TestUser) string {
	return mc.GetOIDCTokenForRealm(t, ctx, user.Email, user.Password, "main")
}

// GetSpokeKubeconfig returns the kubeconfig path for a spoke cluster
func (mc *MultiClusterTestContext) GetSpokeKubeconfig(clusterName string) string {
	switch clusterName {
	case mc.Config.SpokeAClusterName:
		return mc.Config.SpokeAKubeconfig
	case mc.Config.SpokeBClusterName:
		return mc.Config.SpokeBKubeconfig
	case mc.Config.HubClusterName:
		return mc.Config.HubKubeconfig
	default:
		return ""
	}
}

// GetSpokeOIDCKubeconfig returns the OIDC-only kubeconfig path for a spoke cluster.
// This kubeconfig has no client certificates, so kubectl MUST use the --token flag
// for authentication. This is required for testing OIDC-based authorization flows.
func (mc *MultiClusterTestContext) GetSpokeOIDCKubeconfig(clusterName string) string {
	switch clusterName {
	case mc.Config.SpokeAClusterName:
		return mc.Config.SpokeAOIDCKubeconfig
	case mc.Config.SpokeBClusterName:
		return mc.Config.SpokeBOIDCKubeconfig
	default:
		return ""
	}
}
