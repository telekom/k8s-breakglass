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
	"os"
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
	HubKubeconfig       string
	SpokeAKubeconfig    string
	SpokeBKubeconfig    string
	HubClusterName      string
	SpokeAClusterName   string
	SpokeBClusterName   string
	MainRealm           string
	ContractorsRealm    string
	MainClientID        string
	ContractorsClientID string
	// Hub external access for spoke clusters
	HubExternalIP string
	HubWebhookURL string
	HubAPIURL     string
}

// GetMultiClusterConfig returns the full multi-cluster configuration
func GetMultiClusterConfig() MultiClusterConfig {
	return MultiClusterConfig{
		HubKubeconfig:       GetHubKubeconfig(),
		SpokeAKubeconfig:    GetSpokeAKubeconfig(),
		SpokeBKubeconfig:    GetSpokeBKubeconfig(),
		HubClusterName:      GetHubClusterName(),
		SpokeAClusterName:   GetSpokeAClusterName(),
		SpokeBClusterName:   GetSpokeBClusterName(),
		MainRealm:           GetKeycloakMainRealm(),
		ContractorsRealm:    GetKeycloakContractorsRealm(),
		MainClientID:        GetKeycloakClientID(),
		ContractorsClientID: GetContractorsClientID(),
		HubExternalIP:       GetHubExternalIP(),
		HubWebhookURL:       GetHubWebhookURL(),
		HubAPIURL:           GetHubAPIURL(),
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
		Email:    "test-user@example.com",
		Password: "testpassword",
		Groups:   []string{"developers", "breakglass-users"},
	},
	Approver: struct {
		Email    string
		Password string
		Groups   []string
	}{
		Email:    "approver@example.org",
		Password: "testpassword",
		Groups:   []string{"breakglass-approvers", "team-leads"},
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
