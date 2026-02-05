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
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getEnvOrDefault returns the environment variable value or the default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// IsE2EEnabled returns true if E2E tests should run
func IsE2EEnabled() bool {
	return os.Getenv("E2E_TEST") == "true"
}

// GetTestNamespace returns the namespace to use for E2E tests
func GetTestNamespace() string {
	return getEnvOrDefault("E2E_NAMESPACE", "default")
}

// GetTmuxDebugImage returns the image used for tmux-enabled terminal sharing tests.
func GetTmuxDebugImage() string {
	return getEnvOrDefault("TMUX_DEBUG_IMAGE", "breakglass-tmux-debug:latest")
}

// GetAPIBaseURL returns the base URL for the breakglass API
// Defaults to localhost:8080 which works with port-forwarding to the breakglass service
func GetAPIBaseURL() string {
	return getEnvOrDefault("BREAKGLASS_API_URL", "http://localhost:8080")
}

// GetKeycloakHost returns the Keycloak host URL
func GetKeycloakHost() string {
	return getEnvOrDefault("KEYCLOAK_HOST", "http://localhost:8180")
}

// GetKeycloakRealm returns the Keycloak realm name
func GetKeycloakRealm() string {
	return getEnvOrDefault("KEYCLOAK_REALM", "breakglass-e2e")
}

// GetTestClusterName returns the cluster name for E2E tests
func GetTestClusterName() string {
	return getEnvOrDefault("E2E_CLUSTER_NAME", "tenant-a")
}

// GetTestUserEmail returns the test user email
// Defaults to TestUsers.Requester.Email to match Keycloak realm configuration
func GetTestUserEmail() string {
	return getEnvOrDefault("E2E_TEST_USER", "test-user@example.com")
}

// GetTestApproverEmail returns the test approver email
// Defaults to TestUsers.Approver.Email to match Keycloak realm configuration
func GetTestApproverEmail() string {
	return getEnvOrDefault("E2E_TEST_APPROVER", "approver@example.org")
}

// GetWebhookURL returns the webhook URL for E2E tests
// Defaults to the API base URL since the SAR webhook is served via the API server
// at /api/breakglass/webhook/authorize/:cluster
func GetWebhookURL() string {
	return getEnvOrDefault("BREAKGLASS_WEBHOOK_URL", GetAPIBaseURL())
}

// GetWebhookAuthorizePath returns the full path for the webhook authorize endpoint for a specific cluster
// The SAR webhook is served at /api/breakglass/webhook/authorize/:cluster
func GetWebhookAuthorizePath(clusterName string) string {
	return fmt.Sprintf("%s/api/breakglass/webhook/authorize/%s", GetWebhookURL(), clusterName)
}

// GetTestUserPassword returns the test user password
func GetTestUserPassword() string {
	return getEnvOrDefault("E2E_TEST_USER_PASSWORD", "testpassword")
}

// GetTestApproverPassword returns the test approver password
func GetTestApproverPassword() string {
	return getEnvOrDefault("E2E_TEST_APPROVER_PASSWORD", "testpassword")
}

// GetKubernetesAPIServerURL returns the Kubernetes API server URL to use in ClusterConfig.
// This URL must be reachable FROM THE CONTROLLER POD, not from the test runner.
// The controller runs inside the cluster, so it needs an in-cluster URL.
//
// Priority order:
// 1. KUBERNETES_API_SERVER_INTERNAL environment variable (Docker container IP:6443)
// 2. E2E_SPOKE_API_SERVER environment variable (multi-cluster spoke - external IP)
// 3. Default to https://kubernetes.default.svc:443 (standard in-cluster URL)
//
// Note: KUBERNETES_API_SERVER (from kubeconfig) is for external test access.
// For ClusterConfig.Server field, always use an in-cluster reachable URL.
func GetKubernetesAPIServerURL() string {
	// Explicit internal URL (Docker container IP:6443) takes priority
	// This is consistent between single-cluster and multi-cluster setups
	if url := os.Getenv("KUBERNETES_API_SERVER_INTERNAL"); url != "" {
		return url
	}
	// Multi-cluster spoke API server (these use external IPs reachable from hub controller)
	if url := os.Getenv("E2E_SPOKE_API_SERVER"); url != "" {
		return url
	}
	// Default to in-cluster API server (controller runs inside the cluster)
	return "https://kubernetes.default.svc:443"
}

// GetOIDCEnabledAPIServerURL returns a Kubernetes API server URL that has OIDC authentication enabled.
// In multi-cluster mode, this returns a spoke cluster's API server (spokes have OIDC configured).
// In single-cluster mode, this returns the internal API server URL.
//
// This is specifically for tests that need to validate OIDC authentication against a cluster.
// The hub cluster in multi-cluster mode does NOT have OIDC configured.
//
// IMPORTANT: Returns the INTERNAL URL (container IP:6443) that's reachable from the controller pod,
// not the localhost URL used by the test runner. The controller runs inside a Kind cluster and
// cannot reach localhost port-forwards.
func GetOIDCEnabledAPIServerURL() string {
	// In multi-cluster mode, use spoke A's internal API server (container IP)
	// This is reachable from the controller pod running in the hub cluster
	if IsMultiClusterEnabled() {
		// MUST use internal URL - external URLs (localhost port-forwards) are NOT reachable
		// from the controller pod inside the Kind cluster
		if url := os.Getenv("E2E_SPOKE_A_API_SERVER_INTERNAL"); url != "" {
			return url
		}
		// DO NOT fall back to E2E_SPOKE_A_API_SERVER - it's a localhost URL that won't work
		// from controller pod. Fall through to kubernetes.default.svc instead.
	}

	// Single-cluster mode: use the internal API server URL (container IP:6443)
	// This is set by kind-setup-single.sh as KUBERNETES_API_SERVER_INTERNAL
	if url := os.Getenv("KUBERNETES_API_SERVER_INTERNAL"); url != "" {
		return url
	}

	// Fallback to standard in-cluster service URL
	// Note: This may not have OIDC configured depending on cluster setup
	return "https://kubernetes.default.svc:443"
}

// IsWebhookTestEnabled returns true if webhook tests should run
// Webhook tests require the API to be port-forwarded and accessible
func IsWebhookTestEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_WEBHOOK_TESTS") == "true" {
		return false
	}
	// Webhook tests are enabled when E2E is enabled
	return IsE2EEnabled()
}

// IsMetricsTestEnabled returns true if metrics tests should run
// Metrics tests require the metrics endpoint to be port-forwarded and accessible
func IsMetricsTestEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_METRICS_TESTS") == "true" {
		return false
	}
	// Metrics tests are enabled by default when E2E is enabled
	return IsE2EEnabled()
}

// IsAuditTestEnabled returns true if audit tests should run
// Audit tests require the audit log to be configured and accessible
func IsAuditTestEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_AUDIT_TESTS") == "true" {
		return false
	}
	// Audit tests are enabled by default when E2E is enabled
	return IsE2EEnabled()
}

// GetKeycloakClientID returns the Keycloak client ID for the breakglass UI
func GetKeycloakClientID() string {
	return getEnvOrDefault("KEYCLOAK_CLIENT_ID", "breakglass-ui")
}

// GetKeycloakIssuerHost returns the host to use for the token issuer claim
// This is used to override the Host header when requesting tokens via port-forward
func GetKeycloakIssuerHost() string {
	return getEnvOrDefault("KEYCLOAK_ISSUER_HOST", "")
}

// GetMailHogAPIURL returns the MailHog API URL for testing email notifications
// MailHog exposes an API on port 8025 for retrieving emails
func GetMailHogAPIURL() string {
	return getEnvOrDefault("MAILHOG_API_URL", "http://localhost:8025")
}

// IsMailHogTestEnabled returns true if MailHog notification tests should run
func IsMailHogTestEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_MAILHOG_TESTS") == "true" {
		return false
	}
	// MailHog tests are enabled when E2E is enabled
	return IsE2EEnabled()
}

// GetKeycloakURL returns the Keycloak base URL for testing (external/port-forward URL)
// Falls back to KEYCLOAK_HOST if KEYCLOAK_URL is not set.
// Use this for direct test-to-Keycloak communication (e.g., getting tokens for tests).
func GetKeycloakURL() string {
	if url := os.Getenv("KEYCLOAK_URL"); url != "" {
		return url
	}
	if url := os.Getenv("KEYCLOAK_HOST"); url != "" {
		return url
	}
	return "http://localhost:8180"
}

// GetKeycloakInternalURL returns the Keycloak URL as seen from inside the cluster.
// This should be used when creating ClusterConfig OIDC issuer URLs that the controller
// will use - the controller runs inside the cluster and cannot reach localhost URLs.
// Returns the internal service URL (e.g., https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443).
func GetKeycloakInternalURL() string {
	// Check for explicit internal URL (set by multi-cluster setup)
	if url := os.Getenv("KEYCLOAK_INTERNAL_URL"); url != "" {
		return url
	}
	// Check for explicit issuer URL override
	if url := os.Getenv("KEYCLOAK_ISSUER_URL"); url != "" {
		return url
	}
	// Check for issuer host (without scheme/realm)
	if host := os.Getenv("KEYCLOAK_ISSUER_HOST"); host != "" {
		return "https://" + host
	}
	// Check for internal service hostname
	if host := os.Getenv("KEYCLOAK_SERVICE_HOSTNAME"); host != "" {
		return "https://" + host + ":8443"
	}
	// Default to standard in-cluster service URL
	return "https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443"
}

// IsKeycloakTestEnabled returns true if Keycloak-specific tests should run
func IsKeycloakTestEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_KEYCLOAK_TESTS") == "true" {
		return false
	}
	// Check if Keycloak URL is configured
	return GetKeycloakURL() != "" && IsE2EEnabled()
}

// GetKeycloakServiceAccountClientID returns the Keycloak client ID for the service account
// used for admin API access (e.g., group sync operations).
// Uses KEYCLOAK_GROUP_SYNC_CLIENT_ID which is set by e2e setup scripts.
func GetKeycloakServiceAccountClientID() string {
	// Try the group sync specific env var first (set by kind-setup-single.sh)
	if id := os.Getenv("KEYCLOAK_GROUP_SYNC_CLIENT_ID"); id != "" {
		return id
	}
	// Fall back to generic service account env var
	return getEnvOrDefault("KEYCLOAK_SERVICE_ACCOUNT_CLIENT_ID", "breakglass-group-sync")
}

// GetKeycloakServiceAccountSecret returns the client secret for the Keycloak service account.
// Uses KEYCLOAK_GROUP_SYNC_CLIENT_SECRET which is set by e2e setup scripts.
func GetKeycloakServiceAccountSecret() string {
	// Try the group sync specific env var first (set by kind-setup-single.sh)
	if secret := os.Getenv("KEYCLOAK_GROUP_SYNC_CLIENT_SECRET"); secret != "" {
		return secret
	}
	// Fall back to generic service account env var
	return getEnvOrDefault("KEYCLOAK_SERVICE_ACCOUNT_SECRET", "breakglass-group-sync-secret")
}

// OIDCClientConfig holds the configuration for an OIDC client.
// It can represent either a public client (no secret, uses PKCE/kubelogin)
// or a confidential client (with secret, uses client credentials flow).
type OIDCClientConfig struct {
	// ClientID is the OIDC client identifier
	ClientID string
	// ClientSecret is the client secret (empty for public clients)
	ClientSecret string
	// IsPublic indicates if this is a public client (no secret, uses PKCE)
	IsPublic bool
}

// GetOIDCClientConfig returns the appropriate OIDC client configuration based on environment.
// It supports two authentication models:
//
// 1. Service Account Client (Confidential): Uses client credentials flow.
//   - Set KEYCLOAK_GROUP_SYNC_CLIENT_ID and KEYCLOAK_GROUP_SYNC_CLIENT_SECRET
//   - This is the preferred method for controller-to-Keycloak authentication
//   - Example: breakglass-group-sync client
//
// 2. Public Client: Uses Authorization Code + PKCE flow (like kubelogin).
//   - Set KEYCLOAK_USE_PUBLIC_CLIENT=true to prefer public client
//   - Set KEYCLOAK_CLIENT_ID to specify the public client ID (default: breakglass-ui)
//   - Requires user interaction or pre-existing token
//
// The controller uses client credentials flow when ClusterConfig has a clientSecretRef,
// so tests that validate OIDC ClusterConfig connectivity should use a confidential client.
func GetOIDCClientConfig() OIDCClientConfig {
	// Check if public client mode is explicitly requested
	if os.Getenv("KEYCLOAK_USE_PUBLIC_CLIENT") == "true" {
		return OIDCClientConfig{
			ClientID:     GetKeycloakClientID(),
			ClientSecret: "",
			IsPublic:     true,
		}
	}

	// Default to service account (confidential) client
	clientID := GetKeycloakServiceAccountClientID()
	clientSecret := GetKeycloakServiceAccountSecret()

	// If we have a valid service account secret, use confidential client
	// Note: "breakglass-group-sync-secret" is the actual Keycloak client secret value
	// defined in config/dev/resources/breakglass-e2e-realm.json, so it IS a valid secret.
	if clientSecret != "" {
		return OIDCClientConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			IsPublic:     false,
		}
	}

	// Fall back to public client if no secret is configured
	return OIDCClientConfig{
		ClientID:     GetKeycloakClientID(),
		ClientSecret: "",
		IsPublic:     true,
	}
}

// GetKeycloakCAFromCluster retrieves the Keycloak TLS CA certificate from the cluster.
// The CA certificate is stored in a ConfigMap named "breakglass-certs" in the system namespace.
// This should be used when creating ClusterConfig with OIDC to allow the controller to
// verify Keycloak's TLS certificate. Returns empty string if the ConfigMap is not found.
// Requires a Kubernetes client to be available.
//
// Priority order:
// 1. KEYCLOAK_CA environment variable (direct PEM content)
// 2. KEYCLOAK_CA_FILE environment variable (path to CA file)
// 3. ConfigMap breakglass-breakglass-certs or breakglass-certs in system namespace
func GetKeycloakCAFromCluster(ctx context.Context, cli client.Client, _ string) string {
	// 1. Check for direct CA content in environment
	if caData := os.Getenv("KEYCLOAK_CA"); caData != "" {
		return caData
	}

	// 2. Check for CA file path
	if caFile := os.Getenv("KEYCLOAK_CA_FILE"); caFile != "" {
		data, err := os.ReadFile(caFile)
		if err == nil {
			return string(data)
		}
		// Fall through to ConfigMap lookup
	}

	// 3. Look in ConfigMap
	// The CA cert is stored in the breakglass-certs ConfigMap in the system namespace
	// (created by kustomize from config/dev/kustomization.yaml)
	systemNamespace := getEnvOrDefault("BREAKGLASS_SYSTEM_NAMESPACE", "breakglass-system")

	var configMap corev1.ConfigMap
	key := client.ObjectKey{Namespace: systemNamespace, Name: "breakglass-breakglass-certs"}
	if err := cli.Get(ctx, key, &configMap); err != nil {
		// Try without the prefix (in case namePrefix is not applied)
		key.Name = "breakglass-certs"
		if err := cli.Get(ctx, key, &configMap); err != nil {
			return ""
		}
	}
	if caData, ok := configMap.Data["ca.crt"]; ok {
		return caData
	}
	return ""
}

// IsKafkaEnabled returns true if Kafka-specific tests should run
// Kafka tests require the Kafka deployment to be available in the e2e environment
func IsKafkaEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_KAFKA_TESTS") == "true" {
		return false
	}
	// Check if explicitly enabled
	if os.Getenv("KAFKA_TEST") == "true" {
		return true
	}
	// Kafka tests are disabled by default since Kafka may not always be available
	return false
}

// GetKafkaBrokers returns the Kafka broker addresses for e2e tests
// Note: Uses breakglass-kafka (kustomize adds breakglass- prefix to kafka service)
func GetKafkaBrokers() string {
	return getEnvOrDefault("KAFKA_BROKERS", "breakglass-kafka.breakglass-system.svc.cluster.local:9092")
}

// GetKafkaAuditTopic returns the Kafka topic for audit events
func GetKafkaAuditTopic() string {
	return getEnvOrDefault("KAFKA_AUDIT_TOPIC", "breakglass-audit-events")
}

// GetAuditWebhookReceiverURL returns the URL for the audit webhook receiver service
// This is used to test webhook audit sink functionality in e2e tests.
// Note: Uses breakglass-audit-webhook-receiver (kustomize adds breakglass- prefix)
func GetAuditWebhookReceiverURL() string {
	return getEnvOrDefault("AUDIT_WEBHOOK_RECEIVER_URL",
		"http://breakglass-audit-webhook-receiver.breakglass-system.svc.cluster.local")
}

// GetAuditWebhookReceiverExternalURL returns the externally accessible URL for the webhook receiver.
// Used for port-forwarded access from e2e tests running outside the cluster.
func GetAuditWebhookReceiverExternalURL() string {
	return getEnvOrDefault("AUDIT_WEBHOOK_RECEIVER_EXTERNAL_URL", "http://localhost:8090")
}

// IsAuditWebhookTestEnabled returns true if audit webhook tests should run
func IsAuditWebhookTestEnabled() bool {
	// Check if explicitly disabled
	if os.Getenv("E2E_SKIP_AUDIT_WEBHOOK_TESTS") == "true" {
		return false
	}
	// Check if explicitly enabled
	if os.Getenv("AUDIT_WEBHOOK_TEST") == "true" {
		return true
	}
	// Audit webhook tests are enabled by default when E2E is enabled
	return IsE2EEnabled()
}
