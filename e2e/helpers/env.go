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
	"fmt"
	"os"
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

// GetKeycloakURL returns the Keycloak base URL for testing
// Falls back to KEYCLOAK_HOST if KEYCLOAK_URL is not set
func GetKeycloakURL() string {
	if url := os.Getenv("KEYCLOAK_URL"); url != "" {
		return url
	}
	if url := os.Getenv("KEYCLOAK_HOST"); url != "" {
		return url
	}
	return "http://localhost:8180"
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
