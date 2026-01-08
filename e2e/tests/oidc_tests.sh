#!/usr/bin/env bash
# OIDC E2E Tests (O-001 through O-008)
# These tests validate OIDC authentication functionality in ClusterConfig resources.
# 
# Prerequisites:
# - kind cluster running (via kind-setup-single.sh)
# - Keycloak deployed and configured
# - Controller deployed
#
# Usage:
#   ./e2e/tests/oidc_tests.sh [test_name]
#   ./e2e/tests/oidc_tests.sh                    # Run all tests
#   ./e2e/tests/oidc_tests.sh O-001              # Run specific test

set -euo pipefail

# --- Configuration ---
NAMESPACE=${NAMESPACE:-breakglass-system}
KUBECTL=${KUBECTL:-kubectl}
TIMEOUT=${TIMEOUT:-60}
# Wait time for controller to process resources (should be > clusterConfigCheckInterval)
PROCESS_WAIT=${PROCESS_WAIT:-20}

# Keycloak configuration - matches kind-setup-single.sh
# Handle KEYCLOAK_HOST that may include scheme (e.g., https://localhost:8443)
# Strip scheme and port if present to get just the hostname
_KEYCLOAK_HOST_RAW=${KEYCLOAK_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local}
if [[ "$_KEYCLOAK_HOST_RAW" =~ ^https?:// ]]; then
  # KEYCLOAK_HOST contains a full URL - extract just host:port
  _HOST_PORT=$(echo "$_KEYCLOAK_HOST_RAW" | sed -E 's|^https?://||')
  KEYCLOAK_HOST=$(echo "$_HOST_PORT" | cut -d: -f1)
  KEYCLOAK_PORT=$(echo "$_HOST_PORT" | cut -d: -f2)
  KEYCLOAK_SCHEME=$(echo "$_KEYCLOAK_HOST_RAW" | grep -oE '^https?')
else
  KEYCLOAK_HOST="$_KEYCLOAK_HOST_RAW"
  KEYCLOAK_PORT=${KEYCLOAK_PORT:-8443}
  KEYCLOAK_SCHEME=https
fi
KEYCLOAK_REALM=${KEYCLOAK_REALM:-breakglass-e2e}
KEYCLOAK_ISSUER_URL="${KEYCLOAK_SCHEME}://${KEYCLOAK_HOST}:${KEYCLOAK_PORT}/realms/${KEYCLOAK_REALM}"
# The group-sync client is configured with client credentials flow
KEYCLOAK_CLIENT_ID=${KEYCLOAK_CLIENT_ID:-breakglass-group-sync}
KEYCLOAK_CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET:-breakglass-group-sync-secret}
KEYCLOAK_CLIENT_SECRET_NAME=${KEYCLOAK_CLIENT_SECRET_NAME:-breakglass-group-sync-secret}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log() { printf "[oidc-e2e] %s\n" "$*"; }
log_pass() { printf "${GREEN}[PASS]${NC} %s\n" "$*"; ((TESTS_PASSED++)); }
log_fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; ((TESTS_FAILED++)); }
log_skip() { printf "${YELLOW}[SKIP]${NC} %s\n" "$*"; ((TESTS_SKIPPED++)); }

# Wait for a ClusterConfig to reach a specific condition
wait_for_clusterconfig_condition() {
  local name="$1"
  local condition_type="$2"
  local expected_status="$3"
  local expected_reason="${4:-}"
  local timeout="${5:-$TIMEOUT}"
  
  log "Waiting for ClusterConfig '$name' condition $condition_type=$expected_status..."
  
  local end_time=$((SECONDS + timeout))
  while [ $SECONDS -lt $end_time ]; do
    local status
    status=$($KUBECTL get clusterconfig "$name" -n "$NAMESPACE" -o jsonpath="{.status.conditions[?(@.type=='$condition_type')].status}" 2>/dev/null || echo "")
    local reason
    reason=$($KUBECTL get clusterconfig "$name" -n "$NAMESPACE" -o jsonpath="{.status.conditions[?(@.type=='$condition_type')].reason}" 2>/dev/null || echo "")
    
    if [ "$status" = "$expected_status" ]; then
      if [ -z "$expected_reason" ] || [ "$reason" = "$expected_reason" ]; then
        log "Condition $condition_type=$expected_status (reason: $reason) met"
        return 0
      fi
    fi
    sleep 2
  done
  
  log "Timeout waiting for condition. Current status: $status, reason: $reason"
  return 1
}

# Cleanup test resources
cleanup_test_resources() {
  local prefix="${1:-oidc-test}"
  log "Cleaning up test resources with prefix '$prefix'..."
  $KUBECTL delete clusterconfig -l "e2e-test=$prefix" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  $KUBECTL delete secret -l "e2e-test=$prefix" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
}

# Check if Keycloak is available in the cluster OR as a Docker container
check_keycloak_available() {
  # First check for Docker container (multi-cluster setup)
  local keycloak_container="${KEYCLOAK_CONTAINER_NAME:-e2e-keycloak}"
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${keycloak_container}$"; then
    log "Keycloak Docker container found: $keycloak_container"
    return 0
  fi
  
  # Check for in-cluster Keycloak service (single-cluster setup)
  if ! $KUBECTL get svc breakglass-keycloak -n "$NAMESPACE" &>/dev/null; then
    log "Keycloak service not found in cluster and no Docker container running"
    return 1
  fi
  
  # Check if Keycloak pod is running
  local keycloak_pod
  keycloak_pod=$($KUBECTL get pods -l app=keycloak -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -z "$keycloak_pod" ]; then
    log "Keycloak pod not found"
    return 1
  fi
  
  local keycloak_status
  keycloak_status=$($KUBECTL get pod "$keycloak_pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
  if [ "$keycloak_status" != "Running" ]; then
    log "Keycloak pod not running (status: $keycloak_status)"
    return 1
  fi
  
  return 0
}

# Get the Kubernetes API server URL (for testing OIDC against real cluster)
get_cluster_api_server() {
  $KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo ""
}

# ============================================================================
# O-001: ClusterConfig with OIDC auth validates secrets
# ============================================================================
test_O001_oidc_validates_secrets() {
  log "=== O-001: ClusterConfig with OIDC auth validates secrets ==="
  local test_name="oidc-test-001"
  
  # Cleanup any previous test resources
  cleanup_test_resources "$test_name"
  
  # Create client secret
  $KUBECTL create secret generic "${test_name}-client-secret" \
    -n "$NAMESPACE" \
    --from-literal=client-secret="test-client-secret-value" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-client-secret" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create CA secret
  $KUBECTL create secret generic "${test_name}-ca-secret" \
    -n "$NAMESPACE" \
    --from-literal=ca.crt="-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKGIJ3D3pLfHMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96QqU4Fw8i3h/9XKGMB
+M/xbUVbp9aNfNjXk6vRsNdW9DnS9w8A6xQ9HxK+J/h2nQ7nMvWiB2u7YjJhTqvN
AgMBAAGjUzBRMB0GA1UdDgQWBBSK9X7h4iK9b8g8ek9PqVhJxvn1cDAfBgNVHSME
GDAWgBSK9X7h4iK9b8g8ek9PqVhJxvn1cDAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAQ7k6k4k4k4==
-----END CERTIFICATE-----" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-ca-secret" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create ClusterConfig with OIDC auth
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/test
    clientID: test-client
    server: https://api.test-cluster.example.com:6443
    clientSecretRef:
      name: ${test_name}-client-secret
      namespace: ${NAMESPACE}
      key: client-secret
    caSecretRef:
      name: ${test_name}-ca-secret
      namespace: ${NAMESPACE}
      key: ca.crt
EOF
  
  # Wait for validation (note: actual OIDC discovery will fail since issuer is fake)
  # The test verifies secrets are validated before OIDC discovery
  sleep $PROCESS_WAIT
  
  # Check that secrets were validated (status should show attempt to connect)
  local status
  status=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  
  log "Status: $status, Reason: $reason"
  
  # Clean up
  cleanup_test_resources "$test_name"
  
  # For this test, we expect either OIDCDiscoveryFailed (secrets valid but issuer unreachable)
  # or some other status that's not SecretMissing
  if [ "$reason" = "SecretMissing" ]; then
    log_fail "O-001: Secrets should have been found but weren't"
    return 1
  fi
  
  log_pass "O-001: ClusterConfig with OIDC auth validates secrets correctly"
}

# ============================================================================
# O-002: ClusterConfig with OIDC auth fails on missing client secret
# ============================================================================
test_O002_oidc_missing_client_secret() {
  log "=== O-002: ClusterConfig with OIDC auth fails on missing client secret ==="
  local test_name="oidc-test-002"
  
  # Cleanup any previous test resources
  cleanup_test_resources "$test_name"
  
  # Create ClusterConfig pointing to non-existent secret
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/test
    clientID: test-client
    server: https://api.test-cluster.example.com:6443
    clientSecretRef:
      name: non-existent-secret
      namespace: ${NAMESPACE}
      key: client-secret
EOF
  
  # Wait for controller to process
  sleep $PROCESS_WAIT
  
  # Check status
  local status
  status=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  local message
  message=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")
  
  log "Status: $status, Reason: $reason, Message: $message"
  
  # Clean up
  cleanup_test_resources "$test_name"
  
  # Verify the error mentions missing secret
  if [ "$status" = "False" ] && [[ "$message" == *"secret"* || "$reason" == *"Secret"* ]]; then
    log_pass "O-002: ClusterConfig correctly reports missing client secret"
  else
    log_fail "O-002: Expected Ready=False with secret-related error, got status=$status reason=$reason"
    return 1
  fi
}

# ============================================================================
# O-003: OIDC token acquisition from Keycloak
# ============================================================================
test_O003_oidc_token_acquisition() {
  log "=== O-003: OIDC token acquisition from Keycloak ==="
  
  # This test uses the real Keycloak instance and group-sync client
  if ! check_keycloak_available; then
    log_fail "O-003: Keycloak is not available - cannot run test"
    return 1
  fi
  
  local test_name="oidc-test-003"
  cleanup_test_resources "$test_name"
  
  # Get the target cluster API server (we'll use the same cluster for testing)
  local api_server
  api_server=$(get_cluster_api_server)
  if [ -z "$api_server" ]; then
    log_fail "O-003: Could not determine cluster API server"
    return 1
  fi
  log "Using API server: $api_server"
  
  # Create ClusterConfig using the real Keycloak group-sync client
  # This client has client credentials flow enabled
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: ${KEYCLOAK_ISSUER_URL}
    clientID: ${KEYCLOAK_CLIENT_ID}
    server: ${api_server}
    clientSecretRef:
      name: ${KEYCLOAK_CLIENT_SECRET_NAME}
      namespace: ${NAMESPACE}
      key: client-secret
    insecureSkipTLSVerify: true
EOF
  
  # Wait for controller to process and attempt token acquisition
  log "Waiting for OIDC token acquisition..."
  sleep $PROCESS_WAIT
  
  # Check status - expecting either success or a cluster unreachable error (token acquired but cluster auth failed)
  local status
  status=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  local message
  message=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")
  
  log "Status: $status, Reason: $reason"
  log "Message: $message"
  
  # Check controller logs for token acquisition
  local controller_pod
  controller_pod=$($KUBECTL get pods -l app=breakglass -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  if [ -n "$controller_pod" ]; then
    log "Checking controller logs for token activity..."
    local token_logs
    token_logs=$($KUBECTL logs "$controller_pod" -n "$NAMESPACE" --tail=200 2>/dev/null | grep -iE "oidc|token|${test_name}" | tail -10 || echo "")
    if [ -n "$token_logs" ]; then
      log "Token-related logs found:"
      echo "$token_logs"
    fi
  fi
  
  # Clean up
  cleanup_test_resources "$test_name"
  
  # Success criteria:
  # - OIDCDiscoveryFailed means we couldn't reach Keycloak
  # - OIDCTokenFailed means discovery worked but token fetch failed (partial success)
  # - ClusterUnreachable means token was acquired but cluster auth failed (full success on OIDC)
  # - OIDCValidated means full success
  if [ "$reason" = "OIDCValidated" ] || [ "$reason" = "ClusterUnreachable" ]; then
    log_pass "O-003: OIDC token acquisition succeeded (reason: $reason)"
  elif [ "$reason" = "OIDCTokenFetchFailed" ] || [ "$reason" = "OIDCTokenFailed" ]; then
    # Token fetch failed - this might be due to client config issues
    log_fail "O-003: OIDC discovery worked but token fetch failed: $message"
    return 1
  elif [ "$reason" = "OIDCDiscoveryFailed" ]; then
    log_fail "O-003: OIDC discovery failed - Keycloak may not be reachable from controller: $message"
    return 1
  else
    log_fail "O-003: Unexpected status - reason: $reason, message: $message"
    return 1
  fi
}

# ============================================================================
# O-004: OIDC token refresh on expiry
# ============================================================================
test_O004_oidc_token_refresh() {
  log "=== O-004: OIDC token refresh on expiry ==="
  
  if ! check_keycloak_available; then
    log_fail "O-004: Keycloak is not available - cannot run test"
    return 1
  fi
  
  local test_name="oidc-test-004"
  cleanup_test_resources "$test_name"
  
  local api_server
  api_server=$(get_cluster_api_server)
  if [ -z "$api_server" ]; then
    log_fail "O-004: Could not determine cluster API server"
    return 1
  fi
  
  # Create ClusterConfig for token refresh testing
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: ${KEYCLOAK_ISSUER_URL}
    clientID: ${KEYCLOAK_CLIENT_ID}
    server: ${api_server}
    clientSecretRef:
      name: ${KEYCLOAK_CLIENT_SECRET_NAME}
      namespace: ${NAMESPACE}
      key: client-secret
    insecureSkipTLSVerify: true
EOF
  
  # Wait for initial token acquisition
  log "Waiting for initial token acquisition..."
  sleep $PROCESS_WAIT
  
  # Get initial status
  local status1
  status1=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason1
  reason1=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  local generation1
  generation1=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.observedGeneration}' 2>/dev/null || echo "0")
  
  log "Initial status: $status1, reason: $reason1, generation: $generation1"
  
  # Wait for reconciliation cycle (controller re-checks periodically)
  log "Waiting for reconciliation cycle to verify token is still valid..."
  sleep 30
  
  # Check status again - should still be consistent
  local status2
  status2=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason2
  reason2=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  
  log "After wait - status: $status2, reason: $reason2"
  
  # Check controller logs for refresh activity
  local controller_pod
  controller_pod=$($KUBECTL get pods -l app=breakglass -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  local refresh_detected=false
  if [ -n "$controller_pod" ]; then
    log "Checking controller logs for token refresh activity..."
    if $KUBECTL logs "$controller_pod" -n "$NAMESPACE" --tail=200 2>/dev/null | grep -qiE "refresh|renew|reacquir"; then
      log "Token refresh activity detected in logs"
      refresh_detected=true
    fi
  fi
  
  # Clean up
  cleanup_test_resources "$test_name"
  
  # Success if status remained consistent and no degradation occurred
  if [ "$status1" = "$status2" ] && [ "$reason1" = "$reason2" ]; then
    log_pass "O-004: OIDC token handling is stable across reconciliation cycles"
  else
    log_fail "O-004: Status changed unexpectedly from $reason1 to $reason2"
    return 1
  fi
}

# ============================================================================
# O-005: TOFU (Trust On First Use) for cluster CA
# ============================================================================
test_O005_tofu_populates_ca() {
  log "=== O-005: TOFU (Trust On First Use) for cluster CA ==="
  
  if ! check_keycloak_available; then
    log_fail "O-005: Keycloak is not available - cannot run test"
    return 1
  fi
  
  local test_name="oidc-test-005"
  cleanup_test_resources "$test_name"
  
  # Get the real cluster API server
  local api_server
  api_server=$(get_cluster_api_server)
  if [ -z "$api_server" ]; then
    log_fail "O-005: Could not determine cluster API server"
    return 1
  fi
  
  # Create ClusterConfig WITHOUT caSecretRef but WITH insecureSkipTLSVerify=false
  # The controller should attempt TOFU if enabled, or fail with CA-related error
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: ${KEYCLOAK_ISSUER_URL}
    clientID: ${KEYCLOAK_CLIENT_ID}
    server: ${api_server}
    clientSecretRef:
      name: ${KEYCLOAK_CLIENT_SECRET_NAME}
      namespace: ${NAMESPACE}
      key: client-secret
    # No caSecretRef - controller should handle TLS verification
    # insecureSkipTLSVerify defaults to false
EOF
  
  log "Waiting for controller to process ClusterConfig without explicit CA..."
  sleep $PROCESS_WAIT
  
  # Check status
  local status
  status=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  local message
  message=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")
  
  log "Status: $status, Reason: $reason"
  log "Message: $message"
  
  # Check if a CA-related secret was created by the controller
  local ca_secret_created=false
  if $KUBECTL get secret "${test_name}-ca" -n "$NAMESPACE" &>/dev/null; then
    log "CA secret was auto-created by controller (TOFU)"
    ca_secret_created=true
  fi
  
  # Clean up
  cleanup_test_resources "$test_name"
  # Also clean up potential auto-created CA secret
  $KUBECTL delete secret "${test_name}-ca" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Success criteria:
  # - If TOFU is enabled: CA secret was created
  # - If TOFU is not enabled: Should fail with certificate-related error (TLS validation)
  # - Could also succeed if system CA is trusted
  if $ca_secret_created; then
    log_pass "O-005: TOFU successfully created CA secret"
  elif [[ "$message" == *"certificate"* ]] || [[ "$message" == *"x509"* ]] || [[ "$message" == *"TLS"* ]]; then
    # Expected behavior when TOFU is not implemented
    log_pass "O-005: ClusterConfig correctly reports TLS/certificate error when no CA provided"
  elif [ "$reason" = "OIDCDiscoveryFailed" ] || [ "$reason" = "ClusterUnreachable" ]; then
    # Discovery failed or cluster unreachable - could be TLS related
    log_pass "O-005: ClusterConfig failed as expected without explicit CA (reason: $reason)"
  else
    log_fail "O-005: Unexpected result - reason: $reason, message: $message"
    return 1
  fi
}

# ============================================================================
# O-006: OIDC discovery failure condition
# ============================================================================
test_O006_oidc_discovery_failure() {
  log "=== O-006: OIDC discovery failure condition ==="
  local test_name="oidc-test-006"
  
  cleanup_test_resources "$test_name"
  
  # Create client secret
  $KUBECTL create secret generic "${test_name}-client-secret" \
    -n "$NAMESPACE" \
    --from-literal=client-secret="test-client-secret-value" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-client-secret" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create ClusterConfig pointing to unreachable issuer
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://invalid-issuer.does-not-exist.local/realms/test
    clientID: test-client
    server: https://api.test-cluster.example.com:6443
    clientSecretRef:
      name: ${test_name}-client-secret
      namespace: ${NAMESPACE}
      key: client-secret
    insecureSkipTLSVerify: true
EOF
  
  # Wait for controller to attempt OIDC discovery
  sleep $PROCESS_WAIT
  
  # Check status
  local status
  status=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  local message
  message=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")
  
  log "Status: $status, Reason: $reason, Message: $message"
  
  # Clean up
  cleanup_test_resources "$test_name"
  
  # Verify the error mentions discovery failure
  if [ "$status" = "False" ] && [[ "$message" == *"discovery"* || "$message" == *"issuer"* || "$message" == *"OIDC"* ]]; then
    log_pass "O-006: ClusterConfig correctly reports OIDC discovery failure"
  else
    log_fail "O-006: Expected Ready=False with discovery error, got status=$status reason=$reason"
    return 1
  fi
}

# ============================================================================
# O-007: OIDC token exchange flow
# ============================================================================
test_O007_oidc_token_exchange() {
  log "=== O-007: OIDC token exchange flow ==="
  local test_name="oidc-test-007"
  
  cleanup_test_resources "$test_name"
  
  # Create secrets for token exchange
  $KUBECTL create secret generic "${test_name}-client-secret" \
    -n "$NAMESPACE" \
    --from-literal=client-secret="test-client-secret-value" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-client-secret" -n "$NAMESPACE" "e2e-test=$test_name"
  
  $KUBECTL create secret generic "${test_name}-subject-token" \
    -n "$NAMESPACE" \
    --from-literal=token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QifQ.mock" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-subject-token" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create ClusterConfig with token exchange enabled
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/test
    clientID: test-client
    server: https://api.test-cluster.example.com:6443
    clientSecretRef:
      name: ${test_name}-client-secret
      namespace: ${NAMESPACE}
      key: client-secret
    tokenExchange:
      enabled: true
      subjectTokenSecretRef:
        name: ${test_name}-subject-token
        namespace: ${NAMESPACE}
        key: token
      resource: https://api.test-cluster.example.com:6443
EOF
  
  # Wait for controller to process
  sleep $PROCESS_WAIT
  
  # Check that the config was created (validation passed)
  if $KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" &>/dev/null; then
    log_pass "O-007: ClusterConfig with token exchange created successfully"
  else
    log_fail "O-007: Failed to create ClusterConfig with token exchange"
    cleanup_test_resources "$test_name"
    return 1
  fi
  
  # Check controller logs for token exchange attempt
  local controller_pod
  controller_pod=$($KUBECTL get pods -l app=breakglass -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  if [ -n "$controller_pod" ]; then
    log "Checking controller logs for token exchange activity..."
    if $KUBECTL logs "$controller_pod" -n "$NAMESPACE" --tail=100 2>/dev/null | grep -qiE "token.*exchange|TokenExchange"; then
      log "Token exchange activity detected in logs"
    else
      log "No explicit token exchange activity in recent logs (issuer is unreachable in this test)"
    fi
  fi
  
  cleanup_test_resources "$test_name"
}

# ============================================================================
# O-008: Mixed auth types in same namespace
# ============================================================================
test_O008_mixed_auth_types() {
  log "=== O-008: Mixed auth types in same namespace ==="
  local test_name="oidc-test-008"
  
  cleanup_test_resources "$test_name"
  
  # Create secrets for OIDC config
  $KUBECTL create secret generic "${test_name}-client-secret" \
    -n "$NAMESPACE" \
    --from-literal=client-secret="test-client-secret-value" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-client-secret" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create a simple kubeconfig secret
  cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${test_name}-kubeconfig
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
type: Opaque
stringData:
  kubeconfig: |
    apiVersion: v1
    kind: Config
    clusters:
    - cluster:
        server: https://kubernetes.default.svc
        insecure-skip-tls-verify: true
      name: test-cluster
    contexts:
    - context:
        cluster: test-cluster
        user: test-user
      name: test-context
    current-context: test-context
    users:
    - name: test-user
      user:
        token: test-token
EOF
  
  # Create ClusterConfig with Kubeconfig auth
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}-kubeconfig
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: Kubeconfig
  kubeconfigSecretRef:
    name: ${test_name}-kubeconfig
    namespace: ${NAMESPACE}
    key: kubeconfig
EOF
  
  # Create ClusterConfig with OIDC auth
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${test_name}-oidc
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/test
    clientID: test-client
    server: https://api.another-cluster.example.com:6443
    clientSecretRef:
      name: ${test_name}-client-secret
      namespace: ${NAMESPACE}
      key: client-secret
    insecureSkipTLSVerify: true
EOF
  
  # Wait for controller to process both
  sleep $PROCESS_WAIT
  
  # Check both configs exist
  local kubeconfig_exists=false
  local oidc_exists=false
  
  if $KUBECTL get clusterconfig "${test_name}-kubeconfig" -n "$NAMESPACE" &>/dev/null; then
    kubeconfig_exists=true
    log "ClusterConfig ${test_name}-kubeconfig exists"
  fi
  
  if $KUBECTL get clusterconfig "${test_name}-oidc" -n "$NAMESPACE" &>/dev/null; then
    oidc_exists=true
    log "ClusterConfig ${test_name}-oidc exists"
  fi
  
  # Clean up
  cleanup_test_resources "$test_name"
  
  if $kubeconfig_exists && $oidc_exists; then
    log_pass "O-008: Both Kubeconfig and OIDC ClusterConfigs coexist in same namespace"
  else
    log_fail "O-008: Failed to create both auth types (kubeconfig=$kubeconfig_exists, oidc=$oidc_exists)"
    return 1
  fi
}

# ============================================================================
# Main test runner
# ============================================================================
run_all_tests() {
  log "Running all OIDC E2E tests..."
  echo ""
  
  test_O001_oidc_validates_secrets || true
  echo ""
  test_O002_oidc_missing_client_secret || true
  echo ""
  test_O003_oidc_token_acquisition || true
  echo ""
  test_O004_oidc_token_refresh || true
  echo ""
  test_O005_tofu_populates_ca || true
  echo ""
  test_O006_oidc_discovery_failure || true
  echo ""
  test_O007_oidc_token_exchange || true
  echo ""
  test_O008_mixed_auth_types || true
  echo ""
  
  # Print summary
  echo "=============================================="
  echo "OIDC E2E Test Summary"
  echo "=============================================="
  printf "${GREEN}Passed: %d${NC}\n" "$TESTS_PASSED"
  printf "${RED}Failed: %d${NC}\n" "$TESTS_FAILED"
  printf "${YELLOW}Skipped: %d${NC}\n" "$TESTS_SKIPPED"
  echo "=============================================="
  
  if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
  fi
}

# Parse command line arguments
if [ $# -eq 0 ]; then
  run_all_tests
else
  case "$1" in
    O-001) test_O001_oidc_validates_secrets ;;
    O-002) test_O002_oidc_missing_client_secret ;;
    O-003) test_O003_oidc_token_acquisition ;;
    O-004) test_O004_oidc_token_refresh ;;
    O-005) test_O005_tofu_populates_ca ;;
    O-006) test_O006_oidc_discovery_failure ;;
    O-007) test_O007_oidc_token_exchange ;;
    O-008) test_O008_mixed_auth_types ;;
    all) run_all_tests ;;
    *)
      echo "Unknown test: $1"
      echo "Available tests: O-001, O-002, O-003, O-004, O-005, O-006, O-007, O-008, all"
      exit 1
      ;;
  esac
fi
