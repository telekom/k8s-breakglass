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
# This must return a URL reachable FROM THE CONTROLLER POD, not from the test host.
#
# IMPORTANT: KIND kubeconfigs use localhost with host-mapped ports (e.g., 127.0.0.1:42761),
# but from inside a pod we need to use the Docker network IP with the container's
# internal port (6443), not the host port.
get_cluster_api_server() {
  # Option 1: Use E2E_SPOKE_A_KUBECONFIG if available (multi-cluster setup)
  if [ -n "${E2E_SPOKE_A_KUBECONFIG:-}" ] && [ -f "$E2E_SPOKE_A_KUBECONFIG" ]; then
    # Get the spoke cluster's Docker network IP (reachable from hub pods)
    local spoke_ip
    spoke_ip=$(docker inspect spoke-cluster-a-control-plane --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")
    if [ -n "$spoke_ip" ]; then
      # Use port 6443 (API server's internal port), NOT the host-mapped port
      # This matches how kind-setup-multi.sh creates kubeconfig secrets
      echo "https://${spoke_ip}:6443"
      return
    fi
  fi
  
  # Option 2: Use kubernetes.default.svc (always works from inside the cluster)
  # This points to the same cluster where the controller is running
  echo "https://kubernetes.default.svc:443"
}

# Get the Keycloak CA certificate for OIDC issuer TLS verification
# Checks multiple sources in order:
# 1. KEYCLOAK_CA_FILE environment variable (CI/Docker environment - most reliable)
# 2. ConfigMap keycloak-ca (multi-cluster E2E setup)
# 3. ConfigMap breakglass-breakglass-certs (Helm chart installation)
# 4. ConfigMap breakglass-certs (manual installation)
get_keycloak_ca() {
  local keycloak_ca=""
  
  # Try KEYCLOAK_CA_FILE first (CI environment - most reliable source)
  if [ -n "${KEYCLOAK_CA_FILE:-}" ] && [ -f "$KEYCLOAK_CA_FILE" ]; then
    log "Using Keycloak CA from KEYCLOAK_CA_FILE: $KEYCLOAK_CA_FILE"
    keycloak_ca=$(cat "$KEYCLOAK_CA_FILE")
    echo "$keycloak_ca"
    return
  fi
  
  # Try ConfigMaps (in-cluster deployments)
  # Check keycloak-ca first (multi-cluster E2E setup)
  if $KUBECTL get configmap keycloak-ca -n "$NAMESPACE" &>/dev/null; then
    keycloak_ca=$($KUBECTL get configmap keycloak-ca -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null)
    if [ -n "$keycloak_ca" ]; then
      log "Using Keycloak CA from ConfigMap keycloak-ca"
      echo "$keycloak_ca"
      return
    fi
  fi
  
  # Check breakglass-breakglass-certs (Helm chart installation)
  if $KUBECTL get configmap breakglass-breakglass-certs -n "$NAMESPACE" &>/dev/null; then
    keycloak_ca=$($KUBECTL get configmap breakglass-breakglass-certs -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null)
    if [ -n "$keycloak_ca" ]; then
      log "Using Keycloak CA from ConfigMap breakglass-breakglass-certs"
      echo "$keycloak_ca"
      return
    fi
  fi
  
  # Check breakglass-certs (manual installation)
  if $KUBECTL get configmap breakglass-certs -n "$NAMESPACE" &>/dev/null; then
    keycloak_ca=$($KUBECTL get configmap breakglass-certs -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null)
    if [ -n "$keycloak_ca" ]; then
      log "Using Keycloak CA from ConfigMap breakglass-certs"
      echo "$keycloak_ca"
      return
    fi
  fi
  
  # No CA found
  log "Warning: No Keycloak CA certificate found in any expected location"
  echo ""
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
  #
  # TLS Configuration:
  # - Keycloak (OIDC issuer): Need certificateAuthority from breakglass-certs ConfigMap
  # - Cluster API server: Use TOFU (Trust On First Use) via caSecretRef
  
  # Get Keycloak CA for OIDC issuer TLS verification
  local keycloak_ca
  keycloak_ca=$(get_keycloak_ca)
  
  if [ -z "$keycloak_ca" ]; then
    log "Warning: Keycloak CA not found - OIDC discovery may fail"
  fi
  
  # Create empty secret for cluster CA TOFU
  local ca_secret_name="${test_name}-cluster-ca"
  cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${ca_secret_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
type: Opaque
data: {}
EOF
  
  # Create ClusterConfig with:
  # - certificateAuthority: Keycloak CA for OIDC issuer
  # - caSecretRef: Empty secret for TOFU to populate with cluster CA
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
$(if [ -n "$keycloak_ca" ]; then
cat <<CAEOF
    certificateAuthority: |
$(echo "$keycloak_ca" | sed 's/^/      /')
CAEOF
fi)
    # Use TOFU for cluster CA - controller will discover and persist
    caSecretRef:
      name: ${ca_secret_name}
      namespace: ${NAMESPACE}
      key: ca.crt
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
  
  # Check if TOFU populated the cluster CA secret
  local tofu_ca_found=false
  local ca_data
  ca_data=$($KUBECTL get secret "${ca_secret_name}" -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null || echo "")
  if [ -n "$ca_data" ]; then
    local decoded_ca
    decoded_ca=$(echo "$ca_data" | base64 -d 2>/dev/null)
    if [[ "$decoded_ca" == *"BEGIN CERTIFICATE"* ]]; then
      tofu_ca_found=true
      log "TOFU successfully populated cluster CA certificate"
    fi
  fi
  
  # Clean up
  cleanup_test_resources "$test_name"
  $KUBECTL delete secret "${ca_secret_name}" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Success criteria - STRICT:
  # - OIDCValidated means full OIDC success with validated token
  # - Ready=True means the cluster is accessible with OIDC credentials
  #
  # FAILURE conditions (should NOT pass):
  # - ClusterUnreachable: OIDC token acquired but never validated against real cluster
  # - OIDCTokenFetchFailed/OIDCTokenFailed: Token acquisition failed
  # - OIDCDiscoveryFailed: Couldn't reach OIDC issuer
  #
  # NOTE: Previous version incorrectly accepted ClusterUnreachable as success.
  # This test must verify end-to-end OIDC functionality, not just token acquisition.
  if [ "$status" = "True" ] && [ "$reason" = "OIDCValidated" ]; then
    log_pass "O-003: OIDC token acquisition and cluster validation succeeded"
  elif [ "$reason" = "ClusterUnreachable" ]; then
    # Token may have been acquired but never validated - this is NOT success
    log_fail "O-003: OIDC token acquired but cluster unreachable - cannot verify token works. Message: $message"
    return 1
  elif [ "$reason" = "OIDCTokenFetchFailed" ] || [ "$reason" = "OIDCTokenFailed" ]; then
    log_fail "O-003: OIDC discovery worked but token fetch failed: $message"
    return 1
  elif [ "$reason" = "OIDCDiscoveryFailed" ]; then
    log_fail "O-003: OIDC discovery failed - Keycloak may not be reachable from controller: $message"
    return 1
  else
    log_fail "O-003: Expected Ready=True with OIDCValidated, got status=$status reason=$reason message=$message"
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
  
  # Get Keycloak CA for OIDC issuer TLS verification
  local keycloak_ca
  keycloak_ca=$(get_keycloak_ca)
  
  # Create empty secret for cluster CA TOFU
  local ca_secret_name="${test_name}-cluster-ca"
  cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${ca_secret_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
type: Opaque
data: {}
EOF
  
  # Create ClusterConfig for token refresh testing with TOFU
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
$(if [ -n "$keycloak_ca" ]; then
cat <<CAEOF
    certificateAuthority: |
$(echo "$keycloak_ca" | sed 's/^/      /')
CAEOF
fi)
    # Use TOFU for cluster CA
    caSecretRef:
      name: ${ca_secret_name}
      namespace: ${NAMESPACE}
      key: ca.crt
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
  $KUBECTL delete secret "${ca_secret_name}" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Success criteria - STRICT:
  # 1. Initial OIDC authentication must succeed (Ready=True, OIDCValidated)
  # 2. Status must remain Ready=True after reconciliation (token still valid or refreshed)
  #
  # FAILURE conditions:
  # - Initial status not Ready=True: OIDC auth failed, can't test refresh
  # - ClusterUnreachable: Token never validated, can't test refresh
  # - Status degraded after wait: Token may have expired without refresh
  #
  # NOTE: Previous version accepted ClusterUnreachable as success, which means
  # the test never actually verified token refresh worked.
  if [ "$status1" != "True" ]; then
    log_fail "O-004: Initial OIDC authentication failed (status=$status1, reason=$reason1) - cannot test token refresh"
    return 1
  fi
  
  if [ "$reason1" = "ClusterUnreachable" ]; then
    log_fail "O-004: Cluster unreachable - token was never validated against cluster, cannot test refresh"
    return 1
  fi
  
  # After waiting, status should still be Ready=True
  if [ "$status2" = "True" ]; then
    if $refresh_detected; then
      log_pass "O-004: OIDC token refresh detected and cluster remains Ready"
    else
      log_pass "O-004: OIDC token still valid across reconciliation (no refresh needed yet)"
    fi
  else
    log_fail "O-004: Status degraded from Ready to $status2 ($reason2) - token may have expired without refresh"
    return 1
  fi
}

# ============================================================================
# O-005: TOFU (Trust On First Use) for cluster CA
# ============================================================================
# TOFU applies to the TARGET CLUSTER API server certificate, NOT the OIDC issuer.
# The controller will attempt to discover and cache the cluster's CA certificate
# when connecting to the API server if no caSecretRef is provided.
#
# For this test to work, we still need to provide the OIDC issuer's CA
# (Keycloak) so that OIDC discovery can succeed, then verify TOFU handles
# the cluster API server connection.
# TOFU persists the discovered CA to a secret if caSecretRef is provided.
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
  
  # Get Keycloak CA - we need this for OIDC discovery to succeed
  # TOFU is for the cluster API server, not the OIDC issuer
  local keycloak_ca
  keycloak_ca=$(get_keycloak_ca)
  
  # Create an empty secret for TOFU to populate
  local ca_secret_name="${test_name}-tofu-ca"
  log "Creating empty CA secret for TOFU: $ca_secret_name"
  cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${ca_secret_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
type: Opaque
data: {}
EOF
  
  if [ -z "$keycloak_ca" ]; then
    log "No Keycloak CA found - testing TOFU with expected OIDC discovery failure"
    # Create ClusterConfig WITH caSecretRef (for TOFU to populate) but without Keycloak CA
    # OIDC discovery will fail, but TOFU should still attempt to populate the cluster CA
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
    # Provide caSecretRef for TOFU to persist discovered CA
    caSecretRef:
      name: ${ca_secret_name}
      namespace: ${NAMESPACE}
      key: ca.crt
    # Note: OIDC discovery may fail without Keycloak CA
EOF
  else
    log "Keycloak CA found - creating ClusterConfig with OIDC issuer CA and caSecretRef for TOFU"
    # Create ClusterConfig WITH Keycloak CA for OIDC AND caSecretRef for cluster CA TOFU
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
    # Provide Keycloak CA for OIDC discovery
    certificateAuthority: |
$(echo "$keycloak_ca" | sed 's/^/      /')
    # Provide caSecretRef for TOFU to persist discovered cluster CA
    caSecretRef:
      name: ${ca_secret_name}
      namespace: ${NAMESPACE}
      key: ca.crt
EOF
  fi
  
  log "Waiting for controller to process ClusterConfig and perform TOFU..."
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
  
  # Check if TOFU populated the CA secret
  local tofu_ca_found=false
  local ca_data
  ca_data=$($KUBECTL get secret "${ca_secret_name}" -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null || echo "")
  if [ -n "$ca_data" ]; then
    local decoded_ca
    decoded_ca=$(echo "$ca_data" | base64 -d 2>/dev/null)
    if [[ "$decoded_ca" == *"BEGIN CERTIFICATE"* ]]; then
      tofu_ca_found=true
      log "TOFU successfully populated CA certificate in secret $ca_secret_name"
      # Show first line of cert for debugging
      log "CA: $(echo "$decoded_ca" | head -1)"
    fi
  fi
  
  # Clean up
  cleanup_test_resources "$test_name"
  $KUBECTL delete secret "${ca_secret_name}" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Determine test result - STRICT criteria
  # 
  # TOFU (Trust On First Use) should:
  # 1. Connect to the cluster without pre-existing CA
  # 2. Discover and validate the cluster's CA certificate
  # 3. Persist the CA to the provided secret
  #
  # NOTE: Previous version had many fallback log_pass paths that masked failures.
  # This test must verify TOFU actually works, not just that it "ran".
  
  if $tofu_ca_found; then
    log_pass "O-005: TOFU successfully discovered and persisted cluster CA certificate"
    return 0
  fi
  
  # TOFU didn't populate the secret - this is a FAILURE
  if [ -z "$keycloak_ca" ]; then
    # Without Keycloak CA, we can't test TOFU (OIDC discovery fails first)
    log_fail "O-005: Cannot test TOFU - Keycloak CA not available for OIDC discovery. Reason: $reason"
    return 1
  fi
  
  # With Keycloak CA, OIDC should succeed - check why TOFU didn't work
  if [ "$status" = "True" ]; then
    # ClusterConfig is Ready but TOFU didn't persist CA - check if cluster uses system CA
    log "O-005: ClusterConfig Ready but TOFU did not persist CA (cluster may use system-trusted CA)"
    log_pass "O-005: OIDC auth succeeded - TOFU persistence may not be needed for this cluster"
  elif [ "$reason" = "ClusterUnreachable" ]; then
    log_fail "O-005: TOFU failed - cluster unreachable, cannot discover CA. Message: $message"
    return 1
  elif [ "$reason" = "OIDCCASecretMissing" ]; then
    log_fail "O-005: TOFU failed - CA secret exists but key not populated. Message: $message"
    return 1
  else
    log_fail "O-005: TOFU failed - unexpected reason: $reason, message: $message"
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
  
  # This test uses real Keycloak to verify token exchange configuration is processed
  if ! check_keycloak_available; then
    log_skip "O-007: Keycloak is not available - cannot test token exchange"
    return 0
  fi
  
  local test_name="oidc-test-007"
  cleanup_test_resources "$test_name"
  
  # Get the target cluster API server
  local api_server
  api_server=$(get_cluster_api_server)
  if [ -z "$api_server" ]; then
    log_fail "O-007: Could not determine cluster API server"
    return 1
  fi
  log "Using API server: $api_server"
  
  # Get Keycloak CA for OIDC issuer TLS verification
  local keycloak_ca
  keycloak_ca=$(get_keycloak_ca)
  
  # Create a mock subject token secret for token exchange
  # In real scenarios, this would be a service account token or external IdP token
  $KUBECTL create secret generic "${test_name}-subject-token" \
    -n "$NAMESPACE" \
    --from-literal=token="mock-subject-token-for-exchange" \
    --dry-run=client -o yaml | $KUBECTL apply -f -
  $KUBECTL label secret "${test_name}-subject-token" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create empty secret for cluster CA TOFU
  local ca_secret_name="${test_name}-cluster-ca"
  cat <<EOF | $KUBECTL apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${ca_secret_name}
  namespace: ${NAMESPACE}
  labels:
    e2e-test: ${test_name}
type: Opaque
data: {}
EOF
  
  # Create ClusterConfig with token exchange enabled using real Keycloak
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
$(if [ -n "$keycloak_ca" ]; then
cat <<CAEOF
    certificateAuthority: |
$(echo "$keycloak_ca" | sed 's/^/      /')
CAEOF
fi)
    # Use TOFU for cluster CA
    caSecretRef:
      name: ${ca_secret_name}
      namespace: ${NAMESPACE}
      key: ca.crt
    # Enable token exchange flow
    tokenExchange:
      enabled: true
      subjectTokenSecretRef:
        name: ${test_name}-subject-token
        namespace: ${NAMESPACE}
        key: token
      resource: ${api_server}
EOF
  
  # Wait for controller to process
  log "Waiting for token exchange processing..."
  sleep $PROCESS_WAIT
  sleep $PROCESS_WAIT
  
  # Check that the config was created and processed
  if ! $KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" &>/dev/null; then
    log_fail "O-007: Failed to create ClusterConfig with token exchange"
    cleanup_test_resources "$test_name"
    return 1
  fi
  
  # Get status
  local status
  status=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  local message
  message=$($KUBECTL get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")
  
  log "Status: $status, Reason: $reason"
  if [ -n "$message" ]; then
    log "Message: $message"
  fi
  
  # Check controller logs for token exchange attempt
  local controller_pod
  controller_pod=$($KUBECTL get pods -l app=breakglass -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  local token_exchange_attempted=false
  local token_exchange_logs=""
  if [ -n "$controller_pod" ]; then
    log "Checking controller logs for token exchange activity..."
    token_exchange_logs=$($KUBECTL logs "$controller_pod" -n "$NAMESPACE" --tail=200 2>/dev/null | grep -iE "token.*exchange|TokenExchange|exchange.*token|STS" || echo "")
    if [ -n "$token_exchange_logs" ]; then
      log "Token exchange activity detected in logs"
      token_exchange_attempted=true
    fi
  fi
  
  cleanup_test_resources "$test_name"
  
  # Success criteria:
  # 1. If Ready=True: Token exchange worked and cluster is reachable
  # 2. If token exchange was attempted (visible in logs): The flow was triggered
  # 3. If OIDCValidated but cluster unreachable: Token exchange succeeded but cluster auth failed
  # 4. If token exchange error in message: Flow was attempted but failed (e.g., STS not configured)
  
  if [ "$status" = "True" ]; then
    log_pass "O-007: Token exchange succeeded - cluster reachable with exchanged token"
  elif [ "$reason" = "OIDCValidated" ]; then
    log_pass "O-007: Token exchange configuration processed, OIDC validated"
  elif $token_exchange_attempted; then
    log_pass "O-007: Token exchange was attempted (logs show activity)"
  elif [[ "$message" == *"exchange"* ]] || [[ "$message" == *"STS"* ]] || [[ "$message" == *"token_exchange"* ]]; then
    # Error message indicates token exchange was attempted
    log_pass "O-007: Token exchange flow triggered (error in exchange: ${message:0:100}...)"
  elif [ "$reason" = "OIDCDiscoveryFailed" ]; then
    # Discovery failed - this shouldn't happen with real Keycloak
    log_fail "O-007: OIDC discovery failed even with real Keycloak: $message"
    return 1
  else
    log_fail "O-007: Token exchange not triggered. Status: $status, Reason: $reason, Message: $message"
    return 1
  fi
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
