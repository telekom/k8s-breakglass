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
  
  # This test requires a running Keycloak instance
  # Check if Keycloak is available
  if ! $KUBECTL get deployment -l app=keycloak -n "$NAMESPACE" &>/dev/null; then
    log_skip "O-003: Keycloak deployment not found in namespace $NAMESPACE"
    return 0
  fi
  
  local test_name="oidc-test-003"
  cleanup_test_resources "$test_name"
  
  # Get Keycloak service URL (in-cluster)
  local keycloak_host
  keycloak_host=$($KUBECTL get svc -l app=keycloak -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  if [ -z "$keycloak_host" ]; then
    log_skip "O-003: Could not determine Keycloak service name"
    return 0
  fi
  
  log "Keycloak service: $keycloak_host"
  log_skip "O-003: Full Keycloak integration test requires Keycloak client configuration"
  # TODO: Create a Keycloak client dynamically and test full flow
}

# ============================================================================
# O-004: OIDC token refresh on expiry
# ============================================================================
test_O004_oidc_token_refresh() {
  log "=== O-004: OIDC token refresh on expiry ==="
  log_skip "O-004: Token refresh test requires long-running test with Keycloak"
  # This test would require:
  # 1. Setting up a ClusterConfig with OIDC auth
  # 2. Waiting for initial token acquisition
  # 3. Waiting for token to near expiry
  # 4. Verifying refresh token is used (check controller logs)
}

# ============================================================================
# O-005: TOFU (Trust On First Use) populates CA secret
# ============================================================================
test_O005_tofu_populates_ca() {
  log "=== O-005: TOFU (Trust On First Use) populates CA secret ==="
  log_skip "O-005: TOFU test requires accessible API server without pre-configured CA"
  # This test would require:
  # 1. Creating ClusterConfig without caSecretRef
  # 2. Controller connecting to API server
  # 3. Verifying a CA secret is created
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
    if $KUBECTL logs "$controller_pod" -n "$NAMESPACE" --tail=100 2>/dev/null | grep -q "token.*exchange\|TokenExchange"; then
      log "Token exchange activity detected in logs"
    else
      log "No explicit token exchange activity in recent logs (may need full Keycloak setup)"
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
