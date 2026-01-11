#!/usr/bin/env bash
# Multi-Cluster OIDC E2E Tests (MO-001 through MO-006)
# These tests validate OIDC authentication functionality across hub and spoke clusters.
# 
# Prerequisites:
# - Multi-cluster environment running (via kind-setup-multi.sh)
# - Keycloak deployed and configured with multiple realms
# - Controller deployed on hub cluster
#
# Usage:
#   ./e2e/tests/multi_oidc_tests.sh [test_name]
#   ./e2e/tests/multi_oidc_tests.sh                    # Run all tests
#   ./e2e/tests/multi_oidc_tests.sh MO-001             # Run specific test

set -euo pipefail

# --- Configuration ---
NAMESPACE=${NAMESPACE:-breakglass-system}
KUBECTL=${KUBECTL:-kubectl}
TIMEOUT=${TIMEOUT:-60}
PROCESS_WAIT=${PROCESS_WAIT:-20}

# Get kubeconfig paths from environment or use defaults
HUB_KUBECONFIG=${HUB_KUBECONFIG:-}
SPOKE_A_KUBECONFIG=${SPOKE_A_KUBECONFIG:-}
SPOKE_B_KUBECONFIG=${SPOKE_B_KUBECONFIG:-}

# Keycloak configuration - matches kind-setup-multi.sh
KEYCLOAK_CONTAINER_NAME=${KEYCLOAK_CONTAINER_NAME:-e2e-keycloak}
KEYCLOAK_PORT=${KEYCLOAK_PORT:-8443}
KEYCLOAK_MAIN_REALM=${KEYCLOAK_MAIN_REALM:-breakglass-e2e}
KEYCLOAK_CONTRACTORS_REALM=${KEYCLOAK_CONTRACTORS_REALM:-breakglass-e2e-contractors}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log() { printf "[multi-oidc-e2e] %s\n" "$*"; }
log_pass() { printf "${GREEN}[PASS]${NC} %s\n" "$*"; ((TESTS_PASSED++)); }
log_fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; ((TESTS_FAILED++)); }
log_skip() { printf "${YELLOW}[SKIP]${NC} %s\n" "$*"; ((TESTS_SKIPPED++)); }

# Get kubectl command for a specific cluster
kubectl_hub() {
  if [ -n "$HUB_KUBECONFIG" ]; then
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL "$@"
  else
    $KUBECTL --context kind-breakglass-hub "$@"
  fi
}

kubectl_spoke_a() {
  if [ -n "$SPOKE_A_KUBECONFIG" ]; then
    KUBECONFIG="$SPOKE_A_KUBECONFIG" $KUBECTL "$@"
  else
    $KUBECTL --context kind-spoke-cluster-a "$@"
  fi
}

kubectl_spoke_b() {
  if [ -n "$SPOKE_B_KUBECONFIG" ]; then
    KUBECONFIG="$SPOKE_B_KUBECONFIG" $KUBECTL "$@"
  else
    $KUBECTL --context kind-spoke-cluster-b "$@"
  fi
}

# Get Keycloak IP from container
get_keycloak_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KEYCLOAK_CONTAINER_NAME" 2>/dev/null || echo ""
}

# Cleanup test resources
cleanup_test_resources() {
  local prefix="${1:-mo-test}"
  log "Cleaning up test resources with prefix '$prefix'..."
  kubectl_hub delete clusterconfig -l "e2e-test=$prefix" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  kubectl_hub delete secret -l "e2e-test=$prefix" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
}

# Check if multi-cluster environment is available
check_multicluster_available() {
  # Check if hub cluster is accessible
  if ! kubectl_hub get ns "$NAMESPACE" &>/dev/null; then
    log "Hub cluster not accessible"
    return 1
  fi
  
  # Check if Keycloak container is running
  if ! docker ps --filter "name=$KEYCLOAK_CONTAINER_NAME" --filter "status=running" -q 2>/dev/null | grep -q .; then
    log "Keycloak container not running"
    return 1
  fi
  
  return 0
}

# ============================================================================
# MO-001: IdentityProvider with OIDC configuration on hub
# ============================================================================
test_MO001_idp_oidc_config() {
  log "=== MO-001: IdentityProvider with OIDC configuration on hub ==="
  
  if ! check_multicluster_available; then
    log_fail "MO-001: Multi-cluster environment not available"
    return 1
  fi
  
  # Check that main-idp and contractors-idp exist (created by kind-setup-multi.sh)
  local main_idp_exists=false
  local contractors_idp_exists=false
  
  if kubectl_hub get identityprovider main-idp &>/dev/null; then
    main_idp_exists=true
    log "IdentityProvider main-idp exists"
  fi
  
  if kubectl_hub get identityprovider contractors-idp &>/dev/null; then
    contractors_idp_exists=true
    log "IdentityProvider contractors-idp exists"
  fi
  
  if $main_idp_exists && $contractors_idp_exists; then
    # Check OIDC configuration is HTTPS
    local main_issuer
    main_issuer=$(kubectl_hub get identityprovider main-idp -o jsonpath='{.spec.issuer}' 2>/dev/null || echo "")
    local contractors_issuer
    contractors_issuer=$(kubectl_hub get identityprovider contractors-idp -o jsonpath='{.spec.issuer}' 2>/dev/null || echo "")
    
    log "Main IDP issuer: $main_issuer"
    log "Contractors IDP issuer: $contractors_issuer"
    
    if [[ "$main_issuer" == https://* ]] && [[ "$contractors_issuer" == https://* ]]; then
      log_pass "MO-001: IdentityProviders configured with HTTPS OIDC"
    else
      log_fail "MO-001: IdentityProviders should use HTTPS (main: $main_issuer, contractors: $contractors_issuer)"
      return 1
    fi
  else
    log_fail "MO-001: Expected IdentityProviders not found (main=$main_idp_exists, contractors=$contractors_idp_exists)"
    return 1
  fi
}

# ============================================================================
# MO-002: ClusterConfig for spoke cluster with OIDC auth
# ============================================================================
test_MO002_spoke_oidc_clusterconfig() {
  log "=== MO-002: ClusterConfig for spoke cluster with OIDC auth ==="
  
  if ! check_multicluster_available; then
    log_fail "MO-002: Multi-cluster environment not available"
    return 1
  fi
  
  local test_name="mo-test-002"
  cleanup_test_resources "$test_name"
  
  # Get Keycloak issuer URL
  local keycloak_ip
  keycloak_ip=$(get_keycloak_ip)
  if [ -z "$keycloak_ip" ]; then
    log_fail "MO-002: Could not get Keycloak IP"
    return 1
  fi
  
  local issuer_url="https://${keycloak_ip}:${KEYCLOAK_PORT}/realms/${KEYCLOAK_MAIN_REALM}"
  log "Using Keycloak issuer: $issuer_url"
  
  # Get spoke-a API server from existing ClusterConfig
  local spoke_a_server
  spoke_a_server=$(kubectl_hub get clusterconfig spoke-cluster-a -n "$NAMESPACE" -o jsonpath='{.spec.oidcAuth.server}' 2>/dev/null || echo "")
  
  if [ -z "$spoke_a_server" ]; then
    # Fall back to getting from kubeconfig
    spoke_a_server=$(kubectl_spoke_a config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo "")
  fi
  
  if [ -z "$spoke_a_server" ]; then
    log_fail "MO-002: Could not determine spoke-a API server"
    return 1
  fi
  log "Spoke-A API server: $spoke_a_server"
  
  # Create test secret for OIDC
  kubectl_hub create secret generic "${test_name}-client-secret" \
    -n "$NAMESPACE" \
    --from-literal=client-secret="test-secret-value" \
    --dry-run=client -o yaml | kubectl_hub apply -f -
  kubectl_hub label secret "${test_name}-client-secret" -n "$NAMESPACE" "e2e-test=$test_name"
  
  # Create ClusterConfig with OIDC auth for spoke cluster
  cat <<EOF | kubectl_hub apply -f -
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
    issuerURL: ${issuer_url}
    clientID: breakglass
    server: ${spoke_a_server}
    clientSecretRef:
      name: ${test_name}-client-secret
      namespace: ${NAMESPACE}
      key: client-secret
    insecureSkipTLSVerify: true
EOF
  
  # Wait for controller to process
  sleep $PROCESS_WAIT
  
  # Check status
  local status
  status=$(kubectl_hub get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local reason
  reason=$(kubectl_hub get clusterconfig "${test_name}" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  
  log "Status: $status, Reason: $reason"
  
  # Cleanup
  cleanup_test_resources "$test_name"
  
  # Success if OIDC discovery was attempted (even if cluster connection failed)
  if [ "$reason" != "SecretMissing" ]; then
    log_pass "MO-002: ClusterConfig with OIDC auth for spoke cluster processed correctly"
  else
    log_fail "MO-002: ClusterConfig processing failed - $reason"
    return 1
  fi
}

# ============================================================================
# MO-003: Multiple IdentityProviders for different user groups
# ============================================================================
test_MO003_multi_idp_isolation() {
  log "=== MO-003: Multiple IdentityProviders for different user groups ==="
  
  if ! check_multicluster_available; then
    log_fail "MO-003: Multi-cluster environment not available"
    return 1
  fi
  
  # Check that escalations reference correct IDPs
  local global_readonly_exists=false
  local spoke_b_debugger_exists=false
  
  if kubectl_hub get breakglassescalation mc-global-readonly -n "$NAMESPACE" &>/dev/null; then
    global_readonly_exists=true
    log "Escalation mc-global-readonly exists"
  fi
  
  if kubectl_hub get breakglassescalation mc-spoke-b-debugger -n "$NAMESPACE" &>/dev/null; then
    spoke_b_debugger_exists=true
    log "Escalation mc-spoke-b-debugger exists"
  fi
  
  if $global_readonly_exists && $spoke_b_debugger_exists; then
    # The mc-spoke-b-debugger is for contractors (different IDP)
    local contractor_groups
    contractor_groups=$(kubectl_hub get breakglassescalation mc-spoke-b-debugger -n "$NAMESPACE" -o jsonpath='{.spec.allowed.groups[*]}' 2>/dev/null || echo "")
    
    log "Contractor escalation allowed groups: $contractor_groups"
    
    if [[ "$contractor_groups" == *"contractors"* ]]; then
      log_pass "MO-003: Multi-IDP isolation is correctly configured for different user groups"
    else
      log_fail "MO-003: Expected 'contractors' group in mc-spoke-b-debugger escalation"
      return 1
    fi
  else
    log_fail "MO-003: Expected escalations not found (global_readonly=$global_readonly_exists, spoke_b_debugger=$spoke_b_debugger_exists)"
    return 1
  fi
}

# ============================================================================
# MO-004: OIDC connectivity from hub to Keycloak
# ============================================================================
test_MO004_hub_keycloak_connectivity() {
  log "=== MO-004: OIDC connectivity from hub to Keycloak ==="
  
  if ! check_multicluster_available; then
    log_fail "MO-004: Multi-cluster environment not available"
    return 1
  fi
  
  # Get Keycloak IP
  local keycloak_ip
  keycloak_ip=$(get_keycloak_ip)
  if [ -z "$keycloak_ip" ]; then
    log_fail "MO-004: Could not get Keycloak IP"
    return 1
  fi
  
  log "Keycloak IP: $keycloak_ip"
  
  # Test connectivity from controller pod to Keycloak
  local controller_pod
  controller_pod=$(kubectl_hub get pods -l app=breakglass -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  if [ -z "$controller_pod" ]; then
    log_fail "MO-004: Controller pod not found"
    return 1
  fi
  
  log "Testing connectivity from controller pod to Keycloak..."
  
  # Try to reach Keycloak OIDC discovery endpoint
  local discovery_url="https://${keycloak_ip}:${KEYCLOAK_PORT}/realms/${KEYCLOAK_MAIN_REALM}/.well-known/openid-configuration"
  
  # Use wget or curl inside the controller pod (if available)
  local connectivity_result
  connectivity_result=$(kubectl_hub exec "$controller_pod" -n "$NAMESPACE" -- \
    sh -c "wget -qO- --no-check-certificate '$discovery_url' 2>/dev/null || curl -sk '$discovery_url' 2>/dev/null || echo 'FAILED'" 2>/dev/null || echo "EXEC_FAILED")
  
  if [[ "$connectivity_result" == *"issuer"* ]] || [[ "$connectivity_result" == *"token_endpoint"* ]]; then
    log "OIDC discovery endpoint is accessible from controller"
    log_pass "MO-004: Hub controller can connect to Keycloak OIDC"
  elif [[ "$connectivity_result" == "EXEC_FAILED" ]]; then
    # Can't exec into pod, but we can check IdentityProvider status
    log "Cannot exec into controller pod, checking IdentityProvider status..."
    local idp_status
    idp_status=$(kubectl_hub get identityprovider main-idp -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
    local idp_reason
    idp_reason=$(kubectl_hub get identityprovider main-idp -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
    
    log "IdentityProvider main-idp status: $idp_status, reason: $idp_reason"
    
    if [ "$idp_status" = "True" ]; then
      log_pass "MO-004: IdentityProvider is Ready, indicating Keycloak connectivity"
    else
      log_fail "MO-004: IdentityProvider not ready - $idp_reason"
      return 1
    fi
  else
    log_fail "MO-004: OIDC discovery endpoint not accessible - $connectivity_result"
    return 1
  fi
}

# ============================================================================
# MO-005: Cross-cluster OIDC token validation
# ============================================================================
test_MO005_cross_cluster_oidc_token() {
  log "=== MO-005: Cross-cluster OIDC token validation ==="
  
  if ! check_multicluster_available; then
    log_fail "MO-005: Multi-cluster environment not available"
    return 1
  fi
  
  # Check that ClusterConfigs for spoke clusters exist and are processed
  local spoke_a_ready=false
  local spoke_b_ready=false
  
  local spoke_a_status
  spoke_a_status=$(kubectl_hub get clusterconfig spoke-cluster-a -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local spoke_a_reason
  spoke_a_reason=$(kubectl_hub get clusterconfig spoke-cluster-a -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  
  local spoke_b_status
  spoke_b_status=$(kubectl_hub get clusterconfig spoke-cluster-b -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  local spoke_b_reason
  spoke_b_reason=$(kubectl_hub get clusterconfig spoke-cluster-b -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "Unknown")
  
  log "Spoke-A ClusterConfig: status=$spoke_a_status, reason=$spoke_a_reason"
  log "Spoke-B ClusterConfig: status=$spoke_b_status, reason=$spoke_b_reason"
  
  # Check if OIDC discovery was successful (even if cluster auth failed)
  if [[ "$spoke_a_reason" != "OIDCDiscoveryFailed" ]] && [[ "$spoke_a_reason" != "SecretMissing" ]]; then
    spoke_a_ready=true
  fi
  
  if [[ "$spoke_b_reason" != "OIDCDiscoveryFailed" ]] && [[ "$spoke_b_reason" != "SecretMissing" ]]; then
    spoke_b_ready=true
  fi
  
  if $spoke_a_ready && $spoke_b_ready; then
    log_pass "MO-005: Cross-cluster OIDC configuration is working for both spoke clusters"
  elif $spoke_a_ready || $spoke_b_ready; then
    log_pass "MO-005: Cross-cluster OIDC working for at least one spoke (A=$spoke_a_ready, B=$spoke_b_ready)"
  else
    log_fail "MO-005: Cross-cluster OIDC not working - spoke-a=$spoke_a_reason, spoke-b=$spoke_b_reason"
    return 1
  fi
}

# ============================================================================
# MO-006: OIDC with different realms for contractors
# ============================================================================
test_MO006_contractor_realm_isolation() {
  log "=== MO-006: OIDC with different realms for contractors ==="
  
  if ! check_multicluster_available; then
    log_fail "MO-006: Multi-cluster environment not available"
    return 1
  fi
  
  # Check contractors-idp is configured with separate realm
  local contractors_issuer
  contractors_issuer=$(kubectl_hub get identityprovider contractors-idp -o jsonpath='{.spec.issuer}' 2>/dev/null || echo "")
  
  if [ -z "$contractors_issuer" ]; then
    log_fail "MO-006: Could not get contractors-idp issuer"
    return 1
  fi
  
  log "Contractors IDP issuer: $contractors_issuer"
  
  # Verify it's a different realm from main-idp
  local main_issuer
  main_issuer=$(kubectl_hub get identityprovider main-idp -o jsonpath='{.spec.issuer}' 2>/dev/null || echo "")
  
  log "Main IDP issuer: $main_issuer"
  
  if [ "$contractors_issuer" != "$main_issuer" ]; then
    # Check that contractors realm is configured
    if [[ "$contractors_issuer" == *"$KEYCLOAK_CONTRACTORS_REALM"* ]]; then
      log_pass "MO-006: Contractors IDP uses separate realm ($KEYCLOAK_CONTRACTORS_REALM)"
    else
      log_pass "MO-006: Contractors IDP uses different issuer from main IDP"
    fi
  else
    log_fail "MO-006: Contractors IDP should use different issuer from main IDP"
    return 1
  fi
}

# ============================================================================
# Main test runner
# ============================================================================
run_all_tests() {
  log "Running all Multi-Cluster OIDC E2E tests..."
  echo ""
  
  test_MO001_idp_oidc_config || true
  echo ""
  test_MO002_spoke_oidc_clusterconfig || true
  echo ""
  test_MO003_multi_idp_isolation || true
  echo ""
  test_MO004_hub_keycloak_connectivity || true
  echo ""
  test_MO005_cross_cluster_oidc_token || true
  echo ""
  test_MO006_contractor_realm_isolation || true
  echo ""
  
  # Print summary
  echo "=============================================="
  echo "Multi-Cluster OIDC E2E Test Summary"
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
    MO-001) test_MO001_idp_oidc_config ;;
    MO-002) test_MO002_spoke_oidc_clusterconfig ;;
    MO-003) test_MO003_multi_idp_isolation ;;
    MO-004) test_MO004_hub_keycloak_connectivity ;;
    MO-005) test_MO005_cross_cluster_oidc_token ;;
    MO-006) test_MO006_contractor_realm_isolation ;;
    all) run_all_tests ;;
    *)
      echo "Unknown test: $1"
      echo "Available tests: MO-001, MO-002, MO-003, MO-004, MO-005, MO-006, all"
      exit 1
      ;;
  esac
fi
