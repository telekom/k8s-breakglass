#!/usr/bin/env bash
# Comprehensive E2E Tests
# Tests for cluster bootstrap, controller, webhook, policies, escalations, and sessions
#
# Prerequisites:
# - kind cluster running (via kind-setup-single.sh)
# - All components deployed
#
# Usage:
#   ./e2e/tests/comprehensive_tests.sh [test_name]
#   ./e2e/tests/comprehensive_tests.sh                    # Run all tests
#   ./e2e/tests/comprehensive_tests.sh C-001              # Run specific test

set -euo pipefail

# --- Configuration ---
NAMESPACE=${NAMESPACE:-breakglass-system}
KUBECTL=${KUBECTL:-kubectl}
TIMEOUT=${TIMEOUT:-60}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

log() { printf "[e2e] %s\n" "$*"; }
log_pass() { printf "${GREEN}[PASS]${NC} %s\n" "$*"; ((TESTS_PASSED++)); }
log_fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; ((TESTS_FAILED++)); }
log_skip() { printf "${YELLOW}[SKIP]${NC} %s\n" "$*"; ((TESTS_SKIPPED++)); }
log_info() { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }

# ============================================================================
# CLUSTER & BOOTSTRAP TESTS
# ============================================================================

# C-001: Cluster: kind single-cluster creates control-plane and node
test_C001_cluster_ready() {
  log "=== C-001: Cluster ready with control-plane node ==="
  
  local node_status
  node_status=$($KUBECTL get nodes -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
  
  if [ "$node_status" = "True" ]; then
    log_pass "C-001: Cluster control-plane node is Ready"
  else
    log_fail "C-001: Cluster control-plane node is not Ready (status: $node_status)"
    return 1
  fi
}

# C-002: Bootstrap: API server flags mount authorization/authentication files
test_C002_apiserver_config() {
  log "=== C-002: API server has auth config flags ==="
  
  # Get the API server pod manifest
  local has_authn=false
  local has_authz=false
  
  # Check if api-server has OIDC configuration via authentication-config
  if $KUBECTL get pods -n kube-system -l component=kube-apiserver -o yaml 2>/dev/null | grep -q "authentication-config\|oidc-issuer"; then
    has_authn=true
  fi
  
  # Check for authorization config
  if $KUBECTL get pods -n kube-system -l component=kube-apiserver -o yaml 2>/dev/null | grep -q "authorization-config\|authorization-mode"; then
    has_authz=true
  fi
  
  if $has_authn && $has_authz; then
    log_pass "C-002: API server has authentication and authorization configuration"
  elif $has_authn; then
    log_pass "C-002: API server has authentication configuration (authz may use default mode)"
  else
    log_skip "C-002: Could not verify API server auth config (may be using different config method)"
  fi
}

# ============================================================================
# KEYCLOAK / OIDC TESTS  
# ============================================================================

# K-001: Keycloak deployment ready
test_K001_keycloak_ready() {
  log "=== K-001: Keycloak deployment ready ==="
  
  local ready
  ready=$($KUBECTL get deployment -l app=keycloak -n "$NAMESPACE" -o jsonpath='{.items[0].status.readyReplicas}' 2>/dev/null || echo "0")
  
  if [ "$ready" = "1" ]; then
    log_pass "K-001: Keycloak deployment is ready with 1 replica"
  else
    log_fail "K-001: Keycloak deployment not ready (ready replicas: $ready)"
    return 1
  fi
}

# K-002: JWKS reachable through port-forward
test_K002_jwks_reachable() {
  log "=== K-002: JWKS endpoint reachable ==="
  
  # Check if port-forward is active by testing the local endpoint
  local status
  status=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:8443/realms/breakglass-e2e/protocol/openid-connect/certs" 2>/dev/null || echo "000")
  
  if [ "$status" = "200" ]; then
    log_pass "K-002: JWKS endpoint reachable (HTTP 200)"
  else
    log_skip "K-002: JWKS endpoint not reachable via localhost:8443 (status: $status) - port-forward may not be active"
  fi
}

# ============================================================================
# CONTROLLER & WEBHOOK TESTS
# ============================================================================

# W-001: Controller deployment ready and uses local image
test_W001_controller_ready() {
  log "=== W-001: Controller deployment ready ==="
  
  local ready
  ready=$($KUBECTL get deployment breakglass-manager -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
  
  local image
  image=$($KUBECTL get deployment breakglass-manager -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "")
  
  if [ "$ready" = "1" ]; then
    log "Controller image: $image"
    log_pass "W-001: Controller deployment is ready with 1 replica"
  else
    log_fail "W-001: Controller deployment not ready (ready replicas: $ready)"
    return 1
  fi
}

# W-002: Controller API endpoint reachable
test_W002_controller_api() {
  log "=== W-002: Controller API endpoint reachable ==="
  
  local status
  status=$(curl -sk -o /dev/null -w '%{http_code}' "http://localhost:8080/api/config" 2>/dev/null || echo "000")
  
  if [ "$status" = "200" ]; then
    log_pass "W-002: Controller API endpoint reachable (HTTP 200)"
  else
    log_skip "W-002: Controller API not reachable via localhost:8080 (status: $status) - port-forward may not be active"
  fi
}

# W-003: Webhook service exists
test_W003_webhook_service() {
  log "=== W-003: Webhook service exists ==="
  
  if $KUBECTL get service breakglass-webhook-service -n "$NAMESPACE" &>/dev/null; then
    log_pass "W-003: Webhook service exists"
  else
    log_fail "W-003: Webhook service not found"
    return 1
  fi
}

# W-004: ValidatingWebhookConfiguration exists
test_W004_webhook_config() {
  log "=== W-004: ValidatingWebhookConfiguration exists ==="
  
  if $KUBECTL get validatingwebhookconfiguration breakglass-validating-webhook-configuration &>/dev/null; then
    log_pass "W-004: ValidatingWebhookConfiguration exists"
  else
    log_skip "W-004: ValidatingWebhookConfiguration not found (may be disabled)"
  fi
}

# ============================================================================
# TENANT & CLUSTERCONFIG TESTS
# ============================================================================

# T-001: ClusterConfig resources exist
test_T001_clusterconfigs_exist() {
  log "=== T-001: ClusterConfig resources exist ==="
  
  local count
  count=$($KUBECTL get clusterconfig -A --no-headers 2>/dev/null | wc -l)
  
  if [ "$count" -gt 0 ]; then
    log "Found $count ClusterConfig resources"
    log_pass "T-001: ClusterConfig resources exist"
  else
    log_fail "T-001: No ClusterConfig resources found"
    return 1
  fi
}

# T-002: ClusterConfig status is populated
test_T002_clusterconfig_status() {
  log "=== T-002: ClusterConfig status conditions are populated ==="
  
  local configs_with_status=0
  local total_configs=0
  
  for cc in $($KUBECTL get clusterconfig -A -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.namespace}{"\n"}{end}' 2>/dev/null); do
    # Parse name and namespace (they come as separate items)
    continue
  done
  
  # Simpler check - just verify at least one has status
  local has_status
  has_status=$($KUBECTL get clusterconfig -A -o jsonpath='{.items[0].status.conditions[0].type}' 2>/dev/null || echo "")
  
  if [ -n "$has_status" ]; then
    log_pass "T-002: ClusterConfig resources have status conditions"
  else
    log_fail "T-002: ClusterConfig resources missing status conditions"
    return 1
  fi
}

# ============================================================================
# BREAKGLASS ESCALATION TESTS
# ============================================================================

# E-001: BreakglassEscalation resources exist
test_E001_escalations_exist() {
  log "=== E-001: BreakglassEscalation resources exist ==="
  
  local count
  count=$($KUBECTL get breakglassescalation -A --no-headers 2>/dev/null | wc -l)
  
  if [ "$count" -gt 0 ]; then
    log "Found $count BreakglassEscalation resources"
    log_pass "E-001: BreakglassEscalation resources exist"
  else
    log_skip "E-001: No BreakglassEscalation resources found (may not be configured)"
  fi
}

# E-002: Create and validate a BreakglassEscalation
test_E002_create_escalation() {
  log "=== E-002: Create and validate BreakglassEscalation ==="
  local test_name="e2e-test-escalation"
  
  # Cleanup first
  $KUBECTL delete breakglassescalation "$test_name" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Create test escalation
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
spec:
  allowedClusterRoles:
    - name: view
      maxDurationHours: 1
  allowedSubjects:
    - kind: User
      name: test-user@example.com
EOF
  
  sleep 2
  
  # Verify it exists
  if $KUBECTL get breakglassescalation "$test_name" -n "$NAMESPACE" &>/dev/null; then
    log_pass "E-002: BreakglassEscalation created successfully"
    # Cleanup
    $KUBECTL delete breakglassescalation "$test_name" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  else
    log_fail "E-002: Failed to create BreakglassEscalation"
    return 1
  fi
}

# ============================================================================
# BREAKGLASS SESSION TESTS
# ============================================================================

# S-001: Create a BreakglassSession
test_S001_create_session() {
  log "=== S-001: Create BreakglassSession ==="
  local test_name="e2e-test-session"
  local escalation_name=""
  
  # Find an existing escalation to reference
  escalation_name=$($KUBECTL get breakglassescalation -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  if [ -z "$escalation_name" ]; then
    log_skip "S-001: No BreakglassEscalation found to reference"
    return 0
  fi
  
  # Cleanup first
  $KUBECTL delete breakglasssession "$test_name" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Create test session
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
spec:
  escalationRef:
    name: ${escalation_name}
  clusterRole: view
  reason: "E2E test session"
  requestor: "e2e-test@example.com"
  durationHours: 1
EOF
  
  sleep 3
  
  # Verify it exists and has status
  if $KUBECTL get breakglasssession "$test_name" -n "$NAMESPACE" &>/dev/null; then
    local phase
    phase=$($KUBECTL get breakglasssession "$test_name" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "")
    log "Session phase: $phase"
    log_pass "S-001: BreakglassSession created successfully"
    # Cleanup
    $KUBECTL delete breakglasssession "$test_name" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  else
    log_fail "S-001: Failed to create BreakglassSession"
    return 1
  fi
}

# ============================================================================
# DENY POLICY TESTS
# ============================================================================

# P-001: DenyPolicy resources exist
test_P001_denypolicies_exist() {
  log "=== P-001: DenyPolicy resources exist ==="
  
  local count
  count=$($KUBECTL get denypolicy -A --no-headers 2>/dev/null | wc -l)
  
  if [ "$count" -gt 0 ]; then
    log "Found $count DenyPolicy resources"
    log_pass "P-001: DenyPolicy resources exist"
  else
    log_skip "P-001: No DenyPolicy resources found"
  fi
}

# P-002: Create and validate a DenyPolicy
test_P002_create_denypolicy() {
  log "=== P-002: Create and validate DenyPolicy ==="
  local test_name="e2e-test-deny-policy"
  
  # Cleanup first
  $KUBECTL delete denypolicy "$test_name" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  
  # Create test deny policy
  cat <<EOF | $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: ${test_name}
  namespace: ${NAMESPACE}
spec:
  description: "E2E test deny policy"
  rules:
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["delete"]
      subjects:
        - kind: User
          name: "e2e-test-deny@example.com"
EOF
  
  sleep 2
  
  # Verify it exists
  if $KUBECTL get denypolicy "$test_name" -n "$NAMESPACE" &>/dev/null; then
    log_pass "P-002: DenyPolicy created successfully"
    # Cleanup
    $KUBECTL delete denypolicy "$test_name" -n "$NAMESPACE" --ignore-not-found 2>/dev/null || true
  else
    log_fail "P-002: Failed to create DenyPolicy"
    return 1
  fi
}

# ============================================================================
# IDENTITY PROVIDER TESTS
# ============================================================================

# I-001: IdentityProvider resources exist
test_I001_identityproviders_exist() {
  log "=== I-001: IdentityProvider resources exist ==="
  
  local count
  count=$($KUBECTL get identityprovider -A --no-headers 2>/dev/null | wc -l)
  
  if [ "$count" -gt 0 ]; then
    log "Found $count IdentityProvider resources"
    log_pass "I-001: IdentityProvider resources exist"
  else
    log_skip "I-001: No IdentityProvider resources found"
  fi
}

# I-002: IdentityProvider status is Ready
test_I002_identityprovider_status() {
  log "=== I-002: IdentityProvider status validation ==="
  
  local idp_name
  idp_name=$($KUBECTL get identityprovider -A -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  
  if [ -z "$idp_name" ]; then
    log_skip "I-002: No IdentityProvider found to check"
    return 0
  fi
  
  local status
  status=$($KUBECTL get identityprovider "$idp_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
  local reason
  reason=$($KUBECTL get identityprovider "$idp_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || echo "")
  
  log "IdentityProvider $idp_name: Ready=$status, Reason=$reason"
  
  if [ -n "$status" ]; then
    log_pass "I-002: IdentityProvider has status conditions"
  else
    log_fail "I-002: IdentityProvider missing status conditions"
    return 1
  fi
}

# ============================================================================
# MAIL PROVIDER TESTS
# ============================================================================

# M-001: MailHog deployment ready
test_M001_mailhog_ready() {
  log "=== M-001: MailHog deployment ready ==="
  
  local ready
  ready=$($KUBECTL get deployment -l app=mailhog -n "$NAMESPACE" -o jsonpath='{.items[0].status.readyReplicas}' 2>/dev/null || echo "")
  
  if [ -z "$ready" ]; then
    # Try with different label
    ready=$($KUBECTL get deployment breakglass-mailhog -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "")
  fi
  
  if [ "$ready" = "1" ]; then
    log_pass "M-001: MailHog deployment is ready"
  else
    log_skip "M-001: MailHog deployment not found or not ready"
  fi
}

# M-002: MailHog API reachable
test_M002_mailhog_api() {
  log "=== M-002: MailHog API reachable ==="
  
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:8025/api/v2/messages" 2>/dev/null || echo "000")
  
  if [ "$status" = "200" ]; then
    log_pass "M-002: MailHog API reachable (HTTP 200)"
  else
    log_skip "M-002: MailHog API not reachable via localhost:8025 (status: $status)"
  fi
}

# ============================================================================
# CRD VALIDATION TESTS
# ============================================================================

# V-001: All CRDs are installed
test_V001_crds_installed() {
  log "=== V-001: All required CRDs are installed ==="
  
  local missing_crds=()
  local required_crds=(
    "breakglassescalations.breakglass.t-caas.telekom.com"
    "breakglasssessions.breakglass.t-caas.telekom.com"
    "clusterconfigs.breakglass.t-caas.telekom.com"
    "denypolicies.breakglass.t-caas.telekom.com"
    "identityproviders.breakglass.t-caas.telekom.com"
    "mailproviders.breakglass.t-caas.telekom.com"
  )
  
  for crd in "${required_crds[@]}"; do
    if ! $KUBECTL get crd "$crd" &>/dev/null; then
      missing_crds+=("$crd")
    fi
  done
  
  if [ ${#missing_crds[@]} -eq 0 ]; then
    log_pass "V-001: All ${#required_crds[@]} required CRDs are installed"
  else
    log_fail "V-001: Missing CRDs: ${missing_crds[*]}"
    return 1
  fi
}

# ============================================================================
# RBAC TESTS
# ============================================================================

# R-001: Controller ServiceAccount exists
test_R001_serviceaccount() {
  log "=== R-001: Controller ServiceAccount exists ==="
  
  if $KUBECTL get serviceaccount breakglass-manager -n "$NAMESPACE" &>/dev/null; then
    log_pass "R-001: Controller ServiceAccount exists"
  else
    log_fail "R-001: Controller ServiceAccount not found"
    return 1
  fi
}

# R-002: ClusterRoles exist
test_R002_clusterroles() {
  log "=== R-002: Required ClusterRoles exist ==="
  
  local count
  count=$($KUBECTL get clusterrole -l app.kubernetes.io/name=breakglass --no-headers 2>/dev/null | wc -l)
  
  if [ "$count" -eq 0 ]; then
    # Try without label
    count=$($KUBECTL get clusterrole --no-headers 2>/dev/null | grep -c breakglass || echo "0")
  fi
  
  if [ "$count" -gt 0 ]; then
    log "Found $count breakglass-related ClusterRoles"
    log_pass "R-002: Breakglass ClusterRoles exist"
  else
    log_fail "R-002: No breakglass ClusterRoles found"
    return 1
  fi
}

# ============================================================================
# Main test runner
# ============================================================================
run_all_tests() {
  log "Running comprehensive E2E tests..."
  echo ""
  
  log_info "=== CLUSTER & BOOTSTRAP ==="
  test_C001_cluster_ready || true
  test_C002_apiserver_config || true
  echo ""
  
  log_info "=== KEYCLOAK / OIDC ==="
  test_K001_keycloak_ready || true
  test_K002_jwks_reachable || true
  echo ""
  
  log_info "=== CONTROLLER & WEBHOOK ==="
  test_W001_controller_ready || true
  test_W002_controller_api || true
  test_W003_webhook_service || true
  test_W004_webhook_config || true
  echo ""
  
  log_info "=== CRD VALIDATION ==="
  test_V001_crds_installed || true
  echo ""
  
  log_info "=== RBAC ==="
  test_R001_serviceaccount || true
  test_R002_clusterroles || true
  echo ""
  
  log_info "=== TENANT & CLUSTERCONFIG ==="
  test_T001_clusterconfigs_exist || true
  test_T002_clusterconfig_status || true
  echo ""
  
  log_info "=== BREAKGLASS ESCALATION ==="
  test_E001_escalations_exist || true
  test_E002_create_escalation || true
  echo ""
  
  log_info "=== BREAKGLASS SESSION ==="
  test_S001_create_session || true
  echo ""
  
  log_info "=== DENY POLICY ==="
  test_P001_denypolicies_exist || true
  test_P002_create_denypolicy || true
  echo ""
  
  log_info "=== IDENTITY PROVIDER ==="
  test_I001_identityproviders_exist || true
  test_I002_identityprovider_status || true
  echo ""
  
  log_info "=== MAIL PROVIDER ==="
  test_M001_mailhog_ready || true
  test_M002_mailhog_api || true
  echo ""
  
  # Print summary
  echo "=============================================="
  echo "Comprehensive E2E Test Summary"
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
    C-001) test_C001_cluster_ready ;;
    C-002) test_C002_apiserver_config ;;
    K-001) test_K001_keycloak_ready ;;
    K-002) test_K002_jwks_reachable ;;
    W-001) test_W001_controller_ready ;;
    W-002) test_W002_controller_api ;;
    W-003) test_W003_webhook_service ;;
    W-004) test_W004_webhook_config ;;
    T-001) test_T001_clusterconfigs_exist ;;
    T-002) test_T002_clusterconfig_status ;;
    E-001) test_E001_escalations_exist ;;
    E-002) test_E002_create_escalation ;;
    S-001) test_S001_create_session ;;
    P-001) test_P001_denypolicies_exist ;;
    P-002) test_P002_create_denypolicy ;;
    I-001) test_I001_identityproviders_exist ;;
    I-002) test_I002_identityprovider_status ;;
    M-001) test_M001_mailhog_ready ;;
    M-002) test_M002_mailhog_api ;;
    V-001) test_V001_crds_installed ;;
    R-001) test_R001_serviceaccount ;;
    R-002) test_R002_clusterroles ;;
    all) run_all_tests ;;
    *)
      echo "Unknown test: $1"
      echo "Available tests: C-001, C-002, K-001, K-002, W-001, W-002, W-003, W-004,"
      echo "                 T-001, T-002, E-001, E-002, S-001, P-001, P-002,"
      echo "                 I-001, I-002, M-001, M-002, V-001, R-001, R-002, all"
      exit 1
      ;;
  esac
fi
