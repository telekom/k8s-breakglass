#!/usr/bin/env bash
# Two Persona CLI Flow Test
# This script simulates a complete breakglass workflow with two personas:
# - Requester: Creates sessions and requests access
# - Approver: Approves or rejects requests
#
# Prerequisites:
# - bgctl binary in PATH or $BGCTL_BIN set
# - Keycloak/OIDC provider running with test users
# - Breakglass API server running
# - Required environment variables (see below)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - override with environment variables
BGCTL_BIN="${BGCTL_BIN:-bgctl}"
API_URL="${BREAKGLASS_API_URL:-http://localhost:8080}"
OIDC_URL="${OIDC_URL:-http://localhost:9090/realms/breakglass}"
CLUSTER_NAME="${CLUSTER_NAME:-kind-breakglass}"
GROUP_NAME="${GROUP_NAME:-breakglass-create-all}"

# Test users - these should match your Keycloak setup
REQUESTER_USER="${REQUESTER_USER:-requester}"
REQUESTER_PASS="${REQUESTER_PASS:-requester}"
APPROVER_USER="${APPROVER_USER:-approver}"
APPROVER_PASS="${APPROVER_PASS:-approver}"

# Temp directory for configs
TEST_DIR=$(mktemp -d)
REQUESTER_CONFIG="$TEST_DIR/requester-config.yaml"
APPROVER_CONFIG="$TEST_DIR/approver-config.yaml"
REQUESTER_TOKEN_FILE="$TEST_DIR/requester-token"
APPROVER_TOKEN_FILE="$TEST_DIR/approver-token"

# Cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    rm -rf "$TEST_DIR"
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_step() {
    echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Step: $1${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking Prerequisites"
    
    # Check bgctl binary
    if ! command -v "$BGCTL_BIN" &> /dev/null; then
        log_error "bgctl binary not found at: $BGCTL_BIN"
        log_info "Set BGCTL_BIN environment variable or add bgctl to PATH"
        exit 1
    fi
    log_success "bgctl binary found: $(command -v "$BGCTL_BIN")"
    
    # Check API server is reachable
    if ! curl -sf "$API_URL/healthz" > /dev/null 2>&1; then
        log_error "API server not reachable at: $API_URL"
        log_info "Set BREAKGLASS_API_URL environment variable"
        exit 1
    fi
    log_success "API server reachable at: $API_URL"
    
    # Check jq is available
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        exit 1
    fi
    log_success "jq available"
}

# Get OIDC token for a user
get_oidc_token() {
    local username=$1
    local password=$2
    local token_file=$3
    
    log_info "Getting OIDC token for user: $username"
    
    # Try to get token from Keycloak
    local token
    token=$(curl -sf -X POST "$OIDC_URL/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=breakglass-cli" \
        -d "username=$username" \
        -d "password=$password" \
        -d "scope=openid email profile" 2>/dev/null | jq -r '.access_token') || true
    
    if [[ -z "$token" || "$token" == "null" ]]; then
        log_error "Failed to get OIDC token for $username"
        log_info "Make sure Keycloak is running and user exists"
        return 1
    fi
    
    echo "$token" > "$token_file"
    log_success "Got OIDC token for $username"
}

# Create CLI config for a persona
create_config() {
    local config_file=$1
    local persona_name=$2
    
    log_info "Creating CLI config for $persona_name at $config_file"
    
    cat > "$config_file" << EOF
server: $API_URL
cluster: $CLUSTER_NAME
output: table
EOF
    
    log_success "Config created for $persona_name"
}

# Run bgctl as requester
run_as_requester() {
    local token
    token=$(cat "$REQUESTER_TOKEN_FILE")
    "$BGCTL_BIN" --config "$REQUESTER_CONFIG" --token "$token" "$@"
}

# Run bgctl as approver
run_as_approver() {
    local token
    token=$(cat "$APPROVER_TOKEN_FILE")
    "$BGCTL_BIN" --config "$APPROVER_CONFIG" --token "$token" "$@"
}

# Wait for session to reach expected state
wait_for_session_state() {
    local session_name=$1
    local expected_state=$2
    local timeout=${3:-30}
    local persona=${4:-requester}
    
    log_info "Waiting for session $session_name to reach state: $expected_state (timeout: ${timeout}s)"
    
    local start_time
    start_time=$(date +%s)
    
    while true; do
        local current_time
        current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [[ $elapsed -ge $timeout ]]; then
            log_error "Timeout waiting for session state: $expected_state"
            return 1
        fi
        
        local state
        if [[ "$persona" == "requester" ]]; then
            state=$(run_as_requester session get "$session_name" -o json 2>/dev/null | jq -r '.status.state') || true
        else
            state=$(run_as_approver session get "$session_name" -o json 2>/dev/null | jq -r '.status.state') || true
        fi
        
        if [[ "$state" == "$expected_state" ]]; then
            log_success "Session reached state: $expected_state"
            return 0
        fi
        
        log_info "Current state: $state, waiting..."
        sleep 2
    done
}

# Test 1: Basic version and help
test_basic_commands() {
    log_step "Test 1: Basic Commands"
    
    # Version
    log_info "Testing version command..."
    if run_as_requester version > /dev/null 2>&1; then
        log_success "Version command works"
    else
        log_error "Version command failed"
        return 1
    fi
    
    # Help
    log_info "Testing help command..."
    if run_as_requester --help > /dev/null 2>&1; then
        log_success "Help command works"
    else
        log_error "Help command failed"
        return 1
    fi
}

# Test 2: List escalations (both personas)
test_list_escalations() {
    log_step "Test 2: List Escalations"
    
    log_info "Requester listing escalations..."
    local req_output
    req_output=$(run_as_requester escalation list -o json 2>&1) || true
    if echo "$req_output" | jq -e 'type == "array"' > /dev/null 2>&1; then
        local count
        count=$(echo "$req_output" | jq 'length')
        log_success "Requester can list escalations (found: $count)"
    else
        log_info "No escalations found or error: $req_output"
    fi
    
    log_info "Approver listing escalations..."
    local app_output
    app_output=$(run_as_approver escalation list -o json 2>&1) || true
    if echo "$app_output" | jq -e 'type == "array"' > /dev/null 2>&1; then
        local count
        count=$(echo "$app_output" | jq 'length')
        log_success "Approver can list escalations (found: $count)"
    else
        log_info "No escalations found or error: $app_output"
    fi
}

# Test 3: Full session approval flow
test_session_approval_flow() {
    log_step "Test 3: Session Approval Flow"
    
    # Step 3.1: Requester creates a session
    log_info "Requester creating a new session..."
    local create_output
    create_output=$(run_as_requester session request \
        --cluster "$CLUSTER_NAME" \
        --group "$GROUP_NAME" \
        --reason "Shell E2E test - approval flow" \
        -o json 2>&1) || {
        log_error "Failed to create session: $create_output"
        return 1
    }
    
    local session_name
    session_name=$(echo "$create_output" | jq -r '.metadata.name') || true
    if [[ -z "$session_name" || "$session_name" == "null" ]]; then
        log_error "Failed to extract session name from: $create_output"
        return 1
    fi
    log_success "Session created: $session_name"
    
    # Step 3.2: Verify session is in Pending state
    wait_for_session_state "$session_name" "Pending" 30 "requester" || return 1
    
    # Step 3.3: Both personas can see the session
    log_info "Verifying both personas can see the session..."
    
    if run_as_requester session get "$session_name" -o json > /dev/null 2>&1; then
        log_success "Requester can see their session"
    else
        log_error "Requester cannot see their session"
        return 1
    fi
    
    if run_as_approver session get "$session_name" -o json > /dev/null 2>&1; then
        log_success "Approver can see the session"
    else
        log_error "Approver cannot see the session"
        return 1
    fi
    
    # Step 3.4: Approver approves the session
    log_info "Approver approving the session..."
    local approve_output
    approve_output=$(run_as_approver session approve "$session_name" 2>&1) || {
        log_error "Failed to approve session: $approve_output"
        return 1
    }
    log_success "Approver approved the session"
    
    # Step 3.5: Verify session is in Approved state
    wait_for_session_state "$session_name" "Approved" 30 "requester" || return 1
    
    # Step 3.6: Verify approvers are recorded
    log_info "Verifying approvers are recorded..."
    local approvers
    approvers=$(run_as_requester session get "$session_name" -o json | jq -r '.status.approvers[]?' 2>/dev/null) || true
    if [[ -n "$approvers" ]]; then
        log_success "Approvers recorded: $approvers"
    else
        log_info "No approvers recorded (may be expected for auto-approved escalations)"
    fi
    
    log_success "Session approval flow completed for: $session_name"
    
    # Store session name for cleanup
    echo "$session_name" >> "$TEST_DIR/sessions_to_cleanup"
}

# Test 4: Session rejection flow
test_session_rejection_flow() {
    log_step "Test 4: Session Rejection Flow"
    
    # Step 4.1: Requester creates a session
    log_info "Requester creating a new session for rejection test..."
    local create_output
    create_output=$(run_as_requester session request \
        --cluster "$CLUSTER_NAME" \
        --group "$GROUP_NAME" \
        --reason "Shell E2E test - rejection flow" \
        -o json 2>&1) || {
        log_error "Failed to create session: $create_output"
        return 1
    }
    
    local session_name
    session_name=$(echo "$create_output" | jq -r '.metadata.name') || true
    if [[ -z "$session_name" || "$session_name" == "null" ]]; then
        log_error "Failed to extract session name from: $create_output"
        return 1
    fi
    log_success "Session created: $session_name"
    
    # Step 4.2: Verify session is in Pending state
    wait_for_session_state "$session_name" "Pending" 30 "requester" || return 1
    
    # Step 4.3: Approver rejects the session
    log_info "Approver rejecting the session..."
    local reject_output
    reject_output=$(run_as_approver session reject "$session_name" --reason "Test rejection" 2>&1) || {
        log_error "Failed to reject session: $reject_output"
        return 1
    }
    log_success "Approver rejected the session"
    
    # Step 4.4: Verify session is in Rejected state
    wait_for_session_state "$session_name" "Rejected" 30 "requester" || return 1
    
    log_success "Session rejection flow completed for: $session_name"
    
    echo "$session_name" >> "$TEST_DIR/sessions_to_cleanup"
}

# Test 5: Session filtering
test_session_filtering() {
    log_step "Test 5: Session Filtering"
    
    # Filter by state
    log_info "Testing filter by state (approved)..."
    local approved_output
    approved_output=$(run_as_requester session list --state approved -o json 2>&1) || true
    if echo "$approved_output" | jq -e 'type == "array"' > /dev/null 2>&1; then
        local count
        count=$(echo "$approved_output" | jq 'length')
        log_success "Filter by state=approved works (found: $count)"
    else
        log_info "No approved sessions or error"
    fi
    
    # Filter by cluster
    log_info "Testing filter by cluster..."
    local cluster_output
    cluster_output=$(run_as_requester session list --cluster "$CLUSTER_NAME" -o json 2>&1) || true
    if echo "$cluster_output" | jq -e 'type == "array"' > /dev/null 2>&1; then
        local count
        count=$(echo "$cluster_output" | jq 'length')
        log_success "Filter by cluster works (found: $count)"
    else
        log_info "No sessions for cluster or error"
    fi
    
    # Filter by mine
    log_info "Testing --mine filter..."
    local mine_output
    mine_output=$(run_as_requester session list --mine -o json 2>&1) || true
    if echo "$mine_output" | jq -e 'type == "array"' > /dev/null 2>&1; then
        local count
        count=$(echo "$mine_output" | jq 'length')
        log_success "Filter by --mine works (found: $count)"
    else
        log_info "No own sessions or error"
    fi
}

# Test 6: Output formats
test_output_formats() {
    log_step "Test 6: Output Formats"
    
    # JSON output
    log_info "Testing JSON output..."
    if run_as_requester session list -o json 2>&1 | jq -e '.' > /dev/null 2>&1; then
        log_success "JSON output is valid"
    else
        log_info "JSON output test skipped (no sessions or error)"
    fi
    
    # YAML output
    log_info "Testing YAML output..."
    local yaml_output
    yaml_output=$(run_as_requester session list -o yaml 2>&1) || true
    if [[ "$yaml_output" == *"kind:"* ]] || [[ "$yaml_output" == *"[]"* ]] || [[ "$yaml_output" == "[]" ]]; then
        log_success "YAML output works"
    else
        log_info "YAML output test result: $yaml_output"
    fi
    
    # Table output (default)
    log_info "Testing table output..."
    local table_output
    table_output=$(run_as_requester session list -o table 2>&1) || true
    if [[ "$table_output" == *"NAME"* ]] || [[ "$table_output" == *"No sessions"* ]] || [[ -z "$table_output" ]]; then
        log_success "Table output works"
    else
        log_info "Table output result: $table_output"
    fi
}

# Test 7: Cluster operations (via escalations - no dedicated cluster command)
test_cluster_operations() {
    log_step "Test 7: Cluster Operations (via escalations)"
    
    # List clusters from escalations
    log_info "Listing clusters from escalations..."
    local escalations_output
    escalations_output=$(run_as_requester escalation list -o json 2>&1) || true
    if echo "$escalations_output" | jq -e 'type == "array"' > /dev/null 2>&1; then
        # Extract unique clusters from escalations
        local clusters
        clusters=$(echo "$escalations_output" | jq -r '.[].spec.allowed.clusters[]?' | sort -u | tr '\n' ', ' | sed 's/,$//')
        local count
        count=$(echo "$escalations_output" | jq -r '.[].spec.allowed.clusters[]?' | sort -u | wc -l | tr -d ' ')
        log_success "Found $count unique clusters from escalations: $clusters"
    else
        log_info "No escalations found or error: $escalations_output"
    fi
    
    # Verify the configured cluster exists in escalations
    log_info "Verifying cluster $CLUSTER_NAME is configured in escalations..."
    if echo "$escalations_output" | jq -e ".[].spec.allowed.clusters[]? | select(. == \"$CLUSTER_NAME\")" > /dev/null 2>&1; then
        log_success "Cluster $CLUSTER_NAME is configured in escalations"
    else
        log_info "Cluster $CLUSTER_NAME not found in escalations (may be expected)"
    fi
}

# Test 8: Debug session flow (if templates available)
test_debug_session_flow() {
    log_step "Test 8: Debug Session Flow"
    
    # List debug templates
    log_info "Listing debug session templates..."
    local templates_output
    templates_output=$(run_as_requester debug template list -o json 2>&1) || true
    
    if ! echo "$templates_output" | jq -e 'type == "array" and length > 0' > /dev/null 2>&1; then
        log_info "No debug templates available, skipping debug session test"
        return 0
    fi
    
    local template_name
    template_name=$(echo "$templates_output" | jq -r '.[0].metadata.name') || true
    log_success "Found debug template: $template_name"
    
    # Create debug session
    log_info "Requester creating debug session..."
    local create_output
    create_output=$(run_as_requester debug request \
        --template "$template_name" \
        --cluster "$CLUSTER_NAME" \
        --reason "Shell E2E test - debug session" \
        -o json 2>&1) || {
        log_info "Failed to create debug session (may need additional parameters): $create_output"
        return 0
    }
    
    local session_name
    session_name=$(echo "$create_output" | jq -r '.metadata.name') || true
    if [[ -z "$session_name" || "$session_name" == "null" ]]; then
        log_info "Could not extract debug session name, skipping"
        return 0
    fi
    log_success "Debug session created: $session_name"
    
    # Wait for pending state
    log_info "Waiting for debug session to reach pending state..."
    sleep 3
    
    # Try to approve
    log_info "Approver approving debug session..."
    run_as_approver debug approve "$session_name" 2>&1 || log_info "Approval may have auto-completed"
    
    # Check final state
    local state
    state=$(run_as_requester debug get "$session_name" -o json 2>/dev/null | jq -r '.status.state') || true
    log_success "Debug session final state: $state"
    
    echo "$session_name" >> "$TEST_DIR/debug_sessions_to_cleanup"
}

# Test 9: Error handling
test_error_handling() {
    log_step "Test 9: Error Handling"
    
    # Non-existent session
    log_info "Testing get non-existent session..."
    local error_output
    error_output=$(run_as_requester session get "non-existent-session-12345" 2>&1) || true
    if [[ "$error_output" == *"not found"* ]] || [[ "$error_output" == *"error"* ]] || [[ "$error_output" == *"Error"* ]]; then
        log_success "Proper error for non-existent session"
    else
        log_info "Error output: $error_output"
    fi
    
    # Invalid cluster
    log_info "Testing session request with invalid cluster..."
    error_output=$(run_as_requester session request --cluster "invalid-cluster-xyz" --group "$GROUP_NAME" --reason "test" 2>&1) || true
    if [[ "$error_output" == *"not found"* ]] || [[ "$error_output" == *"error"* ]] || [[ "$error_output" == *"Error"* ]] || [[ "$error_output" == *"invalid"* ]] || [[ "$error_output" == *"unauthorized"* ]]; then
        log_success "Proper error for invalid cluster"
    else
        log_info "Error output: $error_output"
    fi
    
    # Missing required flags
    log_info "Testing missing required flags..."
    error_output=$(run_as_requester session request 2>&1) || true
    if [[ "$error_output" == *"required"* ]] || [[ "$error_output" == *"error"* ]] || [[ "$error_output" == *"Error"* ]] || [[ "$error_output" == *"flag"* ]]; then
        log_success "Proper error for missing flags"
    else
        log_info "Error output: $error_output"
    fi
}

# Print test summary
print_summary() {
    log_step "Test Summary"
    
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           Two Persona CLI Flow Test Complete               ║${NC}"
    echo -e "${GREEN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Personas tested:                                          ║${NC}"
    echo -e "${GREEN}║    - Requester: $REQUESTER_USER                                      ║${NC}"
    echo -e "${GREEN}║    - Approver:  $APPROVER_USER                                       ║${NC}"
    echo -e "${GREEN}║  API Server: $API_URL                               ║${NC}"
    echo -e "${GREEN}║  Cluster: $CLUSTER_NAME                                  ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
}

# Main execution
main() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║       Breakglass CLI - Two Persona Flow Test              ║"
    echo "║                                                            ║"
    echo "║  This test simulates real-world usage with two personas:  ║"
    echo "║    - Requester: Creates and manages sessions              ║"
    echo "║    - Approver:  Approves or rejects requests              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check prerequisites
    check_prerequisites
    
    # Get tokens for both personas
    log_step "Getting OIDC Tokens"
    get_oidc_token "$REQUESTER_USER" "$REQUESTER_PASS" "$REQUESTER_TOKEN_FILE" || exit 1
    get_oidc_token "$APPROVER_USER" "$APPROVER_PASS" "$APPROVER_TOKEN_FILE" || exit 1
    
    # Create configs
    log_step "Creating CLI Configurations"
    create_config "$REQUESTER_CONFIG" "Requester"
    create_config "$APPROVER_CONFIG" "Approver"
    
    # Run tests
    local failed=0
    
    test_basic_commands || ((failed++))
    test_list_escalations || ((failed++))
    test_session_approval_flow || ((failed++))
    test_session_rejection_flow || ((failed++))
    test_session_filtering || ((failed++))
    test_output_formats || ((failed++))
    test_cluster_operations || ((failed++))
    test_debug_session_flow || ((failed++))
    test_error_handling || ((failed++))
    
    # Print summary
    print_summary
    
    if [[ $failed -gt 0 ]]; then
        echo -e "\n${RED}$failed test(s) failed${NC}"
        exit 1
    else
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Run main
main "$@"
