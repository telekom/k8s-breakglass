#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2024 Deutsche Telekom
# SPDX-License-Identifier: Apache-2.0
#
# E2E Test Environment Setup Script
# Sets up port-forwards and environment variables for running e2e tests
#
# Usage:
#   source ./e2e/setup-e2e-env.sh           # Source to export env vars
#   ./e2e/setup-e2e-env.sh --start          # Start port-forwards
#   ./e2e/setup-e2e-env.sh --stop           # Stop port-forwards
#   ./e2e/setup-e2e-env.sh --check          # Check if services are accessible
#
set -euo pipefail

# Configuration
NAMESPACE="${E2E_NAMESPACE:-breakglass-system}"
API_PORT="${BREAKGLASS_API_PORT:-8080}"
WEBHOOK_PORT="${BREAKGLASS_WEBHOOK_PORT:-8080}"  # Same as API since SAR is served via API
METRICS_PORT="${BREAKGLASS_METRICS_PORT:-8081}"  # Controller metrics endpoint
KEYCLOAK_PORT="${KEYCLOAK_PORT:-8443}"
MAILHOG_PORT="${MAILHOG_PORT:-8025}"
PF_FILE="${PF_FILE:-e2e/port-forward-pids}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[e2e-env]${NC} $*"; }
warn() { echo -e "${YELLOW}[e2e-env]${NC} $*"; }
error() { echo -e "${RED}[e2e-env]${NC} $*" >&2; }

# Discover service names (kustomize may add prefixes)
discover_services() {
    API_SVC=$(kubectl get svc -n "$NAMESPACE" -l app.kubernetes.io/name=breakglass -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "breakglass-breakglass")
    KEYCLOAK_SVC=$(kubectl get svc -n "$NAMESPACE" -l app=keycloak -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "breakglass-keycloak")
    MAILHOG_SVC=$(kubectl get svc -n "$NAMESPACE" -l app=mailhog -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "breakglass-mailhog")
    
    log "Discovered services:"
    log "  API: $API_SVC"
    log "  Keycloak: $KEYCLOAK_SVC"
    log "  MailHog: $MAILHOG_SVC"
}

# Start port-forwards
start_port_forwards() {
    log "Starting port-forwards..."
    
    discover_services
    
    # Clean up old port-forwards
    stop_port_forwards 2>/dev/null || true
    
    mkdir -p "$(dirname "$PF_FILE")"
    > "$PF_FILE"
    
    # Port-forward API (also serves the SAR webhook at /api/breakglass/webhook/authorize/:cluster)
    log "Starting API port-forward: localhost:$API_PORT -> $API_SVC:8080"
    kubectl -n "$NAMESPACE" port-forward "svc/$API_SVC" "$API_PORT:8080" >/dev/null 2>&1 &
    echo $! >> "$PF_FILE"
    
    # Port-forward Keycloak (if not already running)
    if ! curl -sk "https://localhost:$KEYCLOAK_PORT" >/dev/null 2>&1; then
        log "Starting Keycloak port-forward: localhost:$KEYCLOAK_PORT -> $KEYCLOAK_SVC:8443"
        kubectl -n "$NAMESPACE" port-forward "svc/$KEYCLOAK_SVC" "$KEYCLOAK_PORT:8443" >/dev/null 2>&1 &
        echo $! >> "$PF_FILE"
    else
        log "Keycloak already accessible on port $KEYCLOAK_PORT"
    fi
    
    # Port-forward MailHog
    log "Starting MailHog port-forward: localhost:$MAILHOG_PORT -> $MAILHOG_SVC:8025"
    kubectl -n "$NAMESPACE" port-forward "svc/$MAILHOG_SVC" "$MAILHOG_PORT:8025" >/dev/null 2>&1 &
    echo $! >> "$PF_FILE"
    
    # Port-forward Metrics (controller metrics endpoint on port 8081)
    log "Starting Metrics port-forward: localhost:$METRICS_PORT -> $API_SVC:8081"
    kubectl -n "$NAMESPACE" port-forward "svc/$API_SVC" "$METRICS_PORT:8081" >/dev/null 2>&1 &
    echo $! >> "$PF_FILE"
    
    log "Port-forwards started. PIDs saved to $PF_FILE"
    
    # Wait for port-forwards to be ready
    log "Waiting for services to be accessible..."
    for i in {1..30}; do
        if curl -s "http://localhost:$API_PORT/api/config" >/dev/null 2>&1; then
            log "API is ready on localhost:$API_PORT"
            break
        fi
        sleep 1
    done
    
    if ! curl -s "http://localhost:$API_PORT/api/config" >/dev/null 2>&1; then
        error "API not accessible after 30 seconds"
        return 1
    fi
}

# Stop port-forwards
stop_port_forwards() {
    log "Stopping port-forwards..."
    
    if [ -f "$PF_FILE" ]; then
        while read -r pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                log "Stopping process $pid"
                kill "$pid" 2>/dev/null || true
            fi
        done < "$PF_FILE"
        rm -f "$PF_FILE"
    fi
    
    # Also kill any stray port-forwards for our services
    pkill -f "kubectl.*port-forward.*breakglass" 2>/dev/null || true
    
    log "Port-forwards stopped"
}

# Check if services are accessible
check_services() {
    log "Checking service accessibility..."
    
    local all_ok=true
    
    # Check API
    if curl -s "http://localhost:$API_PORT/api/config" >/dev/null 2>&1; then
        log "✓ API accessible at http://localhost:$API_PORT"
    else
        error "✗ API NOT accessible at http://localhost:$API_PORT"
        all_ok=false
    fi
    
    # Check webhook endpoint (via API)
    if curl -s "http://localhost:$WEBHOOK_PORT/api/breakglass/webhook/authorize/test" -X POST -d '{}' >/dev/null 2>&1; then
        log "✓ Webhook endpoint accessible at http://localhost:$WEBHOOK_PORT/api/breakglass/webhook/authorize/"
    else
        warn "⚠ Webhook endpoint may not be accessible (POST returns error, which is expected for empty body)"
    fi
    
    # Check Keycloak
    if curl -sk "https://localhost:$KEYCLOAK_PORT" >/dev/null 2>&1; then
        log "✓ Keycloak accessible at https://localhost:$KEYCLOAK_PORT"
    else
        warn "⚠ Keycloak NOT accessible at https://localhost:$KEYCLOAK_PORT (may not be needed)"
    fi
    
    # Check MailHog
    if curl -s "http://localhost:$MAILHOG_PORT" >/dev/null 2>&1; then
        log "✓ MailHog accessible at http://localhost:$MAILHOG_PORT"
    else
        warn "⚠ MailHog NOT accessible at http://localhost:$MAILHOG_PORT (may not be needed)"
    fi
    
    # Check Metrics
    if curl -s "http://localhost:$METRICS_PORT/metrics" >/dev/null 2>&1; then
        log "✓ Metrics accessible at http://localhost:$METRICS_PORT/metrics"
    else
        warn "⚠ Metrics NOT accessible at http://localhost:$METRICS_PORT/metrics (may not be needed)"
    fi
    
    if [ "$all_ok" = true ]; then
        log "All critical services are accessible"
        return 0
    else
        error "Some services are not accessible"
        return 1
    fi
}

# Export environment variables for e2e tests
export_env_vars() {
    export E2E_TEST=true
    export E2E_NAMESPACE="${E2E_NAMESPACE:-default}"
    export E2E_CLUSTER_NAME="${E2E_CLUSTER_NAME:-tenant-a}"
    export E2E_TEST_USER="${E2E_TEST_USER:-testuser@example.com}"
    export E2E_TEST_APPROVER="${E2E_TEST_APPROVER:-approver@example.com}"
    export BREAKGLASS_API_URL="http://localhost:$API_PORT"
    export BREAKGLASS_WEBHOOK_URL="http://localhost:$WEBHOOK_PORT"
    export BREAKGLASS_METRICS_URL="http://localhost:$METRICS_PORT/metrics"
    export KEYCLOAK_HOST="https://localhost:$KEYCLOAK_PORT"
    export KEYCLOAK_REALM="${KEYCLOAK_REALM:-breakglass-e2e}"
    # KEYCLOAK_ISSUER_HOST is the host that will be used in the token's issuer claim.
    # This must match the authority in the IdentityProvider CR for token verification to work.
    export KEYCLOAK_ISSUER_HOST="${KEYCLOAK_ISSUER_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local:8443}"
    
    log "Environment variables exported:"
    log "  E2E_TEST=$E2E_TEST"
    log "  E2E_NAMESPACE=$E2E_NAMESPACE"
    log "  E2E_CLUSTER_NAME=$E2E_CLUSTER_NAME"
    log "  BREAKGLASS_API_URL=$BREAKGLASS_API_URL"
    log "  BREAKGLASS_WEBHOOK_URL=$BREAKGLASS_WEBHOOK_URL"
    log "  KEYCLOAK_HOST=$KEYCLOAK_HOST"
    log "  KEYCLOAK_ISSUER_HOST=$KEYCLOAK_ISSUER_HOST"
}

# Print usage instructions
print_usage() {
    cat <<EOF
E2E Test Environment Setup

Usage:
  source ./e2e/setup-e2e-env.sh           # Source to export env vars only
  ./e2e/setup-e2e-env.sh --start          # Start port-forwards
  ./e2e/setup-e2e-env.sh --stop           # Stop port-forwards
  ./e2e/setup-e2e-env.sh --check          # Check if services are accessible
  ./e2e/setup-e2e-env.sh --all            # Start port-forwards and export vars

Environment Variables (configurable):
  E2E_NAMESPACE           Kubernetes namespace (default: breakglass-system)
  BREAKGLASS_API_PORT     Local port for Breakglass API (default: 8080)
  KEYCLOAK_PORT           Local port for Keycloak (default: 8443)
  MAILHOG_PORT            Local port for MailHog (default: 8025)

Example workflow:
  # 1. Start port-forwards
  ./e2e/setup-e2e-env.sh --start
  
  # 2. Run tests
  E2E_TEST=true go test -v ./e2e/api/...
  
  # 3. Stop port-forwards
  ./e2e/setup-e2e-env.sh --stop

EOF
}

# Main entry point
main() {
    case "${1:-}" in
        --start)
            start_port_forwards
            export_env_vars
            ;;
        --stop)
            stop_port_forwards
            ;;
        --check)
            check_services
            ;;
        --all)
            start_port_forwards
            export_env_vars
            check_services
            ;;
        --help|-h)
            print_usage
            ;;
        "")
            # If sourced without args, just export env vars
            export_env_vars
            ;;
        *)
            error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
}

# Only run main if script is executed (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
