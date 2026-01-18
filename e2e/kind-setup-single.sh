#!/usr/bin/env bash
set -euo pipefail
# Single-cluster variant: Keycloak + Breakglass controller + webhook auth all in one kind cluster.
# Replaces previous hub+tenant topology by creating only one cluster and using a ClusterConfig
# that points back to the same cluster (simulated tenant "tenant-a").

# --- Script directory and common library ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_LOG_PREFIX="[single-e2e]"
export E2E_DIR="$SCRIPT_DIR"

# Source common library (provides shared functions for logging, TLS, network, etc.)
if [ -f "${SCRIPT_DIR}/lib/common.sh" ]; then
  source "${SCRIPT_DIR}/lib/common.sh"
else
  # Fallback if common library not found - define minimal log function
  log(){ printf '[single-e2e] %s\n' "$*"; }
  log "Warning: Common library not found at ${SCRIPT_DIR}/lib/common.sh, using minimal functions"
fi

# --- Tools (can be overridden by env) ---
KIND=${KIND:-kind}
KUBECTL=${KUBECTL:-kubectl}
KUSTOMIZE=${KUSTOMIZE:-kustomize}

# --- Images & build ---
IMAGE=${IMAGE:-breakglass:e2e}
# UI flavour: default oss (neutral). Set UI_FLAVOUR=telekom to opt-in.
UI_FLAVOUR=${UI_FLAVOUR:-oss}
export VITE_UI_FLAVOUR=$UI_FLAVOUR
echo "UI flavour selected: $UI_FLAVOUR (IMAGE=$IMAGE)"
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.0}

# --- Cluster / service names (defaults kept from original script) ---
CLUSTER_NAME=${CLUSTER_NAME:-breakglass-hub}
WEBHOOK_HOST_PLACEHOLDER=${WEBHOOK_HOST_PLACEHOLDER:-breakglass.system.svc.cluster.local} # in-cluster service DNS

# --- Ports / forwards ---
NODEPORT=${NODEPORT:-31081}                 # NodePort used to expose the breakglass service for local tests
WEBHOOK_SERVICE_PORT=${WEBHOOK_SERVICE_PORT:-8081} # in-cluster port webhook/controller listens on
# Forward Keycloak HTTPS (container uses 8443) by default so local https access matches container port
KEYCLOAK_SVC_PORT=${KEYCLOAK_SVC_PORT:-8443}     # keycloak service internal port (prefer HTTPS)
KEYCLOAK_FORWARD_PORT=${KEYCLOAK_FORWARD_PORT:-8443} # local port forwarded to Keycloak svc:8443
# CONTROLLER_FORWARD_PORT defaults to 8080 for UI E2E consistency (can be overridden)
MAILHOG_UI_PORT=${MAILHOG_UI_PORT:-8025}
# METRICS_FORWARD_PORT will be set later to a dynamic port if not explicitly provided
# The breakglass controller exposes Prometheus metrics on port 8081

# --- Kind node image ---
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.34.0}

# --- TLS / temp directories (kept as before, but configurable) ---
TDIR=${TDIR:-}
TLS_DIR=${TLS_DIR:-}
KIND_CFG=${KIND_CFG:-}
HUB_KUBECONFIG=${HUB_KUBECONFIG:-}
PF_FILE=${PF_FILE:-e2e/port-forward-pids}

# --- Keycloak realm / issuer ---
# Default to the in-cluster service name that the `config/dev` overlay creates
# (the dev overlay uses a namePrefix breakglass- and namespace breakglass-system).
# This ensures the apiserver OIDC issuer points at a DNS name resolvable inside the cluster.
KEYCLOAK_HOST=${KEYCLOAK_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local}
KEYCLOAK_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT:-8443}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-breakglass-e2e}

# --- Tenants / cluster ids used in rendered CRs ---
TENANT_A=${TENANT_A:-tenant-a}
TENANT_B=${TENANT_B:-tenant-b}
CLUSTER_CONFIG_ID=${CLUSTER_CONFIG_ID:-$CLUSTER_NAME}

# --- Proxy configuration (optional) ---
# Set SKIP_PROXY=true to disable proxy settings (e.g., for macOS/Orbstack local development)
# By default, use corporate HTTP proxy if SKIP_PROXY is not set
if [ "${SKIP_PROXY:-false}" = "true" ]; then
  printf '[single-e2e] SKIP_PROXY=true: Skipping corporate proxy configuration\n'
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
else
  # Corporate proxy settings (override with HTTP_PROXY/HTTPS_PROXY env vars if needed)
  HTTP_PROXY="${HTTP_PROXY:-http://172.17.0.1:8118}"
  HTTPS_PROXY="${HTTPS_PROXY:-http://172.17.0.1:8118}"
  # Also export lowercase variants for tools that read them
  http_proxy="$HTTP_PROXY"
  https_proxy="$HTTPS_PROXY"

  # Ensure proxy doesn't intercept in-cluster / localhost calls
  # include several keycloak DNS variants so pod-internal calls are not proxied
  REQUIRED_NO_PROXY="localhost,127.0.0.1,::1,.svc,.svc.cluster.local,.cluster.local,keycloak,keycloak.keycloak,keycloak.keycloak.svc,keycloak.keycloak.svc.cluster.local,${KEYCLOAK_HOST},${WEBHOOK_HOST_PLACEHOLDER},${CLUSTER_NAME}-control-plane"
  if [ -n "${NO_PROXY:-}" ]; then
    IFS=',' read -r -a existing_np <<< "$NO_PROXY"
    for entry in ${REQUIRED_NO_PROXY//,/ }; do
      found=false
      for e in "${existing_np[@]}"; do [ "$e" = "$entry" ] && found=true && break; done
      $found || NO_PROXY+="${NO_PROXY:+,}$entry"
    done
  else
    NO_PROXY="$REQUIRED_NO_PROXY"
  fi
  export NO_PROXY
  export no_proxy="$NO_PROXY"
  export HTTP_PROXY
  export HTTPS_PROXY
  printf '[single-e2e] Using proxy: HTTP_PROXY=%s, NO_PROXY=%s\n' "$HTTP_PROXY" "$NO_PROXY"
fi

# --- Helper functions ---
# Note: log(), find_free_port() are now provided by lib/common.sh
# The functions below use script-specific global variables ($CLUSTER_NAME, $HUB_KUBECONFIG)
# so they are kept here rather than in the common library.

load_image_into_kind() {
  # Usage: load_image_into_kind imageName
  # Uses global $CLUSTER_NAME
  local img="$1"
  ensure_image_exists "$img" || true
  log "Loading image $img into kind cluster $CLUSTER_NAME"
  
  # Try direct load first, fall back to archive method if containerd snapshotter detection fails
  if $KIND load docker-image "$img" --name "$CLUSTER_NAME" 2>&1 | tee /dev/stderr | grep -q "failed to detect containerd snapshotter"; then
    log "Direct load failed due to containerd snapshotter issue, using archive method..."
    local tmp_archive
    tmp_archive=$(mktemp --suffix=.tar)
    if docker save "$img" -o "$tmp_archive" && $KIND load image-archive "$tmp_archive" --name "$CLUSTER_NAME"; then
      log "Successfully loaded $img via archive method"
    else
      log "WARN: Failed to load image $img via archive method"
    fi
    rm -f "$tmp_archive"
  fi
}

debug_deployment_failure() {
  # Usage: debug_deployment_failure label
  # Uses global $HUB_KUBECONFIG
  local label="$1"
  # Delegate to common library
  e2e_debug_deployment_failure "$HUB_KUBECONFIG" "$label"
}

debug_cluster_state() {
  # Usage: debug_cluster_state [context_message]
  # Uses global $HUB_KUBECONFIG, $CLUSTER_NAME
  local context="${1:-General failure}"
  e2e_print_cluster_debug "$HUB_KUBECONFIG" "$CLUSTER_NAME" "breakglass-system"
}

wait_for_deploy_by_label() {
  # Usage: wait_for_deploy_by_label label max_attempts
  # Uses global $HUB_KUBECONFIG
  local label="$1"
  local max_attempts=${2:-120}
  if ! e2e_wait_for_deployment_by_label "$HUB_KUBECONFIG" "$label" "$max_attempts"; then
    e2e_debug_deployment_failure "$HUB_KUBECONFIG" "$label"
    return 1
  fi
}

start_port_forward() {
  # Usage: start_port_forward namespace svc localPort remotePort
  # Uses global $HUB_KUBECONFIG, $PF_FILE
  local ns="$1"
  local svc="$2"
  local local_port="$3"
  local remote_port="$4"
  log "Starting port-forward for svc/$svc in ns $ns -> localhost:$local_port:$remote_port"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$ns" port-forward svc/"$svc" ${local_port}:${remote_port} >/dev/null 2>&1 &
  local pid=$!
  [ -n "$PF_FILE" ] && mkdir -p "$(dirname "$PF_FILE")" 2>/dev/null || true
  echo $pid >> "$PF_FILE" 2>/dev/null || true
  echo $pid
}

apply_kustomize() {
  # Usage: apply_kustomize path
  local path="$1"
  log "Applying kustomize overlay: $path"
  # Use --server-side --force-conflicts to handle resources that may have been modified
  # by other processes (e.g., ValidatingWebhookConfiguration CA bundle patching)
  KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build "$path" | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply --server-side --force-conflicts -f -
}

wait_for_mailprovider_ready() {
  # Wait for MailProvider to be reconciled and ready (condition Ready=True)
  # This is critical for email notification tests - the controller needs time to
  # pick up the MailProvider CR and initialize the mail service
  local name="$1"
  local namespace="${2:-breakglass-system}"
  local max_attempts="${3:-60}"
  local attempt=0
  
  log "Waiting for MailProvider $name to be Ready..."
  while [ $attempt -lt $max_attempts ]; do
    local ready_status
    ready_status=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get mailprovider "$name" -n "$namespace" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
    
    if [ "$ready_status" = "True" ]; then
      log "MailProvider $name is Ready"
      return 0
    fi
    
    attempt=$((attempt + 1))
    sleep 1
  done
  
  log "Warning: MailProvider $name did not become Ready within $max_attempts seconds"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get mailprovider "$name" -n "$namespace" -o yaml 2>/dev/null || true
  return 1
}

wait_for_identityprovider_ready() {
  # Wait for IdentityProvider to be reconciled and ready (condition Ready=True)
  # This is critical for OIDC authentication and group sync - the controller needs time to
  # pick up the IdentityProvider CR and initialize the OIDC/Keycloak client
  local name="$1"
  local namespace="${2:-breakglass-system}"
  local max_attempts="${3:-60}"
  local attempt=0
  
  log "Waiting for IdentityProvider $name to be Ready..."
  while [ $attempt -lt $max_attempts ]; do
    local ready_status
    ready_status=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get identityprovider "$name" -n "$namespace" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "")
    
    if [ "$ready_status" = "True" ]; then
      log "IdentityProvider $name is Ready"
      return 0
    fi
    
    attempt=$((attempt + 1))
    sleep 1
  done
  
  log "Warning: IdentityProvider $name did not become Ready within $max_attempts seconds"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get identityprovider "$name" -n "$namespace" -o yaml 2>/dev/null || true
  return 1
}

assign_keycloak_service_account_roles() {
  # Assign realm-management roles to the breakglass-group-sync service account
  # This is needed because Keycloak realm import doesn't reliably import service account role mappings
  # The service account needs view-users, query-users, query-groups roles to query the admin API
  local keycloak_pod
  local realm="${KEYCLOAK_REALM:-breakglass-e2e}"
  local admin_user="${KEYCLOAK_ADMIN:-admin}"
  local admin_password="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
  local client_id="breakglass-group-sync"
  local max_wait=60
  local wait_interval=2
  
  log "Assigning realm-management roles to $client_id service account..."
  
  # Find keycloak pod
  keycloak_pod=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get pods -n "$DEV_NS" -l app=keycloak -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
  if [ -z "$keycloak_pod" ]; then
    log "Warning: Keycloak pod not found, cannot assign service account roles"
    return 1
  fi
  
  # Use kcadm.sh inside the container to assign roles
  # First, login as admin
  if ! KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
    /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 \
    --realm master --user "$admin_user" --password "$admin_password" 2>/dev/null; then
    log "Warning: Failed to authenticate to Keycloak admin CLI"
    return 1
  fi
  
  # Wait for the realm import to complete by polling for the client
  # The Keycloak realm import is asynchronous - the pod becomes ready before import finishes
  log "Waiting for realm import to complete (client $client_id to appear)..."
  local sa_user_id=""
  local waited=0
  local max_wait=180  # Keycloak 26 realm import can take 2-3 minutes
  
  # First, wait for the realm itself to exist
  log "Checking if realm '$realm' exists..."
  local realm_exists=""
  while [ -z "$realm_exists" ] && [ $waited -lt $max_wait ]; do
    realm_exists=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh get realms -r "$realm" --fields realm 2>/dev/null | \
      grep "\"realm\"" || echo "")
    
    if [ -z "$realm_exists" ]; then
      sleep $wait_interval
      waited=$((waited + wait_interval))
      [ $((waited % 10)) -eq 0 ] && log "Waiting for realm $realm to be created (${waited}s/${max_wait}s)..."
    fi
  done
  
  if [ -z "$realm_exists" ]; then
    log "Warning: Realm $realm does not exist after ${waited}s"
    # Show available realms for diagnostics
    log "Available realms:"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh get realms --fields realm 2>&1 || true
    # Check Keycloak logs for import errors
    log "Keycloak logs (last 30 lines):"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL logs -n "$DEV_NS" "$keycloak_pod" --tail=30 2>&1 || true
    return 1
  fi
  
  log "Realm $realm exists, now waiting for client $client_id..."
  
  # Reset waited counter for client polling
  waited=0
  
  # Now wait for the client to appear in the realm
  while [ -z "$sa_user_id" ] && [ $waited -lt $max_wait ]; do
    # Try to find the client directly using query filter - more reliable than grep parsing fields
    # Returns [ { "id" : "..." } ] if found
    sa_user_id=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh get clients -r "$realm" -q clientId="$client_id" --fields id 2>/dev/null | \
      grep '"id"' | sed 's/.*: "\(.*\)".*/\1/' | tr -d '" ,' || echo "")
    
    if [ -z "$sa_user_id" ]; then
      sleep $wait_interval
      waited=$((waited + wait_interval))
      if [ $((waited % 10)) -eq 0 ]; then
        log "Still waiting for client $client_id to appear in realm $realm (${waited}s/${max_wait}s)..."
      fi
    fi
  done
  
  if [ -z "$sa_user_id" ]; then
    log "Warning: Could not find client $client_id in realm $realm after ${max_wait}s"
    # List all clients for diagnostics
    log "Available clients in realm $realm:"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh get clients -r "$realm" --fields clientId 2>&1 | head -80 || true
    # Check if realm import is still in progress or failed
    log "Keycloak logs (last 50 lines, look for import errors):"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL logs -n "$DEV_NS" "$keycloak_pod" --tail=50 2>&1 | grep -iE "(import|realm|error|exception|failed)" || true
    return 1
  fi
  
  log "Client $client_id found after ${waited}s"
  
  # Get service account user
  local sa_user
  sa_user=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
    /opt/keycloak/bin/kcadm.sh get clients/"$sa_user_id"/service-account-user -r "$realm" 2>/dev/null | \
    grep '"id"' | head -1 | sed 's/.*: "\(.*\)".*/\1/' || echo "")
  
  if [ -z "$sa_user" ]; then
    log "Warning: Could not find service account user for client $client_id"
    return 1
  fi
  
  log "Found service account user ID: $sa_user"
  
  # Get realm-management client ID
  local realm_mgmt_client_id
  realm_mgmt_client_id=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
    /opt/keycloak/bin/kcadm.sh get clients -r "$realm" --fields id,clientId 2>/dev/null | \
    grep -A1 '"clientId" : "realm-management"' | grep '"id"' | sed 's/.*: "\(.*\)".*/\1/' || echo "")
  
  if [ -z "$realm_mgmt_client_id" ]; then
    log "Warning: Could not find realm-management client"
    return 1
  fi
  
  log "Found realm-management client ID: $realm_mgmt_client_id"
  
  # Assign required roles
  local roles=("view-users" "query-users" "query-groups" "view-realm")
  for role in "${roles[@]}"; do
    log "Assigning role: $role"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n "$DEV_NS" "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh add-roles -r "$realm" \
      --uusername "service-account-$client_id" \
      --cclientid realm-management \
      --rolename "$role" 2>/dev/null || log "Warning: Failed to assign role $role (may already exist)"
  done
  
  log "Service account role assignment completed"
  return 0
}

# apply_cr_with_retry applies a CR file with retry logic for transient webhook failures
# Args: $1 = cr_file path, $2 = max retries (default 5), $3 = retry delay in seconds (default 5)
apply_cr_with_retry() {
  local cr_file="$1"
  local max_retries="${2:-5}"
  local retry_delay="${3:-5}"
  local attempt=1
  
  while [ $attempt -le $max_retries ]; do
    log "Applying $cr_file (attempt $attempt/$max_retries)"
    # Apply directly with kubectl, transforming namespace and name prefix using sed
    # This avoids kustomize's restriction on absolute paths
    # Also transform podTemplateRef.name to match the prefixed DebugPodTemplate names
    if sed -e 's/namespace: default/namespace: breakglass-system/g' \
           -e 's/namespace: breakglass$/namespace: breakglass-system/g' \
           -e '/^  name:/s/name: /name: breakglass-/g' \
           -e '/podTemplateRef:/,/^[^ ]/{s/name: /name: breakglass-/}' \
           "$cr_file" | \
       KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -n breakglass-system -f - 2>&1; then
      return 0
    fi
    
    if [ $attempt -lt $max_retries ]; then
      log "Apply failed, retrying in ${retry_delay}s..."
      sleep "$retry_delay"
    fi
    attempt=$((attempt + 1))
  done
  
  log "Warning: failed to apply $cr_file after $max_retries attempts (continuing)"
  return 1
}

# apply_stdin_with_retry applies YAML from stdin with retry logic for transient webhook failures
# Args: $1 = max retries (default 5), $2 = retry delay in seconds (default 5)
# Usage: cat <<YAML | apply_stdin_with_retry 5 5
apply_stdin_with_retry() {
  local max_retries="${1:-5}"
  local retry_delay="${2:-5}"
  local attempt=1
  local yaml_content
  yaml_content=$(cat)  # Read stdin once
  
  while [ $attempt -le $max_retries ]; do
    log "Applying YAML from stdin (attempt $attempt/$max_retries)"
    if echo "$yaml_content" | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - 2>&1; then
      return 0
    fi
    
    if [ $attempt -lt $max_retries ]; then
      log "Apply failed, retrying in ${retry_delay}s..."
      sleep "$retry_delay"
    fi
    attempt=$((attempt + 1))
  done
  
  log "Warning: failed to apply YAML after $max_retries attempts (continuing)"
  return 1
}

apply_e2e_test_crs() {
  # Apply e2e test CRs that require webhook validation
  # These are excluded from config/dev/kustomization.yaml to avoid race conditions
  # with the webhook CA bundle patching. They must be applied AFTER:
  # 1. The webhook CA bundle is patched
  # 2. The controller is ready and webhook server is serving
  log "Applying e2e test CRs (excluded from kustomize to avoid webhook validation race)..."
  
  # NOTE: idp.yaml is NOT included here - the IdentityProvider is created later
  # in the script with proper wait logic (see "Create IdentityProvider for OIDC authentication")
  # NOTE: mailprovider.yaml is included to set up MailHog for e2e email testing
  local cr_files=(
    "config/dev/resources/mailprovider.yaml"
    "config/dev/resources/crs/audit-config-test.yaml"
    "config/dev/resources/crs/cluster-configs-test.yaml"
    "config/dev/resources/crs/debug-templates-test.yaml"
    "config/dev/resources/crs/deny-policies-test.yaml"
    "config/dev/resources/crs/escalations-test.yaml"
    "config/dev/resources/crs/ui-e2e-escalations.yaml"
  )
  
  for cr_file in "${cr_files[@]}"; do
    if [ -f "$cr_file" ]; then
      apply_cr_with_retry "$cr_file" 5 5
    else
      log "Warning: CR file not found: $cr_file"
    fi
  done
  
  # Wait for MailProvider to be ready so email notifications work in tests
  # The name becomes breakglass-mailhog after sed prefix transformation
  wait_for_mailprovider_ready "breakglass-mailhog" "breakglass-system" 60
  
  log "Finished applying e2e test CRs"
}

patch_webhook_ca_bundle() {
  # Patch the ValidatingWebhookConfiguration with the CA bundle from our webhook TLS secret
  # This is needed because we're not using cert-manager to inject the CA
  # The CA bundle is read from WEBHOOK_TLS_DIR/ca.crt (must be set before calling)
  if [ ! -f "$WEBHOOK_TLS_DIR/ca.crt" ]; then
    log "Warning: Webhook CA file not found at $WEBHOOK_TLS_DIR/ca.crt"
    return 1
  fi
  log "Patching ValidatingWebhookConfiguration with webhook CA bundle..."
  # Use cat | base64 for macOS compatibility (base64 < file can have issues)
  local ca_bundle
  ca_bundle=$(cat "$WEBHOOK_TLS_DIR/ca.crt" | base64 | tr -d '\n')
  local vwc_name
  vwc_name=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get validatingwebhookconfiguration -o name 2>/dev/null | grep breakglass | head -n1 | sed 's#validatingwebhookconfiguration.admissionregistration.k8s.io/##' || true)
  if [ -n "$vwc_name" ]; then
    # Get the current webhook configuration and patch each webhook's caBundle
    # Use kubectl get + jq to build a proper patch, then apply
    local current_config
    current_config=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get validatingwebhookconfiguration "$vwc_name" -o json)
    
    # Build patched config using jq if available, otherwise fall back to strategic merge patch
    if command -v jq &>/dev/null; then
      # Build a JSON patch for all webhooks
      local webhook_count
      webhook_count=$(echo "$current_config" | jq '.webhooks | length')
      local patch_ops='['
      for ((idx=0; idx<webhook_count; idx++)); do
        [ $idx -gt 0 ] && patch_ops="$patch_ops,"
        patch_ops="$patch_ops{\"op\":\"add\",\"path\":\"/webhooks/$idx/clientConfig/caBundle\",\"value\":\"$ca_bundle\"}"
      done
      patch_ops="$patch_ops]"
      KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL patch validatingwebhookconfiguration "$vwc_name" --type='json' -p="$patch_ops" && \
        log "Patched ValidatingWebhookConfiguration $vwc_name with CA bundle" || \
        log "Warning: failed to patch ValidatingWebhookConfiguration (webhooks may not work)"
    else
      # Fallback: use kubectl patch with strategic merge
      # Get webhook names using jsonpath
      local webhook_names
      webhook_names=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get validatingwebhookconfiguration "$vwc_name" -o jsonpath='{range .webhooks[*]}{.name}{"\n"}{end}' 2>/dev/null)
      local patch_json='{"webhooks":['
      local first=true
      while IFS= read -r wh_name; do
        [ -z "$wh_name" ] && continue
        $first || patch_json="$patch_json,"
        first=false
        patch_json="$patch_json{\"name\":\"$wh_name\",\"clientConfig\":{\"caBundle\":\"$ca_bundle\"}}"
      done <<< "$webhook_names"
      patch_json="$patch_json]}"
      KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL patch validatingwebhookconfiguration "$vwc_name" --type='strategic' -p="$patch_json" && \
        log "Patched ValidatingWebhookConfiguration $vwc_name with CA bundle" || \
        log "Warning: failed to patch ValidatingWebhookConfiguration (webhooks may not work)"
    fi
  else
    log "Warning: No ValidatingWebhookConfiguration found for breakglass (webhooks may not validate)"
    return 1
  fi
}

# Wait for cert-manager to inject the CA bundle into ValidatingWebhookConfiguration
# This is the preferred approach when using cert-manager for webhook certificates
wait_for_webhook_ca_injection() {
  local max_attempts=${1:-60}
  local vwc_name
  vwc_name=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get validatingwebhookconfiguration -o name 2>/dev/null | grep breakglass | head -n1 | sed 's#validatingwebhookconfiguration.admissionregistration.k8s.io/##' || true)
  
  if [ -z "$vwc_name" ]; then
    log "Warning: No ValidatingWebhookConfiguration found for breakglass"
    return 1
  fi
  
  log "Waiting for cert-manager to inject CA bundle into ValidatingWebhookConfiguration $vwc_name..."
  local attempt=0
  while [ $attempt -lt $max_attempts ]; do
    # Check if caBundle is set on first webhook (cert-manager injects to all webhooks)
    local ca_bundle
    ca_bundle=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get validatingwebhookconfiguration "$vwc_name" -o jsonpath='{.webhooks[0].clientConfig.caBundle}' 2>/dev/null || echo "")
    
    if [ -n "$ca_bundle" ] && [ "$ca_bundle" != "null" ] && [ ${#ca_bundle} -gt 100 ]; then
      log "CA bundle injected by cert-manager (length: ${#ca_bundle})"
      return 0
    fi
    
    attempt=$((attempt + 1))
    [ $((attempt % 10)) -eq 0 ] && log "Still waiting for CA bundle injection (attempt $attempt/$max_attempts)..."
    sleep 1
  done
  
  log "Warning: CA bundle not injected after $max_attempts seconds"
  log "Checking cert-manager resources..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get certificate -n breakglass-system 2>/dev/null || true
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL describe certificate breakglass-webhook-serving-cert -n breakglass-system 2>/dev/null | tail -20 || true
  return 1
}

set_image_and_wait_by_label() {
  # Usage: set_image_and_wait_by_label label containerName image
  local label="$1"; local container="$2"; local image="$3"
  MANAGER_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
  MANAGER_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$MANAGER_NAME" ] && [ -n "$MANAGER_NS" ]; then
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL set image deployment/"$MANAGER_NAME" -n "$MANAGER_NS" ${container}=${image} || true
    # wait for ready
    for i in {1..60}; do a=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy/"$MANAGER_NAME" -n "$MANAGER_NS" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0); [ "$a" = "1" ] && break; sleep 3; done
    [ "$a" = "1" ] || { log "Deployment ${MANAGER_NAME} not ready"; debug_deployment_failure "$MANAGER_NAME" "$MANAGER_NS"; return 1; }
  else
    log "Warning: deployment with label app=${label} not found; attempting fallback"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL set image deployment/manager -n system ${container}=${image} || true
    for i in {1..60}; do a=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy/manager -n system -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0); [ "$a" = "1" ] && break; sleep 3; done
    [ "$a" = "1" ] || { log 'Controller not ready'; debug_deployment_failure "manager" "system"; return 1; }
  fi
  return 0
}


# Prefer repo-local temporary directories instead of /tmp to avoid ephemeral
# cross-user conflicts and to keep artifacts inside the workspace. Allow
# overriding via environment variables (TDIR, TLS_DIR, KIND_CFG, HUB_KUBECONFIG).
# Derive repository root from the script location so paths are deterministic.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TDIR=${TDIR:-"$REPO_ROOT/e2e/kind-setup-single-tdir"}
mkdir -p "$TDIR"
AUTHZ_FILE="$TDIR/authorization-config.yaml"
AUTHN_FILE="$TDIR/authentication-config.yaml"
WEBHOOK_KCFG="$TDIR/authorization-kubeconfig.yaml"
KEYCLOAK_CA_FILE="$TDIR/keycloak-ca.crt"

TLS_DIR=${TLS_DIR:-"$REPO_ROOT/e2e/kind-setup-single-tls"}
mkdir -p "$TLS_DIR"
OPENSSL_CONF_KEYCLOAK="$TLS_DIR/req.cnf"

# Default KIND_CFG and HUB_KUBECONFIG to repo-local files (can be overridden)
KIND_CFG=${KIND_CFG:-"$REPO_ROOT/e2e/kind-setup-single-kind-cfg.yaml"}
HUB_KUBECONFIG=${HUB_KUBECONFIG:-"$REPO_ROOT/e2e/kind-setup-single-hub-kubeconfig.yaml"}

# Pre-generate CA/certs for Keycloak so we can embed CA into auth config before cluster creation
cat > "$OPENSSL_CONF_KEYCLOAK" << EOF
[ req ]
distinguished_name = dn
req_extensions = req_ext
prompt = no
[ dn ]
CN = keycloak.keycloak.svc.cluster.local
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = keycloak
DNS.2 = keycloak.keycloak
DNS.3 = keycloak.keycloak.svc
DNS.4 = keycloak.keycloak.svc.cluster.local
DNS.5 = localhost
DNS.6 = ${KEYCLOAK_HOST}
DNS.7 = breakglass-keycloak
DNS.8 = breakglass.system.svc.cluster.local
EOF
openssl genrsa -out "$TLS_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" -subj "/CN=breakglass-keycloak-ca" -days 365 -out "$TLS_DIR/ca.crt"
openssl genrsa -out "$TLS_DIR/server.key" 2048
openssl req -new -key "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" -config "$OPENSSL_CONF_KEYCLOAK"
openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial -out "$TLS_DIR/server.crt" -days 365 -extensions req_ext -extfile "$OPENSSL_CONF_KEYCLOAK"
cp "$TLS_DIR/ca.crt" "$KEYCLOAK_CA_FILE"

# Generate webhook serving certificates for the breakglass controller webhook server
log "Generating webhook TLS certificates"
WEBHOOK_TLS_DIR="$TLS_DIR/webhook"
mkdir -p "$WEBHOOK_TLS_DIR"
OPENSSL_CONF_WEBHOOK="$WEBHOOK_TLS_DIR/req.cnf"

# The webhook server is accessed via the breakglass service in the dev namespace
cat > "$OPENSSL_CONF_WEBHOOK" << EOF
[ req ]
distinguished_name = dn
req_extensions = req_ext
prompt = no
[ dn ]
CN = breakglass-webhook-service.breakglass-system.svc
[ req_ext ]
subjectAltName = @alt_names
[ alt_names ]
DNS.1 = breakglass-manager
DNS.2 = breakglass-manager.breakglass-system
DNS.3 = breakglass-manager.breakglass-system.svc
DNS.4 = breakglass-manager.breakglass-system.svc.cluster.local
DNS.5 = breakglass-webhook-service
DNS.6 = breakglass-webhook-service.breakglass-system
DNS.7 = breakglass-webhook-service.breakglass-system.svc
DNS.8 = breakglass-webhook-service.breakglass-system.svc.cluster.local
DNS.9 = localhost
EOF

# Generate webhook CA (separate from Keycloak CA for isolation)
openssl genrsa -out "$WEBHOOK_TLS_DIR/ca.key" 2048
openssl req -x509 -new -nodes -key "$WEBHOOK_TLS_DIR/ca.key" -subj "/CN=breakglass-webhook-ca" -days 365 -out "$WEBHOOK_TLS_DIR/ca.crt"
# Generate webhook server cert
openssl genrsa -out "$WEBHOOK_TLS_DIR/tls.key" 2048
openssl req -new -key "$WEBHOOK_TLS_DIR/tls.key" -out "$WEBHOOK_TLS_DIR/webhook.csr" -config "$OPENSSL_CONF_WEBHOOK"
openssl x509 -req -in "$WEBHOOK_TLS_DIR/webhook.csr" -CA "$WEBHOOK_TLS_DIR/ca.crt" -CAkey "$WEBHOOK_TLS_DIR/ca.key" -CAcreateserial -out "$WEBHOOK_TLS_DIR/tls.crt" -days 365 -extensions req_ext -extfile "$OPENSSL_CONF_WEBHOOK"
log "Webhook TLS certificates generated in $WEBHOOK_TLS_DIR"

# Ensure the Keycloak hostname resolves to localhost on the host machine so local port-forwards
# and HTTPS hostname verification (when using the supplied CA) work consistently. Idempotent.
if [ -n "${KEYCLOAK_HOST:-}" ]; then
  if ! grep -Fq "$KEYCLOAK_HOST" /etc/hosts 2>/dev/null; then
    log "Adding host entry for $KEYCLOAK_HOST -> 127.0.0.1 in /etc/hosts (requires sudo)"
    # Use sudo tee to append, avoid subshell redirection which would run without sudo
    printf '%s\n' "127.0.0.1 $KEYCLOAK_HOST" | sudo tee -a /etc/hosts >/dev/null || log "Warning: failed to append $KEYCLOAK_HOST to /etc/hosts"
  else
    log "Host entry for $KEYCLOAK_HOST already present in /etc/hosts"
  fi
fi

# Authorization config (webhook authorizer) for single apiserver
# Aligned with production config but using NoOpinion for e2e bootstrap
cat > "$AUTHZ_FILE" <<'EOF'
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
- type: Node
  name: node
- type: RBAC
  name: rbac
- type: Webhook
  name: breakglass
  webhook:
    timeout: 3s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    cacheAuthorizedRequests: false
    cacheUnauthorizedRequests: false
    # NoOpinion allows requests to proceed if webhook unreachable
    # This prevents breakglass from blocking cluster operations
    failurePolicy: NoOpinion
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/kubernetes/authorization-kubeconfig.yaml
    matchConditions:
    # Only call webhook for authenticated users
    - expression: "'system:authenticated' in request.groups"
    # Skip webhook for system users
    - expression: "!request.user.startsWith('system:')"
    # Skip webhook for system service accounts
    - expression: "!('system:serviceaccounts' in request.groups)"
EOF
cat > "$WEBHOOK_KCFG" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: breakglass
  cluster:
    server: http://${WEBHOOK_HOST_PLACEHOLDER}:${WEBHOOK_SERVICE_PORT}/api/breakglass/webhook/authorize/${TENANT_A}
    insecure-skip-tls-verify: true
users:
- name: kube-apiserver
  user:
    token: dGhpc2lzanVzdGFkdW1teXRva2VuYXN3ZXNob3VsZG5vdG5lZWRvbmVoZXJl
current-context: webhook
contexts:
- name: webhook
  context:
    cluster: breakglass
    user: kube-apiserver
EOF

AUTHN_API_VER=apiserver.config.k8s.io/v1beta1
if [[ "$KIND_NODE_IMAGE" =~ v1\.34 ]]; then AUTHN_API_VER=apiserver.config.k8s.io/v1; fi
CA_INLINE=$(sed 's/^/        /' "$TLS_DIR/ca.crt")
cat > "$AUTHN_FILE" <<EOF
apiVersion: ${AUTHN_API_VER}
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://${KEYCLOAK_HOST}:${KEYCLOAK_HTTPS_PORT}/realms/${KEYCLOAK_REALM}
      certificateAuthority: |
$CA_INLINE
      audiences:
        - kubernetes
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: "oidc:"
EOF

# Create an audit policy that logs unauthenticated requests and requests resulting in 4xx/5xx (RBAC denies show up as 403)
# The policy is intentionally conservative: RequestResponse for anonymous users and for responses with 4xx/5xx.
cat > "$TDIR/audit-policy.yaml" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Skip audit logging for common non-resource health/readiness probes
  - level: None
    nonResourceURLs:
      - "/readyz"
      - "/livez"

  # Skip audit logging for internal control-plane/system components and probe users
  - level: None
    users:
      - "kube-probe"
      - "system:kube-probe"
      - "kubernetes-admin"
      - "system:apiserver"
      - "system:kube-scheduler"
      - "system:kube-controller-manager"
      - "system:serviceaccount:kube-system:generic-garbage-collector"
      - "system:serviceaccount:kube-system:resourcequota-controller"
      - "system:serviceaccount:kube-system:deployment-controller"
      - "system:serviceaccount:kube-system:root-ca-cert-publisher"
      - "system:serviceaccount:kube-system:node-controller"
      - "system:serviceaccount:kube-system:clusterrole-aggregation-controller"
      - "system:serviceaccount:kube-system:service-account-controller"
      - "system:serviceaccount:kube-system:legacy-service-account-token-cleaner"
      - "system:serviceaccount:kube-system:daemon-set-controller"
      - "system:serviceaccount:kube-system:certificate-controller"
      - "system:serviceaccount:kube-system:endpointslice-controller"
      - "system:serviceaccount:kube-system:ttl-controller"
      - "system:serviceaccount:kube-system:replicaset-controller"
      - "system:serviceaccount:kube-system:kube-proxy"
      - "system:serviceaccount:kube-system:kindnet"
      - "system:serviceaccount:kube-system:coredns"
      - "system:serviceaccount:local-path-storage:local-path-provisioner-service-account"
  - level: None
    userGroups:
      - "system:nodes"
  # Don't log requests to a configmap called "controller-leader"
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]

  # Don't log watch requests by the "system:kube-proxy" on endpoints or services
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API group
      resources: ["endpoints", "services"]

  # Don't log authenticated requests to certain non-resource URL paths.
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" # Wildcard matching.
    - "/version"

  # Always log anonymous requests with full RequestResponse
  - level: RequestResponse
    users:
      - "system:anonymous"
  # Default to Metadata for everything else
  - level: Metadata
  # (Note) responseStatus removed for broad decoder compatibility; if you need 4xx/5xx
  # logging enable responseStatus on kube-apiserver that supports it or add targeted rules.
EOF

# Ensure an audit log file exists on the host (will be mounted into the control-plane)
mkdir -p "$(dirname "$TDIR/audit.log")"
touch "$TDIR/audit.log"


# kind cluster config with extra volumes
# NOTE: For Kubernetes 1.34+, kind uses kubeadm v1beta4 API internally.
# We use the simpler kubeadmConfigPatches format without apiVersion.
# Authentication and authorization configs are initially placeholder files;
# they will be properly configured AFTER Keycloak is running.
cat > "$KIND_CFG" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        # Audit logging configuration
        audit-policy-file: /etc/kubernetes/audit-policy.yaml
        audit-log-path: /var/log/kubernetes/audit.log
        audit-log-maxage: "30"
        audit-log-maxbackup: "10"
        audit-log-maxsize: "100"
        # Verbosity for debugging OIDC issues
        v: "6"
      extraVolumes:
        - name: authorization-config
          hostPath: /etc/kubernetes/authorization-config.yaml
          mountPath: /etc/kubernetes/authorization-config.yaml
          readOnly: true
        - name: authorization-kubeconfig
          hostPath: /etc/kubernetes/authorization-kubeconfig.yaml
          mountPath: /etc/kubernetes/authorization-kubeconfig.yaml
          readOnly: true
        - name: authentication-config
          hostPath: /etc/kubernetes/authentication-config.yaml
          mountPath: /etc/kubernetes/authentication-config.yaml
          readOnly: true
        - name: audit-policy
          hostPath: /etc/kubernetes/audit-policy.yaml
          mountPath: /etc/kubernetes/audit-policy.yaml
          readOnly: true
        - name: audit-log
          hostPath: /var/log/kubernetes/audit.log
          mountPath: /var/log/kubernetes/audit.log
  extraPortMappings:
  - containerPort: ${NODEPORT}
    hostPort: ${NODEPORT}
    protocol: TCP
  extraMounts:
  - hostPath: $AUTHZ_FILE
    containerPath: /etc/kubernetes/authorization-config.yaml
    readOnly: true
  - hostPath: $AUTHN_FILE
    containerPath: /etc/kubernetes/authentication-config.yaml
    readOnly: true
  - hostPath: $WEBHOOK_KCFG
    containerPath: /etc/kubernetes/authorization-kubeconfig.yaml
    readOnly: true
  - hostPath: $TDIR/audit-policy.yaml
    containerPath: /etc/kubernetes/audit-policy.yaml
    readOnly: true
  - hostPath: $TDIR/audit.log
    containerPath: /var/log/kubernetes/audit.log
EOF

if $KIND get clusters | grep -q "^${CLUSTER_NAME}$"; then log "Deleting existing ${CLUSTER_NAME}"; $KIND delete cluster --name "$CLUSTER_NAME" || true; fi
log "Creating single cluster ${CLUSTER_NAME} (image $KIND_NODE_IMAGE)"

# Build kind create command with optional --retain flag for debugging failures
# Set KIND_RETAIN_ON_FAILURE=true to keep cluster nodes on failure
kind_create_args=(create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" --config "$KIND_CFG" --wait 120s)
if [ "${KIND_RETAIN_ON_FAILURE:-false}" = "true" ]; then
  log "KIND_RETAIN_ON_FAILURE=true: Nodes will be preserved on failure for debugging"
  kind_create_args+=(--retain)
fi

if ! $KIND "${kind_create_args[@]}"; then
  exit_code=$?
  log "Kind cluster creation failed (exit code: $exit_code)"
  
  # Capture logs before potential cleanup
  log "Capturing docker logs for ${CLUSTER_NAME}-control-plane..."
  docker logs "${CLUSTER_NAME}-control-plane" 2>&1 | tail -200 || true
  
  # Try to capture kubelet logs
  log "Attempting to capture kubelet logs..."
  docker exec "${CLUSTER_NAME}-control-plane" journalctl -u kubelet --no-pager -n 100 2>&1 || true
  
  # Capture crictl status
  log "Capturing crictl container status..."
  docker exec "${CLUSTER_NAME}-control-plane" crictl ps -a 2>&1 || true
  
  if [ "${KIND_RETAIN_ON_FAILURE:-false}" = "true" ]; then
    log "Cluster nodes retained for debugging. To clean up manually run:"
    log "  kind delete cluster --name $CLUSTER_NAME"
    log "  docker rm -f ${CLUSTER_NAME}-control-plane"
  fi
  
  exit $exit_code
fi

$KIND get kubeconfig --name "$CLUSTER_NAME" > "$HUB_KUBECONFIG"

# Build controller image unless SKIP_BUILD is set or image already exists
if [ "${SKIP_BUILD:-false}" = "true" ]; then
  log "SKIP_BUILD=true, skipping image build (expecting image $IMAGE to exist)"
elif docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "Image $IMAGE already exists locally, skipping build"
else
  log 'Build & load controller image (respect UI_FLAVOUR build arg)'
  # Use --load to ensure the image is available in local Docker (required for Orbstack/buildx)
  docker build --load --build-arg UI_FLAVOUR="$UI_FLAVOUR" -t "$IMAGE" . >/dev/null
fi

# Build tmux debug image used by terminal sharing tests
ensure_tmux_debug_image

# load built images into kind node using helper
load_image_into_kind "$IMAGE"
load_image_into_kind "$KEYCLOAK_IMAGE"
load_image_into_kind "mailhog/mailhog:v1.0.1"
# Ensure the init container image (curl) is available in kind node to avoid unsupported manifest errors
load_image_into_kind "curlimages/curl:8.4.0"
# Preload netshoot so we can create a persistent debug pod without image pull delays
load_image_into_kind "nicolaka/netshoot"
# Preload tmux debug image for terminal sharing tests
load_image_into_kind "$TMUX_DEBUG_IMAGE"
# Preload busybox for debug session tests (used by test-basic-debug template)
load_image_into_kind "busybox:latest"
# Load Kafka image for audit sink testing
load_image_into_kind "apache/kafka:3.7.0"

log 'Deploy development stack via kustomize (config/dev)'
# Create TLS secret data for kustomize resources (if keycloak expects a secret, we create it first)
# Use the dev namespace kustomize writes to (namePrefix on config/dev is breakglass- and namespace is breakglass-system)
DEV_NS=breakglass-system

# Allocate CONTROLLER_FORWARD_PORT early so it can be used in ConfigMap templates
# This port will be used for the API port-forward and in the baseURL configuration
if [ -z "${CONTROLLER_FORWARD_PORT:-}" ]; then
  # Use fixed port 8080 for UI E2E tests (frontend expects this)
  # Can be overridden with CONTROLLER_FORWARD_PORT env var for other use cases
  CONTROLLER_FORWARD_PORT=8080
  log "Using default API port: $CONTROLLER_FORWARD_PORT (set CONTROLLER_FORWARD_PORT to override)"
fi

KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace "$DEV_NS" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret tls keycloak-tls -n "$DEV_NS" --cert="$TLS_DIR/server.crt" --key="$TLS_DIR/server.key" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Create webhook TLS secret for the controller's webhook server
WEBHOOK_TLS_DIR="$TLS_DIR/webhook"
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret tls breakglass-webhook-tls -n "$DEV_NS" --cert="$WEBHOOK_TLS_DIR/tls.crt" --key="$WEBHOOK_TLS_DIR/tls.key" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
log "Created webhook TLS secret breakglass-webhook-tls in $DEV_NS"
# Create breakglass-certs ConfigMap from generated CA so deployments mounting it succeed
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create configmap breakglass-certs -n "$DEV_NS" --from-file=ca.crt="$TLS_DIR/ca.crt" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Apply the whole development overlay via kustomize so all resources come from config/dev
ensure_no_placeholders "config/dev/resources/keycloak.yaml"
# explicitly apply CRDs first
apply_kustomize config/crd

# Copy certs so kustomize can find them (expected by config/dev/kustomization.yaml)
# Remove any existing symlink first, then create real directory with copied files
KUSTOMIZE_CERTS_DIR="$REPO_ROOT/config/dev/certs/kind-setup-single-tls"
rm -rf "$KUSTOMIZE_CERTS_DIR"
mkdir -p "$KUSTOMIZE_CERTS_DIR"
cp "$TLS_DIR/ca.crt" "$KUSTOMIZE_CERTS_DIR/"
cp "$TLS_DIR/server.crt" "$KUSTOMIZE_CERTS_DIR/"
cp "$TLS_DIR/server.key" "$KUSTOMIZE_CERTS_DIR/"

# Install cert-manager to provide Certificate and Issuer CRDs
# This is needed for the dev overlay which references these types
log 'Installing cert-manager...'
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.3/cert-manager.yaml
log 'Waiting for cert-manager to be ready...'
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL wait --for=condition=available --timeout=120s -n cert-manager deployment/cert-manager
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL wait --for=condition=available --timeout=120s -n cert-manager deployment/cert-manager-webhook
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL wait --for=condition=available --timeout=120s -n cert-manager deployment/cert-manager-cainjector
log 'cert-manager is ready'

# Apply the dev overlay (creates config ConfigMap among other resources)
apply_kustomize config/dev

# Wait for cert-manager to inject the CA bundle (instead of manually patching)
# cert-manager's cainjector watches the Certificate and injects CA into ValidatingWebhookConfiguration
wait_for_webhook_ca_injection 60 || log "Warning: CA injection may not have completed"

# Patch the generated config ConfigMap in-cluster to embed the generated CA so the
# running controller can validate Keycloak TLS. The configMap created by the kustomize
# overlay is namePrefix'd to 'breakglass-config' in namespace $DEV_NS.
TMP_CFG="$TDIR/tmp-config-with-ca.yaml"
if [ -f "$TLS_DIR/ca.crt" ]; then
  # indent CA so it nests properly under data.config.yaml -> authorizationServer -> certificateAuthority
  CA_INLINE=$(sed 's/^/        /' "$TLS_DIR/ca.crt")
else
  CA_INLINE=""
fi
cat > "$TMP_CFG" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: breakglass-config
  namespace: $DEV_NS
data:
  config.yaml: |
    server:
      listenAddress: 0.0.0.0:8080
    authorizationServer:
      url: https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443
      jwksEndpoint: "realms/breakglass-e2e/protocol/openid-connect/certs"
      certificateAuthority: |
$CA_INLINE
    frontend:
      oidcAuthority: https://localhost:8443/realms/breakglass-e2e
      oidcClientID: breakglass-ui
      baseURL: http://localhost:${CONTROLLER_FORWARD_PORT}
      uiFlavour: "$UI_FLAVOUR"
    mail:
      host: breakglass-mailhog.breakglass-system.svc.cluster.local
      port: 1025
      insecureSkipVerify: true
    kubernetes:
      context: ""
      oidcPrefixes:
        - "keycloak:"
        - "oidc:"

EOF

# Determine the kustomize-generated ConfigMap name (it has a hash suffix) and apply the patched data to that exact name
# Wait for the kustomize-generated ConfigMap to appear; it has a hash suffix and may not be immediately present
TARGET_NAME=""
for i in {1..60}; do
  CFG_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get cm -o name 2>/dev/null | sed 's#configmap/##' | grep '^breakglass-config' | head -n1 || true)
  if [ -n "$CFG_NAME" ]; then
    TARGET_NAME="$CFG_NAME"
    log "Detected rendered configmap name: $TARGET_NAME"
    break
  fi
  sleep 1
done
if [ -z "$TARGET_NAME" ]; then
  log "Could not detect rendered breakglass-config name after wait; using base name breakglass-config"
  TARGET_NAME=breakglass-config
fi

# Rewrite TMP_CFG with the actual target name so apply updates the live ConfigMap
cat > "$TMP_CFG" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: $TARGET_NAME
  namespace: $DEV_NS
data:
  config.yaml: |
    server:
      listenAddress: 0.0.0.0:8080
    authorizationServer:
      url: https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443
      jwksEndpoint: "realms/breakglass-e2e/protocol/openid-connect/certs"
      certificateAuthority: |
$CA_INLINE
    frontend:
      oidcAuthority: https://localhost:8443/realms/breakglass-e2e
      oidcClientID: breakglass-ui
      baseURL: http://localhost:${CONTROLLER_FORWARD_PORT}
      uiFlavour: "$UI_FLAVOUR"
    mail:
      host: breakglass-mailhog.breakglass-system.svc.cluster.local
      port: 1025
      insecureSkipVerify: true
    kubernetes:
      context: ""
      oidcPrefixes:
        - "keycloak:"
        - "oidc:"
EOF

KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply --server-side --force-conflicts -f "$TMP_CFG" || log "Warning: failed to apply patched $TARGET_NAME"

# Wait for keycloak and mailhog deployments to be ready (use helper)
if ! wait_for_deploy_by_label keycloak 120; then log 'Keycloak deployment not ready'; debug_cluster_state; exit 1; fi

# Assign realm-management roles to the breakglass-group-sync service account
# This is critical for group sync to work - the realm import doesn't reliably set up these roles
assign_keycloak_service_account_roles || log "Warning: Failed to assign service account roles (group sync may not work)"

if ! wait_for_deploy_by_label mailhog 120; then log 'Mailhog deployment not ready'; debug_cluster_state; exit 1; fi
if ! wait_for_deploy_by_label kafka 120; then log 'Kafka deployment not ready (continuing anyway)'; fi

# Wait for Kafka broker to be fully ready (deployment ready != broker ready due to initialDelaySeconds)
log 'Waiting for Kafka broker to be fully ready...'
KAFKA_POD=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get pods -n breakglass-system -l app=kafka -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
KAFKA_READY=false
if [ -n "$KAFKA_POD" ]; then
  for i in {1..60}; do
    # Check if Kafka broker is responding by listing topics (requires broker to be fully initialized)
    if KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-system "$KAFKA_POD" -- \
        kafka-broker-api-versions.sh --bootstrap-server localhost:9092 >/dev/null 2>&1; then
      log "Kafka broker ready (attempt $i)"
      KAFKA_READY=true
      break
    fi
    if [ $i -eq 60 ]; then
      log "Warning: Kafka broker not responding after 60 attempts (continuing anyway)"
    fi
    sleep 2
  done
else
  log 'Warning: Kafka pod not found, cannot verify broker readiness'
fi

# Pre-create Kafka topics to avoid "Unknown Topic Or Partition" errors on first message
if [ "$KAFKA_READY" = true ] && [ -n "$KAFKA_POD" ]; then
  log 'Pre-creating Kafka audit topic...'
  # Create the audit topic with appropriate settings (3 partitions, replication factor 1 for single-node)
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-system "$KAFKA_POD" -- \
    kafka-topics.sh --bootstrap-server localhost:9092 --create --topic breakglass-audit-events \
    --partitions 3 --replication-factor 1 --if-not-exists 2>/dev/null && \
    log 'Kafka topic breakglass-audit-events created' || \
    log 'Kafka topic creation skipped (may already exist or Kafka not ready)'
  # Also create the functional test topic used by e2e tests
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-system "$KAFKA_POD" -- \
    kafka-topics.sh --bootstrap-server localhost:9092 --create --topic breakglass-audit-functional-test \
    --partitions 1 --replication-factor 1 --if-not-exists 2>/dev/null && \
    log 'Kafka topic breakglass-audit-functional-test created' || \
    log 'Kafka functional test topic creation skipped'
else
  log 'Warning: Kafka broker not ready, skipping topic pre-creation'
fi

# Wait for breakglass controller to be ready (webhooks need to be ready for E2E tests)
log 'Waiting for breakglass controller deployment to be ready...'
if ! wait_for_deploy_by_label breakglass 120; then log 'Breakglass controller deployment not ready'; debug_cluster_state; exit 1; fi

# Wait for webhook endpoints to be ready (deployment ready doesn't mean endpoints are ready)
log 'Waiting for webhook endpoints to be ready...'
WEBHOOK_SVC_NAME="breakglass-webhook-service"
WEBHOOK_NS="breakglass-system"
for i in {1..60}; do
  # Check if the endpoints have at least one address
  ENDPOINT_COUNT=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get endpoints "$WEBHOOK_SVC_NAME" -n "$WEBHOOK_NS" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null | wc -w | tr -d '[:space:]' || echo 0)
  if [ "$ENDPOINT_COUNT" -gt 0 ]; then
    log "Webhook endpoints ready ($ENDPOINT_COUNT addresses, attempt $i)"
    break
  fi
  if [ $i -eq 60 ]; then
    log "Warning: Webhook endpoints not ready after 60 attempts (continuing anyway)"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get endpoints "$WEBHOOK_SVC_NAME" -n "$WEBHOOK_NS" -o yaml 2>&1 || true
  fi
  sleep 2
done

# Give webhook server a moment to start accepting connections after endpoints are registered
sleep 3

# Actively test webhook connectivity via port-forward before running E2E tests
log 'Testing webhook connectivity via port-forward...'
WEBHOOK_TEST_PORT=$(find_free_port)
WEBHOOK_TEST_SUCCESS=false
for i in {1..20}; do
  # Start a port-forward to the webhook service
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL port-forward "svc/${WEBHOOK_SVC_NAME}" "${WEBHOOK_TEST_PORT}:443" -n "$WEBHOOK_NS" &
  WEBHOOK_PF_PID=$!
  sleep 2
  
  # Test connectivity with curl (webhook won't respond to GET but will accept the connection)
  if curl -sk --max-time 3 "https://localhost:${WEBHOOK_TEST_PORT}/healthz" >/dev/null 2>&1|| \
     curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://localhost:${WEBHOOK_TEST_PORT}/" 2>/dev/null | grep -qE '^[0-9]+$'; then
    log "Webhook connectivity test passed (attempt $i)"
    WEBHOOK_TEST_SUCCESS=true
    kill $WEBHOOK_PF_PID 2>/dev/null || true
    wait $WEBHOOK_PF_PID 2>/dev/null || true
    break
  fi
  
  # Clean up port-forward
  kill $WEBHOOK_PF_PID 2>/dev/null || true
  wait $WEBHOOK_PF_PID 2>/dev/null || true
  
  if [ $i -ge 5 ]; then
    log "Webhook test: attempt $i - waiting 3s..."
  fi
  sleep 3
done
if [ "$WEBHOOK_TEST_SUCCESS" != "true" ]; then
  log "Warning: Webhook connectivity test did not confirm success after 20 attempts (continuing anyway)"
  # Extra wait as fallback
  sleep 5
fi

# Note: E2E tests do NOT apply sample manifests from config/samples/.
# Samples are documentation/examples showing all possible use-cases and may reference
# non-existent resources (clusters, secrets, etc.). They are validated separately.
# E2E tests use only crafted test resources from config/dev/resources/crs/ and
# dynamically created resources via the API.

log 'Wait Keycloak JWKS (HTTP)'
KC_SVC_NAME=""
KC_SVC_NS=""
for i in {1..60}; do
  KC_SVC_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=keycloak -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  KC_SVC_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=keycloak -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
  if [ -n "$KC_SVC_NAME" ] && [ -n "$KC_SVC_NS" ]; then
    log "Found Keycloak service: $KC_SVC_NAME (ns: $KC_SVC_NS)"
    break
  fi
  sleep 2
done
[ -n "$KC_SVC_NAME" ] || { log "Keycloak service not found after wait"; debug_cluster_state "Keycloak service lookup"; exit 1; }

PF=$(start_port_forward "$KC_SVC_NS" "$KC_SVC_NAME" ${KEYCLOAK_FORWARD_PORT} ${KEYCLOAK_SVC_PORT})
JWKS_URL="https://breakglass-keycloak.breakglass-system.svc.cluster.local:${KEYCLOAK_FORWARD_PORT}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs"
# Prefer using the generated CA for TLS validation when available; fall back to insecure if not present
if [ -n "${KEYCLOAK_CA_FILE:-}" ] && [ -f "${KEYCLOAK_CA_FILE}" ]; then
  KC_CURL_CA=(--cacert "$KEYCLOAK_CA_FILE")
else
  KC_CURL_CA=(--insecure)
fi
for i in {1..120}; do
    if ! kill -0 $PF 2>/dev/null; then
      log "Port-forward process died; restarting (attempt $i)"
      PF=$(start_port_forward "$KC_SVC_NS" "$KC_SVC_NAME" ${KEYCLOAK_FORWARD_PORT} ${KEYCLOAK_SVC_PORT})
      sleep 2
    fi
  log "JWKS curl attempt $i: curl $JWKS_URL"
  full_output=$(curl -v "${KC_CURL_CA[@]}" "$JWKS_URL" 2>&1 || true)
  code=$(curl "${KC_CURL_CA[@]}" -s -o /dev/null -w '%{http_code}' "$JWKS_URL" || echo 000)
  printf '%s\n' "[single-e2e] JWKS attempt $i raw output BEGIN" >&2
  printf '%s\n' "$full_output" >&2
  printf '%s\n' "[single-e2e] JWKS attempt $i raw output END (status=$code)" >&2
  if [ "$code" = "200" ]; then
    log "JWKS ready (attempt $i)"
    break
  fi
  sleep 2
done
# Keep Keycloak port-forward running for tests and record its PID so later steps won't re-create it
[ -n "$PF_FILE" ] && mkdir -p "$(dirname "$PF_FILE")"
echo $PF >> "$PF_FILE" || true
if [ "$code" != "200" ]; then
  log "JWKS timeout after 120 attempts (last status=$code)"
  debug_deployment_failure keycloak
  debug_cluster_state "JWKS timeout"
  exit 1
fi
  # Before restarting kube-apiserver, ensure the apiserver will be able to reach the
  # Keycloak issuer using cluster DNS. Previously we only checked JWKS via a local
  # port-forward which doesn't guarantee in-cluster DNS/HTTP connectivity. If the
  # apiserver restarts before cluster DNS and Keycloak are reachable from the
  # cluster network, the OIDC authenticator will fail to initialize (no such host).
  log 'Check issuer reachable from inside the cluster using a persistent netshoot pod'

  # Ensure a long-lived netshoot pod exists in the dev namespace so we can exec into it
  NETS_POD_NAME=tmp-netshoot
  if ! KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" >/dev/null 2>&1; then
    log "Creating persistent netshoot pod: $NETS_POD_NAME in ns $DEV_NS"
    # netshoot has many network tools; run it in sleep loop to keep it alive
    # Use IfNotPresent to avoid pulling when the image is pre-loaded into kind
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" run "$NETS_POD_NAME" --image=nicolaka/netshoot --image-pull-policy=IfNotPresent --restart=Always --command -- sleep infinity >/dev/null 2>&1 || true
  else
    log "Persistent netshoot pod $NETS_POD_NAME already present in ns $DEV_NS"
  fi

  # Wait for the netshoot pod to become Running and Ready
  for i in {1..60}; do
    phase=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    ready=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo false)
    if [ "$phase" = "Running" ] && [ "$ready" = "true" ]; then
      log "netshoot pod $NETS_POD_NAME is running and ready"
      break
    fi
    sleep 2
  done
  phase=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [ "$phase" != "Running" ]; then
    log "netshoot pod $NETS_POD_NAME did not become Running (phase=$phase); aborting"
    debug_cluster_state "netshoot pod not ready"
    exit 1
  fi

  # Exec curl from the netshoot pod to verify DNS and HTTPS connectivity to the issuer
  INST_CODE=000
  for i in {1..60}; do
    log "In-cluster issuer attempt $i: exec into $NETS_POD_NAME and curl https://${KEYCLOAK_HOST}:${KEYCLOAK_HTTPS_PORT}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"
    INST_CODE=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" exec "$NETS_POD_NAME" -- curl -s -o /dev/null -w '%{http_code}' --insecure "https://${KEYCLOAK_HOST}:${KEYCLOAK_HTTPS_PORT}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration" 2>/dev/null || echo 000)
    printf '[single-e2e] In-cluster issuer http status: %s
' "$INST_CODE"
    if [ "$INST_CODE" = "200" ]; then
      log "Issuer reachable from inside the cluster (attempt $i)"
      break
    fi
    sleep 2
  done
  if [ "$INST_CODE" != "200" ]; then
    log "Issuer not reachable in-cluster after 60 attempts (last=$INST_CODE)"
    debug_cluster_state "Issuer in-cluster check failed"
    exit 1
  fi

  # Ensure apiserver can resolve the in-cluster Keycloak hostname when it runs with hostNetwork
  KC_CLUSTER_IP=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$KC_SVC_NS" get svc "$KC_SVC_NAME" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
  if [ -n "$KC_CLUSTER_IP" ] && [ "$KC_CLUSTER_IP" != "None" ]; then
    # Collect entries we want to ensure in control-plane /etc/hosts
    declare -a HOST_ENTRIES=()
    HOST_ENTRIES+=("$KC_CLUSTER_IP $KEYCLOAK_HOST")
    # Also map the webhook placeholder host (if it points to an in-cluster service) to the breakglass service IP when available
    BG_SVC_IP=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null || true)
    if [ -n "$BG_SVC_IP" ] && [ "$BG_SVC_IP" != "None" ]; then
      HOST_ENTRIES+=("$BG_SVC_IP ${WEBHOOK_HOST_PLACEHOLDER}")
    fi

    # Idempotently write each host entry into control-plane /etc/hosts
    for he in "${HOST_ENTRIES[@]}"; do
      hn=$(echo "$he" | awk '{print $2}')
      if ! docker exec ${CLUSTER_NAME}-control-plane sh -c "grep -Fq \"$hn\" /etc/hosts >/dev/null 2>&1"; then
        log "Adding hosts entry in control-plane: $he"
        docker exec ${CLUSTER_NAME}-control-plane sh -c "echo '$he' >> /etc/hosts" || log "Warning: failed to write /etc/hosts in control-plane"
      else
        log "Hosts entry for $hn already present in control-plane /etc/hosts"
      fi
    done

    # As an additional robust option, detect the kube-apiserver container runtime host path
    # for the pod's /etc/hosts (inside the kind node) and append the same entries there.
    log "Attempting to locate kube-apiserver container host /etc/hosts path via crictl"
    KUBE_APISERVER_CRIT_ID=$(docker exec ${CLUSTER_NAME}-control-plane sh -c "crictl ps --name kube-apiserver -o json 2>/dev/null | sed -n 's/.*\"id\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p' | head -n1" || true)
    if [ -n "$KUBE_APISERVER_CRIT_ID" ]; then
      log "Found kube-apiserver container id: $KUBE_APISERVER_CRIT_ID"
      INSPECT_JSON=$(docker exec ${CLUSTER_NAME}-control-plane sh -c "crictl inspect $KUBE_APISERVER_CRIT_ID 2>/dev/null || true" ) || INSPECT_JSON=""
      if [ -n "$INSPECT_JSON" ]; then
        # Prefer jq (if available) for robust JSON extraction. Otherwise use a
        # Perl multiline regex to find the mount whose containerPath/container_path
        # equals "/etc/hosts" and extract the corresponding hostPath/host_path.
        HOSTS_HOST_PATH=""
        if command -v jq >/dev/null 2>&1; then
          HOSTS_HOST_PATH=$(printf "%s" "$INSPECT_JSON" | jq -r '
            (.info.config.mounts[]? // .status.mounts[]?)
            | select((.container_path // .containerPath) == "/etc/hosts")
            | (.host_path // .hostPath)'
        )
        else
          HOSTS_HOST_PATH=$(printf "%s" "$INSPECT_JSON" | perl -0777 -ne 'if(/\{[^}]*?(?:"container_path"|"containerPath")\s*:\s*"\/etc\/hosts"[^}]*?(?:"host_path"|"hostPath")\s*:\s*"([^\"]+)"/s){print $1}');
        fi
        if [ -n "$HOSTS_HOST_PATH" ]; then
          log "Located host path for kube-apiserver /etc/hosts: $HOSTS_HOST_PATH"
          HOSTS_DIR=$(dirname "$HOSTS_HOST_PATH")
          for he in "${HOST_ENTRIES[@]}"; do
              hn=$(echo "$he" | awk '{print $2}')
              if ! docker exec ${CLUSTER_NAME}-control-plane sh -c "grep -Fq \"$hn\" '$HOSTS_HOST_PATH' >/dev/null 2>&1"; then
                log "Appending $he to kube-apiserver host file: $HOSTS_HOST_PATH"
                # Pipe the host entry into the control-plane container and append it
                printf '%s\n' "$he" | docker exec -i ${CLUSTER_NAME}-control-plane sh -c "mkdir -p '$HOSTS_DIR' >/dev/null 2>&1 || true; cat >> '$HOSTS_HOST_PATH'" || log "Warning: failed to append to $HOSTS_HOST_PATH"
              else
                log "kube-apiserver host file already contains $hn"
              fi
          done
        else
          log "Could not parse host path for kube-apiserver /etc/hosts from crictl inspect"
        fi
      else
        log "crictl inspect returned empty output for $KUBE_APISERVER_CRIT_ID"
      fi
    else
      log "kube-apiserver container id not found via crictl; skipping host file injection"
    fi
  else
    log "Could not determine Keycloak service ClusterIP (got: $KC_CLUSTER_IP); apiserver may still fail DNS"
  fi

  # Ensure a long-lived netshoot pod exists in the dev namespace so we can exec into it
  NETS_POD_NAME=tmp-netshoot
  if ! KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" >/dev/null 2>&1; then
    log "Creating persistent netshoot pod: $NETS_POD_NAME in ns $DEV_NS"
    # netshoot has bash/sh and many network tools; run it in sleep loop to keep it alive
    # Use IfNotPresent to avoid pulling when the image is pre-loaded into kind
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" run "$NETS_POD_NAME" --image=nicolaka/netshoot --image-pull-policy=IfNotPresent --restart=Always --command -- sleep infinity >/dev/null 2>&1 || true
  else
    log "Persistent netshoot pod $NETS_POD_NAME already present in ns $DEV_NS"
  fi

  # Wait for the netshoot pod to become Running and Ready
  for i in {1..60}; do
    phase=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    ready=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || echo false)
    if [ "$phase" = "Running" ] && [ "$ready" = "true" ]; then
      log "netshoot pod $NETS_POD_NAME is running and ready"
      break
    fi
    sleep 2
  done
  phase=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" get pod "$NETS_POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [ "$phase" != "Running" ]; then
    log "netshoot pod $NETS_POD_NAME did not become Running (phase=$phase); aborting"
    debug_cluster_state "netshoot pod not ready (post-restart)"
    exit 1
  fi

  # Exec curl from the netshoot pod to verify DNS and HTTPS connectivity to the issuer
  INST_CODE=000
  for i in {1..60}; do
    log "In-cluster issuer attempt $i: exec into $NETS_POD_NAME and curl https://${KEYCLOAK_HOST}:${KEYCLOAK_HTTPS_PORT}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration"
    INST_CODE=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$DEV_NS" exec "$NETS_POD_NAME" -- curl -s -o /dev/null -w '%{http_code}' --insecure "https://${KEYCLOAK_HOST}:${KEYCLOAK_HTTPS_PORT}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration" 2>/dev/null || echo 000)
    printf '[single-e2e] In-cluster issuer http status: %s\n' "$INST_CODE"
    if [ "$INST_CODE" = "200" ]; then
      log "Issuer reachable from inside the cluster (attempt $i)"
      break
    fi
    sleep 2
  done
  if [ "$INST_CODE" != "200" ]; then
    log "Issuer not reachable in-cluster after 60 attempts (last=$INST_CODE)"
    debug_deployment_failure keycloak
    debug_cluster_state "Issuer in-cluster check failed (netshoot)"
    exit 1
  fi
  # Ensure apiserver can resolve the in-cluster Keycloak hostname when it runs with hostNetwork
  # Many kind control-plane pods run with hostNetwork=true, so the apiserver will use the host
  # network's DNS servers. If host DNS can't resolve the cluster service name, the OIDC
  # authenticator will fail during initialization. To guarantee name resolution we add an
  # idempotent /etc/hosts entry inside the control-plane container mapping the Keycloak
  # service ClusterIP to the in-cluster hostname.
  KC_CLUSTER_IP=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL -n "$KC_SVC_NS" get svc "$KC_SVC_NAME" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
  if [ -n "$KC_CLUSTER_IP" ] && [ "$KC_CLUSTER_IP" != "None" ]; then
    # Collect entries we want to ensure in control-plane /etc/hosts
    declare -a HOST_ENTRIES=()
    HOST_ENTRIES+=("$KC_CLUSTER_IP $KEYCLOAK_HOST")
    # Also map the webhook placeholder host (if it points to an in-cluster service) to the breakglass service IP when available
    # Try to find breakglass service clusterIP
    BG_SVC_IP=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null || true)
    if [ -n "$BG_SVC_IP" ] && [ "$BG_SVC_IP" != "None" ]; then
      HOST_ENTRIES+=("$BG_SVC_IP ${WEBHOOK_HOST_PLACEHOLDER}")
    fi
  else
    log "Could not determine Keycloak service ClusterIP (got: $KC_CLUSTER_IP); apiserver may still fail DNS"
  fi

  # Inject authentication-config and authorization-config flags into kube-apiserver manifest
  # This is done AFTER Keycloak is running so the API server can fetch OIDC discovery
  log 'Injecting authentication-config and authorization-config flags into kube-apiserver manifest'
  
  # First, add the /etc/hosts entries if we have them
  if [ ${#HOST_ENTRIES[@]} -gt 0 ]; then
    for entry in "${HOST_ENTRIES[@]}"; do
      docker exec ${CLUSTER_NAME}-control-plane sh -c "grep -qF '$entry' /etc/hosts || echo '$entry' >> /etc/hosts"
    done
    log "Added /etc/hosts entries for Keycloak and webhook service"
  fi
  
  # Patch the kube-apiserver manifest to add authentication-config and authorization-config flags
  # We use sed to insert these flags right after the existing flags
  # NOTE: We check for "--authentication-config" (the flag) not just "authentication-config"
  # because the manifest also has volume/mount names containing that string
  # NOTE: We must also remove --authorization-mode flag because it conflicts with --authorization-config
  docker exec ${CLUSTER_NAME}-control-plane sh -c '
    MANIFEST=/etc/kubernetes/manifests/kube-apiserver.yaml
    
    # Remove --authorization-mode flag (conflicts with --authorization-config)
    if grep -q -- "--authorization-mode" "$MANIFEST" 2>/dev/null; then
      sed -i "/--authorization-mode=/d" "$MANIFEST"
      echo "Removed --authorization-mode flag (conflicts with --authorization-config)"
    fi
    
    # Check if flags are already present (look for the actual flag, not volume names)
    if grep -q -- "--authentication-config" "$MANIFEST" 2>/dev/null; then
      echo "authentication-config flag already present in kube-apiserver manifest"
    else
      # Insert --authentication-config after the --audit-log-path flag
      sed -i "/--audit-log-path/a\\    - --authentication-config=/etc/kubernetes/authentication-config.yaml" "$MANIFEST"
      echo "Added --authentication-config flag"
    fi
    
    if grep -q -- "--authorization-config" "$MANIFEST" 2>/dev/null; then
      echo "authorization-config flag already present in kube-apiserver manifest"
    else
      # Insert --authorization-config after --authentication-config flag
      sed -i "/--authentication-config/a\\    - --authorization-config=/etc/kubernetes/authorization-config.yaml" "$MANIFEST"
      echo "Added --authorization-config flag"
    fi
  '

  # Wait for kube-apiserver to detect the manifest change and restart
  log 'Waiting for kube-apiserver to restart with new flags...'
  sleep 5
  apiserver_ready=false
  for i in {1..60}; do
    # Use || true to prevent set -e from exiting on grep returning 0 matches
    st=$(docker exec ${CLUSTER_NAME}-control-plane crictl ps --name kube-apiserver -o json 2>/dev/null | grep -c 'kube-apiserver' || true)
    if [ "${st:-0}" -gt 0 ]; then
      # Check apiserver readiness
      if kubectl get --raw='/readyz?verbose' >/dev/null 2>&1; then
        log "kube-apiserver restarted and ready (attempt $i)"
        apiserver_ready=true
        break
      fi
    fi
    [ $(( i % 5 )) -eq 0 ] && log "Waiting for kube-apiserver restart (attempt $i)"
    sleep 3
  done
  
  if [ "$apiserver_ready" != "true" ]; then
    log "ERROR: kube-apiserver did not become ready after 60 attempts"
    log "Collecting diagnostic information..."
    docker exec ${CLUSTER_NAME}-control-plane crictl ps -a --name kube-apiserver 2>&1 || true
    docker exec ${CLUSTER_NAME}-control-plane cat /etc/kubernetes/manifests/kube-apiserver.yaml 2>&1 | tail -50 || true
    exit 1
  fi
  
  # Verify flags are present (best effort, don't fail if logs not available)
  APISERVER_CONTAINER_ID=$(docker exec ${CLUSTER_NAME}-control-plane crictl ps --name kube-apiserver -o json 2>/dev/null | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
  if [ -n "$APISERVER_CONTAINER_ID" ]; then
    docker exec ${CLUSTER_NAME}-control-plane crictl logs "$APISERVER_CONTAINER_ID" 2>&1 | grep -i "authentication-config\|authorization-config" | head -5 || log "Could not verify flags in apiserver logs"
  else
    log "Could not get apiserver container ID to verify flags"
  fi

log 'Deploy controller and supporting resources via kustomize (config/dev)'
# create the system namespace and apply the development kustomize overlay
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace system --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Create breakglass-debug namespace for debug session workloads (used by DebugSessionTemplate targetNamespace)
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace breakglass-debug --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
log 'Created breakglass-debug namespace for debug session workloads'

# Render and apply the dev overlay; this includes controller, rbac, mailhog, and other dev resources
# Use --server-side --force-conflicts to handle ValidatingWebhookConfiguration that may have been
# previously patched with CA bundle (resourceVersion conflict resolution)
KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build config/dev | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply --server-side --force-conflicts -f -

# Wait for cert-manager to inject the CA bundle into ValidatingWebhookConfiguration
# This replaces manual patching which caused CA mismatch issues
wait_for_webhook_ca_injection 60 || log "Warning: CA injection may not have completed"

log 'Wait controller'
### Ensure controller uses the locally built image and wait for rollout by label
set_image_and_wait_by_label breakglass breakglass ${IMAGE} || { log 'Controller not ready'; debug_cluster_state; exit 1; }

# Wait a moment for the webhook server to start serving after deployment is ready
log 'Waiting for webhook server to be ready...'
sleep 5

# Create kubeconfig secrets BEFORE applying e2e test CRs (ClusterConfigs reference these secrets)
log 'Creating kubeconfig secrets for ClusterConfigs...'
# The kind kubeconfig uses a loopback IP/ephemeral port (https://127.0.0.1:PORT) which is unreachable from pods.
# Rewrite the server endpoint to the in-cluster service DNS so the controller can reach the API.
MOD_KUBECONFIG="$TDIR/kind-setup-single-mod-kubeconfig.yaml"
cp "$HUB_KUBECONFIG" "$MOD_KUBECONFIG" || { log "ERROR: failed to copy kubeconfig $HUB_KUBECONFIG to $MOD_KUBECONFIG"; exit 1; }

# Prefer yq when available, but write to a temp file and verify the change.
if command -v yq >/dev/null 2>&1; then
  if ! yq '(.clusters[] | .cluster.server) |= "https://kubernetes.default.svc"' "$MOD_KUBECONFIG" > "$MOD_KUBECONFIG.tmp" 2>/dev/null; then
    log "yq failed to edit kubeconfig; falling back to sed"
    sed -i -E 's#(server: )https://[^[:space:]]+#\1https://kubernetes.default.svc#' "$MOD_KUBECONFIG" || true
  else
    mv "$MOD_KUBECONFIG.tmp" "$MOD_KUBECONFIG"
  fi
else
  sed -i -E 's#(server: )https://[^[:space:]]+#\1https://kubernetes.default.svc#' "$MOD_KUBECONFIG" || true
fi

# Verify the modification; fail early if it didn't take effect
if ! grep -q 'https://kubernetes.default.svc' "$MOD_KUBECONFIG"; then
  log 'ERROR: failed to rewrite kubeconfig server endpoint; aborting to avoid creating broken secrets'
  exit 1
fi

# Create tenant kubeconfig secrets (needed by cluster-configs-test.yaml ClusterConfigs)
for tenant in "${TENANT_A}" "${TENANT_B}"; do
  secret_name="${tenant}-admin"
  log "Creating kubeconfig secret: $secret_name (in both default and breakglass-system namespaces)"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "$secret_name" -n default --from-file=kubeconfig="$MOD_KUBECONFIG" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "$secret_name" -n breakglass-system --from-file=kubeconfig="$MOD_KUBECONFIG" --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || true
done

# Apply the e2e test CRs that were excluded from kustomize to avoid webhook validation race
apply_e2e_test_crs

# Apply cluster-config and deny-policy overrides AFTER controller is ready (webhooks need to be serving)
# NOTE: Cluster configs and deny policies are now applied by apply_e2e_test_crs function above
# with proper namespace and name-prefix transformation. The old sed-based placeholder substitution
# has been removed to avoid duplicate resource creation (with/without breakglass- prefix).

# Create RBAC manifest to allow all users (including unauthenticated) to create SelfSubjectReview
RBAC_SELF_SUBJECT_REVIEW_MANIFEST="$TDIR/selfsubjectreview-allow-all.yaml"
cat > "$RBAC_SELF_SUBJECT_REVIEW_MANIFEST" <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: allow-selfsubjectreview-all
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["selfsubjectreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: allow-selfsubjectreview-all
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: allow-selfsubjectreview-all
subjects:
  - kind: Group
    name: system:unauthenticated
    apiGroup: rbac.authorization.k8s.io
  - kind: Group
    name: system:authenticated
    apiGroup: rbac.authorization.k8s.io
EOF

log "Applying RBAC to allow all users to create SelfSubjectReview (kubectl auth whoami)"
$KUBECTL --kubeconfig="$HUB_KUBECONFIG" apply -f "$RBAC_SELF_SUBJECT_REVIEW_MANIFEST"

log 'Expose breakglass service NodePort for local tests'
# Find the breakglass service created by kustomize (it may have a namePrefix)
BG_SVC_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
BG_SVC_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=breakglass -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "$BG_SVC_NAME" ] && [ -n "$BG_SVC_NS" ]; then
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL patch svc "$BG_SVC_NAME" -n "$BG_SVC_NS" -p "{\"spec\":{\"type\":\"NodePort\",\"ports\":[{\"port\":8080,\"targetPort\":8080,\"nodePort\":${NODEPORT},\"protocol\":\"TCP\",\"name\":\"http\"}]}}" >/dev/null 2>&1 || true
else
  log 'Warning: breakglass service not found; skipping NodePort patch'
fi

log 'Create simulated tenant ClusterConfigs (secrets already created earlier)'
# MOD_KUBECONFIG was already prepared and secrets already created before apply_e2e_test_crs
# Here we just create the base ClusterConfigs for tenant-a and tenant-b (without breakglass- prefix)

## Helpers: create ClusterConfig for tenant (secrets already exist)
create_tenant() {
  local tenant="$1"
  local secret_name="${tenant}-admin"

  log "Applying ClusterConfig for tenant: $tenant"
  cat <<YAML | apply_stdin_with_retry 5 5
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${tenant}
spec:
  kubeconfigSecretRef:
    name: ${secret_name}
    namespace: default
    key: kubeconfig
YAML
}

# Build and apply tenant artifacts (they share the same kubeconfig file)
TENANTS=("${TENANT_A}" "${TENANT_B}")
for t in "${TENANTS[@]}"; do
  create_tenant "$t"
done

log 'Create IdentityProvider for OIDC authentication'
# IdentityProvider is a mandatory cluster-scoped resource that configures user authentication.
# It must be created before the controller can fully function.

# First, create the secret for Keycloak group sync client credentials
log 'Creating Keycloak group sync client secret...'
KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic breakglass-group-sync-secret \
  --namespace="$DEV_NS" \
  --from-literal=client-secret=breakglass-group-sync-secret \
  --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -

# Export the secret for e2e tests
export KEYCLOAK_GROUP_SYNC_CLIENT_ID="breakglass-group-sync"
export KEYCLOAK_GROUP_SYNC_CLIENT_SECRET="breakglass-group-sync-secret"

# For E2E tests: Use in-cluster service name so controller can access Keycloak
# Frontend will need DNS resolution to make this hostname work via port-forward
KEYCLOAK_SERVICE_HOSTNAME="breakglass-keycloak.breakglass-system.svc.cluster.local"

cat <<YAML | apply_stdin_with_retry 5 5
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: breakglass-e2e-idp
  labels:
    e2e-test: "true"
spec:
  # Mark as primary so controller uses this as default provider
  primary: true
  # Issuer URL - use in-cluster service name so controller can validate tokens
  issuer: "https://${KEYCLOAK_SERVICE_HOSTNAME}:8443/realms/${KEYCLOAK_REALM}"
  oidc:
    # Authority URL - use in-cluster service name for consistency
    # Frontend will access this via port-forward with /etc/hosts mapping
    authority: "https://${KEYCLOAK_SERVICE_HOSTNAME}:8443/realms/${KEYCLOAK_REALM}"
    # OIDC client ID (must match realm configuration)
    clientID: "breakglass-ui"
    # Skip TLS verification for self-signed test certificates (NOT for production!)
    insecureSkipVerify: true
  # Enable Keycloak group sync for resolving group memberships
  groupSyncProvider: Keycloak
  keycloak:
    # Group sync uses in-cluster service name (controller runs in cluster)
    baseURL: "https://${KEYCLOAK_SERVICE_HOSTNAME}:8443"
    realm: "${KEYCLOAK_REALM}"
    clientID: "breakglass-group-sync"
    clientSecretRef:
      name: "breakglass-group-sync-secret"
      namespace: "${DEV_NS}"
      key: "client-secret"
    cacheTTL: "5m"
    requestTimeout: "10s"
    insecureSkipVerify: true
YAML

# Wait for IdentityProvider to be reconciled and ready
# This ensures the controller has initialized OIDC validation and group sync before tests run
wait_for_identityprovider_ready "breakglass-e2e-idp" "breakglass-system" 60 || \
  log "Warning: IdentityProvider may not be fully ready, tests might have authentication issues"

log 'Port-forward controller and keycloak for tests'
rm -f "$PF_FILE" || true

# Start Keycloak port-forward for tests (was started earlier but may have been killed)
log "Starting Keycloak port-forward on port: $KEYCLOAK_FORWARD_PORT"
start_port_forward "$DEV_NS" "breakglass-keycloak" ${KEYCLOAK_FORWARD_PORT} ${KEYCLOAK_SVC_PORT:-8443} >/dev/null 2>&1 || true
sleep 1

# CONTROLLER_FORWARD_PORT was allocated earlier; just log it
log "Starting controller port-forward on port: $CONTROLLER_FORWARD_PORT"

# Expose controller API
# Use the discovered breakglass service name/namespace (BG_SVC_NAME/BG_SVC_NS) when available
if [ -n "${BG_SVC_NAME:-}" ] && [ -n "${BG_SVC_NS:-}" ]; then
  start_port_forward "$BG_SVC_NS" "$BG_SVC_NAME" ${CONTROLLER_FORWARD_PORT} 8080 >/dev/null 2>&1 || true
else
  start_port_forward "$DEV_NS" "breakglass" ${CONTROLLER_FORWARD_PORT} 8080 >/dev/null 2>&1 || true
fi
for i in {1..40}; do
  c=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${CONTROLLER_FORWARD_PORT}/api/config" || true)
  if [ "$c" = "200" ]; then
    log "Controller API ready (attempt $i)"
    break
  else
    [ $(( i % 5 )) -eq 0 ] && log "Controller API attempt $i: status=$c"
  fi
  sleep 2
done
if [ "$c" != "200" ]; then
  log "Controller API timeout after 40 attempts (last status=$c)"
  debug_deployment_failure breakglass
  debug_cluster_state "Controller API timeout"
  exit 1
fi

# Set up metrics port-forward for e2e test visibility
# The controller exposes Prometheus metrics on port 8081
# Use a fixed local port (8181) for consistency with Go test defaults
METRICS_FORWARD_PORT=${METRICS_FORWARD_PORT:-8181}
log "Starting controller metrics port-forward on port: $METRICS_FORWARD_PORT"
if [ -n "${BG_SVC_NAME:-}" ] && [ -n "${BG_SVC_NS:-}" ]; then
  start_port_forward "$BG_SVC_NS" "$BG_SVC_NAME" ${METRICS_FORWARD_PORT} 8081 >/dev/null 2>&1 || true
else
  start_port_forward "$DEV_NS" "breakglass" ${METRICS_FORWARD_PORT} 8081 >/dev/null 2>&1 || true
fi
# Verify metrics endpoint is accessible
sleep 2
if curl -s "http://localhost:${METRICS_FORWARD_PORT}/metrics" | grep -q "breakglass_"; then
  log "Controller metrics endpoint ready at http://localhost:${METRICS_FORWARD_PORT}/metrics"
else
  log "Warning: Controller metrics not yet accessible on port ${METRICS_FORWARD_PORT}; may take a moment"
fi

# Start audit webhook receiver port-forward (for audit webhook tests)
AUDIT_WEBHOOK_RECEIVER_PORT=8090
log "Starting audit webhook receiver port-forward on port: $AUDIT_WEBHOOK_RECEIVER_PORT"
start_port_forward "$DEV_NS" "audit-webhook-receiver" ${AUDIT_WEBHOOK_RECEIVER_PORT} 80 >/dev/null 2>&1 || true
sleep 2
if curl -s "http://localhost:${AUDIT_WEBHOOK_RECEIVER_PORT}/health" >/dev/null 2>&1; then
  log "Audit webhook receiver ready at http://localhost:${AUDIT_WEBHOOK_RECEIVER_PORT}"
else
  log "Warning: Audit webhook receiver not accessible on port ${AUDIT_WEBHOOK_RECEIVER_PORT} (tests may fail)"
fi

# Wait for IdentityProvider to be reconciled by the controller
log 'Waiting for IdentityProvider to be ready...'
for i in {1..30}; do
  IDP_STATUS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get identityprovider breakglass-e2e-idp -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
  if [ "$IDP_STATUS" = "True" ]; then
    log "IdentityProvider is ready"
    break
  fi
  [ $(( i % 5 )) -eq 0 ] && log "IdentityProvider status attempt $i: $IDP_STATUS"
  sleep 2
done

# Verify server-side OIDC proxy by calling the proxied discovery endpoint
PROXY_OK=000
for i in {1..40}; do
  PROXY_URL="http://localhost:${CONTROLLER_FORWARD_PORT}/api/oidc/authority/.well-known/openid-configuration"
  PROXY_OK=$(curl -s -o /dev/null -w '%{http_code}' "${PROXY_URL}" || echo 000)
  printf '[single-e2e] OIDC proxy check attempt %d status=%s\n' "$i" "$PROXY_OK" >&2
  if [ "${PROXY_OK}" = "200" ]; then
    log "OIDC proxy discovery reachable"
    break
  fi
  # On failure, periodically show debug info
  if [ $i -eq 10 ] || [ $i -eq 20 ] || [ $i -eq 30 ]; then
    log "OIDC proxy still returning $PROXY_OK after $i attempts - debugging..."
    log "--- Controller logs (last 50 lines) ---"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL logs -l app=breakglass -n "$DEV_NS" --tail=50 2>&1 || true
    log "--- IdentityProvider status ---"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get identityprovider -o yaml 2>&1 | head -80 || true
    log "--- Keycloak pod status ---"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get pods -l app=keycloak -n "$DEV_NS" -o wide 2>&1 || true
    log "--- Keycloak service ---"
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc -l app=keycloak -n "$DEV_NS" -o wide 2>&1 || true
    log "--- Testing Keycloak connectivity via netshoot pod ---"
    # Use a temporary netshoot pod to test connectivity (controller image is distroless)
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL run keycloak-test-$i --rm -i --restart=Never --image=nicolaka/netshoot:latest \
      --namespace="$DEV_NS" -- curl -sk --max-time 5 \
      "https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443/realms/breakglass-e2e/.well-known/openid-configuration" 2>&1 | head -10 || \
      log "Keycloak connectivity test via netshoot failed"
    log "--- End debug info ---"
  fi
  sleep 3
done
if [ "${PROXY_OK}" != "200" ]; then
  log "Warning: OIDC proxy discovery did not return 200 (last=${PROXY_OK}); continuing but login flows may fail"
  log "--- Final debug: Controller logs (last 100 lines) ---"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL logs -l app=breakglass -n "$DEV_NS" --tail=100 2>&1 || true
  log "--- Final debug: All IdentityProviders ---"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get identityprovider -o yaml 2>&1 || true
  log "--- Final debug: Keycloak logs (last 20 lines) ---"
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL logs -l app=keycloak -n "$DEV_NS" --tail=20 2>&1 || true
fi

# Create BreakglassEscalation resources for UI E2E tests
# These escalations match the test users defined in config/dev/resources/breakglass-e2e-realm.json:
# - Bob (bob@example.com): groups = ["developers", "team-alpha"]
# - Carol (carol@example.com): groups = ["approvers", "security-team"]
log 'Creating BreakglassEscalation resources for UI E2E tests...'

cat <<YAML | apply_stdin_with_retry 5 5
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ui-e2e-cluster-admin
  labels:
    breakglass.dev/test-resource: "true"
spec:
  allowed:
    clusters:
      - ${TENANT_A}
    groups:
      - developers
      - team-alpha
  escalatedGroup: cluster-admin-access
  approvers:
    groups:
      - approvers
      - security-team
  requestReason:
    mandatory: true
    description: "Please provide a justification for cluster admin access"
  maxValidFor: 1h
  retainFor: 24h
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ui-e2e-pod-debug
  labels:
    breakglass.dev/test-resource: "true"
spec:
  allowed:
    clusters:
      - ${TENANT_A}
      - ${TENANT_B}
    groups:
      - developers
  escalatedGroup: pod-debug-access
  approvers:
    groups:
      - approvers
  requestReason:
    mandatory: true
    description: "Describe the pod or issue you need to debug"
  maxValidFor: 30m
  approvalTimeout: 15m
  retainFor: 12h
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: ui-e2e-namespace-admin
  labels:
    breakglass.dev/test-resource: "true"
spec:
  allowed:
    clusters:
      - ${TENANT_A}
    groups:
      - team-alpha
  escalatedGroup: namespace-admin-access
  approvers:
    groups:
      - security-team
  requestReason:
    mandatory: false
  maxValidFor: 2h
  retainFor: 48h
YAML

log "Created BreakglassEscalation resources for UI E2E tests"

log 'Deploy/verify MailHog for testing emails'
ensure_no_placeholders config/dev/resources/mailhog.yaml
MH_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
if [ -n "$MH_NS" ]; then
  log "MailHog already present in namespace $MH_NS; skipping apply"
else
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f config/dev/resources/mailhog.yaml
fi
for i in {1..60}; do
  MH_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
  MH_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [ -n "$MH_NS" ] && [ -n "$MH_NAME" ]; then
    ready=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get deploy/"$MH_NAME" -n "$MH_NS" -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo 0)
  else
    ready=0
  fi
  [ "$ready" = "1" ] && break
  sleep 2
done
if [ "$ready" != "1" ]; then
  log 'MailHog not ready'
  debug_deployment_failure mailhog
  debug_cluster_state "MailHog timeout"
  exit 1
fi

log 'Port-forward MailHog UI'
# Discover mailhog service name (kustomize may add a namePrefix)
MH_SVC_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
MH_SVC_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
if [ -n "$MH_SVC_NAME" ] && [ -n "$MH_SVC_NS" ]; then
  start_port_forward "$MH_SVC_NS" "$MH_SVC_NAME" ${MAILHOG_UI_PORT} 8025 >/dev/null 2>&1 || true
  log "MailHog UI available at http://localhost:${MAILHOG_UI_PORT} (svc: $MH_SVC_NAME ns: $MH_SVC_NS)"
else
  log 'MailHog service not found for port-forward; skipping'
fi

log 'Port-forward Kafka'
KF_SVC_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=kafka -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
KF_SVC_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=kafka -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
if [ -n "$KF_SVC_NAME" ] && [ -n "$KF_SVC_NS" ]; then
  start_port_forward "$KF_SVC_NS" "$KF_SVC_NAME" 9094 9094 >/dev/null 2>&1 || true
  log "Kafka available at localhost:9094 (svc: $KF_SVC_NAME ns: $KF_SVC_NS)"
else
  log 'Kafka service not found for port-forward; skipping'
fi

log 'Single-cluster setup complete'

# Generate a kubeconfig for an OIDC test user so host-side tests can authenticate
# Uses the local Keycloak port-forward which was started earlier (KEYCLOAK_FORWARD_PORT)
# Defaults match the users created in config/dev/resources/breakglass-e2e-realm.json
OIDC_TEST_USERNAME=${OIDC_TEST_USERNAME:-test-user}
OIDC_TEST_PASSWORD=${OIDC_TEST_PASSWORD:-test-password}
OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-kubernetes}
OIDC_ISSUER="https://breakglass-keycloak.breakglass-system.svc.cluster.local:${KEYCLOAK_FORWARD_PORT}/realms/${KEYCLOAK_REALM}"
OIDC_KUBECONFIG="$TDIR/oidc-test-user.kubeconfig"

log "Generating kubeconfig for OIDC test user (kubelogin exec) : $OIDC_TEST_USERNAME -> $OIDC_KUBECONFIG"

# Create a kubeconfig copy and configure the user to use kubelogin as an exec credential plugin.
# kubelogin will perform the OIDC token retrieval on demand. We pass username/password via env
# so kubelogin can use Resource Owner Password Credentials Grant if configured; adjust as needed.
cp "$HUB_KUBECONFIG" "$OIDC_KUBECONFIG" || { log "ERROR: failed to copy kubeconfig $HUB_KUBECONFIG to $OIDC_KUBECONFIG"; exit 1; }

# Ensure the copied kubeconfig is present and readable. Some environments may have
# delayed filesystem visibility; if the file is missing, attempt to write a view
# of the hub kubeconfig as a fallback so subsequent kubectl --kubeconfig calls work.
if [ ! -f "$OIDC_KUBECONFIG" ] || [ ! -s "$OIDC_KUBECONFIG" ]; then
  log "Warning: copied kubeconfig $OIDC_KUBECONFIG not found or empty; attempting fallback write"
  $KUBECTL --kubeconfig="$HUB_KUBECONFIG" config view --raw > "$OIDC_KUBECONFIG" || { log "ERROR: failed to create $OIDC_KUBECONFIG via kubectl"; exit 1; }
fi

# Determine current context name in the copied kubeconfig
CUR_CTX=$($KUBECTL --kubeconfig="$OIDC_KUBECONFIG" config current-context 2>/dev/null || true)
if [ -z "$CUR_CTX" ]; then
  log "Warning: could not determine current context in $OIDC_KUBECONFIG; leaving kubeconfig mostly unchanged"
else
  # Create a dedicated user entry name
  USER_NAME=oidc-test-user

  # Delete any existing user with the same name to avoid duplication
  $KUBECTL --kubeconfig="$OIDC_KUBECONFIG" config unset users."$USER_NAME" >/dev/null 2>&1 || true

  # Use kubectl to set an empty placeholder user, then write the exec block with yq if available,
  # otherwise use a portable approach: create a temporary kubeconfig fragment and merge.
  TMP_FRAGMENT="$TDIR/oidc-kube-fragment.yaml"
  cat > "$TMP_FRAGMENT" <<EOF
apiVersion: v1
kind: Config
users:
- name: $USER_NAME
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: kubectl
      interactiveMode: IfAvailable
      provideClusterInfo: false
      args:
        - oidc-login
        - get-token
        - --oidc-issuer-url=${OIDC_ISSUER}
        - --oidc-client-id=${OIDC_CLIENT_ID}
        - --skip-open-browser
        - --insecure-skip-tls-verify
      env:
        - name: KUBELOGIN_OIDC_USERNAME
          value: "${OIDC_TEST_USERNAME}"
        - name: KUBELOGIN_OIDC_PASSWORD
          value: "${OIDC_TEST_PASSWORD}"
EOF

  # Merge the fragment into the kubeconfig. Prefer yq if available for safe merging.
  if command -v yq >/dev/null 2>&1; then
    # merge users array by name
    yq eval-all 'select(fi == 0) *+ select(fi == 1)' "$OIDC_KUBECONFIG" "$TMP_FRAGMENT" > "$OIDC_KUBECONFIG.tmp" && mv "$OIDC_KUBECONFIG.tmp" "$OIDC_KUBECONFIG" || true
  elif command -v jq >/dev/null 2>&1; then
    # Fallback: perform a safe JSON merge using kubectl and jq.
    TMP_FRAGMENT_JSON="$TDIR/oidc-kube-fragment.json"
JSONEOF
    cat > "$TMP_FRAGMENT_JSON" <<JSONEOF
{
  "users": [
    {
      "name": "$USER_NAME",
      "user": {
        "exec": {
          "apiVersion": "client.authentication.k8s.io/v1",
          "command": "kubectl",
          "args": [
            "oidc-login",
            "get-token",
            "--oidc-issuer-url=${OIDC_ISSUER}",
            "--oidc-client-id=${OIDC_CLIENT_ID}",
            "--skip-open-browser",
            "--insecure-skip-tls-verify"
          ],
          "env": [
            { "name": "KUBELOGIN_OIDC_USERNAME", "value": "${OIDC_TEST_USERNAME}" },
            { "name": "KUBELOGIN_OIDC_PASSWORD", "value": "${OIDC_TEST_PASSWORD}" }
          ]
        }
      }
    }
  ]
}
JSONEOF

    # Read existing kubeconfig as JSON, merge users arrays (append new user, avoid duplicates by name)
    EXISTING_JSON=$($KUBECTL --kubeconfig="$OIDC_KUBECONFIG" config view --raw -o json 2>/dev/null || true)
    if [ -z "$EXISTING_JSON" ]; then
      log "ERROR: could not read existing kubeconfig as JSON; aborting merge"
    else
      MERGED_JSON=$(printf '%s' "$EXISTING_JSON" | jq --argfile add "$TMP_FRAGMENT_JSON" '
        def byname(a): (a // []) | map({key: .name, val: .}) | from_entries;
        $add as $a | . as $orig |
        .users = ((.users // []) + ($a.users // [])) | .
      ' ) || true
      if [ -n "$MERGED_JSON" ]; then
        # Write merged JSON kubeconfig back (kubectl and clients accept JSON kubeconfig)
        printf '%s' "$MERGED_JSON" > "$OIDC_KUBECONFIG" || true
      else
        log "ERROR: jq merge failed; please install yq or ensure kubeconfig is readable"
      fi
    fi
  else
    log "ERROR: neither 'yq' nor 'jq' found; please install one to enable robust kubeconfig merging."
    log "As a workaround, install 'yq' (recommended) or 'jq' and rerun the script."
  fi

  # Point the current context to use the new user
  # As a robust fallback (and to ensure the exec block exists even if merging failed),
  # use kubectl to set the user credentials with an exec plugin. kubectl supports
  # --exec-command/--exec-arg/--exec-api-version and --exec-env flags which write a
  # proper exec entry into the kubeconfig. This will override any leftover client
  # certificate/key entries for the same user name.
  $KUBECTL --kubeconfig="$OIDC_KUBECONFIG" config set-credentials "$USER_NAME" \
    --exec-command=kubectl \
    --exec-api-version=client.authentication.k8s.io/v1 \
    --exec-arg=oidc-login \
    --exec-arg=get-token \
    --exec-arg=--oidc-issuer-url=${OIDC_ISSUER} \
    --exec-arg=--oidc-client-id=${OIDC_CLIENT_ID} \
    --exec-arg=--skip-open-browser \
    --exec-arg=--insecure-skip-tls-verify \
    --exec-env=KUBELOGIN_OIDC_USERNAME=${OIDC_TEST_USERNAME} \
    --exec-env=KUBELOGIN_OIDC_PASSWORD=${OIDC_TEST_PASSWORD} >/dev/null 2>&1 || true

  $KUBECTL --kubeconfig="$OIDC_KUBECONFIG" config set-context "$CUR_CTX" --user="$USER_NAME" >/dev/null 2>&1 || true

  log "Created kubeconfig for OIDC user (exec plugin) at: $OIDC_KUBECONFIG"
  log "kubelogin must be installed on the machine using this kubeconfig. Use it with: KUBECONFIG=$OIDC_KUBECONFIG $KUBECTL get pods --all-namespaces"
fi

# --- E2E Test Environment Setup ---
# Set up port-forwards and export environment variables needed for e2e tests
log "Setting up E2E test environment..."

# Reuse the controller port-forward that was set up earlier (CONTROLLER_FORWARD_PORT)
# This avoids conflicts from having multiple port-forwards to the same service
API_PORT=${CONTROLLER_FORWARD_PORT}
log "Using controller port-forward for E2E tests: localhost:$API_PORT"

# Verify the API is still accessible
if ! curl -s "http://localhost:$API_PORT/api/config" >/dev/null 2>&1; then
  log "Warning: API not accessible on port $API_PORT; e2e tests may fail"
fi

# Export environment variables for e2e tests
E2E_ENV_FILE="$TDIR/e2e-env.sh"
# Extract the K8s API server URL from kubeconfig for OIDC tests
KUBERNETES_API_SERVER=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')
# Get the Docker container IP of the control plane for in-cluster access via port 6443
# This is consistent with multi-cluster setup and works for OIDC ClusterConfig tests
CLUSTER_DOCKER_IP=$(docker inspect "${CLUSTER_NAME}-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
# KUBERNETES_API_SERVER_INTERNAL is the URL reachable from inside the cluster (controller pods)
KUBERNETES_API_SERVER_INTERNAL="https://${CLUSTER_DOCKER_IP}:6443"
log "Cluster Docker IP: ${CLUSTER_DOCKER_IP}"
log "Internal K8s API Server URL: ${KUBERNETES_API_SERVER_INTERNAL}"
cat > "$E2E_ENV_FILE" <<EOF
# E2E Test Environment Variables
# Source this file before running tests: source $E2E_ENV_FILE
export E2E_TEST=true
export E2E_NAMESPACE=default
export E2E_CLUSTER_NAME=tenant-a
export E2E_TEST_USER=testuser@example.com
export E2E_TEST_APPROVER=approver@example.com
export BREAKGLASS_API_URL=http://localhost:$API_PORT
export BREAKGLASS_WEBHOOK_URL=http://localhost:$API_PORT
export BREAKGLASS_METRICS_URL=http://localhost:${METRICS_FORWARD_PORT}/metrics
export KEYCLOAK_URL=https://localhost:${KEYCLOAK_FORWARD_PORT}
export KEYCLOAK_HOST=https://localhost:${KEYCLOAK_FORWARD_PORT}
export KEYCLOAK_PORT=${KEYCLOAK_FORWARD_PORT}
export KEYCLOAK_REALM=${KEYCLOAK_REALM}
export KEYCLOAK_CLIENT_ID=breakglass-ui
# Keycloak Group Sync client credentials (for admin API access)
export KEYCLOAK_GROUP_SYNC_CLIENT_ID=breakglass-group-sync
export KEYCLOAK_GROUP_SYNC_CLIENT_SECRET=breakglass-group-sync-secret
# KEYCLOAK_ISSUER_HOST is the in-cluster service hostname (matches IdentityProvider issuer)
# Frontend will access this via /etc/hosts mapping to localhost
export KEYCLOAK_ISSUER_HOST=breakglass-keycloak.breakglass-system.svc.cluster.local:8443
export KEYCLOAK_SERVICE_HOSTNAME=breakglass-keycloak.breakglass-system.svc.cluster.local
# KEYCLOAK_INTERNAL_URL is used by tests to construct issuer URLs reachable from controller
export KEYCLOAK_INTERNAL_URL=https://breakglass-keycloak.breakglass-system.svc.cluster.local:8443
# Kubernetes API server URL (external, for kubectl from test runner)
export KUBERNETES_API_SERVER=$KUBERNETES_API_SERVER
# Kubernetes API server URL (internal, reachable from controller pod via Docker network)
# This is the Docker container IP with port 6443, consistent with multi-cluster setup
export KUBERNETES_API_SERVER_INTERNAL=$KUBERNETES_API_SERVER_INTERNAL
# Keycloak CA certificate file for OIDC TLS verification
export KEYCLOAK_CA_FILE=$KEYCLOAK_CA_FILE
export TLS_DIR=$TLS_DIR
export AUDIT_WEBHOOK_RECEIVER_EXTERNAL_URL=http://localhost:${AUDIT_WEBHOOK_RECEIVER_PORT}
export KUBECONFIG=$HUB_KUBECONFIG
EOF

log "E2E environment file created: $E2E_ENV_FILE"
log "To run tests, source the env file and run:"
log "  source $E2E_ENV_FILE"
log "  go test -v ./e2e/api/..."

log "Single-cluster e2e setup complete!"
log ""
log "Services available:"
log "  - API:                 http://localhost:$API_PORT"
log "  - Webhook:             http://localhost:$API_PORT/api/breakglass/webhook/authorize/{cluster}"
log "  - Metrics:             http://localhost:${METRICS_FORWARD_PORT}/metrics"
log "  - Keycloak:            https://localhost:${KEYCLOAK_FORWARD_PORT}"
log "  - MailHog:             http://localhost:${MAILHOG_UI_PORT}"
log "  - Audit Webhook Recv:  http://localhost:${AUDIT_WEBHOOK_RECEIVER_PORT}"
log ""
log "To stop port-forwards: kill \$(cat $PF_FILE)"

