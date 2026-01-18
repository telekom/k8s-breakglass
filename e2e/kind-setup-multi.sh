#!/usr/bin/env bash
set -euo pipefail
# Multi-cluster E2E setup: 1 hub + 2 spoke clusters with full OIDC authentication.
# This script creates a true hub-and-spoke topology where:
# - Hub cluster runs the Breakglass controller, API, webhooks, Keycloak, and MailHog
# - Spoke clusters are registered via ClusterConfig and use the hub for webhook authorization
# - Multiple OIDC realms support different user populations (employees vs contractors)

# --- Script directory and common library ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export E2E_DIR="$SCRIPT_DIR"
E2E_LOG_PREFIX="[multi-e2e]"

# Source common library (provides shared functions)
if [ -f "${SCRIPT_DIR}/lib/common.sh" ]; then
  source "${SCRIPT_DIR}/lib/common.sh"
else
  echo "ERROR: Common library not found at ${SCRIPT_DIR}/lib/common.sh"
  exit 1
fi

# --- Tools (can be overridden by env) ---
KIND=${KIND:-kind}
KUBECTL=${KUBECTL:-kubectl}
KUSTOMIZE=${KUSTOMIZE:-kustomize}

# --- Images & build ---
IMAGE=${IMAGE:-breakglass:e2e}
UI_FLAVOUR=${UI_FLAVOUR:-oss}
export VITE_UI_FLAVOUR=$UI_FLAVOUR
echo "UI flavour selected: $UI_FLAVOUR (IMAGE=$IMAGE)"
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.5.0}

# --- Cluster names ---
HUB_CLUSTER=${HUB_CLUSTER:-breakglass-hub}
SPOKE_A_CLUSTER=${SPOKE_A_CLUSTER:-spoke-cluster-a}
SPOKE_B_CLUSTER=${SPOKE_B_CLUSTER:-spoke-cluster-b}

# --- Ports / forwards ---
NODEPORT=${NODEPORT:-31081}
WEBHOOK_NODEPORT=${WEBHOOK_NODEPORT:-31443}
API_NODEPORT=${API_NODEPORT:-31080}
WEBHOOK_SERVICE_PORT=${WEBHOOK_SERVICE_PORT:-8081}
KEYCLOAK_SVC_PORT=${KEYCLOAK_SVC_PORT:-8443}
KEYCLOAK_FORWARD_PORT=${KEYCLOAK_FORWARD_PORT:-8443}
KEYCLOAK_HTTP_NODEPORT=${KEYCLOAK_HTTP_NODEPORT:-31880}
MAILHOG_UI_PORT=${MAILHOG_UI_PORT:-8025}

# --- Hub external URL (will be set after cluster creation) ---
HUB_EXTERNAL_IP=""
HUB_WEBHOOK_URL=""
HUB_API_URL=""

# --- Kind node image ---
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.34.0}

# --- Directories ---
TDIR=${TDIR:-"$SCRIPT_DIR/kind-setup-multi-tdir"}
TLS_DIR=${TLS_DIR:-"$SCRIPT_DIR/kind-setup-multi-tls"}
PF_FILE=${PF_FILE:-"$SCRIPT_DIR/multi-cluster-port-forward-pids"}

# --- Kubeconfig paths ---
HUB_KUBECONFIG=""
SPOKE_A_KUBECONFIG=""
SPOKE_B_KUBECONFIG=""

# --- OIDC-only kubeconfigs (no client certs, for token-based auth tests) ---
SPOKE_A_OIDC_KUBECONFIG=""
SPOKE_B_OIDC_KUBECONFIG=""

# --- Keycloak settings ---
KEYCLOAK_HOST=${KEYCLOAK_HOST:-breakglass-keycloak.breakglass-system.svc.cluster.local}
KEYCLOAK_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT:-8443}
KEYCLOAK_PORT=${KEYCLOAK_PORT:-8443}
KEYCLOAK_MAIN_REALM=${KEYCLOAK_MAIN_REALM:-breakglass-e2e}
KEYCLOAK_CONTRACTORS_REALM=${KEYCLOAK_CONTRACTORS_REALM:-breakglass-e2e-contractors}

# --- Breakglass namespace ---
NAMESPACE=${NAMESPACE:-breakglass-system}

# --- Proxy configuration ---
if [ "${SKIP_PROXY:-false}" = "true" ]; then
  printf '[multi-e2e] SKIP_PROXY=true: Skipping corporate proxy configuration\n'
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
fi

# Initialize temporary directories
init_temp_dirs() {
  log "Creating temporary directories..."
  mkdir -p "$TDIR" "$TLS_DIR"
}

# Generate TLS certificates (called after we know the hub IP)
generate_tls_certificates() {
  local hub_ip="${1:-127.0.0.1}"
  
  log "Generating TLS certificates with hub IP: $hub_ip..."
  
  # Use common library function for comprehensive TLS generation
  generate_breakglass_tls "$TLS_DIR" "$hub_ip" "$NAMESPACE"
  
  # Also generate Keycloak TLS if needed
  generate_keycloak_tls "${TLS_DIR}/keycloak" "$hub_ip" "$NAMESPACE"
}

# Create Kind cluster configuration for HUB cluster (no OIDC/webhook needed - it IS the hub)
create_hub_kind_config() {
  local cluster_name="$1"
  local config_file="$TDIR/${cluster_name}-kind.yaml"
  
  cat > "$config_file" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${cluster_name}
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        authorization-mode: Node,RBAC
        v: "6"
  extraPortMappings:
  - containerPort: 30080
    hostPort: 0
    protocol: TCP
EOF
  echo "$config_file"
}

# Create Kind cluster configuration for SPOKE clusters with OIDC + Authorization Webhook
# These clusters will authenticate users via OIDC (Keycloak) and authorize via hub webhook
create_spoke_kind_config() {
  local cluster_name="$1"
  local hub_ip="$2"
  local keycloak_ip="$3"
  local keycloak_ca_file="$4"
  local config_file="$TDIR/${cluster_name}-kind.yaml"
  local authz_config_file="$TDIR/${cluster_name}-authorization-config.yaml"
  local authn_config_file="$TDIR/${cluster_name}-authentication-config.yaml"
  local webhook_kubeconfig_file="$TDIR/${cluster_name}-webhook.kubeconfig"
  local patches_dir="$TDIR/${cluster_name}-patches"
  
  # Create patches directory for kubeadm patches
  mkdir -p "$patches_dir"
  
  # Create a patch to add hostAliases to kube-apiserver pod
  # This allows the apiserver pod to resolve e2e-keycloak to the Keycloak container IP
  # CRITICAL: The issuer URL in OIDC tokens must match the issuer in AuthenticationConfiguration
  cat > "$patches_dir/kube-apiserver+strategic.yaml" <<EOF
spec:
  hostAliases:
  - ip: "${keycloak_ip}"
    hostnames:
    - "e2e-keycloak"
EOF
  
  # Read the Keycloak CA certificate content for embedding in authentication config
  local keycloak_ca_content
  keycloak_ca_content=$(cat "$keycloak_ca_file")
  
  # Create authorization configuration for this spoke (Kubernetes 1.32+ stable feature)
  # This tells the apiserver to use Node, RBAC, then Webhook for authorization
  # See: https://kubernetes.io/docs/reference/access-authn-authz/authorization/#using-configuration-file-for-authorization
  #
  # CEL matchConditions filter out system accounts so they don't hit the webhook:
  # - system:apiserver, system:kube-controller-manager, system:kube-scheduler
  # - system:node:* (kubelet)
  # - system:serviceaccount:* (all service accounts)
  # This improves performance and prevents webhook dependency for internal operations.
  #
  # CRITICAL: failurePolicy must be NoOpinion (not Deny) to allow cluster bootstrap!
  # If set to Deny and webhook is slow/unreachable, the API server cannot start.
  #
  # Authorization order: Node → RBAC → Webhook
  # 
  # The breakglass webhook is consulted AFTER RBAC. It grants ADDITIONAL temporary access
  # when RBAC denies the request but the user has a valid breakglass session.
  # Users who already have RBAC permissions don't need breakglass sessions.
  #
  # The matchConditions filter ensures only OIDC users (not system accounts) hit the webhook.
  cat > "$authz_config_file" <<'AUTHZEOF'
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  # RBAC first - handles normal permissions
  - type: RBAC
    name: rbac
  # Breakglass webhook AFTER RBAC - grants ADDITIONAL temporary access
  # Only consulted when RBAC denies but user has valid breakglass session
  - type: Webhook
    name: breakglass
    webhook:
      timeout: 3s
      # Disable caching for e2e tests - decisions should always hit the webhook
      # Note: Setting TTL to 0 uses default, so we must set cacheXxxRequests: false
      cacheAuthorizedRequests: false
      cacheUnauthorizedRequests: false
      # NoOpinion allows requests to proceed if webhook unreachable
      # This prevents breakglass from blocking cluster operations
      failurePolicy: NoOpinion
      subjectAccessReviewVersion: v1
      matchConditionSubjectAccessReviewVersion: v1
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook.kubeconfig
      matchConditions:
        # Only call webhook for authenticated users
        - expression: "'system:authenticated' in request.groups"
        # Skip webhook for system users
        - expression: "!request.user.startsWith('system:')"
        # Skip webhook for system service accounts
        - expression: "!('system:serviceaccounts' in request.groups)"
        # Skip webhook for the breakglass manager's OIDC service account
        # This prevents recursive webhook calls when the manager fetches namespace labels
        - expression: "request.user != 'breakglass-group-sync@service.local'"
AUTHZEOF

  # Create authentication configuration for this spoke (Kubernetes 1.34+ structured auth)
  # This uses the AuthenticationConfiguration API instead of --oidc-* flags
  # See: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration
  #
  # IMPORTANT: We configure MULTIPLE issuers to support:
  # 1. Main realm (employees): breakglass-e2e
  # 2. Contractors realm: breakglass-e2e-contractors
  # Both realms use the same Keycloak instance with the same CA certificate.
  #
  # CRITICAL: Must use DNS name (e2e-keycloak) not IP in issuer URLs.
  # The issuer in the JWT token must EXACTLY match the issuer configured here.
  # Users get tokens from Keycloak using DNS name, so we must configure the same DNS name.
  # We add /etc/hosts entry in the spoke apiserver container to resolve e2e-keycloak to keycloak IP.
  cat > "$authn_config_file" <<EOF
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
# Main realm for employees
- issuer:
    url: https://e2e-keycloak:8443/realms/${KEYCLOAK_MAIN_REALM}
    audiences:
    - kubernetes
    certificateAuthority: |
$(echo "$keycloak_ca_content" | sed 's/^/      /')
  claimMappings:
    username:
      claim: email
      prefix: ""
    groups:
      claim: groups
      prefix: ""
# Contractors realm for external contractors
- issuer:
    url: https://e2e-keycloak:8443/realms/${KEYCLOAK_CONTRACTORS_REALM}
    audiences:
    - kubernetes
    certificateAuthority: |
$(echo "$keycloak_ca_content" | sed 's/^/      /')
  claimMappings:
    username:
      claim: email
      prefix: ""
    groups:
      claim: groups
      prefix: ""
EOF

  # Create webhook kubeconfig that points to hub breakglass webhook
  # The spoke apiserver will use this to call the hub for authorization decisions
  # NOTE: The webhook is served on the same port as the API (8080), not a separate port
  # NOTE: Breakglass runs in HTTP mode in e2e (no TLS on the API server)
  cat > "$webhook_kubeconfig_file" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: breakglass-hub
    cluster:
      server: http://${hub_ip}:${API_NODEPORT}/api/breakglass/webhook/authorize/${cluster_name}
users:
  - name: spoke-webhook-client
    user:
contexts:
  - name: default
    context:
      cluster: breakglass-hub
      user: spoke-webhook-client
current-context: default
EOF

  # Create Kind cluster config with structured authentication and authorization
  # IMPORTANT: extraMounts are Docker host → container mappings
  # The kubeadmConfigPatches then reference paths INSIDE the container
  # Uses --authentication-config instead of --oidc-* flags (Kubernetes 1.34+ approach)
  cat > "$config_file" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${cluster_name}
nodes:
- role: control-plane
  image: ${KIND_NODE_IMAGE}
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        authentication-config: /etc/kubernetes/authentication-config.yaml
        authorization-config: /etc/kubernetes/authorization-config.yaml
        v: "6"
      extraVolumes:
        - name: authentication-config
          hostPath: /etc/kubernetes/authentication-config.yaml
          mountPath: /etc/kubernetes/authentication-config.yaml
          readOnly: true
        - name: authorization-config
          hostPath: /etc/kubernetes/authorization-config.yaml
          mountPath: /etc/kubernetes/authorization-config.yaml
          readOnly: true
        - name: webhook-kubeconfig
          hostPath: /etc/kubernetes/breakglass-webhook.kubeconfig
          mountPath: /etc/kubernetes/breakglass-webhook.kubeconfig
          readOnly: true
  - |
    kind: InitConfiguration
    patches:
      directory: /etc/kubernetes/patches
  extraMounts:
    - hostPath: ${authn_config_file}
      containerPath: /etc/kubernetes/authentication-config.yaml
      readOnly: true
    - hostPath: ${authz_config_file}
      containerPath: /etc/kubernetes/authorization-config.yaml
      readOnly: true
    - hostPath: ${webhook_kubeconfig_file}
      containerPath: /etc/kubernetes/breakglass-webhook.kubeconfig
      readOnly: true
    - hostPath: ${patches_dir}
      containerPath: /etc/kubernetes/patches
      readOnly: true
  extraPortMappings:
  - containerPort: 30080
    hostPort: 0
    protocol: TCP
EOF
  echo "$config_file"
}

# Internal helper to run kind create with retain-on-failure support
# Uses the same env vars as create_kind_cluster from common.sh
_kind_create_with_retain() {
  local cluster_name="$1"
  local config_file="$2"
  local wait_time="${3:-120s}"
  
  # Build kind create command with optional --retain flag
  local kind_create_args=(create cluster --name "$cluster_name" --config "$config_file" --wait "$wait_time")
  
  # Add --retain flag to keep nodes on failure for debugging
  if [ "${KIND_RETAIN_ON_FAILURE:-false}" = "true" ]; then
    log "KIND_RETAIN_ON_FAILURE=true: Nodes will be preserved on failure for debugging"
    kind_create_args+=(--retain)
  fi
  
  if ! $KIND "${kind_create_args[@]}"; then
    local exit_code=$?
    log_error "Kind cluster creation failed for $cluster_name (exit code: $exit_code)"
    
    # Capture logs before potential cleanup (use function from common.sh if available)
    if declare -f capture_kind_logs_on_failure > /dev/null 2>&1; then
      local log_dir="${KIND_FAILURE_LOG_DIR:-/tmp/kind-failure-logs}/${cluster_name}"
      capture_kind_logs_on_failure "$cluster_name" "$log_dir"
    else
      # Inline fallback: capture basic docker logs
      log_error "Capturing docker logs for ${cluster_name}-control-plane..."
      docker logs "${cluster_name}-control-plane" 2>&1 | tail -100 || true
    fi
    
    if [ "${KIND_RETAIN_ON_FAILURE:-false}" = "true" ]; then
      log_error "Cluster nodes retained for debugging. To clean up manually run:"
      log_error "  kind delete cluster --name $cluster_name"
    fi
    
    return $exit_code
  fi
}

# Create hub cluster FIRST (so we can get its IP for spoke configuration)
create_hub_cluster() {
  log "Creating hub cluster: $HUB_CLUSTER"
  local hub_config=$(create_hub_kind_config "$HUB_CLUSTER")
  _kind_create_with_retain "$HUB_CLUSTER" "$hub_config" "120s"
  HUB_KUBECONFIG="$TDIR/${HUB_CLUSTER}.kubeconfig"
  $KIND get kubeconfig --name "$HUB_CLUSTER" > "$HUB_KUBECONFIG"
  
  # Get hub's Docker IP immediately - needed for spoke configuration
  HUB_EXTERNAL_IP=$(docker inspect "${HUB_CLUSTER}-control-plane" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  log "Hub cluster created with IP: $HUB_EXTERNAL_IP"
  
  # Save hub IP for later use
  echo "$HUB_EXTERNAL_IP" > "$TDIR/hub-external-ip"
}

# Create spoke clusters WITH OIDC and webhook configuration
create_spoke_clusters() {
  local hub_ip="$1"
  
  # Get Keycloak container IP (must be running already)
  local keycloak_ip
  keycloak_ip=$(cat "$TDIR/keycloak-ip" 2>/dev/null || get_keycloak_ip)
  if [ -z "$keycloak_ip" ]; then
    log_error "Keycloak IP not available - make sure setup_keycloak is called first"
    return 1
  fi
  
  # Get Keycloak CA file path
  local keycloak_ca_file="${TLS_DIR}/keycloak/ca.crt"
  if [ ! -f "$keycloak_ca_file" ]; then
    log_error "Keycloak CA file not found at $keycloak_ca_file"
    return 1
  fi
  
  log "Creating spoke cluster A: $SPOKE_A_CLUSTER (with OIDC to Keycloak at $keycloak_ip + webhook to hub at $hub_ip)"
  
  local spoke_a_config=$(create_spoke_kind_config "$SPOKE_A_CLUSTER" "$hub_ip" "$keycloak_ip" "$keycloak_ca_file")
  _kind_create_with_retain "$SPOKE_A_CLUSTER" "$spoke_a_config" "120s"
  SPOKE_A_KUBECONFIG="$TDIR/${SPOKE_A_CLUSTER}.kubeconfig"
  $KIND get kubeconfig --name "$SPOKE_A_CLUSTER" > "$SPOKE_A_KUBECONFIG"
  
  log "Creating spoke cluster B: $SPOKE_B_CLUSTER (with OIDC to Keycloak at $keycloak_ip + webhook to hub at $hub_ip)"
  
  local spoke_b_config=$(create_spoke_kind_config "$SPOKE_B_CLUSTER" "$hub_ip" "$keycloak_ip" "$keycloak_ca_file")
  _kind_create_with_retain "$SPOKE_B_CLUSTER" "$spoke_b_config" "120s"
  SPOKE_B_KUBECONFIG="$TDIR/${SPOKE_B_CLUSTER}.kubeconfig"
  $KIND get kubeconfig --name "$SPOKE_B_CLUSTER" > "$SPOKE_B_KUBECONFIG"
  
  # Create OIDC-only kubeconfigs for token-based authentication tests
  # These kubeconfigs have no client certificates, forcing kubectl to use
  # only the --token flag for authentication (OIDC flow)
  log "Creating OIDC-only kubeconfigs for spoke clusters..."
  SPOKE_A_OIDC_KUBECONFIG=$(create_oidc_kubeconfig "$SPOKE_A_CLUSTER" "$SPOKE_A_KUBECONFIG")
  log "Created OIDC kubeconfig for $SPOKE_A_CLUSTER: $SPOKE_A_OIDC_KUBECONFIG"
  SPOKE_B_OIDC_KUBECONFIG=$(create_oidc_kubeconfig "$SPOKE_B_CLUSTER" "$SPOKE_B_KUBECONFIG")
  log "Created OIDC kubeconfig for $SPOKE_B_CLUSTER: $SPOKE_B_OIDC_KUBECONFIG"
  
  log "All spoke clusters created with OIDC + webhook configuration"
}

# Create all clusters - hub first (with breakglass deployed), then spokes
# IMPORTANT: Hub must have breakglass controller running BEFORE spoke clusters are created,
# because spoke clusters use authorization webhook that calls hub's breakglass webhook.
# If breakglass isn't running, spoke cluster's API server will never become healthy.
create_clusters() {
  # Create hub cluster first
  create_hub_cluster
  
  # Load breakglass image into hub cluster BEFORE setup_hub_cluster needs it
  log "Loading breakglass image into hub cluster..."
  load_image_into_cluster "$HUB_CLUSTER" "$IMAGE"
  
  # Setup hub cluster with Breakglass controller BEFORE creating spoke clusters.
  # This is critical because spoke clusters have authorization webhook pointing to hub.
  # The webhook has failurePolicy: Deny, so if hub isn't ready, spoke API server won't start.
  setup_hub_cluster
  
  # CRITICAL: Verify hub services are ready BEFORE creating spoke clusters.
  # Spoke clusters have authorization webhooks pointing to hub, so if hub isn't
  # reachable, the spoke API servers will never become healthy.
  if ! verify_hub_services_ready; then
    log_error "Hub services verification failed - aborting spoke cluster creation"
    log_error "This would cause spoke cluster API servers to fail with webhook errors"
    return 1
  fi
  
  # Now create spoke clusters with hub IP for webhook configuration
  # Hub's breakglass controller is now running and can handle webhook requests
  create_spoke_clusters "$HUB_EXTERNAL_IP"
  
  log "All clusters created successfully"
}

# Preload images to all clusters (hub + spokes)
# This ensures debug session tests and other pods don't have image pull delays
preload_images_all_clusters() {
  log "Preloading images to all clusters..."
  ensure_tmux_debug_image
  
  local clusters=("$HUB_CLUSTER" "$SPOKE_A_CLUSTER" "$SPOKE_B_CLUSTER")
  local images=(
    "$IMAGE"
    "nicolaka/netshoot"
    "busybox:latest"
    "$TMUX_DEBUG_IMAGE"
  )
  
  for cluster in "${clusters[@]}"; do
    log "Loading images into cluster: $cluster"
    for img in "${images[@]}"; do
      load_image_into_cluster "$cluster" "$img"
    done
  done
  
  log "All images preloaded to all clusters"
}

# Load Docker image into cluster (use common library function)
load_image_into_cluster() {
  local cluster_name="$1"
  local image="$2"
  e2e_load_image_into_kind "$cluster_name" "$image"
}

# Wait for deployment to be ready (use common library function)
# On failure, calls e2e_debug_deployment_failure to provide diagnostic output
wait_for_deploy_by_label() {
  local kubeconfig="$1"
  local label="$2"
  local max_attempts=${3:-120}
  if ! e2e_wait_for_deployment_by_label "$kubeconfig" "$label" "$max_attempts"; then
    e2e_debug_deployment_failure "$kubeconfig" "$label"
    return 1
  fi
}

# Start port forward (use common library function)
start_port_forward_multi() {
  local kubeconfig="$1"
  local ns="$2"
  local svc="$3"
  local local_port="$4"
  local remote_port="$5"
  start_port_forward "$kubeconfig" "$ns" "$svc" "$local_port" "$remote_port" "$PF_FILE"
}

# Setup hub cluster with Breakglass controller
setup_hub_cluster() {
  log "Setting up hub cluster with Breakglass controller..."
  
  # Get the hub's Docker network IP first (needed for TLS certs)
  HUB_EXTERNAL_IP=$(docker inspect "${HUB_CLUSTER}-control-plane" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  log "Hub cluster IP: $HUB_EXTERNAL_IP"
  
  # Generate TLS certs with the hub IP included
  generate_tls_certificates "$HUB_EXTERNAL_IP"
  
  # Copy certs so kustomize can find them (expected by config/dev/kustomization.yaml)
  log "Copying certs for kustomize..."
  KUSTOMIZE_CERTS_DIR="$(pwd)/config/dev/certs/kind-setup-single-tls"
  rm -rf "$KUSTOMIZE_CERTS_DIR"
  mkdir -p "$KUSTOMIZE_CERTS_DIR"
  cp "$TLS_DIR/ca.crt" "$KUSTOMIZE_CERTS_DIR/"
  cp "$TLS_DIR/tls.crt" "$KUSTOMIZE_CERTS_DIR/server.crt"
  cp "$TLS_DIR/tls.key" "$KUSTOMIZE_CERTS_DIR/server.key"
  
  # Load hub-specific images (not needed on spoke clusters)
  log "Loading hub-specific images..."
  load_image_into_cluster "$HUB_CLUSTER" "mailhog/mailhog:v1.0.1"
  load_image_into_cluster "$HUB_CLUSTER" "curlimages/curl:8.4.0"
  load_image_into_cluster "$HUB_CLUSTER" "apache/kafka:3.7.0"
  
  # Apply CRDs
  log "Applying CRDs..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f config/crd/bases/
  
  # Install cert-manager to provide Certificate and Issuer CRDs
  log "Installing cert-manager..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.3/cert-manager.yaml
  log "Waiting for cert-manager to be ready..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL wait --for=condition=available --timeout=120s -n cert-manager deployment/cert-manager
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL wait --for=condition=available --timeout=120s -n cert-manager deployment/cert-manager-webhook
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL wait --for=condition=available --timeout=120s -n cert-manager deployment/cert-manager-cainjector
  log "cert-manager is ready"
  
  # Create namespace
  log "Creating namespace..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace breakglass-system --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
  
  # Create TLS secret for webhook
  log "Creating TLS secret..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret tls breakglass-webhook-server-cert \
    --cert="$TLS_DIR/tls.crt" \
    --key="$TLS_DIR/tls.key" \
    -n breakglass-system \
    --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
  
  # Deploy using kustomize (this will deploy Keycloak in-cluster, we'll delete it)
  log "Deploying Breakglass controller..."
  
  # Set the image to match what was loaded into kind
  # The IMAGE variable is set by the CI (e.g., IMAGE=breakglass:dev)
  # Kustomization uses image substitution, so we need to update it
  local image_name image_tag
  image_name="${IMAGE%%:*}"  # Extract image name (before colon)
  image_tag="${IMAGE##*:}"   # Extract tag (after colon)
  
  # Use kustomize to set the image tag, but we need to build from a temp dir
  # to avoid modifying the source tree
  local kustomize_tmp="$TDIR/kustomize-tmp"
  rm -rf "$kustomize_tmp"
  cp -r config "$kustomize_tmp/"
  
  # Multi-cluster uses standalone Keycloak container, NOT in-cluster Keycloak.
  # Remove the init container that waits for in-cluster Keycloak (it would never succeed).
  # Also remove the in-cluster Keycloak deployment from the kustomization.
  log "Patching kustomization for standalone Keycloak..."
  
  # Remove keycloak.yaml from resources section  
  sed -i.bak '/\.\/resources\/keycloak\.yaml/d' "$kustomize_tmp/dev/kustomization.yaml"
  
  # Remove the keycloak_wait_initcontainer patch block entirely using Python for reliable
  # multi-line regex. The block looks like:
  #   - target:
  #       group: apps
  #       version: v1
  #       kind: Deployment
  #       name: manager
  #     path: ./resources/keycloak_wait_initcontainer.yaml
  python3 -c "
import re
with open('$kustomize_tmp/dev/kustomization.yaml', 'r') as f:
    content = f.read()
# Remove the patch block for keycloak_wait_initcontainer
pattern = r'- target:\n    group: apps\n    version: v1\n    kind: Deployment\n    name: manager\n  path: \./resources/keycloak_wait_initcontainer\.yaml\n'
content = re.sub(pattern, '', content)
with open('$kustomize_tmp/dev/kustomization.yaml', 'w') as f:
    f.write(content)
"
  rm -f "$kustomize_tmp/dev/kustomization.yaml.bak"
  
  # Update image in kustomization
  cd "$kustomize_tmp/dev"
  $KUSTOMIZE edit set image "breakglass=${image_name}:${image_tag}"
  cd - > /dev/null
  
  KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build "$kustomize_tmp/dev" | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply --server-side --force-conflicts -f -
  
  # NOTE: In-cluster Keycloak is no longer deployed (removed from kustomization above)
  # The standalone Keycloak container was started earlier in start_standalone_keycloak()
  
  # Wait for remaining deployments
  wait_for_deploy_by_label "$HUB_KUBECONFIG" "mailhog" 60
  wait_for_deploy_by_label "$HUB_KUBECONFIG" "breakglass" 120
  
  # Patch breakglass deployment with hostAliases for Keycloak DNS resolution
  # This allows the controller pod to resolve e2e-keycloak to the Keycloak container IP
  log "Patching breakglass deployment with Keycloak hostAliases..."
  local keycloak_ip
  if [ -f "$TDIR/keycloak-ip" ]; then
    keycloak_ip=$(cat "$TDIR/keycloak-ip")
  else
    keycloak_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KEYCLOAK_CONTAINER_NAME" 2>/dev/null || echo "")
  fi
  if [ -n "$keycloak_ip" ]; then
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL patch deployment -n breakglass-system breakglass-manager --type=json -p="[
      {
        \"op\": \"add\",
        \"path\": \"/spec/template/spec/hostAliases\",
        \"value\": [{\"ip\": \"$keycloak_ip\", \"hostnames\": [\"e2e-keycloak\", \"$KEYCLOAK_CONTAINER_NAME\"]}]
      }
    ]" || log "Warning: Could not patch hostAliases (may already exist)"
    # Wait for the pod to restart after patch
    sleep 5
    wait_for_deploy_by_label "$HUB_KUBECONFIG" "breakglass" 60
  else
    log "Warning: Could not get Keycloak IP for hostAliases patch"
  fi
  
  # Expose breakglass service via NodePort for spoke cluster access
  expose_hub_services
  
  log "Hub cluster setup complete"
}

# Expose hub services via NodePort so spoke clusters can reach them
expose_hub_services() {
  log "Exposing hub services via NodePort..."
  
  # Get the hub's Docker network IP (accessible from other Kind clusters)
  HUB_EXTERNAL_IP=$(docker inspect "${HUB_CLUSTER}-control-plane" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  log "Hub cluster IP: $HUB_EXTERNAL_IP"
  
  # Create NodePort service for breakglass API (which also serves the webhook on the same port)
  # and metrics (port 8081 - metrics only, NOT the webhook)
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: v1
kind: Service
metadata:
  name: breakglass-external
  namespace: breakglass-system
  labels:
    app: breakglass
spec:
  type: NodePort
  selector:
    app: breakglass
  ports:
  - name: api
    port: 8080
    targetPort: 8080
    nodePort: ${API_NODEPORT}
  - name: metrics
    port: 8081
    targetPort: 8081
    nodePort: ${WEBHOOK_NODEPORT}
EOF
  # NOTE: Keycloak runs as a standalone Docker container (not in-cluster),
  # so we don't need a keycloak-external service here.
  # Spoke clusters reach Keycloak directly via Docker network IP.

  # Set the external URLs that spoke clusters will use
  # The webhook is served on the same port as the API (8080), not a separate port
  HUB_WEBHOOK_URL="http://${HUB_EXTERNAL_IP}:${API_NODEPORT}"
  HUB_API_URL="http://${HUB_EXTERNAL_IP}:${API_NODEPORT}"
  # Keycloak is running as standalone Docker container - read its IP from saved file
  local keycloak_ip
  if [ -f "$TDIR/keycloak-ip" ]; then
    keycloak_ip=$(cat "$TDIR/keycloak-ip")
  else
    keycloak_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KEYCLOAK_CONTAINER_NAME" 2>/dev/null || echo "")
  fi
  HUB_KEYCLOAK_URL="http://${keycloak_ip}:8080"
  
  log "Hub webhook URL for spoke clusters: $HUB_WEBHOOK_URL"
  log "Hub API URL for spoke clusters: $HUB_API_URL"
  log "Hub Keycloak URL for spoke clusters: $HUB_KEYCLOAK_URL"
  
  # Store URLs in temp dir for reference
  echo "$HUB_WEBHOOK_URL" > "$TDIR/hub-webhook-url"
  echo "$HUB_API_URL" > "$TDIR/hub-api-url"
  echo "$HUB_KEYCLOAK_URL" > "$TDIR/hub-keycloak-url"
  echo "$HUB_EXTERNAL_IP" > "$TDIR/hub-external-ip"
}

# Verify hub services are ready and reachable BEFORE creating spoke clusters.
# This is a critical pre-flight check because spoke clusters have authorization
# webhooks configured to point to the hub. If hub services are not reachable,
# the spoke API servers will never become healthy.
verify_hub_services_ready() {
  log "=============================================="
  log "PRE-FLIGHT: Verifying hub services are ready"
  log "=============================================="
  
  local hub_ip
  if [ -f "$TDIR/hub-external-ip" ]; then
    hub_ip=$(cat "$TDIR/hub-external-ip")
  else
    log_error "Hub external IP not found - cannot verify connectivity"
    return 1
  fi
  
  local keycloak_ip
  if [ -f "$TDIR/keycloak-ip" ]; then
    keycloak_ip=$(cat "$TDIR/keycloak-ip")
  else
    log_error "Keycloak IP not found - cannot verify connectivity"
    return 1
  fi
  
  local failed=0
  
  # 1. Check hub API/webhook port (they share the same port)
  log "Checking hub API at $hub_ip:$API_NODEPORT..."
  if ! wait_for_port "$hub_ip" "$API_NODEPORT" 30 "hub API"; then
    log_error "Hub API not reachable at $hub_ip:$API_NODEPORT"
    failed=1
  else
    log "✓ Hub API is reachable at $hub_ip:$API_NODEPORT"
  fi
  
  # 2. Check hub metrics/webhook port
  log "Checking hub metrics at $hub_ip:$WEBHOOK_NODEPORT..."
  if ! wait_for_port "$hub_ip" "$WEBHOOK_NODEPORT" 30 "hub metrics"; then
    log_error "Hub metrics not reachable at $hub_ip:$WEBHOOK_NODEPORT"
    failed=1
  else
    log "✓ Hub metrics is reachable at $hub_ip:$WEBHOOK_NODEPORT"
  fi
  
  # 3. Check Keycloak HTTP (used for OIDC by spoke clusters)
  log "Checking Keycloak at $keycloak_ip:8080..."
  if ! wait_for_port "$keycloak_ip" 8080 30 "Keycloak HTTP"; then
    log_error "Keycloak not reachable at $keycloak_ip:8080"
    failed=1
  else
    log "✓ Keycloak is reachable at $keycloak_ip:8080"
  fi
  
  # 4. Verify breakglass API actually responds (not just port open)
  log "Checking breakglass API health at http://$hub_ip:$API_NODEPORT/healthz..."
  if ! curl -sf --connect-timeout 5 "http://$hub_ip:$API_NODEPORT/healthz" >/dev/null 2>&1; then
    log_error "Breakglass API health check failed"
    failed=1
  else
    log "✓ Breakglass API health check passed"
  fi
  
  # 5. Verify Keycloak realm is accessible (OIDC discovery endpoint)
  log "Checking Keycloak OIDC discovery at http://$keycloak_ip:8080/realms/${KEYCLOAK_MAIN_REALM}/.well-known/openid-configuration..."
  if ! curl -sf --connect-timeout 5 "http://$keycloak_ip:8080/realms/${KEYCLOAK_MAIN_REALM}/.well-known/openid-configuration" >/dev/null 2>&1; then
    log_error "Keycloak OIDC discovery check failed for realm ${KEYCLOAK_MAIN_REALM}"
    failed=1
  else
    log "✓ Keycloak OIDC discovery accessible for realm ${KEYCLOAK_MAIN_REALM}"
  fi
  
  if [ "$failed" -ne 0 ]; then
    log_error "=============================================="
    log_error "PRE-FLIGHT FAILED: Hub services not ready"
    log_error "Spoke clusters WILL FAIL to start with current config"
    log_error "=============================================="
    return 1
  fi
  
  log "=============================================="
  log "PRE-FLIGHT PASSED: All hub services ready"
  log "=============================================="
  return 0
}

# Setup spoke cluster for hub connectivity
# This injects required hostnames and installs the CA bundle
setup_spoke_for_hub() {
  local spoke_name="$1"
  local spoke_kubeconfig="$2"
  
  log "Setting up spoke cluster $spoke_name for hub connectivity..."
  
  # Get hub IP from saved file
  local hub_ip
  if [ -f "$TDIR/hub-external-ip" ]; then
    hub_ip=$(cat "$TDIR/hub-external-ip")
  else
    log_error "Hub IP not available, cannot setup spoke connectivity"
    return 1
  fi
  
  # Inject hub service hostnames into spoke cluster's control plane node
  local spoke_node="${spoke_name}-control-plane"
  inject_hub_hostnames_into_spoke "$spoke_node" "$hub_ip" "$NAMESPACE"
  
  # Create namespace on spoke cluster
  ensure_namespace "$spoke_kubeconfig" "$NAMESPACE"
  
  # Create a ConfigMap with the hub CA bundle on spoke cluster
  # This allows spoke cluster pods to trust the hub's TLS certificates
  log "Installing hub CA bundle on $spoke_name..."
  KUBECONFIG="$spoke_kubeconfig" $KUBECTL create configmap breakglass-hub-ca \
    --from-file=ca.crt="$TLS_DIR/ca.crt" \
    -n "$NAMESPACE" \
    --dry-run=client -o yaml | KUBECONFIG="$spoke_kubeconfig" $KUBECTL apply -f -
  
  log "Spoke cluster $spoke_name is configured for hub connectivity"
}

# Verify spoke-to-hub connectivity
verify_spoke_connectivity() {
  local spoke_name="$1"
  local spoke_kubeconfig="$2"
  
  log "Verifying connectivity from $spoke_name to hub..."
  
  # Get hub IP and ports
  local hub_ip
  hub_ip=$(cat "$TDIR/hub-external-ip" 2>/dev/null || echo "")
  if [ -z "$hub_ip" ]; then
    log_error "Hub IP not found in $TDIR/hub-external-ip"
    return 1
  fi
  
  # Check cross-cluster connectivity using common library function
  if ! check_cross_cluster_connectivity "$spoke_kubeconfig" "$spoke_name" "$hub_ip" "$API_NODEPORT" "$WEBHOOK_NODEPORT"; then
    log_error "Cross-cluster connectivity check failed for $spoke_name"
    return 1
  fi
  
  # Also verify Keycloak reachability
  log "Checking hub Keycloak at $hub_ip:$KEYCLOAK_HTTP_NODEPORT..."
  if ! check_tcp_reachable "$hub_ip" "$KEYCLOAK_HTTP_NODEPORT" 5; then
    log_warn "Hub Keycloak not reachable at $hub_ip:$KEYCLOAK_HTTP_NODEPORT (may affect OIDC)"
  else
    log "Hub Keycloak is reachable"
  fi
  
  log "Connectivity verification complete for $spoke_name"
  return 0
}

# Extract kubeconfig for spoke cluster and modify for in-cluster access
get_spoke_kubeconfig_for_hub() {
  local cluster_name="$1"
  local output_file="$TDIR/${cluster_name}-hub-kubeconfig"
  
  # Get kubeconfig
  $KIND get kubeconfig --name "$cluster_name" > "$output_file"
  
  # Get the internal IP of the control plane node
  local control_plane_ip
  control_plane_ip=$(docker inspect "${cluster_name}-control-plane" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  
  # Replace server URL with internal IP
  sed -i.bak "s|server:.*|server: https://${control_plane_ip}:6443|" "$output_file"
  rm -f "${output_file}.bak"
  
  echo "$output_file"
}

# Create OIDC-only kubeconfig for a cluster (no client certificates)
# This is required for tests that use OIDC tokens for authentication.
# When using --token with a kubeconfig that has client certificates,
# Kubernetes authenticates using the client cert first (ignoring the token).
# This function creates a kubeconfig that only has cluster info (server, CA),
# forcing kubectl to use only the --token for authentication.
create_oidc_kubeconfig() {
  local cluster_name="$1"
  local admin_kubeconfig="$2"
  local output_file="$TDIR/${cluster_name}-oidc.kubeconfig"
  
  # Extract server URL and CA from admin kubeconfig
  local server_url
  server_url=$(KUBECONFIG="$admin_kubeconfig" $KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  
  # Get CA data (base64 encoded)
  local ca_data
  ca_data=$(KUBECONFIG="$admin_kubeconfig" $KUBECTL config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  
  # Create a clean kubeconfig with only cluster info, no user credentials
  cat > "$output_file" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${ca_data}
    server: ${server_url}
  name: ${cluster_name}
contexts:
- context:
    cluster: ${cluster_name}
    user: oidc-user
  name: ${cluster_name}
current-context: ${cluster_name}
users:
- name: oidc-user
  user: {}
EOF
  
  echo "$output_file"
}

# Create kubeconfig secrets on hub for spoke clusters
setup_kubeconfig_secrets() {
  log "Setting up kubeconfig secrets on hub..."
  
  for cluster in "$SPOKE_A_CLUSTER" "$SPOKE_B_CLUSTER"; do
    local kubeconfig_file=$(get_spoke_kubeconfig_for_hub "$cluster")
    local secret_name="${cluster}-kubeconfig"
    
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "$secret_name" \
      --namespace=breakglass-system \
      --from-file=value="$kubeconfig_file" \
      --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
    
    log "Created kubeconfig secret for $cluster"
  done
  
  # Also create self-referencing hub kubeconfig secret
  local hub_kubeconfig_file=$(get_spoke_kubeconfig_for_hub "$HUB_CLUSTER")
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "${HUB_CLUSTER}-kubeconfig" \
    --namespace=breakglass-system \
    --from-file=value="$hub_kubeconfig_file" \
    --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
}

# Apply multi-cluster test resources
apply_multi_cluster_resources() {
  log "Applying multi-cluster test resources..."
  
  # Get spoke cluster API server addresses (internal Docker network IPs)
  local spoke_a_ip spoke_b_ip
  spoke_a_ip=$(docker inspect ${SPOKE_A_CLUSTER}-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}' 2>/dev/null || echo "")
  spoke_b_ip=$(docker inspect ${SPOKE_B_CLUSTER}-control-plane --format '{{.NetworkSettings.Networks.kind.IPAddress}}' 2>/dev/null || echo "")
  
  if [ -z "$spoke_a_ip" ] || [ -z "$spoke_b_ip" ]; then
    log "ERROR: Could not get spoke cluster IPs"
    return 1
  fi
  
  local spoke_a_server="https://${spoke_a_ip}:6443"
  local spoke_b_server="https://${spoke_b_ip}:6443"
  log "Spoke-A API server: $spoke_a_server"
  log "Spoke-B API server: $spoke_b_server"
  
  # Get Keycloak issuer URL
  # CRITICAL: Use DNS name (e2e-keycloak) NOT IP address!
  # The spoke clusters' AuthenticationConfiguration expects tokens with issuer using DNS name.
  # The breakglass controller pod has hostAliases to resolve e2e-keycloak to the container IP.
  local issuer_url="https://${KEYCLOAK_CONTAINER_NAME}:${KEYCLOAK_PORT}/realms/${KEYCLOAK_MAIN_REALM}"
  log "OIDC issuer URL for ClusterConfigs: $issuer_url"
  
  # Read Keycloak CA certificate for OIDC issuer TLS validation
  local keycloak_ca_pem
  keycloak_ca_pem=$(cat "${TLS_DIR}/keycloak/ca.crt")
  log "Loaded Keycloak CA for ClusterConfig OIDC issuer TLS"
  
  # ============================================================================
  # CREATE CLIENT SECRET FOR OIDC AUTHENTICATION
  # ============================================================================
  # This secret is used by both spoke ClusterConfigs for OIDC client credentials flow.
  # The breakglass-group-sync client is configured in Keycloak with:
  # - Service accounts enabled (client credentials grant)
  # - Email claim: breakglass-group-sync@service.local
  # ============================================================================
  log "Creating group-sync client secret for OIDC ClusterConfigs..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: breakglass-group-sync-secret
  namespace: breakglass-system
type: Opaque
stringData:
  client-secret: breakglass-group-sync-secret
EOF

  # ============================================================================
  # CREATE CLUSTERCONFIGS
  # ============================================================================
  # Hub cluster: Uses kubeconfig auth (controller runs on hub)
  # Spoke clusters: Use OIDC auth to test full OIDC flow
  # ============================================================================
  log "Creating ClusterConfig resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Hub cluster configuration - uses kubeconfig (controller runs here)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${HUB_CLUSTER}
  namespace: breakglass-system
spec:
  clusterID: ${HUB_CLUSTER}
  tenant: "e2e-test"
  environment: "multi-cluster-e2e"
  kubeconfigSecretRef:
    name: ${HUB_CLUSTER}-kubeconfig
    namespace: breakglass-system
    key: value
---
# Spoke cluster A - uses OIDC auth to test cross-cluster OIDC authentication
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${SPOKE_A_CLUSTER}
  namespace: breakglass-system
spec:
  clusterID: ${SPOKE_A_CLUSTER}
  tenant: "e2e-test"
  environment: "multi-cluster-e2e"
  authType: OIDC
  oidcAuth:
    issuerURL: ${issuer_url}
    clientID: breakglass-group-sync
    server: ${spoke_a_server}
    clientSecretRef:
      name: breakglass-group-sync-secret
      namespace: breakglass-system
      key: client-secret
    certificateAuthority: |
$(echo "$keycloak_ca_pem" | sed 's/^/      /')
---
# Spoke cluster B - uses OIDC auth to test cross-cluster OIDC authentication
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${SPOKE_B_CLUSTER}
  namespace: breakglass-system
spec:
  clusterID: ${SPOKE_B_CLUSTER}
  tenant: "e2e-test"
  environment: "multi-cluster-e2e"
  authType: OIDC
  oidcAuth:
    issuerURL: ${issuer_url}
    clientID: breakglass-group-sync
    server: ${spoke_b_server}
    clientSecretRef:
      name: breakglass-group-sync-secret
      namespace: breakglass-system
      key: client-secret
    certificateAuthority: |
$(echo "$keycloak_ca_pem" | sed 's/^/      /')
EOF

  # Apply IdentityProviders (cluster-scoped) - pointing to real Keycloak
  log "Creating IdentityProvider resources..."
  local main_issuer_url contractors_issuer_url
  # Use HTTPS with port 8443 - CRD validation requires HTTPS for issuer/authority URLs
  main_issuer_url=$(get_keycloak_issuer_url "$KEYCLOAK_MAIN_REALM" "$KEYCLOAK_CONTAINER_NAME" "8443" "https")
  contractors_issuer_url=$(get_keycloak_issuer_url "$KEYCLOAK_CONTRACTORS_REALM" "$KEYCLOAK_CONTAINER_NAME" "8443" "https")
  
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: main-idp
  labels:
    e2e-test: "true"
spec:
  displayName: "Main IDP (Employees)"
  oidc:
    authority: "${main_issuer_url}"
    clientID: "breakglass"
    insecureSkipVerify: true
  issuer: "${main_issuer_url}"
  primary: true
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: "${main_issuer_url%/realms/*}"
    realm: "${KEYCLOAK_MAIN_REALM}"
    clientSecretRef:
      name: breakglass-group-sync-secret
      namespace: breakglass-system
      key: client-secret
    clientID: "breakglass-group-sync"
    insecureSkipVerify: true
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: contractors-idp
spec:
  displayName: "Contractors IDP"
  oidc:
    authority: "${contractors_issuer_url}"
    clientID: "breakglass-contractors"
    insecureSkipVerify: true
  issuer: "${contractors_issuer_url}"
EOF

  # Create MailProvider for email notification tests
  log "Creating MailProvider for MailHog..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: breakglass-mailhog
  namespace: breakglass-system
spec:
  displayName: "Development MailHog"
  default: true
  smtp:
    host: breakglass-mailhog.breakglass-system.svc.cluster.local
    port: 1025
    disableTLS: true
    insecureSkipVerify: true
  sender:
    address: noreply@breakglass.local
    name: "Breakglass Dev"
  retry:
    count: 3
    initialBackoffMs: 100
    queueSize: 1000
EOF

  # Wait for MailProvider to be ready
  log "Waiting for MailProvider to be ready..."
  for i in {1..30}; do
    mp_status=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get mailprovider breakglass-mailhog -n breakglass-system -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
    if [ "$mp_status" = "True" ]; then
      log "MailProvider is ready"
      break
    fi
    log "Waiting for MailProvider... ($i/30)"
    sleep 1
  done

  # Apply debug templates for CLI debug session tests
  local debug_templates_file="config/dev/resources/crs/debug-templates-test.yaml"
  if [ -f "$debug_templates_file" ]; then
    log "Applying debug session templates for e2e tests..."
    sed -e '/^  name:/s/name: /name: breakglass-/g' \
      "$debug_templates_file" | \
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f - || log "Warning: failed to apply debug templates"
  else
    log "Warning: debug templates file not found: $debug_templates_file"
  fi

  # Apply Escalations
  log "Creating BreakglassEscalation resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Global escalation - applies to all clusters (use "*" for global scope)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-global-readonly
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-read-only"
  clusterConfigRefs:
  - "*"
  maxValidFor: 2h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Hub-only escalation
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-hub-admin
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-emergency-admin"
  clusterConfigRefs:
  - ${HUB_CLUSTER}
  maxValidFor: 1h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Spoke A only escalation
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-a-pods
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-pods-admin"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  maxValidFor: 4h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Spoke B only escalation - for contractors
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-b-debugger
  namespace: breakglass-system
spec:
  escalatedGroup: "contractor-debugger"
  clusterConfigRefs:
  - ${SPOKE_B_CLUSTER}
  maxValidFor: 2h
  allowed:
    groups:
    - contractors
  approvers:
    groups:
    - vendor-supervisors
---
# Employee access escalation for spoke-a (used by multi-IDP tests)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-employee-access
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-employee-access"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  maxValidFor: 4h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Contractor access escalation for spoke-b (used by multi-IDP tests)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-contractor-access
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-contractor-access"
  clusterConfigRefs:
  - ${SPOKE_B_CLUSTER}
  maxValidFor: 4h
  allowed:
    groups:
    - contractors
  approvers:
    groups:
    - breakglass-approvers
    - vendor-supervisors
---
# Multi-cluster escalation (both spokes)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-clusters-admin
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-pods-admin"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  - ${SPOKE_B_CLUSTER}
  maxValidFor: 4h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Pods reader escalation (used by SpokeHubAuthorizationSuite tests)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-pods-reader
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-pods-reader"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  - ${SPOKE_B_CLUSTER}
  maxValidFor: 4h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Limited access escalation with DenyPolicy for secrets (used by SpokeHubAuthorizationSuite tests)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-limited-access
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-limited-access"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  - ${SPOKE_B_CLUSTER}
  maxValidFor: 4h
  denyPolicyRefs:
  - mc-deny-secrets-readonly
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
---
# Emergency admin escalation for spoke clusters (used by SpokeHubAuthorizationSuite tests)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-emergency-admin
  namespace: breakglass-system
spec:
  escalatedGroup: "breakglass-emergency-admin"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  - ${SPOKE_B_CLUSTER}
  maxValidFor: 1h
  allowed:
    groups:
    - breakglass-users
  approvers:
    groups:
    - breakglass-approvers
EOF

  # Apply DenyPolicies
  log "Creating DenyPolicy resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Policy blocking secrets access for read-only groups
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: mc-deny-secrets-readonly
  namespace: breakglass-system
spec:
  appliesTo:
    clusters:
    - ${HUB_CLUSTER}
    - ${SPOKE_A_CLUSTER}
    - ${SPOKE_B_CLUSTER}
  rules:
  - verbs: ["get", "list", "watch"]
    apiGroups: [""]
    resources: ["secrets"]
  precedence: 200
EOF

  log "Multi-cluster resources applied"
}

# Setup RBAC on spoke clusters for breakglass groups
setup_spoke_rbac() {
  local kubeconfig="$1"
  local cluster_name="$2"
  
  log "Setting up RBAC on $cluster_name..."
  
  # Create namespace for breakglass
  KUBECONFIG="$kubeconfig" $KUBECTL create namespace breakglass-system --dry-run=client -o yaml | \
    KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
  
  # Create breakglass-debug namespace for debug session workloads (used by DebugSessionTemplate targetNamespace)
  KUBECONFIG="$kubeconfig" $KUBECTL create namespace breakglass-debug --dry-run=client -o yaml | \
    KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
  log "Created breakglass-debug namespace on $cluster_name for debug session workloads"
  
  # ============================================================================
  # IMPERSONATION PERMISSIONS FOR OIDC SERVICE ACCOUNT
  # ============================================================================
  # The breakglass controller uses OIDC authentication to connect to spoke clusters
  # via ClusterConfig. The CanGroupsDo() function in group_checker.go impersonates
  # "system:auth-checker" with user groups to verify RBAC permissions.
  #
  # Without these permissions, the OIDC-authenticated service account cannot
  # impersonate users, and RBAC checks will fail with:
  #   "users \"system:auth-checker\" is forbidden: User \"breakglass-group-sync@service.local\"
  #    cannot impersonate resource \"users\""
  #
  # We grant impersonation for:
  # - users: system:auth-checker (the synthetic user for RBAC checks)
  # - groups: any group (to check if user's escalated groups have permissions)
  # ============================================================================
  cat <<EOF | KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-impersonator
rules:
# Allow impersonating the system:auth-checker user (used by CanGroupsDo for RBAC checks)
- apiGroups: [""]
  resources: ["users"]
  verbs: ["impersonate"]
  resourceNames: ["system:auth-checker"]
# Allow impersonating any group (needed to check escalated group permissions)
- apiGroups: [""]
  resources: ["groups"]
  verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-impersonator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-impersonator
subjects:
# Grant to the OIDC service account used by ClusterConfig
# The email claim "breakglass-group-sync@service.local" becomes the username
- kind: User
  name: "breakglass-group-sync@service.local"
  apiGroup: rbac.authorization.k8s.io
---
# ============================================================================
# NAMESPACE READER PERMISSIONS FOR OIDC SERVICE ACCOUNT
# ============================================================================
# The breakglass webhook needs to fetch namespace labels for DenyPolicy evaluation.
# Without these permissions, the namespace GET request would trigger the authorization
# webhook recursively (since the OIDC user doesn't have RBAC permissions), causing
# timeouts. By granting namespace read via RBAC, the request is allowed by RBAC
# directly and the webhook is never consulted (RBAC runs before the webhook).
# ============================================================================
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-namespace-reader
rules:
# Allow reading namespaces for DenyPolicy namespace selector evaluation
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-namespace-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-namespace-reader
subjects:
# Grant to the OIDC service account used by ClusterConfig
- kind: User
  name: "breakglass-group-sync@service.local"
  apiGroup: rbac.authorization.k8s.io
---
# ============================================================================
# DEBUG SESSION WORKLOAD MANAGER PERMISSIONS FOR OIDC SERVICE ACCOUNT
# ============================================================================
# The breakglass manager needs to deploy debug session workloads (pods, daemonsets,
# deployments) on spoke clusters. Without these permissions, the manager cannot
# create/manage the debug session resources and sessions will fail with forbidden errors.
# ============================================================================
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-workload-manager
rules:
# Allow managing pods for debug sessions
- apiGroups: [""]
  resources: ["pods", "pods/exec", "pods/log", "pods/portforward"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Allow managing services for debug sessions
- apiGroups: [""]
  resources: ["services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Allow reading nodes for kubectl debug node functionality (node label validation)
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
# Allow managing deployments and daemonsets for debug session workloads
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Allow creating events for debug session status reporting
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-workload-manager-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-workload-manager
subjects:
# Grant to the OIDC service account used by ClusterConfig
- kind: User
  name: "breakglass-group-sync@service.local"
  apiGroup: rbac.authorization.k8s.io
EOF
  log "Created impersonation RBAC for OIDC service account on $cluster_name"
  log "Created namespace-reader RBAC for OIDC service account on $cluster_name"
  log "Created workload-manager RBAC for OIDC service account on $cluster_name"
  
  # Create ClusterRole for breakglass groups
  cat <<EOF | KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-pods-admin
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "pods/exec", "pods/portforward"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["namespaces", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-emergency-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-read-only
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: contractor-debugger
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
# ClusterRole for breakglass-employee-access (used by multi-IDP tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-employee-access
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "pods/exec", "pods/portforward"]
  verbs: ["*"]
- apiGroups: [""]
  resources: ["namespaces", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
---
# ClusterRole for breakglass-contractor-access (used by multi-IDP tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-contractor-access
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: team-alpha-ns-admin
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]
---
# ClusterRole for complete-flow-test-admins (used by TestCompleteBreakglassFlow)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: complete-flow-test-admins
rules:
- apiGroups: [""]
  resources: ["configmaps", "pods", "services", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
# ClusterRole for breakglass-pods-reader (used by SpokeHubAuthorizationSuite tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-pods-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["namespaces", "services"]
  verbs: ["get", "list", "watch"]
---
# ClusterRole for breakglass-limited-access (used by SpokeHubAuthorizationSuite tests)
# This role has permissions for pods but INTENTIONALLY NO SECRETS permission.
# The breakglass webhook will grant access (user has session), but the DenyPolicy
# attached to the escalation will block secrets access.
#
# IMPORTANT: If we included secrets here, RBAC would allow it BEFORE the webhook
# is consulted, and the DenyPolicy would never be evaluated!
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-limited-access
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["namespaces", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
# NOTE: secrets are INTENTIONALLY NOT included here - the DenyPolicy blocks them via webhook
---
# ClusterRoleBindings - bind groups to their respective ClusterRoles
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-pods-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-pods-admin
subjects:
- kind: Group
  name: breakglass-pods-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-emergency-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-emergency-admin
subjects:
- kind: Group
  name: breakglass-emergency-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-read-only-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-read-only
subjects:
- kind: Group
  name: breakglass-read-only
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: contractor-debugger-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: contractor-debugger
subjects:
- kind: Group
  name: contractor-debugger
  apiGroup: rbac.authorization.k8s.io
---
# ClusterRoleBinding for breakglass-employee-access (used by multi-IDP tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-employee-access-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-employee-access
subjects:
- kind: Group
  name: breakglass-employee-access
  apiGroup: rbac.authorization.k8s.io
---
# ClusterRoleBinding for breakglass-contractor-access (used by multi-IDP tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-contractor-access-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-contractor-access
subjects:
- kind: Group
  name: breakglass-contractor-access
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: team-alpha-ns-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: team-alpha-ns-admin
subjects:
- kind: Group
  name: team-alpha-ns-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: complete-flow-test-admins-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: complete-flow-test-admins
subjects:
- kind: Group
  name: complete-flow-test-admins
  apiGroup: rbac.authorization.k8s.io
---
# ClusterRoleBinding for breakglass-pods-reader (used by SpokeHubAuthorizationSuite tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-pods-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-pods-reader
subjects:
- kind: Group
  name: breakglass-pods-reader
  apiGroup: rbac.authorization.k8s.io
---
# ClusterRoleBinding for breakglass-limited-access (used by SpokeHubAuthorizationSuite tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-limited-access-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-limited-access
subjects:
- kind: Group
  name: breakglass-limited-access
  apiGroup: rbac.authorization.k8s.io
---
# ClusterRole for breakglass-multi-cluster-ops (used by TestDenyPolicyBlocksSpecificAPIGroups and other tests)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-multi-cluster-ops
rules:
- apiGroups: [""]
  resources: ["pods", "services", "persistentvolumes", "persistentvolumeclaims"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "statefulsets"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-multi-cluster-ops-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-multi-cluster-ops
subjects:
- kind: Group
  name: breakglass-multi-cluster-ops
  apiGroup: rbac.authorization.k8s.io
EOF

  log "RBAC setup complete on $cluster_name"
}

# Print environment summary
print_summary() {
  local hub_ip
  local hub_webhook_url
  local hub_api_url
  local keycloak_ip
  local keycloak_main_url
  local keycloak_contractors_url
  
  # Read saved URLs
  if [ -f "$TDIR/hub-external-ip" ]; then
    hub_ip=$(cat "$TDIR/hub-external-ip")
  else
    hub_ip="(unknown)"
  fi
  if [ -f "$TDIR/hub-webhook-url" ]; then
    hub_webhook_url=$(cat "$TDIR/hub-webhook-url")
  else
    hub_webhook_url="(unknown)"
  fi
  if [ -f "$TDIR/hub-api-url" ]; then
    hub_api_url=$(cat "$TDIR/hub-api-url")
  else
    hub_api_url="(unknown)"
  fi
  
  # Get Keycloak container IP
  keycloak_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$KEYCLOAK_CONTAINER_NAME" 2>/dev/null || echo "(unknown)")
  # Use HTTPS with port 8443 - CRD validation requires HTTPS for issuer/authority URLs
  keycloak_main_url=$(get_keycloak_issuer_url "$KEYCLOAK_MAIN_REALM" "$KEYCLOAK_CONTAINER_NAME" "8443" "https")
  keycloak_contractors_url=$(get_keycloak_issuer_url "$KEYCLOAK_CONTRACTORS_REALM" "$KEYCLOAK_CONTAINER_NAME" "8443" "https")
  
  log "=================================================="
  log "Multi-cluster E2E environment ready!"
  log "=================================================="
  log ""
  log "Clusters:"
  log "  Hub:      $HUB_CLUSTER"
  log "  Spoke A:  $SPOKE_A_CLUSTER"
  log "  Spoke B:  $SPOKE_B_CLUSTER"
  log ""
  log "Hub External Access (for spoke clusters):"
  log "  Hub IP:       $hub_ip"
  log "  Webhook URL:  $hub_webhook_url"
  log "  API URL:      $hub_api_url"
  log ""
  log "Keycloak (standalone container):"
  log "  Container:    $KEYCLOAK_CONTAINER_NAME"
  log "  IP:           $keycloak_ip"
  log "  Main realm:   $keycloak_main_url"
  log "  Contractors:  $keycloak_contractors_url"
  log ""
  log "Kubeconfigs:"
  log "  Hub:      export KUBECONFIG=$HUB_KUBECONFIG"
  log "  Spoke A:  export KUBECONFIG=$SPOKE_A_KUBECONFIG"
  log "  Spoke B:  export KUBECONFIG=$SPOKE_B_KUBECONFIG"
  log ""
  log "Environment variables for tests:"
  log "  export E2E_HUB_KUBECONFIG=$HUB_KUBECONFIG"
  log "  export E2E_SPOKE_A_KUBECONFIG=$SPOKE_A_KUBECONFIG"
  log "  export E2E_SPOKE_B_KUBECONFIG=$SPOKE_B_KUBECONFIG"
  log "  export E2E_MULTI_CLUSTER=true"
  log "  export E2E_HUB_EXTERNAL_IP=$hub_ip"
  log "  export E2E_HUB_WEBHOOK_URL=$hub_webhook_url"
  log "  export E2E_HUB_API_URL=$hub_api_url"
  log "  export KEYCLOAK_URL=https://localhost:8443"
  log "  export KEYCLOAK_HOST=https://localhost:8443"
  log "  export KEYCLOAK_PORT=8443"
  log ""
  log "To run multi-cluster tests:"
  log "  go test ./e2e/api/... -v -tags=multicluster -timeout=30m"
  log ""
  log "To tear down:"
  log "  $KIND delete cluster --name $HUB_CLUSTER"
  log "  $KIND delete cluster --name $SPOKE_A_CLUSTER"
  log "  $KIND delete cluster --name $SPOKE_B_CLUSTER"
  log "  docker rm -f $KEYCLOAK_CONTAINER_NAME"
  log "=================================================="
  
  # Export environment variables
  # Note: KEYCLOAK_HOST uses localhost:8443 because Go tests run on the host
  # The container name (e2e-keycloak) is only resolvable inside Kind nodes via /etc/hosts
  # KEYCLOAK_ISSUER_HOST is passed as Host header to Keycloak so token issuer matches IdentityProvider
  
  # Extract K8s API server URLs from kubeconfigs (for test runner access via localhost)
  local hub_api_server spoke_a_api_server spoke_b_api_server
  hub_api_server=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  spoke_a_api_server=$(KUBECONFIG="$SPOKE_A_KUBECONFIG" $KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  spoke_b_api_server=$(KUBECONFIG="$SPOKE_B_KUBECONFIG" $KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  
  # Get Docker container IPs for internal access (from controller pod in hub cluster)
  # These are needed for OIDC ClusterConfig tests where controller validates cluster reachability
  local hub_container_ip spoke_a_container_ip spoke_b_container_ip
  hub_container_ip=$(docker inspect "${HUB_CLUSTER}-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  spoke_a_container_ip=$(docker inspect "${SPOKE_A_CLUSTER}-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  spoke_b_container_ip=$(docker inspect "${SPOKE_B_CLUSTER}-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  
  cat > "$TDIR/env.sh" <<EOF
export E2E_HUB_KUBECONFIG=$HUB_KUBECONFIG
export E2E_SPOKE_A_KUBECONFIG=$SPOKE_A_KUBECONFIG
export E2E_SPOKE_B_KUBECONFIG=$SPOKE_B_KUBECONFIG
export E2E_SPOKE_A_OIDC_KUBECONFIG=$SPOKE_A_OIDC_KUBECONFIG
export E2E_SPOKE_B_OIDC_KUBECONFIG=$SPOKE_B_OIDC_KUBECONFIG
export E2E_MULTI_CLUSTER=true
export KEYCLOAK_CONTAINER_NAME=$KEYCLOAK_CONTAINER_NAME
export KEYCLOAK_URL=https://localhost:8443
export KEYCLOAK_HOST=https://localhost:8443
export KEYCLOAK_PORT=8443
export KEYCLOAK_MAIN_REALM=$KEYCLOAK_MAIN_REALM
export KEYCLOAK_CONTRACTORS_REALM=$KEYCLOAK_CONTRACTORS_REALM
export KEYCLOAK_CLIENT_ID=breakglass-ui
export KEYCLOAK_ISSUER_HOST=${KEYCLOAK_CONTAINER_NAME}:8443
export E2E_HUB_EXTERNAL_IP=$hub_ip
export E2E_HUB_WEBHOOK_URL=$hub_webhook_url
export E2E_HUB_API_URL=$hub_api_url
export KEYCLOAK_CA_FILE=${TLS_DIR}/keycloak/ca.crt
export KEYCLOAK_INTERNAL_URL=https://${KEYCLOAK_CONTAINER_NAME}:8443
export TLS_DIR=$TLS_DIR
# K8s API server URLs for OIDC tests
# External URLs (localhost) for test runner access
export KUBERNETES_API_SERVER=$hub_api_server
export E2E_HUB_API_SERVER=$hub_api_server
export E2E_SPOKE_A_API_SERVER=$spoke_a_api_server
export E2E_SPOKE_B_API_SERVER=$spoke_b_api_server
# Internal URLs (container IPs) for controller pod access
# Use these for ClusterConfig.Server when controller needs to reach spoke clusters
# KUBERNETES_API_SERVER_INTERNAL is for hub (consistency with single-cluster setup)
export KUBERNETES_API_SERVER_INTERNAL=https://${hub_container_ip}:6443
export E2E_HUB_API_SERVER_INTERNAL=https://${hub_container_ip}:6443
export E2E_SPOKE_A_API_SERVER_INTERNAL=https://${spoke_a_container_ip}:6443
export E2E_SPOKE_B_API_SERVER_INTERNAL=https://${spoke_b_container_ip}:6443
EOF
  log "Environment file written to: $TDIR/env.sh"
  log "  source $TDIR/env.sh"
}

# Track script failure state
SCRIPT_FAILED=false

# Cleanup function
cleanup() {
  # Skip cleanup if PRESERVE_ON_FAILURE is set - we want to preserve resources for tests
  # that run after this script completes (not just on failure)
  if [ "${PRESERVE_ON_FAILURE:-false}" = "true" ]; then
    log "PRESERVE_ON_FAILURE=true - skipping cleanup to preserve environment for tests"
    log "WARNING: Resources (Keycloak container, clusters) are still running!"
    log "To clean up manually, run: docker rm -f e2e-keycloak; kind delete cluster --name breakglass-hub; kind delete cluster --name spoke-cluster-a; kind delete cluster --name spoke-cluster-b"
    return 0
  fi
  
  log "Cleaning up..."
  kill_port_forwards "$PF_FILE"
  # Stop Keycloak container
  stop_keycloak_container || true
}

# Setup standalone Keycloak container
setup_keycloak() {
  log "Setting up standalone Keycloak container..."
  
  # Generate TLS for Keycloak
  local keycloak_tls_dir="$TLS_DIR/keycloak"
  if ! generate_keycloak_container_tls "$keycloak_tls_dir"; then
    log_error "Failed to generate Keycloak TLS certificates"
    return 1
  fi
  
  # Verify TLS files exist before attempting to start container
  if [ ! -f "$keycloak_tls_dir/tls.crt" ] || [ ! -f "$keycloak_tls_dir/tls.key" ]; then
    log_error "TLS files missing after generation:"
    log "  Expected cert: $keycloak_tls_dir/tls.crt (exists: $([ -f "$keycloak_tls_dir/tls.crt" ] && echo yes || echo no))"
    log "  Expected key: $keycloak_tls_dir/tls.key (exists: $([ -f "$keycloak_tls_dir/tls.key" ] && echo yes || echo no))"
    log "Directory listing:"
    ls -la "$keycloak_tls_dir" || true
    return 1
  fi
  
  log "TLS certificates verified, starting Keycloak container..."
  
  # Use the shared realm JSON files - same as single-cluster setup
  # SCRIPT_DIR is e2e/, so we go up one level to reach repo root
  local realm_json="$SCRIPT_DIR/../config/dev/resources/breakglass-e2e-realm.json"
  local contractors_realm_json="$SCRIPT_DIR/../config/dev/resources/breakglass-e2e-contractors-realm.json"
  
  if [ ! -f "$realm_json" ]; then
    log_error "Main realm JSON file not found at: $realm_json"
    return 1
  fi
  if [ ! -f "$contractors_realm_json" ]; then
    log_error "Contractors realm JSON file not found at: $contractors_realm_json"
    return 1
  fi
  log "Using realm JSON files:"
  log "  Main realm: $realm_json"
  log "  Contractors realm: $contractors_realm_json"
  
  # Start Keycloak container on the kind network with both realm imports
  # Note: We ignore stdout from start_keycloak_container because various commands
  # may pollute it (docker network create, diagnostic output, etc.)
  # Instead, we use get_keycloak_ip which uses docker inspect for reliable IP extraction
  if ! start_keycloak_container "$keycloak_tls_dir" "kind" "$realm_json" "$contractors_realm_json" >/dev/null; then
    log_error "Failed to start Keycloak container"
    return 1
  fi
  
  # Get Keycloak IP reliably via docker inspect (immune to stdout pollution)
  KEYCLOAK_IP=$(get_keycloak_ip)
  if [ -z "$KEYCLOAK_IP" ]; then
    log_error "Failed to get Keycloak container IP via docker inspect"
    return 1
  fi
  log "Keycloak container IP (via docker inspect): $KEYCLOAK_IP"
  
  # Save Keycloak IP for later use
  echo "$KEYCLOAK_IP" > "$TDIR/keycloak-ip"
  
  # Both realms are imported via --import-realm from the JSON files.
  # No manual user/group configuration needed.
  
  log "Keycloak setup complete at http://$KEYCLOAK_IP:8080"
}

# Inject Keycloak into all clusters
inject_keycloak_into_clusters() {
  log "Injecting Keycloak hostname into all clusters..."
  
  local keycloak_ip
  keycloak_ip=$(cat "$TDIR/keycloak-ip" 2>/dev/null || get_keycloak_ip)
  
  if [ -z "$keycloak_ip" ]; then
    log_error "Keycloak IP not available"
    return 1
  fi
  
  # Inject into all cluster nodes
  inject_keycloak_host_into_cluster "$HUB_CLUSTER" "$keycloak_ip"
  inject_keycloak_host_into_cluster "$SPOKE_A_CLUSTER" "$keycloak_ip"
  inject_keycloak_host_into_cluster "$SPOKE_B_CLUSTER" "$keycloak_ip"
  
  # Inject CA into all clusters
  local keycloak_ca="$TLS_DIR/keycloak/ca.crt"
  if [ -f "$keycloak_ca" ]; then
    inject_keycloak_ca_into_cluster "$HUB_KUBECONFIG" "$NAMESPACE" "$keycloak_ca"
    inject_keycloak_ca_into_cluster "$SPOKE_A_KUBECONFIG" "$NAMESPACE" "$keycloak_ca"
    inject_keycloak_ca_into_cluster "$SPOKE_B_KUBECONFIG" "$NAMESPACE" "$keycloak_ca"
  fi
  
  log "Keycloak injection complete"
}

# Main function
main() {
  # Set up traps for cleanup and error tracking
  trap cleanup EXIT
  trap 'SCRIPT_FAILED=true' ERR
  set -E  # Ensure ERR trap is inherited by functions
  
  log "Starting multi-cluster E2E setup..."
  
  # Run prerequisite checks
  run_prerequisite_checks || exit 1
  
  # Initialize directories
  init_temp_dirs
  
  # Start standalone Keycloak container FIRST (before clusters)
  setup_keycloak
  
  # Create all clusters (hub with breakglass, then spokes)
  # NOTE: setup_hub_cluster is now called inside create_clusters to ensure
  # breakglass is running before spoke clusters are created.
  create_clusters
  
  # Preload images to all clusters (hub + spokes) - avoids image pull delays
  # NOTE: Breakglass image is already loaded on hub during create_clusters
  preload_images_all_clusters
  
  # Inject Keycloak hostname into all clusters
  inject_keycloak_into_clusters

  # Setup spoke clusters for hub connectivity (hostnames, CA bundles)
  setup_spoke_for_hub "$SPOKE_A_CLUSTER" "$SPOKE_A_KUBECONFIG"
  setup_spoke_for_hub "$SPOKE_B_CLUSTER" "$SPOKE_B_KUBECONFIG"
  
  # Verify spoke-to-hub connectivity (MUST pass - fail fast if connectivity is broken)
  log "Verifying spoke-to-hub connectivity..."
  if ! verify_spoke_connectivity "$SPOKE_A_CLUSTER" "$SPOKE_A_KUBECONFIG"; then
    log_error "Spoke A connectivity check FAILED - cannot proceed"
    exit 1
  fi
  if ! verify_spoke_connectivity "$SPOKE_B_CLUSTER" "$SPOKE_B_KUBECONFIG"; then
    log_error "Spoke B connectivity check FAILED - cannot proceed"
    exit 1
  fi
  log "All spoke-to-hub connectivity checks passed"
  
  # Setup kubeconfig secrets
  setup_kubeconfig_secrets
  
  # Setup RBAC on spoke clusters
  setup_spoke_rbac "$SPOKE_A_KUBECONFIG" "$SPOKE_A_CLUSTER"
  setup_spoke_rbac "$SPOKE_B_KUBECONFIG" "$SPOKE_B_CLUSTER"
  
  # Apply multi-cluster resources (includes IdentityProviders pointing to real Keycloak)
  apply_multi_cluster_resources
  
  # Start port-forward for MailHog (for notification tests)
  log "Setting up MailHog port-forward..."
  MH_SVC_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  MH_SVC_NS=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc --all-namespaces -l app=mailhog -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
  if [ -n "$MH_SVC_NAME" ] && [ -n "$MH_SVC_NS" ]; then
    start_port_forward "$HUB_KUBECONFIG" "$MH_SVC_NS" "$MH_SVC_NAME" "${MAILHOG_UI_PORT}" 8025 "$PF_FILE" >/dev/null 2>&1 || true
    log "MailHog UI available at http://localhost:${MAILHOG_UI_PORT} (svc: $MH_SVC_NAME ns: $MH_SVC_NS)"
  else
    log "MailHog service not found for port-forward; skipping"
  fi

  # Start port-forward for metrics endpoint (for metrics tests)
  # The controller exposes Prometheus metrics on port 8081
  # Use a fixed local port (8181) for consistency with Go test defaults
  METRICS_FORWARD_PORT=${METRICS_FORWARD_PORT:-8181}
  log "Setting up metrics port-forward on port: $METRICS_FORWARD_PORT..."
  BG_SVC_NAME=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get svc -n breakglass-system -l app.kubernetes.io/name=breakglass -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "breakglass-manager")
  if [ -n "$BG_SVC_NAME" ]; then
    start_port_forward "$HUB_KUBECONFIG" "breakglass-system" "$BG_SVC_NAME" "${METRICS_FORWARD_PORT}" 8081 "$PF_FILE" >/dev/null 2>&1 || true
    sleep 2
    if curl -s "http://localhost:${METRICS_FORWARD_PORT}/metrics" | grep -q "breakglass_"; then
      log "Controller metrics endpoint ready at http://localhost:${METRICS_FORWARD_PORT}/metrics"
    else
      log "Warning: Controller metrics not yet accessible on port ${METRICS_FORWARD_PORT}; may take a moment"
    fi
  else
    log "Breakglass manager service not found for metrics port-forward; skipping"
  fi

  # Print summary
  print_summary
}

main "$@"
