#!/usr/bin/env bash
set -euo pipefail
# Multi-cluster E2E setup: 1 hub + 2 spoke clusters with full OIDC authentication.
# This script creates a true hub-and-spoke topology where:
# - Hub cluster runs the Breakglass controller, API, webhooks, Keycloak, and MailHog
# - Spoke clusters are registered via ClusterConfig and use the hub for webhook authorization
# - Multiple OIDC realms support different user populations (employees vs contractors)

# --- Script directory and common library ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:23.0.0}

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

# --- Keycloak settings ---
KEYCLOAK_HOST=${KEYCLOAK_HOST:-breakglass-dev-keycloak.breakglass-dev-system.svc.cluster.local}
KEYCLOAK_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT:-8443}
KEYCLOAK_MAIN_REALM=${KEYCLOAK_MAIN_REALM:-breakglass-e2e}
KEYCLOAK_CONTRACTORS_REALM=${KEYCLOAK_CONTRACTORS_REALM:-breakglass-e2e-contractors}

# --- Breakglass namespace ---
NAMESPACE=${NAMESPACE:-breakglass-dev-system}

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

# Create Kind cluster configuration
create_kind_config() {
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
  extraPortMappings:
  - containerPort: 30080
    hostPort: 0
    protocol: TCP
EOF
  echo "$config_file"
}

# Create all three clusters
create_clusters() {
  log "Creating hub cluster: $HUB_CLUSTER"
  local hub_config=$(create_kind_config "$HUB_CLUSTER")
  $KIND create cluster --name "$HUB_CLUSTER" --config "$hub_config" --wait 120s
  HUB_KUBECONFIG="$TDIR/${HUB_CLUSTER}.kubeconfig"
  $KIND get kubeconfig --name "$HUB_CLUSTER" > "$HUB_KUBECONFIG"
  
  log "Creating spoke cluster A: $SPOKE_A_CLUSTER"
  local spoke_a_config=$(create_kind_config "$SPOKE_A_CLUSTER")
  $KIND create cluster --name "$SPOKE_A_CLUSTER" --config "$spoke_a_config" --wait 120s
  SPOKE_A_KUBECONFIG="$TDIR/${SPOKE_A_CLUSTER}.kubeconfig"
  $KIND get kubeconfig --name "$SPOKE_A_CLUSTER" > "$SPOKE_A_KUBECONFIG"
  
  log "Creating spoke cluster B: $SPOKE_B_CLUSTER"
  local spoke_b_config=$(create_kind_config "$SPOKE_B_CLUSTER")
  $KIND create cluster --name "$SPOKE_B_CLUSTER" --config "$spoke_b_config" --wait 120s
  SPOKE_B_KUBECONFIG="$TDIR/${SPOKE_B_CLUSTER}.kubeconfig"
  $KIND get kubeconfig --name "$SPOKE_B_CLUSTER" > "$SPOKE_B_KUBECONFIG"
  
  log "All clusters created successfully"
}

# Load Docker image into cluster (use common library function)
load_image_into_cluster() {
  local cluster_name="$1"
  local image="$2"
  e2e_load_image_into_kind "$cluster_name" "$image"
}

# Wait for deployment to be ready (use common library function)
wait_for_deploy_by_label() {
  local kubeconfig="$1"
  local label="$2"
  local max_attempts=${3:-120}
  e2e_wait_for_deployment_by_label "$kubeconfig" "$label" "$max_attempts"
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
  
  # Load required images to hub cluster (no Keycloak - it's standalone)
  log "Loading images into hub cluster..."
  load_image_into_cluster "$HUB_CLUSTER" "$IMAGE"
  load_image_into_cluster "$HUB_CLUSTER" "mailhog/mailhog:v1.0.1"
  load_image_into_cluster "$HUB_CLUSTER" "curlimages/curl:8.4.0"
  load_image_into_cluster "$HUB_CLUSTER" "nicolaka/netshoot"
  load_image_into_cluster "$HUB_CLUSTER" "apache/kafka:3.7.0"
  
  # Apply CRDs
  log "Applying CRDs..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f config/crd/bases/
  
  # Create namespace
  log "Creating namespace..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create namespace breakglass-dev-system --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
  
  # Create TLS secret for webhook
  log "Creating TLS secret..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret tls breakglass-dev-webhook-server-cert \
    --cert="$TLS_DIR/tls.crt" \
    --key="$TLS_DIR/tls.key" \
    -n breakglass-dev-system \
    --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
  
  # Deploy using kustomize (this will deploy Keycloak in-cluster, we'll delete it)
  log "Deploying Breakglass controller..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build config/dev | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply --server-side --force-conflicts -f -
  
  # Remove in-cluster Keycloak since we're using standalone container
  log "Removing in-cluster Keycloak (using standalone container instead)..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL delete deployment -n breakglass-dev-system -l app=keycloak --ignore-not-found=true || true
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL delete service -n breakglass-dev-system -l app=keycloak --ignore-not-found=true || true
  
  # Wait for remaining deployments
  wait_for_deploy_by_label "$HUB_KUBECONFIG" "mailhog" 60
  wait_for_deploy_by_label "$HUB_KUBECONFIG" "breakglass" 120
  
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
  
  # Create NodePort service for breakglass API and webhook
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: v1
kind: Service
metadata:
  name: breakglass-external
  namespace: breakglass-dev-system
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
  - name: webhook
    port: 8081
    targetPort: 8081
    nodePort: ${WEBHOOK_NODEPORT}
---
# Expose Keycloak for spoke cluster OIDC validation
apiVersion: v1
kind: Service
metadata:
  name: keycloak-external
  namespace: breakglass-dev-system
  labels:
    app: keycloak
spec:
  type: NodePort
  selector:
    app: keycloak
  ports:
  - name: https
    port: 8443
    targetPort: 8443
    nodePort: 31443
  - name: http
    port: 8080
    targetPort: 8080
    nodePort: 31880
EOF

  # Set the external URLs that spoke clusters will use
  HUB_WEBHOOK_URL="https://${HUB_EXTERNAL_IP}:${WEBHOOK_NODEPORT}"
  HUB_API_URL="http://${HUB_EXTERNAL_IP}:${API_NODEPORT}"
  HUB_KEYCLOAK_URL="http://${HUB_EXTERNAL_IP}:31880"
  
  log "Hub webhook URL for spoke clusters: $HUB_WEBHOOK_URL"
  log "Hub API URL for spoke clusters: $HUB_API_URL"
  log "Hub Keycloak URL for spoke clusters: $HUB_KEYCLOAK_URL"
  
  # Store URLs in temp dir for reference
  echo "$HUB_WEBHOOK_URL" > "$TDIR/hub-webhook-url"
  echo "$HUB_API_URL" > "$TDIR/hub-api-url"
  echo "$HUB_KEYCLOAK_URL" > "$TDIR/hub-keycloak-url"
  echo "$HUB_EXTERNAL_IP" > "$TDIR/hub-external-ip"
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

# Create kubeconfig secrets on hub for spoke clusters
setup_kubeconfig_secrets() {
  log "Setting up kubeconfig secrets on hub..."
  
  for cluster in "$SPOKE_A_CLUSTER" "$SPOKE_B_CLUSTER"; do
    local kubeconfig_file=$(get_spoke_kubeconfig_for_hub "$cluster")
    local secret_name="${cluster}-kubeconfig"
    
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "$secret_name" \
      --namespace=breakglass-dev-system \
      --from-file=value="$kubeconfig_file" \
      --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
    
    log "Created kubeconfig secret for $cluster"
  done
  
  # Also create self-referencing hub kubeconfig secret
  local hub_kubeconfig_file=$(get_spoke_kubeconfig_for_hub "$HUB_CLUSTER")
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL create secret generic "${HUB_CLUSTER}-kubeconfig" \
    --namespace=breakglass-dev-system \
    --from-file=value="$hub_kubeconfig_file" \
    --dry-run=client -o yaml | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
}

# Apply multi-cluster test resources
apply_multi_cluster_resources() {
  log "Applying multi-cluster test resources..."
  
  # Create ClusterConfigs with the correct webhook URLs
  # Hub can use internal service URL, spokes need external URL
  local hub_internal_webhook="https://breakglass-dev-webhook-service.breakglass-dev-system.svc.cluster.local:8081"
  
  log "Creating ClusterConfig resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Hub cluster configuration - uses internal service URL
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${HUB_CLUSTER}
  namespace: breakglass-dev-system
spec:
  clusterID: ${HUB_CLUSTER}
  tenant: "e2e-test"
  environment: "multi-cluster-e2e"
  kubeconfigSecretRef:
    name: ${HUB_CLUSTER}-kubeconfig
    namespace: breakglass-dev-system
    key: value
---
# Spoke cluster A - uses external webhook URL to reach hub
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${SPOKE_A_CLUSTER}
  namespace: breakglass-dev-system
spec:
  clusterID: ${SPOKE_A_CLUSTER}
  tenant: "e2e-test"
  environment: "multi-cluster-e2e"
  kubeconfigSecretRef:
    name: ${SPOKE_A_CLUSTER}-kubeconfig
    namespace: breakglass-dev-system
    key: value
---
# Spoke cluster B - uses external webhook URL to reach hub
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: ${SPOKE_B_CLUSTER}
  namespace: breakglass-dev-system
spec:
  clusterID: ${SPOKE_B_CLUSTER}
  tenant: "e2e-test"
  environment: "multi-cluster-e2e"
  kubeconfigSecretRef:
    name: ${SPOKE_B_CLUSTER}-kubeconfig
    namespace: breakglass-dev-system
    key: value
EOF

  # Apply IdentityProviders (cluster-scoped) - pointing to real Keycloak
  log "Creating IdentityProvider resources..."
  local main_issuer_url contractors_issuer_url
  main_issuer_url=$(get_keycloak_issuer_url "$KEYCLOAK_MAIN_REALM" "$KEYCLOAK_CONTAINER_NAME" "8080" "http")
  contractors_issuer_url=$(get_keycloak_issuer_url "$KEYCLOAK_CONTRACTORS_REALM" "$KEYCLOAK_CONTAINER_NAME" "8080" "http")
  
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: main-idp
spec:
  displayName: "Main IDP (Employees)"
  oidc:
    authority: "${main_issuer_url}"
    clientID: "breakglass"
    insecureSkipVerify: true
  issuer: "${main_issuer_url}"
  primary: true
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

  # Apply Escalations
  log "Creating BreakglassEscalation resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Global escalation - applies to all clusters
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-global-readonly
  namespace: breakglass-dev-system
spec:
  escalatedGroup: "breakglass-read-only"
  clusterConfigRefs: []
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
  namespace: breakglass-dev-system
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
  namespace: breakglass-dev-system
spec:
  escalatedGroup: "breakglass-pods-admin"
  clusterConfigRefs:
  - ${SPOKE_A_CLUSTER}
  maxValidFor: 4h
  allowed:
    groups:
    - breakglass-users
---
# Spoke B only escalation - for contractors
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-b-debugger
  namespace: breakglass-dev-system
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
# Multi-cluster escalation (both spokes)
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: mc-spoke-clusters-admin
  namespace: breakglass-dev-system
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
EOF

  # Apply DenyPolicies
  log "Creating DenyPolicy resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
# Policy blocking secrets access for read-only groups
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: mc-deny-secrets-readonly
  namespace: breakglass-dev-system
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
  KUBECONFIG="$kubeconfig" $KUBECTL create namespace breakglass-dev-system --dry-run=client -o yaml | \
    KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
  
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
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: team-alpha-ns-admin
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]
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
  keycloak_main_url=$(get_keycloak_issuer_url "$KEYCLOAK_MAIN_REALM" "$KEYCLOAK_CONTAINER_NAME" "8080" "http")
  keycloak_contractors_url=$(get_keycloak_issuer_url "$KEYCLOAK_CONTRACTORS_REALM" "$KEYCLOAK_CONTAINER_NAME" "8080" "http")
  
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
  log "  export KEYCLOAK_HOST=http://${KEYCLOAK_CONTAINER_NAME}:8080"
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
  cat > "$TDIR/env.sh" <<EOF
export E2E_HUB_KUBECONFIG=$HUB_KUBECONFIG
export E2E_SPOKE_A_KUBECONFIG=$SPOKE_A_KUBECONFIG
export E2E_SPOKE_B_KUBECONFIG=$SPOKE_B_KUBECONFIG
export E2E_MULTI_CLUSTER=true
export KEYCLOAK_CONTAINER_NAME=$KEYCLOAK_CONTAINER_NAME
export KEYCLOAK_HOST=http://${KEYCLOAK_CONTAINER_NAME}:8080
export KEYCLOAK_MAIN_REALM=$KEYCLOAK_MAIN_REALM
export KEYCLOAK_CONTRACTORS_REALM=$KEYCLOAK_CONTRACTORS_REALM
export E2E_HUB_EXTERNAL_IP=$hub_ip
export E2E_HUB_WEBHOOK_URL=$hub_webhook_url
export E2E_HUB_API_URL=$hub_api_url
EOF
  log "Environment file written to: $TDIR/env.sh"
  log "  source $TDIR/env.sh"
}

# Track script failure state
SCRIPT_FAILED=false

# Cleanup function
cleanup() {
  # Skip cleanup if PRESERVE_ON_FAILURE is set and script failed
  if [ "${PRESERVE_ON_FAILURE:-false}" = "true" ] && [ "${SCRIPT_FAILED}" = "true" ]; then
    log "PRESERVE_ON_FAILURE=true and script failed - skipping cleanup for diagnostics"
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
  
  # Start Keycloak container on the kind network
  KEYCLOAK_IP=$(start_keycloak_container "$keycloak_tls_dir" "kind")
  if [ -z "$KEYCLOAK_IP" ]; then
    log_error "Failed to start Keycloak container"
    return 1
  fi
  
  # Save Keycloak IP for later use
  echo "$KEYCLOAK_IP" > "$TDIR/keycloak-ip"
  
  # Configure Keycloak realm
  configure_keycloak_realm "$KEYCLOAK_MAIN_REALM"
  
  # Also create contractors realm
  configure_keycloak_realm "$KEYCLOAK_CONTRACTORS_REALM"
  
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
  
  # Create all clusters
  create_clusters
  
  # Inject Keycloak hostname into all clusters
  inject_keycloak_into_clusters
  
  # Setup hub cluster with Breakglass
  setup_hub_cluster
  
  # Setup spoke clusters for hub connectivity (hostnames, CA bundles)
  setup_spoke_for_hub "$SPOKE_A_CLUSTER" "$SPOKE_A_KUBECONFIG"
  setup_spoke_for_hub "$SPOKE_B_CLUSTER" "$SPOKE_B_KUBECONFIG"
  
  # Verify spoke-to-hub connectivity
  verify_spoke_connectivity "$SPOKE_A_CLUSTER" "$SPOKE_A_KUBECONFIG" || log_warn "Spoke A connectivity check failed"
  verify_spoke_connectivity "$SPOKE_B_CLUSTER" "$SPOKE_B_KUBECONFIG" || log_warn "Spoke B connectivity check failed"
  
  # Setup kubeconfig secrets
  setup_kubeconfig_secrets
  
  # Setup RBAC on spoke clusters
  setup_spoke_rbac "$SPOKE_A_KUBECONFIG" "$SPOKE_A_CLUSTER"
  setup_spoke_rbac "$SPOKE_B_KUBECONFIG" "$SPOKE_B_CLUSTER"
  
  # Apply multi-cluster resources (includes IdentityProviders pointing to real Keycloak)
  apply_multi_cluster_resources
  
  # Print summary
  print_summary
}

main "$@"
