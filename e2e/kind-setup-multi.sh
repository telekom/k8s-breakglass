#!/usr/bin/env bash
set -euo pipefail
# Multi-cluster E2E setup: 1 hub + 2 spoke clusters with full OIDC authentication.
# This script creates a true hub-and-spoke topology where:
# - Hub cluster runs the Breakglass controller, API, webhooks, Keycloak, and MailHog
# - Spoke clusters are registered via ClusterConfig and use the hub for webhook authorization
# - Multiple OIDC realms support different user populations (employees vs contractors)

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
MAILHOG_UI_PORT=${MAILHOG_UI_PORT:-8025}

# --- Hub external URL (will be set after cluster creation) ---
HUB_EXTERNAL_IP=""
HUB_WEBHOOK_URL=""
HUB_API_URL=""

# --- Kind node image ---
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.34.0}

# --- Directories ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# --- Proxy configuration ---
if [ "${SKIP_PROXY:-false}" = "true" ]; then
  printf '[multi-e2e] SKIP_PROXY=true: Skipping corporate proxy configuration\n'
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
fi

log(){ printf '[multi-e2e] %s\n' "$*"; }

# Find a free port on the local machine
find_free_port() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
    return
  fi
  local port
  for _ in {1..100}; do
    port=$((RANDOM % 10000 + 30000))
    if ! lsof -i ":$port" >/dev/null 2>&1; then
      echo "$port"
      return
    fi
  done
  echo "$((RANDOM % 10000 + 30000))"
}

# Initialize temporary directories
init_temp_dirs() {
  log "Creating temporary directories..."
  mkdir -p "$TDIR" "$TLS_DIR"
}

# Generate TLS certificates (called after we know the hub IP)
generate_tls_certificates() {
  local hub_ip="${1:-127.0.0.1}"
  
  log "Generating TLS certificates with hub IP: $hub_ip..."
  openssl genrsa -out "$TLS_DIR/ca.key" 2048 2>/dev/null
  openssl req -x509 -new -nodes -key "$TLS_DIR/ca.key" -subj "/CN=breakglass-ca" -days 365 -out "$TLS_DIR/ca.crt" 2>/dev/null
  openssl genrsa -out "$TLS_DIR/tls.key" 2048 2>/dev/null
  
  # Create SAN config for multiple DNS names including the hub's external IP
  cat > "$TLS_DIR/san.cnf" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = breakglass
DNS.2 = breakglass.breakglass-dev-system
DNS.3 = breakglass.breakglass-dev-system.svc
DNS.4 = breakglass.breakglass-dev-system.svc.cluster.local
DNS.5 = breakglass-dev-webhook-service.breakglass-dev-system.svc
DNS.6 = breakglass-dev-webhook-service.breakglass-dev-system.svc.cluster.local
DNS.7 = breakglass-external.breakglass-dev-system.svc
DNS.8 = breakglass-external.breakglass-dev-system.svc.cluster.local
DNS.9 = localhost
IP.1 = 127.0.0.1
IP.2 = ${hub_ip}
EOF

  openssl req -new -key "$TLS_DIR/tls.key" -out "$TLS_DIR/tls.csr" -subj "/CN=breakglass" -config "$TLS_DIR/san.cnf" 2>/dev/null
  openssl x509 -req -in "$TLS_DIR/tls.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
    -out "$TLS_DIR/tls.crt" -days 365 -extensions v3_req -extfile "$TLS_DIR/san.cnf" 2>/dev/null
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

# Load Docker image into cluster
load_image_into_cluster() {
  local cluster_name="$1"
  local image="$2"
  
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    log "Docker image $image not found locally; pulling"
    docker pull "$image" || true
  fi
  log "Loading image $image into kind cluster $cluster_name"
  $KIND load docker-image "$image" --name "$cluster_name" || true
}

# Wait for deployment to be ready
wait_for_deploy_by_label() {
  local kubeconfig="$1"
  local label="$2"
  local max_attempts=${3:-120}
  
  for i in $(seq 1 $max_attempts); do
    DEP_NS=$(KUBECONFIG="$kubeconfig" $KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
    DEP_NAME=$(KUBECONFIG="$kubeconfig" $KUBECTL get deploy --all-namespaces -l app=${label} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    if [ -n "$DEP_NAME" ] && [ -n "$DEP_NS" ]; then
      log "Waiting rollout for $label: $DEP_NAME ns $DEP_NS"
      KUBECONFIG="$kubeconfig" $KUBECTL rollout status deployment/"$DEP_NAME" -n "$DEP_NS" --timeout=240s && return 0
    fi
    sleep 2
  done
  return 1
}

# Start port forward
start_port_forward() {
  local kubeconfig="$1"
  local ns="$2"
  local svc="$3"
  local local_port="$4"
  local remote_port="$5"
  
  log "Starting port-forward for svc/$svc in ns $ns -> localhost:$local_port:$remote_port"
  KUBECONFIG="$kubeconfig" $KUBECTL -n "$ns" port-forward svc/"$svc" ${local_port}:${remote_port} >/dev/null 2>&1 &
  local pid=$!
  mkdir -p "$(dirname "$PF_FILE")" || true
  echo $pid >> "$PF_FILE" || true
  echo $pid
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
  
  # Load images
  load_image_into_cluster "$HUB_CLUSTER" "$IMAGE"
  load_image_into_cluster "$HUB_CLUSTER" "$KEYCLOAK_IMAGE"
  
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
  
  # Deploy using kustomize
  log "Deploying Breakglass controller..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUSTOMIZE build config/dev | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply --server-side --force-conflicts -f -
  
  # Wait for deployments
  wait_for_deploy_by_label "$HUB_KUBECONFIG" "keycloak" 120
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
EOF

  # Set the external URLs that spoke clusters will use
  HUB_WEBHOOK_URL="https://${HUB_EXTERNAL_IP}:${WEBHOOK_NODEPORT}"
  HUB_API_URL="http://${HUB_EXTERNAL_IP}:${API_NODEPORT}"
  
  log "Hub webhook URL for spoke clusters: $HUB_WEBHOOK_URL"
  log "Hub API URL for spoke clusters: $HUB_API_URL"
  
  # Store URLs in temp dir for reference
  echo "$HUB_WEBHOOK_URL" > "$TDIR/hub-webhook-url"
  echo "$HUB_API_URL" > "$TDIR/hub-api-url"
  echo "$HUB_EXTERNAL_IP" > "$TDIR/hub-external-ip"
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

# Setup Keycloak with multiple realms
setup_keycloak_realms() {
  log "Configuring Keycloak realms..."
  
  # Wait for Keycloak to be ready with admin console
  local keycloak_pod
  keycloak_pod=$(KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL get pods -n breakglass-dev-system -l app=keycloak -o jsonpath='{.items[0].metadata.name}')
  
  log "Waiting for Keycloak admin to be available..."
  for i in $(seq 1 60); do
    if KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-dev-system "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 \
      --realm master --user admin --password admin 2>/dev/null; then
      break
    fi
    sleep 5
  done
  
  log "Keycloak admin console is available"
  
  # The main realm (breakglass-e2e) should already be configured by the single-cluster setup
  # We need to create the contractors realm for multi-tenant testing
  
  log "Creating contractors realm..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-dev-system "$keycloak_pod" -- \
    /opt/keycloak/bin/kcadm.sh create realms \
    -s realm=$KEYCLOAK_CONTRACTORS_REALM \
    -s enabled=true \
    -s displayName="Breakglass E2E Contractors" 2>/dev/null || true
  
  # Create client in contractors realm
  log "Creating client in contractors realm..."
  KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-dev-system "$keycloak_pod" -- \
    /opt/keycloak/bin/kcadm.sh create clients \
    -r $KEYCLOAK_CONTRACTORS_REALM \
    -s clientId=breakglass-contractors \
    -s enabled=true \
    -s publicClient=true \
    -s 'redirectUris=["*"]' \
    -s directAccessGrantsEnabled=true 2>/dev/null || true
  
  # Create contractor users
  for user in contractor1 contractor2; do
    log "Creating user $user in contractors realm..."
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-dev-system "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh create users \
      -r $KEYCLOAK_CONTRACTORS_REALM \
      -s username="${user}@vendor.com" \
      -s email="${user}@vendor.com" \
      -s emailVerified=true \
      -s enabled=true 2>/dev/null || true
    
    # Set password
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-dev-system "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh set-password \
      -r $KEYCLOAK_CONTRACTORS_REALM \
      --username "${user}@vendor.com" \
      --new-password "password" 2>/dev/null || true
  done
  
  # Create groups in contractors realm
  for group in contractors vendor-team; do
    log "Creating group $group in contractors realm..."
    KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL exec -n breakglass-dev-system "$keycloak_pod" -- \
      /opt/keycloak/bin/kcadm.sh create groups \
      -r $KEYCLOAK_CONTRACTORS_REALM \
      -s name="$group" 2>/dev/null || true
  done
  
  log "Keycloak realm configuration complete"
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

  # Apply IdentityProviders (cluster-scoped)
  log "Creating IdentityProvider resources..."
  cat <<EOF | KUBECONFIG="$HUB_KUBECONFIG" $KUBECTL apply -f -
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: main-idp
spec:
  displayName: "Main IDP (Employees)"
  oidc:
    authority: "https://auth.example.com"
    clientID: "breakglass"
  issuer: "https://auth.example.com"
  primary: true
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: contractors-idp
spec:
  displayName: "Contractors IDP"
  oidc:
    authority: "https://contractors-auth.example.com"
    clientID: "breakglass-contractors"
  issuer: "https://contractors-auth.example.com"
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
  log "  Hub IP:      $hub_ip"
  log "  Webhook URL: $hub_webhook_url"
  log "  API URL:     $hub_api_url"
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
  log ""
  log "To run multi-cluster tests:"
  log "  go test ./e2e/api/... -v -tags=multicluster -timeout=30m"
  log ""
  log "To tear down:"
  log "  $KIND delete cluster --name $HUB_CLUSTER"
  log "  $KIND delete cluster --name $SPOKE_A_CLUSTER"
  log "  $KIND delete cluster --name $SPOKE_B_CLUSTER"
  log "=================================================="
  
  # Export environment variables
  cat > "$TDIR/env.sh" <<EOF
export E2E_HUB_KUBECONFIG=$HUB_KUBECONFIG
export E2E_SPOKE_A_KUBECONFIG=$SPOKE_A_KUBECONFIG
export E2E_SPOKE_B_KUBECONFIG=$SPOKE_B_KUBECONFIG
export E2E_MULTI_CLUSTER=true
export KEYCLOAK_HOST=http://localhost:${KEYCLOAK_FORWARD_PORT}
export KEYCLOAK_MAIN_REALM=$KEYCLOAK_MAIN_REALM
export KEYCLOAK_CONTRACTORS_REALM=$KEYCLOAK_CONTRACTORS_REALM
export E2E_HUB_EXTERNAL_IP=$hub_ip
export E2E_HUB_WEBHOOK_URL=$hub_webhook_url
export E2E_HUB_API_URL=$hub_api_url
EOF
  log "Environment file written to: $TDIR/env.sh"
  log "  source $TDIR/env.sh"
}

# Cleanup function
cleanup() {
  log "Cleaning up..."
  
  # Kill port forwards
  if [ -f "$PF_FILE" ]; then
    while read -r pid; do
      kill "$pid" 2>/dev/null || true
    done < "$PF_FILE"
    rm -f "$PF_FILE"
  fi
}

# Main function
main() {
  trap cleanup EXIT
  
  log "Starting multi-cluster E2E setup..."
  
  # Initialize directories and TLS
  init_temp_dirs
  
  # Create all clusters
  create_clusters
  
  # Setup hub cluster with Breakglass
  setup_hub_cluster
  
  # Setup kubeconfig secrets
  setup_kubeconfig_secrets
  
  # Setup Keycloak realms
  setup_keycloak_realms
  
  # Setup RBAC on spoke clusters
  setup_spoke_rbac "$SPOKE_A_KUBECONFIG" "$SPOKE_A_CLUSTER"
  setup_spoke_rbac "$SPOKE_B_KUBECONFIG" "$SPOKE_B_CLUSTER"
  
  # Apply multi-cluster resources
  apply_multi_cluster_resources
  
  # Print summary
  print_summary
}

main "$@"
