#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2024 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Shared library for E2E test setup scripts.
# This file contains common functions used by both single-cluster and multi-cluster setups.
#
# Usage: source this file from your setup script after setting required variables.

set -euo pipefail

# ============================================================================
# LOGGING
# ============================================================================

# Log prefix (set by sourcing script)
E2E_LOG_PREFIX=${E2E_LOG_PREFIX:-[e2e]}

log() {
  printf '%s %s\n' "$E2E_LOG_PREFIX" "$*"
}

log_error() {
  printf '%s ERROR: %s\n' "$E2E_LOG_PREFIX" "$*" >&2
}

log_warn() {
  printf '%s WARN: %s\n' "$E2E_LOG_PREFIX" "$*" >&2
}

log_debug() {
  if [ "${E2E_DEBUG:-false}" = "true" ]; then
    printf '%s DEBUG: %s\n' "$E2E_LOG_PREFIX" "$*"
  fi
}

# ============================================================================
# TOOLS & DEPENDENCIES
# ============================================================================

# Tool paths (can be overridden)
KIND=${KIND:-kind}
KUBECTL=${KUBECTL:-kubectl}
KUSTOMIZE=${KUSTOMIZE:-kustomize}
DOCKER=${DOCKER:-docker}
OPENSSL=${OPENSSL:-openssl}

# Check if required tools are available
check_required_tools() {
  local missing=()
  
  for tool in kind kubectl docker openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_error "Missing required tools: ${missing[*]}"
    log_error "Please install them before running this script."
    return 1
  fi
  
  log "All required tools available"
  return 0
}

# ============================================================================
# NETWORK UTILITIES
# ============================================================================

# Find a free port on the local machine
find_free_port() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
    return
  fi
  
  local port
  for _ in {1..100}; do
    port=$((RANDOM % 10000 + 30000))
    if ! lsof -i ":$port" >/dev/null 2>&1 && ! ss -ln 2>/dev/null | grep -q ":$port "; then
      echo "$port"
      return
    fi
  done
  echo "$((RANDOM % 10000 + 30000))"
}

# Get the Docker network IP of a Kind node
get_kind_node_ip() {
  local node_name="$1"
  $DOCKER inspect "$node_name" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
}

# Check if a TCP port is reachable
check_tcp_reachable() {
  local host="$1"
  local port="$2"
  local timeout="${3:-5}"
  
  if command -v nc >/dev/null 2>&1; then
    nc -z -w "$timeout" "$host" "$port" 2>/dev/null
  elif command -v timeout >/dev/null 2>&1; then
    timeout "$timeout" bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null
  else
    # Fallback using curl
    curl -sf --connect-timeout "$timeout" "http://$host:$port" >/dev/null 2>&1 || \
    curl -sf --connect-timeout "$timeout" -k "https://$host:$port" >/dev/null 2>&1
  fi
}

# Wait for a TCP port to become reachable
wait_for_port() {
  local host="$1"
  local port="$2"
  local max_attempts="${3:-60}"
  local description="${4:-$host:$port}"
  
  log "Waiting for $description to be reachable..."
  for i in $(seq 1 "$max_attempts"); do
    if check_tcp_reachable "$host" "$port" 2; then
      log "$description is reachable"
      return 0
    fi
    [ $((i % 10)) -eq 0 ] && log "Still waiting for $description... (attempt $i/$max_attempts)"
    sleep 1
  done
  
  log_error "$description not reachable after $max_attempts attempts"
  return 1
}

# Wait for an HTTP endpoint to return 200
wait_for_http() {
  local url="$1"
  local max_attempts="${2:-60}"
  local description="${3:-$url}"
  local insecure="${4:-false}"
  
  local curl_opts="-sf --connect-timeout 5 --max-time 10"
  [ "$insecure" = "true" ] && curl_opts="$curl_opts -k"
  
  log "Waiting for HTTP endpoint $description (URL: $url)..."
  for i in $(seq 1 "$max_attempts"); do
    # Try to reach the endpoint
    local response
    local exit_code
    response=$(curl $curl_opts -w "\nHTTP_CODE:%{http_code}" "$url" 2>&1) && exit_code=0 || exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
      log "$description is available"
      return 0
    fi
    
    # Log progress and debug info periodically
    if [ $((i % 20)) -eq 0 ]; then
      log "Still waiting for $description... (attempt $i/$max_attempts)"
      # Show what curl is returning for debugging
      log_debug "curl exit code: $exit_code, response: ${response:0:200}"
    fi
    sleep 1
  done
  
  log_error "$description not available after $max_attempts attempts"
  # Final debug output
  log "Final curl attempt output:"
  curl -v --connect-timeout 5 --max-time 10 "$url" 2>&1 | tail -20 || true
  return 1
}

# ============================================================================
# DOCKER IMAGE HANDLING
# ============================================================================

# Pull image if not present locally
ensure_image_exists() {
  local image="$1"
  
  if ! $DOCKER image inspect "$image" >/dev/null 2>&1; then
    log "Docker image $image not found locally; pulling..."
    $DOCKER pull "$image" || {
      log_error "Failed to pull image $image"
      return 1
    }
  fi
  return 0
}

# Load image into Kind cluster
# Uses docker save + kind load image-archive to avoid "failed to detect containerd snapshotter" issues
e2e_load_image_into_kind() {
  local cluster_name="$1"
  local image="$2"
  
  ensure_image_exists "$image" || return 1
  
  log "Loading image $image into Kind cluster $cluster_name"
  
  # Try direct load first
  if $KIND load docker-image "$image" --name "$cluster_name" 2>&1 | tee /dev/stderr | grep -q "failed to detect containerd snapshotter"; then
    log_warn "Direct load failed due to containerd snapshotter issue, using archive method..."
    local tmp_archive
    tmp_archive=$(mktemp --suffix=.tar)
    if $DOCKER save "$image" -o "$tmp_archive" && $KIND load image-archive "$tmp_archive" --name "$cluster_name"; then
      log "Successfully loaded $image via archive method"
    else
      log_warn "Failed to load image $image via archive method"
    fi
    rm -f "$tmp_archive"
  fi
}

# Load all standard images required for breakglass E2E
e2e_load_standard_images() {
  local cluster_name="$1"
  local breakglass_image="${2:-breakglass:e2e}"
  local keycloak_image="${3:-quay.io/keycloak/keycloak:23.0.0}"
  
  log "Loading standard images into cluster $cluster_name..."
  
  e2e_load_image_into_kind "$cluster_name" "$breakglass_image"
  e2e_load_image_into_kind "$cluster_name" "$keycloak_image"
  e2e_load_image_into_kind "$cluster_name" "mailhog/mailhog:v1.0.1"
  e2e_load_image_into_kind "$cluster_name" "curlimages/curl:8.4.0"
  e2e_load_image_into_kind "$cluster_name" "nicolaka/netshoot"
  e2e_load_image_into_kind "$cluster_name" "apache/kafka:3.7.0"
  e2e_load_image_into_kind "$cluster_name" "python:3.11-slim"
  
  log "Standard images loaded into cluster $cluster_name"
}

# ============================================================================
# TLS CERTIFICATE GENERATION
# ============================================================================

# Generate CA certificate
generate_ca_cert() {
  local output_dir="$1"
  local ca_name="${2:-breakglass-ca}"
  
  log "Generating CA certificate..."
  mkdir -p "$output_dir"
  
  $OPENSSL genrsa -out "$output_dir/ca.key" 2048 2>/dev/null
  $OPENSSL req -x509 -new -nodes -key "$output_dir/ca.key" \
    -subj "/CN=$ca_name" -days 365 -out "$output_dir/ca.crt" 2>/dev/null
  
  log "CA certificate generated at $output_dir/ca.crt"
}

# Generate server certificate with SANs
generate_server_cert() {
  local output_dir="$1"
  local cn="$2"
  shift 2
  local extra_sans=("$@")
  
  log "Generating server certificate for $cn..."
  
  # Build SAN config
  local san_config="$output_dir/san.cnf"
  cat > "$san_config" <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $cn
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

  # Add extra SANs
  local dns_idx=3
  local ip_idx=2
  for san in "${extra_sans[@]}"; do
    if [[ "$san" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "IP.$ip_idx = $san" >> "$san_config"
      ip_idx=$((ip_idx + 1))
    else
      echo "DNS.$dns_idx = $san" >> "$san_config"
      dns_idx=$((dns_idx + 1))
    fi
  done
  
  # Generate key and CSR
  $OPENSSL genrsa -out "$output_dir/tls.key" 2048 2>/dev/null
  $OPENSSL req -new -key "$output_dir/tls.key" -out "$output_dir/tls.csr" \
    -subj "/CN=$cn" -config "$san_config" 2>/dev/null
  
  # Sign with CA
  $OPENSSL x509 -req -in "$output_dir/tls.csr" \
    -CA "$output_dir/ca.crt" -CAkey "$output_dir/ca.key" -CAcreateserial \
    -out "$output_dir/tls.crt" -days 365 \
    -extensions v3_req -extfile "$san_config" 2>/dev/null
  
  log "Server certificate generated at $output_dir/tls.crt"
}

# Generate complete TLS bundle for breakglass services
generate_breakglass_tls() {
  local output_dir="$1"
  local hub_ip="${2:-127.0.0.1}"
  local namespace="${3:-breakglass-dev-system}"
  
  log "Generating TLS certificates for breakglass services..."
  mkdir -p "$output_dir"
  
  # Generate CA
  generate_ca_cert "$output_dir" "breakglass-webhook-ca"
  
  # Standard SANs for breakglass services
  local sans=(
    # Breakglass webhook service names
    "breakglass"
    "breakglass.$namespace"
    "breakglass.$namespace.svc"
    "breakglass.$namespace.svc.cluster.local"
    "breakglass-dev-breakglass-webhook-service.$namespace.svc"
    "breakglass-dev-breakglass-webhook-service.$namespace.svc.cluster.local"
    "breakglass-dev-webhook-service.$namespace.svc"
    "breakglass-dev-webhook-service.$namespace.svc.cluster.local"
    # External access
    "breakglass-external.$namespace.svc"
    "breakglass-external.$namespace.svc.cluster.local"
    # Hub IP for cross-cluster access
    "$hub_ip"
  )
  
  generate_server_cert "$output_dir" "breakglass" "${sans[@]}"
  
  log "Breakglass TLS bundle generated at $output_dir"
}

# Generate TLS certificates for Keycloak
generate_keycloak_tls() {
  local output_dir="$1"
  local hub_ip="${2:-127.0.0.1}"
  local namespace="${3:-breakglass-dev-system}"
  
  log "Generating TLS certificates for Keycloak..."
  mkdir -p "$output_dir"
  
  # Generate CA (or reuse existing)
  if [ ! -f "$output_dir/ca.crt" ]; then
    generate_ca_cert "$output_dir" "keycloak-ca"
  fi
  
  # Standard SANs for Keycloak
  local sans=(
    "keycloak"
    "keycloak.$namespace"
    "keycloak.$namespace.svc"
    "keycloak.$namespace.svc.cluster.local"
    "breakglass-dev-keycloak"
    "breakglass-dev-keycloak.$namespace"
    "breakglass-dev-keycloak.$namespace.svc"
    "breakglass-dev-keycloak.$namespace.svc.cluster.local"
    "keycloak-external.$namespace.svc"
    "keycloak-external.$namespace.svc.cluster.local"
    "$hub_ip"
  )
  
  generate_server_cert "$output_dir" "keycloak" "${sans[@]}"
  
  log "Keycloak TLS bundle generated at $output_dir"
}

# ============================================================================
# KIND CLUSTER MANAGEMENT
# ============================================================================

# Create Kind cluster configuration
create_kind_config() {
  local cluster_name="$1"
  local config_file="$2"
  local node_image="${3:-kindest/node:v1.34.0}"
  local extra_port_mappings="${4:-}"
  
  cat > "$config_file" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${cluster_name}
nodes:
- role: control-plane
  image: ${node_image}
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

  if [ -n "$extra_port_mappings" ]; then
    echo "$extra_port_mappings" >> "$config_file"
  fi
  
  log "Kind config written to $config_file"
}

# Create a Kind cluster
create_kind_cluster() {
  local cluster_name="$1"
  local config_file="$2"
  local kubeconfig_file="$3"
  local wait_time="${4:-120s}"
  
  # Delete existing cluster if present
  if $KIND get clusters 2>/dev/null | grep -q "^${cluster_name}$"; then
    log "Deleting existing cluster $cluster_name..."
    $KIND delete cluster --name "$cluster_name" || true
  fi
  
  log "Creating Kind cluster $cluster_name..."
  $KIND create cluster --name "$cluster_name" --config "$config_file" --wait "$wait_time"
  $KIND get kubeconfig --name "$cluster_name" > "$kubeconfig_file"
  
  log "Cluster $cluster_name created, kubeconfig at $kubeconfig_file"
}

# Delete a Kind cluster
delete_kind_cluster() {
  local cluster_name="$1"
  
  if $KIND get clusters 2>/dev/null | grep -q "^${cluster_name}$"; then
    log "Deleting cluster $cluster_name..."
    $KIND delete cluster --name "$cluster_name" || true
  else
    log "Cluster $cluster_name does not exist"
  fi
}

# ============================================================================
# KUBERNETES OPERATIONS
# ============================================================================

# Apply manifest with optional wait
apply_manifest() {
  local kubeconfig="$1"
  local manifest="$2"
  local server_side="${3:-true}"
  
  local apply_cmd="apply"
  [ "$server_side" = "true" ] && apply_cmd="apply --server-side --force-conflicts"
  
  KUBECONFIG="$kubeconfig" $KUBECTL $apply_cmd -f "$manifest"
}

# Wait for deployment to be ready
wait_for_deployment() {
  local kubeconfig="$1"
  local namespace="$2"
  local deployment="$3"
  local timeout="${4:-240s}"
  
  log "Waiting for deployment $deployment in $namespace..."
  KUBECONFIG="$kubeconfig" $KUBECTL rollout status deployment/"$deployment" \
    -n "$namespace" --timeout="$timeout"
}

# Wait for deployment by label
e2e_wait_for_deployment_by_label() {
  local kubeconfig="$1"
  local label="$2"
  local max_attempts="${3:-120}"
  
  for i in $(seq 1 "$max_attempts"); do
    local dep_ns dep_name
    dep_ns=$(KUBECONFIG="$kubeconfig" $KUBECTL get deploy --all-namespaces -l "app=$label" \
      -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
    dep_name=$(KUBECONFIG="$kubeconfig" $KUBECTL get deploy --all-namespaces -l "app=$label" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    
    if [ -n "$dep_name" ] && [ -n "$dep_ns" ]; then
      log "Found deployment $dep_name in $dep_ns, waiting for rollout..."
      if KUBECONFIG="$kubeconfig" $KUBECTL rollout status deployment/"$dep_name" \
          -n "$dep_ns" --timeout=240s; then
        return 0
      fi
    fi
    sleep 2
  done
  
  log_error "Deployment with label app=$label not found after $max_attempts attempts"
  return 1
}

# Create namespace if not exists
ensure_namespace() {
  local kubeconfig="$1"
  local namespace="$2"
  
  KUBECONFIG="$kubeconfig" $KUBECTL create namespace "$namespace" \
    --dry-run=client -o yaml | KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
}

# Create TLS secret
create_tls_secret() {
  local kubeconfig="$1"
  local namespace="$2"
  local secret_name="$3"
  local cert_file="$4"
  local key_file="$5"
  
  KUBECONFIG="$kubeconfig" $KUBECTL create secret tls "$secret_name" \
    --cert="$cert_file" --key="$key_file" \
    -n "$namespace" --dry-run=client -o yaml | \
    KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
}

# Create generic secret from file
create_secret_from_file() {
  local kubeconfig="$1"
  local namespace="$2"
  local secret_name="$3"
  local key="$4"
  local file="$5"
  
  KUBECONFIG="$kubeconfig" $KUBECTL create secret generic "$secret_name" \
    --from-file="$key=$file" \
    -n "$namespace" --dry-run=client -o yaml | \
    KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
}

# ============================================================================
# HOSTNAME INJECTION
# ============================================================================

# Inject hostname into Kind node's /etc/hosts
inject_hostname_into_node() {
  local node_name="$1"
  local ip="$2"
  local hostname="$3"
  
  log_debug "Injecting $hostname -> $ip into $node_name"
  
  # Check if entry already exists
  if $DOCKER exec "$node_name" grep -q "$hostname" /etc/hosts 2>/dev/null; then
    log_debug "Hostname $hostname already in /etc/hosts"
    return 0
  fi
  
  # Add entry
  $DOCKER exec "$node_name" sh -c "echo '$ip $hostname' >> /etc/hosts" || {
    log_warn "Failed to inject hostname $hostname into $node_name"
    return 1
  }
}

# Inject hub service hostnames into spoke cluster node
inject_hub_hostnames_into_spoke() {
  local spoke_node="$1"
  local hub_ip="$2"
  local namespace="${3:-breakglass-dev-system}"
  
  log "Injecting hub service hostnames into $spoke_node..."
  
  local hostnames=(
    # Breakglass service hostnames
    "breakglass-dev-breakglass.$namespace.svc.cluster.local"
    "breakglass-dev-breakglass-webhook-service.$namespace.svc.cluster.local"
    "breakglass-external.$namespace.svc.cluster.local"
    # Keycloak service hostnames
    "breakglass-dev-keycloak.$namespace.svc.cluster.local"
    "keycloak-external.$namespace.svc.cluster.local"
  )
  
  for hostname in "${hostnames[@]}"; do
    inject_hostname_into_node "$spoke_node" "$hub_ip" "$hostname"
  done
  
  log "Hub hostnames injected into $spoke_node"
}

# ============================================================================
# PORT FORWARDING
# ============================================================================

# Start port forward to a service
start_port_forward() {
  local kubeconfig="$1"
  local namespace="$2"
  local service="$3"
  local local_port="$4"
  local remote_port="$5"
  local pid_file="${6:-}"
  
  log "Starting port-forward: localhost:$local_port -> $service:$remote_port"
  KUBECONFIG="$kubeconfig" $KUBECTL -n "$namespace" port-forward \
    "svc/$service" "${local_port}:${remote_port}" >/dev/null 2>&1 &
  local pid=$!
  
  if [ -n "$pid_file" ]; then
    echo "$pid" >> "$pid_file"
  fi
  
  # Wait briefly to ensure port-forward started
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then
    log_error "Port-forward failed to start"
    return 1
  fi
  
  echo "$pid"
}

# Kill port forwards from pid file
kill_port_forwards() {
  local pid_file="$1"
  
  if [ -f "$pid_file" ]; then
    while read -r pid; do
      kill "$pid" 2>/dev/null || true
    done < "$pid_file"
    rm -f "$pid_file"
  fi
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

# Run all prerequisite checks
run_prerequisite_checks() {
  log "Running prerequisite checks..."
  
  check_required_tools || return 1
  
  # Check Docker is running
  if ! $DOCKER info >/dev/null 2>&1; then
    log_error "Docker is not running"
    return 1
  fi
  log "Docker is running"
  
  # Check for sufficient disk space (at least 5GB)
  local free_space
  if command -v df >/dev/null 2>&1; then
    free_space=$(df -BG . 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G')
    if [ -n "$free_space" ] && [ "$free_space" -lt 5 ]; then
      log_warn "Low disk space: ${free_space}GB free (recommend at least 5GB)"
    fi
  fi
  
  log "Prerequisite checks passed"
  return 0
}

# Check cluster connectivity
check_cluster_connectivity() {
  local kubeconfig="$1"
  local cluster_name="$2"
  
  log "Checking connectivity to cluster $cluster_name..."
  
  if ! KUBECONFIG="$kubeconfig" $KUBECTL cluster-info >/dev/null 2>&1; then
    log_error "Cannot connect to cluster $cluster_name"
    return 1
  fi
  
  log "Cluster $cluster_name is reachable"
  return 0
}

# Check cross-cluster connectivity (from spoke to hub services)
check_cross_cluster_connectivity() {
  local spoke_kubeconfig="$1"
  local spoke_name="$2"
  local hub_ip="$3"
  local api_port="${4:-31080}"
  local webhook_port="${5:-31443}"
  
  log "Checking cross-cluster connectivity from $spoke_name to hub..."
  
  # Check API reachability
  log "Checking hub API at $hub_ip:$api_port..."
  if ! check_tcp_reachable "$hub_ip" "$api_port" 5; then
    log_error "Hub API not reachable from host at $hub_ip:$api_port"
    return 1
  fi
  log "Hub API is reachable"
  
  # Check webhook reachability
  log "Checking hub webhook at $hub_ip:$webhook_port..."
  if ! check_tcp_reachable "$hub_ip" "$webhook_port" 5; then
    log_error "Hub webhook not reachable from host at $hub_ip:$webhook_port"
    return 1
  fi
  log "Hub webhook is reachable"
  
  log "Cross-cluster connectivity check passed for $spoke_name"
  return 0
}

# ============================================================================
# DEBUG HELPERS
# ============================================================================

# Print cluster debug info
e2e_print_cluster_debug() {
  local kubeconfig="$1"
  local cluster_name="$2"
  local namespace="${3:-breakglass-dev-system}"
  
  log "=== DEBUG: Cluster $cluster_name ==="
  
  log "--- Nodes ---"
  KUBECONFIG="$kubeconfig" $KUBECTL get nodes -o wide 2>&1 || true
  
  log "--- Pods in $namespace ---"
  KUBECONFIG="$kubeconfig" $KUBECTL get pods -n "$namespace" -o wide 2>&1 || true
  
  log "--- Pod Descriptions ---"
  KUBECONFIG="$kubeconfig" $KUBECTL describe pods -n "$namespace" 2>&1 | head -100 || true
  
  log "--- Events in $namespace ---"
  KUBECONFIG="$kubeconfig" $KUBECTL get events -n "$namespace" \
    --sort-by='.lastTimestamp' 2>&1 | tail -30 || true
  
  log "=== END DEBUG: $cluster_name ==="
}

# Print deployment failure debug info
e2e_debug_deployment_failure() {
  local kubeconfig="$1"
  local label="$2"
  
  log "=== DEBUG: Deployment failure for app=$label ==="
  
  KUBECONFIG="$kubeconfig" $KUBECTL get pods -A -l "app=$label" -o wide 2>&1 || true
  
  local pods
  pods=$(KUBECONFIG="$kubeconfig" $KUBECTL get pods -A -l "app=$label" \
    -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  
  for pod in $pods; do
    local ns="${pod%%/*}"
    local name="${pod##*/}"
    log "--- Describe pod $name in $ns ---"
    KUBECONFIG="$kubeconfig" $KUBECTL describe pod "$name" -n "$ns" 2>&1 | tail -50 || true
    log "--- Logs for pod $name ---"
    KUBECONFIG="$kubeconfig" $KUBECTL logs "$name" -n "$ns" --tail=50 2>&1 || true
  done
  
  log "=== END DEBUG ==="
}

# ============================================================================
# MANIFEST VALIDATION
# ============================================================================

# Check for unreplaced placeholders in manifest
ensure_no_placeholders() {
  local file="$1"
  
  if [ ! -f "$file" ]; then
    return 0
  fi
  
  if grep -Eq '\$\{[A-Z0-9_]+\}|REPLACE_' "$file"; then
    log_error "Manifest $file contains unreplaced placeholder-like tokens"
    grep -En '\$\{[A-Z0-9_]+\}|REPLACE_' "$file" >&2 || true
    return 1
  fi
  
  return 0
}

# ============================================================================
# PROXY CONFIGURATION
# ============================================================================

# Configure proxy settings
configure_proxy() {
  local skip_proxy="${1:-false}"
  local cluster_names="${2:-}"
  
  if [ "$skip_proxy" = "true" ]; then
    log "Skipping proxy configuration"
    unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
    return 0
  fi
  
  # Default corporate proxy
  HTTP_PROXY="${HTTP_PROXY:-http://172.17.0.1:8118}"
  HTTPS_PROXY="${HTTPS_PROXY:-http://172.17.0.1:8118}"
  http_proxy="$HTTP_PROXY"
  https_proxy="$HTTPS_PROXY"
  
  # Build NO_PROXY list
  local no_proxy_entries="localhost,127.0.0.1,::1,.svc,.svc.cluster.local,.cluster.local"
  
  # Add cluster-specific entries
  for cluster in $cluster_names; do
    no_proxy_entries="$no_proxy_entries,${cluster}-control-plane"
  done
  
  NO_PROXY="${NO_PROXY:-}${NO_PROXY:+,}$no_proxy_entries"
  no_proxy="$NO_PROXY"
  
  export HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy
  
  log "Proxy configured: HTTP_PROXY=$HTTP_PROXY"
}

# ============================================================================
# CLEANUP
# ============================================================================

# Cleanup function template
cleanup_e2e() {
  local pid_file="${1:-}"
  local cluster_names="${2:-}"
  
  log "Cleaning up E2E environment..."
  
  # Kill port forwards
  if [ -n "$pid_file" ] && [ -f "$pid_file" ]; then
    kill_port_forwards "$pid_file"
  fi
  
  # Delete clusters
  for cluster in $cluster_names; do
    delete_kind_cluster "$cluster"
  done
  
  log "Cleanup complete"
}

# ============================================================================
# KEYCLOAK DOCKER CONTAINER
# ============================================================================

# Default Keycloak settings
KEYCLOAK_CONTAINER_NAME=${KEYCLOAK_CONTAINER_NAME:-e2e-keycloak}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:23.0.0}
KEYCLOAK_ADMIN_USER=${KEYCLOAK_ADMIN_USER:-admin}
KEYCLOAK_ADMIN_PASS=${KEYCLOAK_ADMIN_PASS:-admin}
KEYCLOAK_HTTP_PORT=${KEYCLOAK_HTTP_PORT:-8080}
KEYCLOAK_HTTPS_PORT=${KEYCLOAK_HTTPS_PORT:-8443}
KEYCLOAK_REALM=${KEYCLOAK_REALM:-breakglass-e2e}

# Get the IP address of the Keycloak container
get_keycloak_ip() {
  $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

# Check if Keycloak container is running
is_keycloak_running() {
  $DOCKER ps --filter "name=$KEYCLOAK_CONTAINER_NAME" --filter "status=running" -q 2>/dev/null | grep -q .
}

# Start Keycloak as a standalone Docker container
start_keycloak_container() {
  local tls_dir="${1:-}"
  local network="${2:-kind}"
  
  log "Starting Keycloak container..."
  
  # Ensure the network exists (Kind creates it when first cluster starts,
  # but we may need it before that)
  if ! $DOCKER network inspect "$network" >/dev/null 2>&1; then
    log "Creating Docker network '$network'..."
    $DOCKER network create "$network" || {
      log_error "Failed to create Docker network '$network'"
      return 1
    }
  fi
  
  # Remove existing container if present
  if $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" -q 2>/dev/null | grep -q .; then
    log "Removing existing Keycloak container..."
    $DOCKER rm -f "$KEYCLOAK_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  
  # Build the docker run command
  local docker_args=(
    run -d
    --name "$KEYCLOAK_CONTAINER_NAME"
    --network "$network"
    -e "KEYCLOAK_ADMIN=$KEYCLOAK_ADMIN_USER"
    -e "KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASS"
    -e "KC_HOSTNAME_STRICT=false"
    -e "KC_HOSTNAME_STRICT_HTTPS=false"
    -e "KC_HTTP_ENABLED=true"
  )
  
  # Add TLS if provided
  if [ -n "$tls_dir" ] && [ -f "$tls_dir/tls.crt" ] && [ -f "$tls_dir/tls.key" ]; then
    log "Configuring Keycloak with TLS from $tls_dir"
    docker_args+=(
      -v "$tls_dir/tls.crt:/opt/keycloak/conf/server.crt.pem:ro"
      -v "$tls_dir/tls.key:/opt/keycloak/conf/server.key.pem:ro"
      -e "KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/conf/server.crt.pem"
      -e "KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/conf/server.key.pem"
    )
  fi
  
  # Expose ports on host (for local testing)
  docker_args+=(
    -p "${KEYCLOAK_HTTP_PORT}:8080"
    -p "${KEYCLOAK_HTTPS_PORT}:8443"
  )
  
  # Add image and command
  docker_args+=(
    "$KEYCLOAK_IMAGE"
    start-dev
  )
  
  log "Running: docker ${docker_args[*]}"
  $DOCKER "${docker_args[@]}"
  
  # Wait for Keycloak to be ready
  log "Waiting for Keycloak to start..."
  
  # Give container a moment to start
  sleep 5
  
  # Verify container is running
  if ! is_keycloak_running; then
    log_error "Keycloak container is not running"
    log "=== Container status ==="
    $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" 2>&1 || true
    log "=== Container logs ==="
    $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" 2>&1 | tail -100 || true
    log "=== Port check ==="
    netstat -tlnp 2>/dev/null | grep -E "${KEYCLOAK_HTTP_PORT}|${KEYCLOAK_HTTPS_PORT}" || ss -tlnp 2>/dev/null | grep -E "${KEYCLOAK_HTTP_PORT}|${KEYCLOAK_HTTPS_PORT}" || echo "No listeners on configured ports"
    return 1
  fi
  
  # Get container IP for later use (e.g., by Kind clusters)
  local keycloak_ip
  keycloak_ip=$(get_keycloak_ip)
  
  if [ -z "$keycloak_ip" ]; then
    log_error "Failed to get Keycloak container IP"
    return 1
  fi
  
  log "Keycloak container IP: $keycloak_ip"
  
  # Log port mappings for debugging
  log "=== Docker port mappings ==="
  $DOCKER port "$KEYCLOAK_CONTAINER_NAME" 2>&1 || true
  
  # Wait for HTTP endpoint - use localhost with mapped port as the container IP
  # may not be routable from the host in CI environments (GitHub Actions)
  log "Checking Keycloak health via localhost:${KEYCLOAK_HTTP_PORT} (mapped port)"
  # Increase timeout to 180 seconds for slow CI environments
  if ! wait_for_http "http://localhost:${KEYCLOAK_HTTP_PORT}/health/ready" 180 "Keycloak health endpoint"; then
    log_error "Keycloak failed to become ready on localhost:${KEYCLOAK_HTTP_PORT}"
    log "=== Keycloak container status ==="
    $DOCKER ps -a --filter "name=$KEYCLOAK_CONTAINER_NAME" 2>&1 || true
    log "=== Keycloak container logs ==="
    $DOCKER logs "$KEYCLOAK_CONTAINER_NAME" 2>&1 | tail -200
    log "=== Docker inspect ==="
    $DOCKER inspect "$KEYCLOAK_CONTAINER_NAME" 2>&1 | head -80
    log "=== Port bindings on host ==="
    netstat -tlnp 2>/dev/null | head -20 || ss -tlnp 2>/dev/null | head -20 || echo "Could not check ports"
    log "Trying container IP as fallback: http://${keycloak_ip}:8080/health/ready"
    if ! wait_for_http "http://${keycloak_ip}:8080/health/ready" 60 "Keycloak health (container IP)"; then
      log_error "Keycloak failed to become ready via container IP as well"
      return 1
    fi
    log "Keycloak is ready via container IP (not localhost) - this may cause issues with host-based tests"
  fi
  
  log "Keycloak is ready (container IP: ${keycloak_ip}, host port: ${KEYCLOAK_HTTP_PORT})"
  echo "$keycloak_ip"
}

# Stop and remove Keycloak container
stop_keycloak_container() {
  log "Stopping Keycloak container..."
  $DOCKER rm -f "$KEYCLOAK_CONTAINER_NAME" >/dev/null 2>&1 || true
}

# Configure Keycloak realm with users and groups for e2e testing
configure_keycloak_realm() {
  local realm="${1:-$KEYCLOAK_REALM}"
  local keycloak_url="${2:-http://$(get_keycloak_ip):8080}"
  
  log "Configuring Keycloak realm: $realm"
  
  # Wait for admin API to be available
  sleep 5
  
  # Use docker exec to run kcadm commands
  local kcadm="$DOCKER exec $KEYCLOAK_CONTAINER_NAME /opt/keycloak/bin/kcadm.sh"
  
  # Authenticate with admin
  log "Authenticating with Keycloak admin..."
  $kcadm config credentials --server http://localhost:8080 \
    --realm master --user "$KEYCLOAK_ADMIN_USER" --password "$KEYCLOAK_ADMIN_PASS" 2>/dev/null || {
    log_error "Failed to authenticate with Keycloak"
    return 1
  }
  
  # Create realm if it doesn't exist
  log "Creating realm $realm..."
  $kcadm create realms -s realm="$realm" -s enabled=true -s displayName="Breakglass E2E" 2>/dev/null || true
  
  # Create a public client for breakglass
  log "Creating breakglass client..."
  $kcadm create clients -r "$realm" \
    -s clientId=breakglass \
    -s enabled=true \
    -s publicClient=true \
    -s 'redirectUris=["*"]' \
    -s directAccessGrantsEnabled=true \
    -s 'webOrigins=["*"]' 2>/dev/null || true
  
  # Also create breakglass-contractors client (for multi-IDP testing)
  log "Creating breakglass-contractors client..."
  $kcadm create clients -r "$realm" \
    -s clientId=breakglass-contractors \
    -s enabled=true \
    -s publicClient=true \
    -s 'redirectUris=["*"]' \
    -s directAccessGrantsEnabled=true \
    -s 'webOrigins=["*"]' 2>/dev/null || true
  
  # Create groups
  local groups=("breakglass-users" "breakglass-approvers" "breakglass-admins" "team-alpha" "team-beta" "contractors" "vendor-supervisors")
  for group in "${groups[@]}"; do
    log "Creating group: $group"
    $kcadm create groups -r "$realm" -s name="$group" 2>/dev/null || true
  done
  
  # Create test users
  # User 1: requester (member of breakglass-users)
  log "Creating user: requester@example.com"
  $kcadm create users -r "$realm" \
    -s username="requester@example.com" \
    -s email="requester@example.com" \
    -s emailVerified=true \
    -s enabled=true \
    -s firstName="Test" \
    -s lastName="Requester" 2>/dev/null || true
  $kcadm set-password -r "$realm" --username "requester@example.com" --new-password "password" 2>/dev/null || true
  
  # User 2: approver (member of breakglass-approvers)
  log "Creating user: approver@example.com"
  $kcadm create users -r "$realm" \
    -s username="approver@example.com" \
    -s email="approver@example.com" \
    -s emailVerified=true \
    -s enabled=true \
    -s firstName="Test" \
    -s lastName="Approver" 2>/dev/null || true
  $kcadm set-password -r "$realm" --username "approver@example.com" --new-password "password" 2>/dev/null || true
  
  # User 3: admin (member of breakglass-admins)
  log "Creating user: admin@example.com"
  $kcadm create users -r "$realm" \
    -s username="admin@example.com" \
    -s email="admin@example.com" \
    -s emailVerified=true \
    -s enabled=true \
    -s firstName="Test" \
    -s lastName="Admin" 2>/dev/null || true
  $kcadm set-password -r "$realm" --username "admin@example.com" --new-password "password" 2>/dev/null || true
  
  # Assign users to groups
  log "Assigning users to groups..."
  
  # Get group IDs
  local users_group_id approvers_group_id admins_group_id
  users_group_id=$($kcadm get groups -r "$realm" --fields id,name 2>/dev/null | grep -A1 '"name" : "breakglass-users"' | grep '"id"' | cut -d'"' -f4 || true)
  approvers_group_id=$($kcadm get groups -r "$realm" --fields id,name 2>/dev/null | grep -A1 '"name" : "breakglass-approvers"' | grep '"id"' | cut -d'"' -f4 || true)
  admins_group_id=$($kcadm get groups -r "$realm" --fields id,name 2>/dev/null | grep -A1 '"name" : "breakglass-admins"' | grep '"id"' | cut -d'"' -f4 || true)
  
  # Get user IDs
  local requester_id approver_id admin_id
  requester_id=$($kcadm get users -r "$realm" -q username="requester@example.com" --fields id 2>/dev/null | grep '"id"' | cut -d'"' -f4 || true)
  approver_id=$($kcadm get users -r "$realm" -q username="approver@example.com" --fields id 2>/dev/null | grep '"id"' | cut -d'"' -f4 || true)
  admin_id=$($kcadm get users -r "$realm" -q username="admin@example.com" --fields id 2>/dev/null | grep '"id"' | cut -d'"' -f4 || true)
  
  # Add users to groups
  if [ -n "$requester_id" ] && [ -n "$users_group_id" ]; then
    $kcadm update users/$requester_id/groups/$users_group_id -r "$realm" -s realm="$realm" -s userId="$requester_id" -s groupId="$users_group_id" -n 2>/dev/null || true
  fi
  if [ -n "$approver_id" ] && [ -n "$approvers_group_id" ]; then
    $kcadm update users/$approver_id/groups/$approvers_group_id -r "$realm" -s realm="$realm" -s userId="$approver_id" -s groupId="$approvers_group_id" -n 2>/dev/null || true
  fi
  if [ -n "$admin_id" ] && [ -n "$admins_group_id" ]; then
    $kcadm update users/$admin_id/groups/$admins_group_id -r "$realm" -s realm="$realm" -s userId="$admin_id" -s groupId="$admins_group_id" -n 2>/dev/null || true
  fi
  
  # Configure groups claim in client scope
  log "Configuring groups claim..."
  # Get the existing groups mapper or create one
  local client_scope_id
  client_scope_id=$($kcadm get client-scopes -r "$realm" --fields id,name 2>/dev/null | grep -B1 '"name" : "profile"' | grep '"id"' | cut -d'"' -f4 || true)
  
  if [ -n "$client_scope_id" ]; then
    $kcadm create client-scopes/$client_scope_id/protocol-mappers/models -r "$realm" \
      -s name=groups \
      -s protocol=openid-connect \
      -s protocolMapper=oidc-group-membership-mapper \
      -s 'config."claim.name"=groups' \
      -s 'config."full.path"=false' \
      -s 'config."id.token.claim"=true' \
      -s 'config."access.token.claim"=true' \
      -s 'config."userinfo.token.claim"=true' 2>/dev/null || true
  fi
  
  log "Keycloak realm $realm configured successfully"
}

# Generate TLS certificates for Keycloak container
generate_keycloak_container_tls() {
  local output_dir="$1"
  local keycloak_container_name="${2:-$KEYCLOAK_CONTAINER_NAME}"
  
  log "Generating TLS certificates for Keycloak container..."
  mkdir -p "$output_dir"
  
  # Generate CA if not exists
  if [ ! -f "$output_dir/ca.crt" ]; then
    generate_ca_cert "$output_dir" "keycloak-ca"
  fi
  
  # SANs for Keycloak container
  local sans=(
    "$keycloak_container_name"
    "keycloak"
    "localhost"
  )
  
  generate_server_cert "$output_dir" "$keycloak_container_name" "${sans[@]}"
  
  log "Keycloak TLS certificates generated at $output_dir"
}

# Inject Keycloak CA into a Kind cluster
inject_keycloak_ca_into_cluster() {
  local kubeconfig="$1"
  local namespace="$2"
  local ca_file="$3"
  local secret_name="${4:-keycloak-ca}"
  
  log "Injecting Keycloak CA into cluster..."
  
  ensure_namespace "$kubeconfig" "$namespace"
  
  KUBECONFIG="$kubeconfig" $KUBECTL create configmap "$secret_name" \
    --from-file=ca.crt="$ca_file" \
    -n "$namespace" \
    --dry-run=client -o yaml | KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
  
  log "Keycloak CA injected as ConfigMap $secret_name in $namespace"
}

# Inject Keycloak hostname into Kind node's /etc/hosts
inject_keycloak_host_into_cluster() {
  local cluster_name="$1"
  local keycloak_ip="$2"
  local keycloak_hostname="${3:-$KEYCLOAK_CONTAINER_NAME}"
  
  local node_name="${cluster_name}-control-plane"
  
  log "Injecting Keycloak hostname into $node_name: $keycloak_hostname -> $keycloak_ip"
  inject_hostname_into_node "$node_name" "$keycloak_ip" "$keycloak_hostname"
  
  # Also add common aliases
  inject_hostname_into_node "$node_name" "$keycloak_ip" "keycloak"
}

# Get the Keycloak issuer URL for IdentityProvider configuration
get_keycloak_issuer_url() {
  local realm="${1:-$KEYCLOAK_REALM}"
  local keycloak_host="${2:-$KEYCLOAK_CONTAINER_NAME}"
  local port="${3:-8080}"
  local scheme="${4:-http}"
  
  echo "${scheme}://${keycloak_host}:${port}/realms/${realm}"
}

# Create IdentityProvider CR pointing to Keycloak
create_keycloak_identity_provider() {
  local kubeconfig="$1"
  local name="$2"
  local realm="${3:-$KEYCLOAK_REALM}"
  local keycloak_host="${4:-$KEYCLOAK_CONTAINER_NAME}"
  local ca_pem="${5:-}"
  local primary="${6:-false}"
  
  local issuer_url
  issuer_url=$(get_keycloak_issuer_url "$realm" "$keycloak_host" "8080" "http")
  
  log "Creating IdentityProvider $name pointing to $issuer_url"
  
  local idp_yaml="apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: $name
spec:
  displayName: \"Keycloak E2E ($realm)\"
  primary: $primary
  issuer: \"$issuer_url\"
  oidc:
    authority: \"$issuer_url\"
    clientID: \"breakglass\"
    insecureSkipVerify: true"
  
  # Add CA if provided
  if [ -n "$ca_pem" ] && [ -f "$ca_pem" ]; then
    local ca_content
    ca_content=$(cat "$ca_pem" | base64 | tr -d '\n')
    idp_yaml="$idp_yaml
    certificateAuthority: \"$ca_content\""
  fi
  
  echo "$idp_yaml" | KUBECONFIG="$kubeconfig" $KUBECTL apply -f -
}

log "Common E2E library loaded"
